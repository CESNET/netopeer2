/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server - NETCONF server
 *
 * Copyright (c) 2019 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <sys/cdefs.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <stdio.h>
#include <pwd.h>
#include <grp.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "config.h"
#include "common.h"
#include "compat.h"
#include "err_netconf.h"
#include "log.h"
#include "netconf.h"
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
# include "netconf_server.h"
#endif
#ifdef NC_ENABLED_SSH
# include "netconf_server_ssh.h"
#endif
#ifdef NC_ENABLED_TLS
# include "netconf_server_tls.h"
#endif
#include "netconf_acm.h"
#include "netconf_monitoring.h"
#include "netconf_nmda.h"
#include "netconf_subscribed_notifications.h"
#include "yang_push.h"

/** @brief flag for main loop */
ATOMIC_T loop_continue = 1;

/* NETCONF SID of session to skip diff check for */
ATOMIC_T skip_nacm_nc_sid;

static void *worker_thread(void *arg);

/**
 * @brief Signal handler to control the process
 */
static void
signal_handler(int sig)
{
    static int quit = 0;

    switch (sig) {
    case SIGINT:
    case SIGTERM:
    case SIGQUIT:
    case SIGABRT:
    case SIGHUP:
        /* stop the process */
        if (quit == 0) {
            /* first attempt */
            quit = 1;
        } else {
            /* second attempt */
            exit(EXIT_FAILURE);
        }
        ATOMIC_STORE_RELAXED(loop_continue, 0);
        break;
    default:
        exit(EXIT_FAILURE);
    }
}

static void
np2srv_del_session_cb(struct nc_session *session)
{
    int i, rc;
    char *host = NULL;
    sr_val_t *event_data;
    struct np2_user_sess *user_sess;
    const struct lys_module *mod;

    if (nc_ps_del_session(np2srv.nc_ps, session)) {
        ERR("Removing session from ps failed.");
    }

    /* terminate any subscriptions for the NETCONF session */
    np2srv_sub_ntf_session_destroy(session);

    /* stop sysrepo session subscriptions */
    user_sess = nc_session_get_data(session);
    sr_session_unsubscribe(user_sess->sess);

    /* stop sysrepo session, if no callback is using it */
    np_release_user_sess(user_sess);

    if ((mod = ly_ctx_get_module_implemented(sr_get_context(np2srv.sr_conn), "ietf-netconf-notifications"))) {
        /* generate ietf-netconf-notification's netconf-session-end event for sysrepo */
        if (nc_session_get_ti(session) != NC_TI_UNIX) {
            host = (char *)nc_session_get_host(session);
        }
        event_data = calloc(5, sizeof *event_data);
        i = 0;

        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/username";
        event_data[i].type = SR_STRING_T;
        event_data[i++].data.string_val = (char *)nc_session_get_username(session);
        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/session-id";
        event_data[i].type = SR_UINT32_T;
        event_data[i++].data.uint32_val = nc_session_get_id(session);
        if (host) {
            event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/source-host";
            event_data[i].type = SR_STRING_T;
            event_data[i++].data.string_val = host;
        }
        if (nc_session_get_killed_by(session)) {
            event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/killed-by";
            event_data[i].type = SR_UINT32_T;
            event_data[i++].data.uint32_val = nc_session_get_killed_by(session);
        }
        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/termination-reason";
        event_data[i].type = SR_ENUM_T;
        switch (nc_session_get_term_reason(session)) {
        case NC_SESSION_TERM_CLOSED:
            event_data[i++].data.enum_val = "closed";
            break;
        case NC_SESSION_TERM_KILLED:
            event_data[i++].data.enum_val = "killed";
            break;
        case NC_SESSION_TERM_DROPPED:
            event_data[i++].data.enum_val = "dropped";
            break;
        case NC_SESSION_TERM_TIMEOUT:
            event_data[i++].data.enum_val = "timeout";
            break;
        default:
            event_data[i++].data.enum_val = "other";
            break;
        }
        rc = sr_event_notif_send(np2srv.sr_sess, "/ietf-netconf-notifications:netconf-session-end", event_data, i,
                np2srv.sr_timeout, 1);
        if (rc != SR_ERR_OK) {
            WRN("Failed to send a notification (%s).", sr_strerror(rc));
        } else {
            VRB("Generated new event (netconf-session-end).");
        }
        free(event_data);
    }

    /* stop monitoring and free NC session */
    ncm_session_del(session);
    nc_session_free(session, NULL);
}

static struct lyd_node *
np2srv_err_nc(sr_error_info_err_t *err)
{
    struct lyd_node *e = NULL, *err_info = NULL;
    const char *err_type, *err_tag, *err_msg, *str, *str2;
    uint32_t err_idx;

    /* mandatory */
    err_idx = 0;
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)&err_type)) {
        WRN("Missing NETCONF error \"error-type\".");
        goto error;
    } else if (sr_get_error_data(err, err_idx++, NULL, (const void **)&err_tag)) {
        WRN("Missing NETCONF error \"error-tag\".");
        goto error;
    } else if (sr_get_error_data(err, err_idx++, NULL, (const void **)&err_msg)) {
        WRN("Missing NETCONF error \"error-message\".");
        goto error;
    }
    /* rpc-error */
    if (lyd_new_opaq2(NULL, sr_get_context(np2srv.sr_conn), "rpc-error", NULL, NULL, NC_NS_BASE, &e)) {
        goto error;
    }
    /* error-type */
    if (lyd_new_opaq2(e, NULL, "error-type", err_type, NULL, NC_NS_BASE, NULL)) {
        goto error;
    }
    /* error-tag */
    if (lyd_new_opaq2(e, NULL, "error-tag", err_tag, NULL, NC_NS_BASE, NULL)) {
        goto error;
    }
    /* error-severity */
    if (lyd_new_opaq2(e, NULL, "error-severity", "error", NULL, NC_NS_BASE, NULL)) {
        goto error;
    }
    /* error-message */
    if (nc_err_set_msg(e, err_msg, "en")) {
        goto error;
    }

    /* error-app-tag */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)&str)) {
        return e;
    }
    if (str[0]) {
        if (nc_err_set_app_tag(e, str)) {
            goto error;
        }
    }
    /* error-path */
    if (sr_get_error_data(err, err_idx++, NULL, (const void **)&str)) {
        return e;
    }
    if (str[0]) {
        if (nc_err_set_path(e, str)) {
            goto error;
        }
    }
    /* error-info */
    while (!sr_get_error_data(err, err_idx++, NULL, (const void **)&str) &&
            !sr_get_error_data(err, err_idx++, NULL, (const void **)&str2)) {
        if (!err_info) {
            if (lyd_new_opaq2(e, NULL, "error-info", NULL, NULL, NC_NS_BASE, &err_info)) {
                goto error;
            }
        }
        if (lyd_new_opaq2(err_info, NULL, str, str2, NULL, NC_NS_BASE, NULL)) {
            goto error;
        }
    }

    return e;

error:
    lyd_free_tree(e);
    return NULL;
}

static struct nc_server_reply *
np2srv_err_reply_sr(const sr_error_info_t *err_info)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node *e;
    size_t i;

    /* try to find a NETCONF error */
    for (i = 0; i < err_info->err_count; ++i) {
        if (err_info->err[i].error_format && !strcmp(err_info->err[i].error_format, "NETCONF")) {
            /* NETCONF error */
            e = np2srv_err_nc(&err_info->err[i]);
            if (e) {
                reply = nc_server_reply_err(e);
            }
            break;
        }
    }

    if (reply) {
        /* return just the NETCONF error */
        return reply;
    }

    for (i = 0; i < err_info->err_count; ++i) {
        /* generic error */
        e = nc_err(sr_get_context(np2srv.sr_conn), NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, err_info->err[i].message, "en");

        if (reply) {
            nc_server_reply_add_err(reply, e);
        } else {
            reply = nc_server_reply_err(e);
        }
        e = NULL;
    }

    return reply;
}

/**
 * @brief Callback for libnetconf2 handling all the RPCs.
 */
static struct nc_server_reply *
np2srv_rpc_cb(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_user_sess *user_sess;
    const struct lyd_node *denied;
    struct lyd_node *node;
    const sr_error_info_t *err_info;
    struct nc_server_reply *reply = NULL;
    struct lyd_node *output, *child = NULL;
    NC_WD_MODE nc_wd;
    struct lyd_node *e;
    char *str;
    int rc;

    /* check NACM */
    if ((denied = ncac_check_operation(rpc, nc_session_get_username(ncs)))) {
        e = nc_err(LYD_CTX(rpc), NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_APP);

        /* set path */
        str = lysc_path(denied->schema, LYSC_PATH_LOG, NULL, 0);
        nc_err_set_path(e, str);
        free(str);

        /* set message */
        asprintf(&str, "Executing the operation is denied because \"%s\" NACM authorization failed.", nc_session_get_username(ncs));
        nc_err_set_msg(e, str, "en");
        free(str);

        return nc_server_reply_err(e);
    }

    /* get this user session with its originator data, no need to use ref-count */
    user_sess = nc_session_get_data(ncs);

    /* sysrepo API, use the default timeout or slightly higher than the configured one */
    rc = sr_rpc_send_tree(user_sess->sess, rpc, np2srv.sr_timeout ? np2srv.sr_timeout + 2000 : 0, &output);
    if (rc) {
        ERR("Failed to send an RPC (%s).", sr_strerror(rc));

        /* build proper error */
        sr_session_get_error(user_sess->sess, &err_info);
        return np2srv_err_reply_sr(err_info);
    }

    /* build RPC Reply */
    if (output) {
        LY_LIST_FOR(lyd_child(output), child) {
            if (!(child->flags & LYD_DEFAULT)) {
                break;
            }
        }
    }
    if (child) {
        /* get with-defaults mode */
        if (!strcmp(rpc->schema->module->name, "ietf-netconf")) {
            /* augment */
            lyd_find_path(rpc, "ietf-netconf-with-defaults:with-defaults", 0, &node);
        } else if (!lys_find_child(rpc->schema, rpc->schema->module, "with-defaults", 0, LYS_LEAF, 0)) {
            /* no with-defaults mode */
            node = NULL;
        } else {
            /* grouping */
            lyd_find_path(rpc, "with-defaults", 0, &node);
        }
        if (node) {
            if (!strcmp(lyd_get_value(node), "report-all")) {
                nc_wd = NC_WD_ALL;
            } else if (!strcmp(lyd_get_value(node), "report-all-tagged")) {
                nc_wd = NC_WD_ALL_TAG;
            } else if (!strcmp(lyd_get_value(node), "trim")) {
                nc_wd = NC_WD_TRIM;
            } else {
                nc_wd = NC_WD_EXPLICIT;
            }
        } else {
            nc_server_get_capab_withdefaults(&nc_wd, NULL);
        }

        reply = nc_server_reply_data(output, nc_wd, NC_PARAMTYPE_FREE);
    } else {
        lyd_free_siblings(output);
        reply = nc_server_reply_ok();
    }

    return reply;
}

static int
np2srv_diff_check_cb(sr_session_ctx_t *session, const struct lyd_node *diff)
{
    const struct lyd_node *node;
    char *path;
    const char *user;
    uint32_t *nc_sid;

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_sid);
    if (ATOMIC_LOAD_RELAXED(skip_nacm_nc_sid) == *nc_sid) {
        /* skip the NACM check */
        return SR_ERR_OK;
    }

    sr_session_get_orig_data(session, 1, NULL, (const void **)&user);
    if ((node = ncac_check_diff(diff, user))) {
        /* access denied */
        path = lysc_path(node->schema, LYSC_PATH_LOG, NULL, 0);
        np_err_nacm_access_denied(session, node->schema->module->name, user, path);
        free(path);
        return SR_ERR_UNAUTHORIZED;
    }

    return SR_ERR_OK;
}

static int
np2srv_check_schemas(sr_session_ctx_t *sr_sess)
{
    const char *mod_name;
    const struct lys_module *mod;
    const struct ly_ctx *ly_ctx;

#define NP2_CHECK_MODULE(name) \
    mod = ly_ctx_get_module_implemented(ly_ctx, name); \
    if (!mod) { \
        ERR("Module \"%s\" not implemented in sysrepo.", name); \
        return -1; \
    }

#define NP2_CHECK_FEATURE(name) \
    if (lys_feature_value(mod, name) != LY_SUCCESS) { \
        ERR("Module \"%s\" feature \"%s\" not enabled in sysrepo.", mod_name, name); \
        return -1; \
    }

    ly_ctx = sr_get_context(sr_session_get_connection(sr_sess));

    /* check that internally used schemas are implemented and with required features: ietf-netconf, ... */
    mod_name = "ietf-netconf";
    NP2_CHECK_MODULE(mod_name);
    NP2_CHECK_FEATURE("writable-running");
    NP2_CHECK_FEATURE("candidate");
    NP2_CHECK_FEATURE("rollback-on-error");
    NP2_CHECK_FEATURE("validate");
    NP2_CHECK_FEATURE("startup");
#ifdef NP2SRV_URL_CAPAB
    NP2_CHECK_FEATURE("url");
#endif
    NP2_CHECK_FEATURE("xpath");

    /* ... ietf-netconf-acm, */
    mod_name = "ietf-netconf-acm";
    NP2_CHECK_MODULE(mod_name);

    /* ... ietf-netconf-monitoring (leave get-schema RPC empty, libnetconf2 will use its callback), */
    mod_name = "ietf-netconf-monitoring";
    NP2_CHECK_MODULE(mod_name);

    /* ... ietf-netconf-with-defaults, */
    mod_name = "ietf-netconf-with-defaults";
    NP2_CHECK_MODULE(mod_name);

    /* ... ietf-netconf-notifications (must be implemented in sysrepo), */
    mod_name = "ietf-netconf-notifications";
    NP2_CHECK_MODULE(mod_name);
    mod_name = "nc-notifications";
    NP2_CHECK_MODULE(mod_name);
    mod_name = "notifications";
    NP2_CHECK_MODULE(mod_name);

    mod_name = "ietf-yang-library";
    NP2_CHECK_MODULE(mod_name);

    /* .. ietf-netconf-server */
    mod_name = "ietf-netconf-server";
    NP2_CHECK_MODULE(mod_name);
    NP2_CHECK_FEATURE("ssh-listen");
    NP2_CHECK_FEATURE("ssh-call-home");

    return 0;
}

static char *
np2srv_content_id_cb(void *UNUSED(user_data))
{
    char buf[11];
    uint32_t content_id;

    content_id = sr_get_content_id(np2srv.sr_conn);
    sprintf(buf, "%u", content_id);
    return strdup(buf);
}

static int
server_init(void)
{
    const struct ly_ctx *ly_ctx;
    int rc;

    /* connect to the sysrepo and set edit-config NACM diff check callback */
    rc = sr_connect(SR_CONN_CACHE_RUNNING, &np2srv.sr_conn);
    if (rc != SR_ERR_OK) {
        ERR("Connecting to sysrepo failed (%s).", sr_strerror(rc));
        goto error;
    }
    sr_set_diff_check_callback(np2srv.sr_conn, np2srv_diff_check_cb);

    ly_ctx = sr_get_context(np2srv.sr_conn);

    /* set the content-id callback */
    nc_server_set_content_id_clb(np2srv_content_id_cb, NULL, NULL);

    /* server session */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &np2srv.sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Creating sysrepo session failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* check libyang context */
    if (np2srv_check_schemas(np2srv.sr_sess)) {
        goto error;
    }

    /* init monitoring */
    ncm_init();

    /* init NACM */
    ncac_init();

    /* init libnetconf2 (it modifies only the dictionary) */
    if (nc_server_init((struct ly_ctx *)ly_ctx)) {
        goto error;
    }

    /* prepare poll session structure for libnetconf2 */
    np2srv.nc_ps = nc_ps_new();

    /* set with-defaults capability basic-mode */
    nc_server_set_capab_withdefaults(NC_WD_EXPLICIT, NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT);

    /* set capabilities for the NETCONF Notifications */
    nc_server_set_capability("urn:ietf:params:netconf:capability:notification:1.0");
    nc_server_set_capability("urn:ietf:params:netconf:capability:interleave:1.0");

    /* set URL capability */
    if (np2srv_url_setcap()) {
        goto error;
    }

    /* set libnetconf2 global PRC callback */
    nc_set_global_rpc_clb(np2srv_rpc_cb);

#ifdef NC_ENABLED_SSH
    /* set libnetconf2 SSH callbacks */
    nc_server_ssh_set_hostkey_clb(np2srv_hostkey_cb, NULL, NULL);
    nc_server_ssh_set_pubkey_auth_clb(np2srv_pubkey_auth_cb, NULL, NULL);
#endif

#ifdef NC_ENABLED_TLS
    /* set libnetconf2 TLS callbacks */
    nc_server_tls_set_server_cert_clb(np2srv_cert_cb, NULL, NULL);
    nc_server_tls_set_trusted_cert_list_clb(np2srv_cert_list_cb, NULL, NULL);
#endif

    /* UNIX socket */
    if (np2srv.unix_path) {
        if (nc_server_add_endpt("unix", NC_TI_UNIX)) {
            goto error;
        }

        if (nc_server_endpt_set_perms("unix", np2srv.unix_mode, np2srv.unix_uid, np2srv.unix_gid)) {
            goto error;
        }

        if (nc_server_endpt_set_address("unix", np2srv.unix_path)) {
            goto error;
        }
    }

    return 0;

error:
    ERR("Server init failed.");
    return -1;
}

static void
server_destroy(void)
{
    struct nc_session *sess;

    /* stop subscriptions */
    sr_unsubscribe(np2srv.sr_rpc_sub);
    sr_unsubscribe(np2srv.sr_data_sub);
    sr_unsubscribe(np2srv.sr_notif_sub);

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    /* remove all CH clients so they do not reconnect */
    nc_server_ch_del_client(NULL);
#endif

    /* close all open sessions */
    if (np2srv.nc_ps) {
        while (nc_ps_session_count(np2srv.nc_ps)) {
            sess = nc_ps_get_session(np2srv.nc_ps, 0);
            nc_session_set_term_reason(sess, NC_SESSION_TERM_OTHER);
            np2srv_del_session_cb(sess);
        }
        nc_ps_free(np2srv.nc_ps);
    }

    /* libnetconf2 cleanup */
    nc_server_destroy();

    /* UNIX socket can now be removed */
    if (np2srv.unix_path) {
        unlink(np2srv.unix_path);
    }

    /* monitoring cleanup */
    ncm_destroy();

    /* NACM cleanup */
    ncac_destroy();

    /* ietf-subscribed-notifications cleanup */
    np2srv_sub_ntf_destroy();

    /* removes the context and clears all the sessions */
    sr_disconnect(np2srv.sr_conn);
}

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)

static int
np2srv_dummy_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    return SR_ERR_OK;
}

#endif

static int
server_rpc_subscribe(void)
{
    int rc;

#define SR_RPC_SUBSCR(xpath, cb) \
    rc = sr_rpc_subscribe_tree(np2srv.sr_sess, xpath, cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &np2srv.sr_rpc_sub); \
    if (rc != SR_ERR_OK) { \
        ERR("Subscribing for \"%s\" RPC failed (%s).", xpath, sr_strerror(rc)); \
        goto error; \
    }

    /* subscribe to standard supported RPCs */
    if (np2srv.sr_rpc_sub) {
        EINT;
        goto error;
    }
    SR_RPC_SUBSCR("/ietf-netconf:get-config", np2srv_rpc_get_cb);
    SR_RPC_SUBSCR("/ietf-netconf:edit-config", np2srv_rpc_editconfig_cb);
    SR_RPC_SUBSCR("/ietf-netconf:copy-config", np2srv_rpc_copyconfig_cb);
    SR_RPC_SUBSCR("/ietf-netconf:delete-config", np2srv_rpc_deleteconfig_cb);
    SR_RPC_SUBSCR("/ietf-netconf:lock", np2srv_rpc_un_lock_cb);
    SR_RPC_SUBSCR("/ietf-netconf:unlock", np2srv_rpc_un_lock_cb);
    SR_RPC_SUBSCR("/ietf-netconf:get", np2srv_rpc_get_cb);
    /* keep close-session empty so that internal lnc2 callback is used */
    SR_RPC_SUBSCR("/ietf-netconf:kill-session", np2srv_rpc_kill_cb);
    SR_RPC_SUBSCR("/ietf-netconf:commit", np2srv_rpc_commit_cb);
    SR_RPC_SUBSCR("/ietf-netconf:discard-changes", np2srv_rpc_discard_cb);
    SR_RPC_SUBSCR("/ietf-netconf:validate", np2srv_rpc_validate_cb);

    /* subscribe to create-subscription */
    SR_RPC_SUBSCR("/notifications:create-subscription", np2srv_rpc_subscribe_cb);

    /* subscribe to NMDA RPCs */
    SR_RPC_SUBSCR("/ietf-netconf-nmda:get-data", np2srv_rpc_getdata_cb);
    SR_RPC_SUBSCR("/ietf-netconf-nmda:edit-data", np2srv_rpc_editdata_cb);

    /* subscribe to ietf-subscribed-notifications RPCs */
    SR_RPC_SUBSCR("/ietf-subscribed-notifications:establish-subscription", np2srv_rpc_establish_sub_cb);
    SR_RPC_SUBSCR("/ietf-subscribed-notifications:modify-subscription", np2srv_rpc_modify_sub_cb);
    SR_RPC_SUBSCR("/ietf-subscribed-notifications:delete-subscription", np2srv_rpc_delete_sub_cb);
    SR_RPC_SUBSCR("/ietf-subscribed-notifications:kill-subscription", np2srv_rpc_kill_sub_cb);

    /* one more yang-push RPC */
    SR_RPC_SUBSCR("/ietf-yang-push:resync-subscription", np2srv_rpc_resync_sub_cb);

    return 0;

error:
    ERR("Server RPC subscribe failed.");
    return -1;
}

static int
server_data_subscribe(void)
{
    const char *mod_name, *xpath;
    int rc;

#define SR_OPER_SUBSCR(mod_name, xpath, cb) \
    rc = sr_oper_get_items_subscribe(np2srv.sr_sess, mod_name, xpath, cb, NULL, SR_SUBSCR_CTX_REUSE, &np2srv.sr_data_sub); \
    if (rc != SR_ERR_OK) { \
        ERR("Subscribing for providing \"%s\" state data failed (%s).", mod_name, sr_strerror(rc)); \
        goto error; \
    }

#define SR_CONFIG_SUBSCR(mod_name, xpath, cb) \
    rc = sr_module_change_subscribe(np2srv.sr_sess, mod_name, xpath, cb, NULL, 0, \
            SR_SUBSCR_CTX_REUSE | SR_SUBSCR_DONE_ONLY | SR_SUBSCR_ENABLED, &np2srv.sr_data_sub); \
    if (rc != SR_ERR_OK) { \
        ERR("Subscribing for \"%s\" data changes failed (%s).", mod_name, sr_strerror(rc)); \
        goto error; \
    }

    /* subscribe for providing state data */
    if (np2srv.sr_data_sub) {
        EINT;
        goto error;
    }
    mod_name = "ietf-netconf-monitoring";
    SR_OPER_SUBSCR(mod_name, "/ietf-netconf-monitoring:netconf-state", np2srv_ncm_oper_cb);

    mod_name = "nc-notifications";
    SR_OPER_SUBSCR(mod_name, "/nc-notifications:netconf", np2srv_nc_ntf_oper_cb);

    /*
     * ietf-subscribed-notifications
     */
    mod_name = "ietf-subscribed-notifications";
    xpath = "/ietf-subscribed-notifications:filters";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_config_sub_ntf_filters_cb);

    /* operational data */
    SR_OPER_SUBSCR(mod_name, "/ietf-subscribed-notifications:streams", np2srv_oper_sub_ntf_streams_cb);
    SR_OPER_SUBSCR(mod_name, "/ietf-subscribed-notifications:subscriptions", np2srv_oper_sub_ntf_subscriptions_cb);

    /*
     * ietf-netconf-server
     */
    mod_name = "ietf-netconf-server";

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    xpath = "/ietf-netconf-server:netconf-server/listen/idle-timeout";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_idle_timeout_cb);
#endif

#ifdef NC_ENABLED_SSH
    /* subscribe for server SSH listen configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_ssh_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh/tcp-server-parameters";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tcp_params_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/server-identity/host-key/"
            "public-key/keystore-reference";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_ssh_hostkey_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/"
            "supported-authentication-methods";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_ssh_auth_methods_cb);

    /* subscribe for providing SSH operational data */
    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/ssh/ssh-server-parameters/client-authentication/users";
    SR_OPER_SUBSCR(mod_name, xpath, np2srv_endpt_ssh_auth_users_oper_cb);
#endif

#ifdef NC_ENABLED_TLS
    /* subscribe for server TLS listen configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/tls";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tls_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/tls/tcp-server-parameters";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tcp_params_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/server-identity/keystore-reference";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tls_servercert_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/client-authentication";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tls_client_auth_cb);

    xpath = "/ietf-netconf-server:netconf-server/listen/endpoint/tls/tls-server-parameters/client-authentication/cert-maps";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_endpt_tls_client_ctn_cb);
#endif

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    /* subscribe for generic Call Home configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/connection-type";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_connection_type_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/reconnect-strategy";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_reconnect_strategy_cb);
#endif

#ifdef NC_ENABLED_SSH
    /* subscribe for server SSH Call Home configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_ssh_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/tcp-client-parameters";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tcp_params_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/ssh-server-parameters/"
            "server-identity/host-key/public-key/keystore-reference";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_endpt_ssh_hostkey_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/ssh/ssh-server-parameters/"
            "client-authentication/supported-authentication-methods";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_endpt_ssh_auth_methods_cb);
#endif

#ifdef NC_ENABLED_TLS
    /* subscribe for TLS Call Home configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tls_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tcp-client-parameters";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tcp_params_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
            "server-identity/keystore-reference";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tls_servercert_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
            "client-authentication";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tls_client_auth_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/endpoints/endpoint/tls/tls-server-parameters/"
            "client-authentication/cert-maps";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_endpt_tls_client_ctn_cb);
#endif

#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    /*
     * ietf-keystore (just for in-use operational data)
     */
    mod_name = "ietf-keystore";
    xpath = "/ietf-keystore:keystore/asymmetric-keys";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_dummy_cb);

    /*
     * ietf-truststore (just for in-use operational data)
     */
    mod_name = "ietf-truststore";
    xpath = "/ietf-truststore:truststore/certificates";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_dummy_cb);
#endif

    /*
     * ietf-netconf-acm
     */
    mod_name = "ietf-netconf-acm";
    xpath = "/ietf-netconf-acm:nacm";
    SR_CONFIG_SUBSCR(mod_name, xpath, ncac_nacm_params_cb);

    xpath = "/ietf-netconf-acm:nacm/groups/group";
    SR_CONFIG_SUBSCR(mod_name, xpath, ncac_group_cb);

    xpath = "/ietf-netconf-acm:nacm/rule-list";
    SR_CONFIG_SUBSCR(mod_name, xpath, ncac_rule_list_cb);

    xpath = "/ietf-netconf-acm:nacm/rule-list/rule";
    SR_CONFIG_SUBSCR(mod_name, xpath, ncac_rule_cb);

    /* state data */
    xpath = "/ietf-netconf-acm:nacm/denied-operations";
    SR_OPER_SUBSCR(mod_name, xpath, ncac_oper_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-data-writes";
    SR_OPER_SUBSCR(mod_name, xpath, ncac_oper_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-notifications";
    SR_OPER_SUBSCR(mod_name, xpath, ncac_oper_cb);

    return 0;

error:
    ERR("Server data subscribe failed.");
    return -1;
}

static void *
worker_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    int rc, idx = *((int *)arg);
    struct nc_session *ncs;

#ifdef NC_ENABLED_SSH
    nc_libssh_thread_verbosity(np2_libssh_verbose_level);
#endif

    while (ATOMIC_LOAD_RELAXED(loop_continue)) {
        /* try to accept new NETCONF sessions */
        if (nc_server_endpt_count()) {
            msgtype = nc_accept(0, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                if (np2srv_new_session_cb(NULL, ncs)) {
                    nc_session_free(ncs, NULL);
                    continue;
                }
            }
        }

        /* listen for incoming requests on active NETCONF sessions */
        rc = nc_ps_poll(np2srv.nc_ps, NP2SRV_POLL_IO_TIMEOUT, &ncs);

        if ((rc & (NC_PSPOLL_NOSESSIONS | NC_PSPOLL_TIMEOUT | NC_PSPOLL_ERROR)) && !(rc & NC_PSPOLL_SESSION_TERM)) {
            /* if there is no active session, timeout, or an error, rest for a while */
            np_sleep(NP2SRV_PS_BACKOFF_SLEEP);
            continue;
        }

        /* process the result of nc_ps_poll(), increase counters */
        if (rc & NC_PSPOLL_BAD_RPC) {
            ncm_session_bad_rpc(ncs);
            VRB("Session %d: thread %d event bad RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_RPC) {
            ncm_session_rpc(ncs);
            VRB("Session %d: thread %d event new RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_REPLY_ERROR) {
            ncm_session_rpc_reply_error(ncs);
            VRB("Session %d: thread %d event reply error.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_SESSION_TERM) {
            VRB("Session %d: thread %d event session terminated.", nc_session_get_id(ncs), idx);
            np2srv_del_session_cb(ncs);
        }
#ifdef NC_ENABLED_SSH
        else if (rc & NC_PSPOLL_SSH_CHANNEL) {
            /* a new SSH channel on existing session was created */
            VRB("Session %d: thread %d event new SSH channel.", nc_session_get_id(ncs), idx);
            msgtype = nc_session_accept_ssh_channel(ncs, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                if (np2srv_new_session_cb(NULL, ncs)) {
                    nc_session_free(ncs, NULL);
                    continue;
                }
            } else if (msgtype == NC_MSG_BAD_HELLO) {
                ncm_bad_hello(ncs);
            }
        }
#endif
    }

    /* cleanup */
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
    nc_thread_destroy();
#endif
    free(arg);
    return NULL;
}

static void
print_version(void)
{
    fprintf(stdout, "netopeer2-server %s\n", NP2SRV_VERSION);
    fprintf(stdout, "compile time: %s, %s\n", __DATE__, __TIME__);
}

static void
print_usage(char* progname)
{
    fprintf(stdout, "Usage: %s [-dhV] [-p path] [-U (path)] [-m mode] [-u uid] [-g gid] [-t timeout] [-v level] [-c category]\n", progname);
    fprintf(stdout, " -d         debug mode (do not daemonize and print verbose messages to stderr instead of syslog)\n");
    fprintf(stdout, " -h         display help\n");
    fprintf(stdout, " -V         show program version\n");
    fprintf(stdout, " -p path    path to pidfile (default path is \"%s\")\n", NP2SRV_PID_FILE_PATH);
    fprintf(stdout, " -U[path]   listen on a local UNIX socket (default path is \"%s\")\n", NP2SRV_UNIX_SOCK_PATH);
    fprintf(stdout, " -m mode    set mode for the listening UNIX socket\n");
    fprintf(stdout, " -u uid     set UID/user for the listening UNIX socket\n");
    fprintf(stdout, " -g gid     set GID/group for the listening UNIX socket\n");
    fprintf(stdout, " -t timeout timeout in seconds of all sysrepo functions (applying edit-config, reading data, ...),\n");
    fprintf(stdout, "            if 0 (default), the default sysrepo timeouts are used\n");
    fprintf(stdout, " -v level   verbose output level:\n");
    fprintf(stdout, "                0 - errors\n");
    fprintf(stdout, "                1 - errors and warnings\n");
    fprintf(stdout, "                2 - errors, warnings, and verbose messages\n");
#ifndef NDEBUG
    fprintf(stdout, " -c category[,category]*\n");
    fprintf(stdout, "            verbose debug level, print only these debug message categories\n");
# ifdef NC_ENABLED_SSH
    fprintf(stdout, "            categories: DICT, YANG, YIN, XPATH, DIFF, MSG, LN2DBG, SSH, SYSREPO\n");
# else
    fprintf(stdout, "            categories: DICT, YANG, YIN, XPATH, DIFF, MSG, LN2DBG, SYSREPO\n");
# endif
#else
    fprintf(stdout, " -c category[,category]*\n");
    fprintf(stdout, "            verbose debug level, NOT SUPPORTED in release build type\n");
#endif
    fprintf(stdout, "\n");
}

int
main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    int c, *idx, i;
    int daemonize = 1, verb = 0;
    int pidfd;
    const char *pidfile = NP2SRV_PID_FILE_PATH;
    char pid[8];
    char *ptr;
    struct passwd *pwd;
    struct group *grp;
    struct sigaction action;
    sigset_t block_mask;

    /* until daemonized, write messages to both syslog and stderr */
    openlog("netopeer2-server", LOG_PID, LOG_DAEMON);
    np2_stderr_log = 1;

    /* set the signal handler */
    sigfillset(&block_mask);
    action.sa_handler = signal_handler;
    action.sa_mask = block_mask;
    action.sa_flags = 0;
    sigaction(SIGINT, &action, NULL);
    sigaction(SIGQUIT, &action, NULL);
    sigaction(SIGABRT, &action, NULL);
    sigaction(SIGTERM, &action, NULL);
    sigaction(SIGHUP, &action, NULL);

    /* ignore SIGPIPE */
    action.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &action, NULL);

    /* process command line options */
    while ((c = getopt(argc, argv, "dhVp:U::m:u:g:t:v:c:")) != -1) {
        switch (c) {
        case 'd':
            daemonize = 0;
            break;
        case 'h':
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        case 'v':
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }
            verb = 1;

            c = atoi(optarg);
            /* normalize verbose level */
            np2_verbose_level = (c > NC_VERB_ERROR) ? ((c > NC_VERB_VERBOSE) ? NC_VERB_VERBOSE : c) : NC_VERB_ERROR;
            switch (np2_verbose_level) {
            case NC_VERB_ERROR:
                np2_sr_verbose_level = SR_LL_ERR;
                np2_libssh_verbose_level = 0;
                break;
            case NC_VERB_WARNING:
                np2_sr_verbose_level = SR_LL_WRN;
                np2_libssh_verbose_level = 1;
                break;
            case NC_VERB_VERBOSE:
                np2_sr_verbose_level = SR_LL_INF;
                np2_libssh_verbose_level = 1;
                break;
            }

            nc_verbosity(np2_verbose_level);
#ifdef NC_ENABLED_SSH
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
#endif
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
        case 'p':
            pidfile = optarg;
            break;
        case 'U':
            np2srv.unix_path = optarg ? optarg : NP2SRV_UNIX_SOCK_PATH;
            break;
        case 'm':
            np2srv.unix_mode = strtoul(optarg, &ptr, 8);
            if (*ptr || (np2srv.unix_mode > 0777)) {
                ERR("Invalid UNIX socket mode \"%s\".", optarg);
                return EXIT_FAILURE;
            }
            break;
        case 'u':
            np2srv.unix_uid = strtoul(optarg, &ptr, 10);
            if (*ptr) {
                pwd = getpwnam(optarg);
                if (!pwd) {
                    ERR("Invalid UNIX socket UID/user \"%s\".", optarg);
                    return EXIT_FAILURE;
                }
                np2srv.unix_uid = pwd->pw_uid;
            }
            break;
        case 'g':
            np2srv.unix_gid = strtoul(optarg, &ptr, 10);
            if (*ptr) {
                grp = getgrnam(optarg);
                if (!grp) {
                    ERR("Invalid UNIX socket GID/group \"%s\".", optarg);
                    return EXIT_FAILURE;
                }
                np2srv.unix_gid = grp->gr_gid;
            }
            break;
        case 't':
            np2srv.sr_timeout = strtoul(optarg, &ptr, 10);
            if (*ptr) {
                ERR("Invalid timeout value \"%s\".", optarg);
                return EXIT_FAILURE;
            }

            /* make ms from s */
            np2srv.sr_timeout *= 1000;
            break;
        case 'c':
#ifndef NDEBUG
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }

            /* set verbose for all, we change to debug later if requested */
            np2_verbose_level = NC_VERB_VERBOSE;
            np2_libssh_verbose_level = 1;

            ptr = strtok(optarg, ",");
            do {
                if (!strcmp(ptr, "DICT")) {
                    verb |= LY_LDGDICT;
                } else if (!strcmp(ptr, "XPATH")) {
                    verb |= LY_LDGXPATH;
                } else if (!strcmp(ptr, "MSG")) {
                    /* NETCONF messages - only lnc2 debug verbosity */
                    np2_verbose_level = NC_VERB_DEBUG;
                } else if (!strcmp(ptr, "LN2DBG")) {
                    np2_verbose_level = NC_VERB_DEBUG_LOWLVL;
# ifdef NC_ENABLED_SSH
                } else if (!strcmp(ptr, "SSH")) {
                    /* 2 should be always enough, 3 is too much useless info */
                    np2_libssh_verbose_level = 2;
# endif
                } else if (!strcmp(ptr, "SYSREPO")) {
                    np2_sr_verbose_level = SR_LL_DBG;
                } else {
                    ERR("Unknown debug message category \"%s\", use -h.", ptr);
                    return EXIT_FAILURE;
                }
            } while ((ptr = strtok(NULL, ",")));
            /* set final verbosity */
            nc_verbosity(np2_verbose_level);
# ifdef NC_ENABLED_SSH
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
# endif
            if (verb) {
                ly_log_level(LY_LLDBG);
                ly_log_dbg_groups(verb);
            }

            verb = 1;
            break;
#else
            WRN("-c parameter not supported in release build type.");
            break;
#endif

        default:
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    /* daemonize */
    if (daemonize == 1) {
        if (daemon(0, 0) != 0) {
            ERR("Daemonizing the server failed (%s).", strerror(errno));
            return EXIT_FAILURE;
        }

        /* from now print only to syslog, not stderr */
        np2_stderr_log = 0;
    }

    /* make sure we are the only instance - lock the PID file and write the PID */
    pidfd = open(pidfile, O_RDWR | O_CREAT, 0640);
    if (pidfd < 0) {
        ERR("Unable to open the PID file \"%s\" (%s).", pidfile, strerror(errno));
        return EXIT_FAILURE;
    }
    if (lockf(pidfd, F_TLOCK, 0) < 0) {
        close(pidfd);
        if (errno == EACCES || errno == EAGAIN) {
            ERR("Another instance of the Netopeer2 server is running.");
        } else {
            ERR("Unable to lock the PID file \"%s\" (%s).", pidfile, strerror(errno));
        }
        return EXIT_FAILURE;
    }
    if (ftruncate(pidfd, 0)) {
        ERR("Failed to truncate PID file (%s).", strerror(errno));
        close(pidfd);
        return EXIT_FAILURE;
    }
    c = snprintf(pid, sizeof(pid), "%d\n", getpid());
    if (write(pidfd, pid, c) < c) {
        ERR("Failed to write into PID file.");
        close(pidfd);
        return EXIT_FAILURE;
    }
    close(pidfd);

    /* set printer callbacks for the used libraries and set proper log levels */
    nc_set_print_clb(np2log_cb_nc2); /* libnetconf2 */
    ly_set_log_clb(np2log_cb_ly, 1); /* libyang */
    sr_log_set_cb(np2log_cb_sr); /* sysrepo, log level is checked by callback */

    /* initiate NETCONF server */
    if (server_init()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* subscribe to sysrepo */
    if (server_rpc_subscribe()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }
    if (server_data_subscribe()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* start additional worker threads */
    for (i = 1; i < NP2SRV_THREAD_COUNT; ++i) {
        idx = malloc(sizeof *idx);
        *idx = i;
        pthread_create(&np2srv.workers[*idx], NULL, worker_thread, idx);
    }

    /* one worker will use this thread */
    np2srv.workers[0] = pthread_self();
    idx = malloc(sizeof *idx);
    *idx = 0;
    worker_thread(idx);

    /* wait for other worker threads to finish */
    for (i = 1; i < NP2SRV_THREAD_COUNT; ++i) {
        c = pthread_join(np2srv.workers[i], NULL);
        if (c) {
            ERR("Failed to join worker thread %d (%s).", i, strerror(c));
        }
    }

cleanup:
    VRB("Server terminated.");

    /* remove PID file */
    unlink(pidfile);

    /* destroy the server */
    server_destroy();

    return ret;
}
