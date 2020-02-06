/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server - NETCONF server
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _POSIX_C_SOUCRE 199309L

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "config.h"
#include "common.h"
#include "log.h"
#include "netconf.h"
#include "netconf_server.h"
#include "netconf_server_ssh.h"
#include "netconf_server_tls.h"
#include "netconf_acm.h"
#include "netconf_monitoring.h"
#include "netconf_nmda.h"

/** @brief flag for main loop */
ATOMIC_T loop_continue = 1;

static void *worker_thread(void *arg);
static int np2srv_state_data_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

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

static struct lyd_node *
np2srv_ntf_get_data(sr_conn_ctx_t *sr_conn)
{
    struct lyd_node *root, *stream, *sr_data = NULL, *sr_mod, *rep_sup;
    struct ly_set *set;
    const struct ly_ctx *ly_ctx;
    const char *mod_name;
    char buf[26];
    int rc;

    ly_ctx = sr_get_context(sr_conn);

    root = lyd_new_path(NULL, ly_ctx, "/nc-notifications:netconf/streams", NULL, 0, 0);
    if (!root || !root->child) {
        goto error;
    }

    /* generic stream */
    stream = lyd_new_path(root, ly_ctx, "/nc-notifications:netconf/streams/stream[name='NETCONF']", NULL, 0, 0);
    if (!stream) {
        goto error;
    }
    if (!lyd_new_leaf(stream, stream->schema->module, "description",
                "Default NETCONF stream containing notifications from all the modules.")) {
        goto error;
    }
    if (!lyd_new_leaf(stream, stream->schema->module, "replaySupport", "true")) {
        goto error;
    }

    /* go through all the sysrepo modules */
    rc = sr_get_module_info(sr_conn, &sr_data);
    if (rc != SR_ERR_OK) {
        ERR("Failed to get sysrepo module info data (%s).", sr_strerror(rc));
        goto error;
    }
    LY_TREE_FOR(sr_data->child, sr_mod) {
        mod_name = ((struct lyd_node_leaf_list *)sr_mod->child)->value_str;

        /* generate information about the stream/module */
        stream = lyd_new(root->child, NULL, "stream");
        if (!stream) {
            goto error;
        }
        if (!lyd_new_leaf(stream, NULL, "name", mod_name)) {
            goto error;
        }
        if (!lyd_new_leaf(stream, NULL, "description", "Stream with all notifications of a module.")) {
            goto error;
        }

        set = lyd_find_path(sr_mod, "replay-support");
        if (!set) {
            EINT;
            goto error;
        }
        if (set->number == 1) {
            rep_sup = set->set.d[0];
        } else {
            rep_sup = NULL;
        }
        ly_set_free(set);

        if (!lyd_new_leaf(stream, NULL, "replaySupport", rep_sup ? "true" : "false")) {
            goto error;
        }
        if (rep_sup) {
            nc_time2datetime(((struct lyd_node_leaf_list *)rep_sup)->value.uint64, NULL, buf);
            if (!lyd_new_leaf(stream, NULL, "replayLogCreationTime", buf)) {
                goto error;
            }
        }
    }

    lyd_free_withsiblings(sr_data);
    return root;

error:
    lyd_free(root);
    lyd_free_withsiblings(sr_data);
    return NULL;
}

static int
np2srv_state_data_cb(sr_session_ctx_t *UNUSED(session), const char *module_name, const char *path,
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *data = NULL, *node;
    struct ly_set *set = NULL;
    int ret = SR_ERR_OK;

    /* get the full module state data tree */
    if (!strcmp(module_name, "ietf-netconf-monitoring")) {
        data = ncm_get_data(np2srv.sr_conn);
    } else if (!strcmp(module_name, "nc-notifications")) {
        data = np2srv_ntf_get_data(np2srv.sr_conn);
    } else {
        EINT;
        ret = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }

    /* find the requested top-level subtree */
    set = lyd_find_path(data, path);
    if (!set || !set->number) {
        ret = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }
    node = set->set.d[0];

    if (node->parent || *parent) {
        EINT;
        ret = SR_ERR_OPERATION_FAILED;
        goto cleanup;
    }

    /* return the subtree */
    if (node == data) {
        data = data->next;
    }
    lyd_unlink(node);
    *parent = node;

    /* success */

cleanup:
    ly_set_free(set);
    lyd_free_withsiblings(data);
    return ret;
}

static void
np2srv_del_session_cb(struct nc_session *session)
{
    int i, rc;
    char *host = NULL;
    sr_val_t *event_data;
    sr_session_ctx_t *sr_sess;
    const struct lys_module *mod;

    if (nc_ps_del_session(np2srv.nc_ps, session)) {
        ERR("Removing session from ps failed.");
    }

    /* stop sysrepo session (also stop any sysrepo notification subscriptions) */
    sr_sess = nc_session_get_data(session);
    sr_session_stop(sr_sess);

    switch (nc_session_get_ti(session)) {
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
        ncm_session_del(session);
        break;
#endif
    default:
        break;
    }

    if ((mod = ly_ctx_get_module(sr_get_context(np2srv.sr_conn), "ietf-netconf-notifications", NULL, 1))) {
        /* generate ietf-netconf-notification's netconf-session-end event for sysrepo */
        if (nc_session_get_ti(session) != NC_TI_UNIX) {
            host = (char *)nc_session_get_host(session);
        }
        event_data = calloc(5, sizeof *event_data);
        i = 0;

        event_data[i].xpath = "/ietf-netconf-notifications:netconf-session-end/username";
        event_data[i].type = SR_STRING_T;
        event_data[i++].data.string_val = (char*)nc_session_get_username(session);
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
        rc = sr_event_notif_send(np2srv.sr_sess, "/ietf-netconf-notifications:netconf-session-end", event_data, i);
        if (rc != SR_ERR_OK) {
            WRN("Failed to send a notification (%s).", sr_strerror(rc));
        } else {
            VRB("Generated new event (netconf-session-end).");
        }
        free(event_data);
    }

    nc_session_free(session, NULL);
}

static struct nc_server_error *
np2srv_err_sr(int err_code, const char *message, const char *xpath)
{
    struct nc_server_error *e;
    const char *ptr;

    switch (err_code) {
    case SR_ERR_LOCKED:
        ptr = strstr(message, "NC SID ");
        if (!ptr) {
            EINT;
            return NULL;
        }
        ptr += 7;
        e = nc_err(NC_ERR_LOCK_DENIED, atoi(ptr));
        nc_err_set_msg(e, message, "en");
        break;
    case SR_ERR_UNAUTHORIZED:
err_access_denied:
        e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, message, "en");
        if (xpath) {
            nc_err_set_path(e, xpath);
        }
        break;
    case SR_ERR_VALIDATION_FAILED:
        if (!strncmp(message, "When condition", 14)) {
            if (xpath) {
                EINT;
                return NULL;
            }
            e = nc_err(NC_ERR_UNKNOWN_ELEM, NC_ERR_TYPE_APP, xpath);
            nc_err_set_msg(e, message, "en");
            break;
        }
        /* fallthrough */
    default:
        if (strstr(message, "authorization failed")) {
            goto err_access_denied;
        }
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, message, "en");
        if (xpath) {
            nc_err_set_path(e, xpath);
        }
        break;
    }

    return e;
}

static struct nc_server_reply *
np2srv_err_reply_sr(const sr_error_info_t *err_info)
{
    struct nc_server_reply *reply = NULL;
    struct nc_server_error *e;
    size_t i;

    for (i = 0; i < err_info->err_count; ++i) {
        e = np2srv_err_sr(err_info->err_code, err_info->err[i].message, err_info->err[i].xpath);
        if (!e) {
            nc_server_reply_free(reply);
            return NULL;
        }

        if (reply) {
            nc_server_reply_add_err(reply, e);
        } else {
            reply = nc_server_reply_err(e);
        }
        e = NULL;
    }

    return reply;
}

static struct nc_server_reply *
np2srv_rpc_cb(struct lyd_node *rpc, struct nc_session *ncs)
{
    sr_session_ctx_t *sr_sess = NULL;
    const struct lyd_node *node;
    const sr_error_info_t *err_info;
    struct nc_server_reply *reply = NULL;
    struct lyd_node *output, *child = NULL;
    NC_WD_MODE nc_wd;
    struct nc_server_error *e;
    char *path;
    int rc;

    /* check NACM */
    if ((node = ncac_check_operation(rpc, nc_session_get_username(ncs)))) {
        e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_APP);
        path = lys_data_path(node->schema);
        nc_err_set_path(e, path);
        free(path);
        reply = nc_server_reply_err(e);
        goto cleanup;
    }

    /* create sysrepo session for this user notifications */
    rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &sr_sess);
    if (rc != SR_ERR_OK) {
        ERR("Failed to start a new SR session (%s).", sr_strerror(rc));
        goto cleanup;
    }
    sr_session_set_nc_id(sr_sess, nc_session_get_id(ncs));

    /* sysrepo API */
    rc = sr_rpc_send_tree(sr_sess, rpc, 0, &output);
    if (rc != SR_ERR_OK) {
        ERR("Failed to send an RPC (%s).", sr_strerror(rc));
        goto cleanup;
    }

    /* build RPC Reply */
    if (output) {
        LY_TREE_FOR(output->child, child) {
            if (!child->dflt) {
                break;
            }
        }
    }
    if (child) {
        nc_server_get_capab_withdefaults(&nc_wd, NULL);
        reply = nc_server_reply_data(output, nc_wd, NC_PARAMTYPE_FREE);
    } else {
        lyd_free_withsiblings(output);
        reply = nc_server_reply_ok();
    }

cleanup:
    if (!reply) {
        if (sr_sess) {
            sr_get_error(sr_sess, &err_info);
            reply = np2srv_err_reply_sr(err_info);
        } else {
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            reply = nc_server_reply_err(e);
        }
    }
    return reply;
}

static int
np2srv_diff_check_cb(sr_session_ctx_t *session, const struct lyd_node *diff)
{
    const struct lyd_node *node;
    char *path;

    if ((node = ncac_check_diff(diff, sr_session_get_user(session)))) {
        /* access denied */
        path = lys_data_path(node->schema);
        sr_set_error(session, path, "Access to the requested data model is denied because authorization failed.");
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

    ly_ctx = sr_get_context(sr_session_get_connection(sr_sess));

    /* check that internally used schemas are implemented and with required features: ietf-netconf, ... */
    mod_name = "ietf-netconf";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    if (lys_features_state(mod, "writable-running") != 1) {
        ERR("Module \"%s\" feature \"writable-running\" not enabled in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "candidate") != 1) {
        ERR("Module \"%s\" feature \"candidate\" not enabled in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "rollback-on-error") != 1) {
        ERR("Module \"%s\" feature \"rollback-on-error\" not enabled in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "validate") != 1) {
        ERR("Module \"%s\" feature \"validate\" not enabled in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "startup") != 1) {
        ERR("Module \"%s\" feature \"startup\" not enabled in sysrepo.", mod_name);
        return -1;
    }
#ifdef NP2SRV_URL_CAPAB
    if (lys_features_state(mod, "url") != 1) {
        ERR("Module \"%s\" feature \"url\" not enabled in sysrepo.", mod_name);
        return -1;
    }
#endif
    if (lys_features_state(mod, "xpath") != 1) {
        ERR("Module \"%s\" feature \"xpath\" not enabled in sysrepo.", mod_name);
        return -1;
    }

    /* ... ietf-netconf-acm, */
    mod_name = "ietf-netconf-acm";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    /* ... ietf-netconf-monitoring (leave get-schema RPC empty, libnetconf2 will use its callback), */
    mod_name = "ietf-netconf-monitoring";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    /* ... ietf-netconf-with-defaults, */
    mod_name = "ietf-netconf-with-defaults";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    /* ... ietf-netconf-notifications (must be implemented in sysrepo), */
    mod_name = "ietf-netconf-notifications";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }
    mod_name = "nc-notifications";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }
    mod_name = "notifications";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    mod_name = "ietf-yang-library";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }

    /* .. ietf-netconf-server */
    mod_name = "ietf-netconf-server";
    mod = ly_ctx_get_module(ly_ctx, mod_name, NULL, 1);
    if (!mod || !mod->implemented) {
        ERR("Module \"%s\" not implemented in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "ssh-listen") != 1) {
        ERR("Module \"%s\" feature \"ssh-listen\" not enabled in sysrepo.", mod_name);
        return -1;
    }
    if (lys_features_state(mod, "ssh-call-home") != 1) {
        ERR("Module \"%s\" feature \"ssh-call-home\" not enabled in sysrepo.", mod_name);
        return -1;
    }

    return 0;
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

    /* set libnetconf2 SSH callbacks */
    nc_server_ssh_set_hostkey_clb(np2srv_hostkey_cb, NULL, NULL);
    nc_server_ssh_set_pubkey_auth_clb(np2srv_pubkey_auth_cb, NULL, NULL);

    /* set libnetconf2 TLS callbacks */
    nc_server_tls_set_server_cert_clb(np2srv_cert_cb, NULL, NULL);
    nc_server_tls_set_trusted_cert_list_clb(np2srv_cert_list_cb, NULL, NULL);

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

static int
server_rpc_subscribe(void)
{
    const char *xpath;
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

    xpath = "/notifications:create-subscription";
    /* subscribes to notifications, needs special flag */
    rc = sr_rpc_subscribe_tree(np2srv.sr_sess, xpath, np2srv_rpc_subscribe_cb, NULL, 0, SR_SUBSCR_UNLOCKED | SR_SUBSCR_CTX_REUSE,
            &np2srv.sr_rpc_sub);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing for \"%s\" RPC failed (%s).", xpath, sr_strerror(rc));
        goto error;
    }

    /* subscribe to NMDA RPCs */
    SR_RPC_SUBSCR("/ietf-netconf-nmda:get-data", np2srv_rpc_getdata_cb);
    SR_RPC_SUBSCR("/ietf-netconf-nmda:edit-data", np2srv_rpc_editdata_cb);

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
    SR_OPER_SUBSCR(mod_name, "/ietf-netconf-monitoring:netconf-state", np2srv_state_data_cb);

    mod_name = "nc-notifications";
    SR_OPER_SUBSCR(mod_name, "/nc-notifications:netconf", np2srv_state_data_cb);

    /*
     * ietf-netconf-server
     */
    mod_name = "ietf-netconf-server";
    xpath = "/ietf-netconf-server:netconf-server/listen/idle-timeout";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_idle_timeout_cb);

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

    /* subscribe for generic Call Home configuration changes */
    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_client_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/connection-type";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_connection_type_cb);

    xpath = "/ietf-netconf-server:netconf-server/call-home/netconf-client/reconnect-strategy";
    SR_CONFIG_SUBSCR(mod_name, xpath, np2srv_ch_reconnect_strategy_cb);

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
    SR_OPER_SUBSCR(mod_name, xpath, ncac_state_data_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-data-writes";
    SR_OPER_SUBSCR(mod_name, xpath, ncac_state_data_cb);

    xpath = "/ietf-netconf-acm:nacm/denied-notifications";
    SR_OPER_SUBSCR(mod_name, xpath, ncac_state_data_cb);

    return 0;

error:
    ERR("Server data subscribe failed.");
    return -1;
}

static void *
worker_thread(void *arg)
{
    NC_MSG_TYPE msgtype;
    int rc, idx = *((int *)arg), monitored;
    struct nc_session *ncs;

    nc_libssh_thread_verbosity(np2_verbose_level);

    while (ATOMIC_LOAD_RELAXED(loop_continue)) {
        /* try to accept new NETCONF sessions */
        if (nc_server_endpt_count()
                && (!np2srv.nc_max_sessions || (nc_ps_session_count(np2srv.nc_ps) < np2srv.nc_max_sessions))) {
            msgtype = nc_accept(0, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                np2srv_new_session_cb(NULL, ncs);
            }
        }

        /* listen for incoming requests on active NETCONF sessions */
        rc = nc_ps_poll(np2srv.nc_ps, 0, &ncs);

        if ((rc & (NC_PSPOLL_NOSESSIONS | NC_PSPOLL_TIMEOUT | NC_PSPOLL_ERROR)) && !(rc & NC_PSPOLL_SESSION_TERM)) {
            /* if there is no active session, timeout, or an error, rest for a while */
            np_sleep(NP2SRV_PS_BACKOFF_SLEEP);
            continue;
        }

        switch (nc_session_get_ti(ncs)) {
#ifdef NC_ENABLED_SSH
        case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
        case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
            monitored = 1;
            break;
#endif
        default:
            monitored = 0;
            break;
        }

        /* process the result of nc_ps_poll(), increase counters */
        if (rc & NC_PSPOLL_BAD_RPC) {
            if (monitored) {
                ncm_session_bad_rpc(ncs);
            }
            VRB("Session %d: thread %d event bad RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_RPC) {
            if (monitored) {
                ncm_session_rpc(ncs);
            }
            VRB("Session %d: thread %d event new RPC.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_REPLY_ERROR) {
            if (monitored) {
                ncm_session_rpc_reply_error(ncs);
            }
            VRB("Session %d: thread %d event reply error.", nc_session_get_id(ncs), idx);
        }
        if (rc & NC_PSPOLL_SESSION_TERM) {
            VRB("Session %d: thread %d event session terminated.", nc_session_get_id(ncs), idx);
            np2srv_del_session_cb(ncs);
        } else if (rc & NC_PSPOLL_SSH_CHANNEL) {
            /* a new SSH channel on existing session was created */
            VRB("Session %d: thread %d event new SSH channel.", nc_session_get_id(ncs), idx);
            msgtype = nc_session_accept_ssh_channel(ncs, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                np2srv_new_session_cb(NULL, ncs);
            } else if (msgtype == NC_MSG_BAD_HELLO) {
                if (monitored) {
                    ncm_bad_hello();
                }
            }
        }
    }

    /* cleanup */
    nc_thread_destroy();
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
    fprintf(stdout, "Usage: %s [-dhV] [-U (path)] [-m mode] [-u uid] [-g gid] [-v level] [-c category]\n", progname);
    fprintf(stdout, " -d        debug mode (do not daemonize and print verbose messages to stderr instead of syslog)\n");
    fprintf(stdout, " -h        display help\n");
    fprintf(stdout, " -V        show program version\n");
    fprintf(stdout, " -U (path) listen on a local UNIX socket (specific path, default is \"%s\")\n", NP2SRV_UNIX_SOCK_PATH);
    fprintf(stdout, " -m mode   set mode for the listening UNIX socket\n");
    fprintf(stdout, " -u uid    set UID/user for the listening UNIX socket\n");
    fprintf(stdout, " -g gid    set GID/group for the listening UNIX socket\n");
    fprintf(stdout, " -v level  verbose output level:\n");
    fprintf(stdout, "               0 - errors\n");
    fprintf(stdout, "               1 - errors and warnings\n");
    fprintf(stdout, "               2 - errors, warnings, and verbose messages\n");
#ifndef NDEBUG
    fprintf(stdout, " -c category[,category]*\n");
    fprintf(stdout, "           verbose debug level, print only these debug message categories\n");
    fprintf(stdout, "           categories: DICT, YANG, YIN, XPATH, DIFF, MSG, SSH, SYSREPO\n");
#else
    fprintf(stdout, " -c category[,category]*\n");
    fprintf(stdout, "           verbose debug level, NOT SUPPORTED in release build type\n");
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
    char pid[8];
    char *ptr;
    struct passwd *pwd;
    struct group *grp;
    struct nc_session *sess;
    struct sigaction action;
    sigset_t block_mask;

    /* until daemonized, write messages to both syslog and stderr */
    openlog("netopeer2-server", LOG_PID, LOG_DAEMON);
    np2_stderr_log = 1;

    /* process command line options */
    while ((c = getopt(argc, argv, "dhVU::m:u:g:v:c:")) != -1) {
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
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
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
        case 'c':
#ifndef NDEBUG
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }

            /* set verbose for all, we change to debug later if requested */
            np2_verbose_level = NC_VERB_VERBOSE;
            nc_verbosity(np2_verbose_level);
            np2_libssh_verbose_level = 1;

            ptr = strtok(optarg, ",");
            do {
                if (!strcmp(ptr, "DICT")) {
                    verb |= LY_LDGDICT;
                } else if (!strcmp(ptr, "YANG")) {
                    verb |= LY_LDGYANG;
                } else if (!strcmp(ptr, "YIN")) {
                    verb |= LY_LDGYIN;
                } else if (!strcmp(ptr, "XPATH")) {
                    verb |= LY_LDGXPATH;
                } else if (!strcmp(ptr, "DIFF")) {
                    verb |= LY_LDGDIFF;
                } else if (!strcmp(ptr, "MSG")) {
                    /* NETCONF messages - only lnc2 debug verbosity */
                    nc_verbosity(NC_VERB_DEBUG);
                } else if (!strcmp(ptr, "SSH")) {
                    /* 2 should be always enough, 3 is too much useless info */
                    np2_libssh_verbose_level = 2;
                } else if (!strcmp(ptr, "SYSREPO")) {
                    np2_sr_verbose_level = SR_LL_DBG;
                } else {
                    ERR("Unknown debug message category \"%s\", use -h.", ptr);
                    return EXIT_FAILURE;
                }
            } while ((ptr = strtok(NULL, ",")));
            /* set final verbosity of libssh and libyang */
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
            if (verb) {
                ly_verb(LY_LLDBG);
                ly_verb_dbg(verb);
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
    pidfd = open(NP2SRV_PID_FILE_PATH, O_RDWR | O_CREAT, 0640);
    if (pidfd < 0) {
        ERR("Unable to open the PID file \"%s\" (%s).", NP2SRV_PID_FILE_PATH, strerror(errno));
        return EXIT_FAILURE;
    }
    if (lockf(pidfd, F_TLOCK, 0) < 0) {
        close(pidfd);
        if (errno == EACCES || errno == EAGAIN) {
            ERR("Another instance of the Netopeer2 server is running.");
        } else {
            ERR("Unable to lock the PID file \"%s\" (%s).", NP2SRV_PID_FILE_PATH, strerror(errno));
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

    /* stop subscriptions */
    sr_unsubscribe(np2srv.sr_rpc_sub);
    sr_unsubscribe(np2srv.sr_data_sub);
    sr_unsubscribe(np2srv.sr_notif_sub);

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

    /* monitoring cleanup */
    ncm_destroy();

    /* NACM cleanup */
    ncac_destroy();

    /* removes the context and clears all the sessions */
    sr_disconnect(np2srv.sr_conn);

    return ret;
}
