/**
 * @file main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server - NETCONF server
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>
#include <sysrepo/error_format.h>
#include <sysrepo/netconf_acm.h>
#include <sysrepo/subscribed_notifications.h>

#include "common.h"
#include "compat.h"
#include "config.h"
#include "log.h"
#include "netconf.h"
#include "netconf_confirmed_commit.h"
#include "netconf_monitoring.h"
#include "netconf_nmda.h"
#include "netconf_subscribed_notifications.h"

#ifdef HAVE_SIGACTION
# include <signal.h>
#endif

#ifdef NP2SRV_HAVE_SYSTEMD
# include <systemd/sd-daemon.h>
#endif

/** @brief flag for main loop */
ATOMIC_T loop_continue;

struct notification_capabilities {
    const char *name;
    const char *value;
};

/* Defines https://datatracker.ietf.org/doc/html/rfc9196#section-5 */
static const struct notification_capabilities notif_capas[] = {
    {"max-nodes-per-update", "4294967295"},
    {"periodic-notifications-supported", "config-changes state-changes"},
    {"minimum-update-period", "0"},
    {"on-change-supported", "config-changes state-changes"},
    {"minimum-dampening-period", "0"},
    {"supported-excluded-change-type", "all"}
};

static void *worker_thread(void *arg);

/**
 * @brief netopeer2 lib terminate function, unused in the binary.
 */
void
np2_server_terminate(void)
{
    ATOMIC_STORE_RELAXED(loop_continue, 0);
}

#ifdef HAVE_SIGACTION

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

#endif

/**
 * @brief Callback for deleting NC sessions.
 *
 * @param[in] session NC session to delete.
 */
static void
np2srv_del_session_cb(struct nc_session *session)
{
    struct np_user_sess *user_sess;
    uint32_t i;

    /* remove from PS structure */
    if (nc_ps_del_session(np2srv.nc_ps, session)) {
        ERR("Removing session from ps failed.");
    }

    /* terminate any subscriptions for the NETCONF session */
    np_sub_ntf_session_destroy(session);

    /* stop sysrepo session subscriptions */
    user_sess = nc_session_get_data(session);
    sr_session_unsubscribe(user_sess->sess);

    /* revert any pending confirmed commits */
    ncc_del_session(user_sess, np2srv.sr_sess);

    /* free sysrepo session, if no callback is using it */
    if (ATOMIC_DEC_RELAXED(user_sess->ref_count) == 1) {
        sr_session_stop(user_sess->sess);
        pthread_mutex_destroy(&user_sess->lock);

        for (i = 0; i < user_sess->ntf_arg.rt_notif_count; ++i) {
            lyd_free_tree(user_sess->ntf_arg.rt_notifs[i].notif);
        }

        free(user_sess);
    }

    /* generate ietf-netconf-notification's netconf-session-end event for sysrepo */
    np_send_notif_session_end(session, np2srv.sr_sess, np2srv.sr_timeout);

    /* stop monitoring and free NC session */
    ncm_session_del(session);
    nc_session_free(session, NULL);
}

/**
 * @brief Get the primary affected DS of a RPC, if any.
 *
 * @param[in] rpc RPC to use.
 * @return Affected datastore identity name with a prefix;
 * @return NULL if no affected datastore.
 */
static const char *
np_rpc_get_ds(const struct lyd_node *rpc)
{
    struct lyd_node *node;
    const char *ds_str = NULL;
    uint32_t temp_lo = 0;

    /* no logging */
    ly_temp_log_options(&temp_lo);

    if (!lyd_find_path(rpc, "target", 0, &node) || !lyd_find_path(rpc, "source", 0, &node)) {
        if (!strcmp(LYD_NAME(lyd_child(node)), "candidate")) {
            ds_str = "ietf-datastores:candidate";
        } else if (!strcmp(LYD_NAME(lyd_child(node)), "running")) {
            ds_str = "ietf-datastores:running";
        } else if (!strcmp(LYD_NAME(lyd_child(node)), "startup")) {
            ds_str = "ietf-datastores:startup";
        }
    } else if (!lyd_find_path(rpc, "datastore", 0, &node)) {
        ds_str = lyd_get_value(node);
    }

    ly_temp_log_options(NULL);
    return ds_str;
}

/**
 * @brief Callback for libnetconf2 handling all the RPCs.
 *
 * @param[in] rpc Received RPC to process.
 * @param[in] ncs NC session that received @p rpc.
 * @return Server reply structure.
 */
static struct nc_server_reply *
np2srv_rpc_cb(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np_user_sess *user_sess = NULL;
    struct nc_server_reply *reply = NULL;
    sr_data_t *output = NULL, *op_data = NULL;
    struct nc_server_reply *(*rpc_cb)(const struct lyd_node *rpc, struct np_user_sess *user_sess) = NULL;
    const char *ds_str;
    NC_RPL rpl_type;
    int rc;

    /* get the user session */
    if (np_acquire_user_sess(ncs, &user_sess)) {
        goto cleanup;
    }

    if (!strcmp(lyd_owner_module(rpc)->name, "ietf-netconf")) {
        /* ietf-netconf */
        if (!strcmp(LYD_NAME(rpc), "get-config")) {
            rpc_cb = np2srv_rpc_get_cb;
        } else if (!strcmp(LYD_NAME(rpc), "edit-config")) {
            rpc_cb = np2srv_rpc_editconfig_cb;
        } else if (!strcmp(LYD_NAME(rpc), "copy-config")) {
            rpc_cb = np2srv_rpc_copyconfig_cb;
        } else if (!strcmp(LYD_NAME(rpc), "delete-config")) {
            rpc_cb = np2srv_rpc_deleteconfig_cb;
        } else if (!strcmp(LYD_NAME(rpc), "lock") || !strcmp(LYD_NAME(rpc), "unlock")) {
            rpc_cb = np2srv_rpc_un_lock_cb;
        } else if (!strcmp(LYD_NAME(rpc), "get")) {
            rpc_cb = np2srv_rpc_get_cb;
        } else if (!strcmp(LYD_NAME(rpc), "close-session")) {
            /* lnc2 callback */
            reply = nc_clb_default_close_session(rpc, ncs);
            goto cleanup;
        } else if (!strcmp(LYD_NAME(rpc), "kill-session")) {
            rpc_cb = np2srv_rpc_kill_cb;
        } else if (!strcmp(LYD_NAME(rpc), "commit")) {
            rpc_cb = np2srv_rpc_commit_cb;
        } else if (!strcmp(LYD_NAME(rpc), "discard-changes")) {
            rpc_cb = np2srv_rpc_discard_cb;
        } else if (!strcmp(LYD_NAME(rpc), "cancel-commit")) {
            rpc_cb = np2srv_rpc_cancel_commit_cb;
        } else if (!strcmp(LYD_NAME(rpc), "validate")) {
            rpc_cb = np2srv_rpc_validate_cb;
        }
    } else if (!strcmp(lyd_owner_module(rpc)->name, "ietf-netconf-monitoring")) {
        /* ietf-netconf-monitoring */
        if (!strcmp(LYD_NAME(rpc), "get-schema")) {
            rpc_cb = np2srv_rpc_getschema_cb;
        }
    } else if (!strcmp(lyd_owner_module(rpc)->name, "notifications")) {
        /* notifications */
        if (!strcmp(LYD_NAME(rpc), "create-subscription")) {
            rpc_cb = np2srv_rpc_subscribe_cb;
        }
    } else if (!strcmp(lyd_owner_module(rpc)->name, "ietf-netconf-nmda")) {
        /* ietf-netconf-nmda */
        if (!strcmp(LYD_NAME(rpc), "get-data")) {
            rpc_cb = np2srv_rpc_getdata_cb;
        } else if (!strcmp(LYD_NAME(rpc), "edit-data")) {
            rpc_cb = np2srv_rpc_editdata_cb;
        }
    } else if (!strcmp(lyd_owner_module(rpc)->name, "ietf-subscribed-notifications")) {
        /* ietf-subscribed-notifications */
        if (!strcmp(LYD_NAME(rpc), "establish-subscription")) {
            rpc_cb = np2srv_rpc_establish_sub_cb;
        } else if (!strcmp(LYD_NAME(rpc), "modify-subscription")) {
            rpc_cb = np2srv_rpc_modify_sub_cb;
        } else if (!strcmp(LYD_NAME(rpc), "delete-subscription")) {
            rpc_cb = np2srv_rpc_delete_sub_cb;
        } else if (!strcmp(LYD_NAME(rpc), "kill-subscription")) {
            rpc_cb = np2srv_rpc_kill_sub_cb;
        }

        if (rpc_cb) {
            /* get filters for validation */
            if (sr_get_data(user_sess->sess, "/ietf-subscribed-notifications:filters", 0, 0, 0, &op_data)) {
                reply = np_reply_err_sr(user_sess->sess, "get");
                goto cleanup;
            }
        }
    } else if (!strcmp(lyd_owner_module(rpc)->name, "ietf-yang-push")) {
        /* ietf-yang-push */
        if (!strcmp(LYD_NAME(rpc), "resync-subscription")) {
            rpc_cb = np2srv_rpc_resync_sub_cb;
        }
    }

    if (rpc_cb) {
        if (lyd_validate_op(rpc, op_data ? op_data->tree : NULL, LYD_TYPE_RPC_YANG, NULL)) {
            /* validation failed */
            reply = np_reply_err_valid(LYD_CTX(rpc));
            goto cleanup;
        } else if (sr_nacm_check_operation(user_sess->sess, rpc)) {
            /* NACM check failed */
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }

        /* get DS, if any */
        ds_str = np_rpc_get_ds(rpc);

        /* pre-NETCONF RPC */
        np_send_notif_rpc(user_sess->sess, NP_RPC_STAGE_PRE, LYD_NAME(rpc), ds_str, np2srv.sr_timeout);

        /* netopeer2 RPC execution */
        reply = rpc_cb(rpc, user_sess);
        if (!reply) {
            goto cleanup;
        }

        /* post-NETCONF RPC */
        rpl_type = nc_server_reply_type(reply);
        np_send_notif_rpc(user_sess->sess, (rpl_type == NC_RPL_ERROR) ? NP_RPC_STAGE_POST_FAIL : NP_RPC_STAGE_POST_SUCCESS,
                LYD_NAME(rpc), ds_str, np2srv.sr_timeout);
    } else {
        /* sysrepo RPC, use the default timeout or slightly higher than the configured one */
        rc = sr_rpc_send_tree(user_sess->sess, rpc, np2srv.sr_timeout ? np2srv.sr_timeout + 2000 : 0, &output);
        if (rc) {
            ERR("Failed to send an RPC (%s).", sr_strerror(rc));

            /* error reply */
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
        } else if (output) {
            /* data reply */
            reply = np_reply_success(rpc, output->tree);
            output->tree = NULL;
        } else {
            /* OK reply */
            reply = np_reply_success(rpc, NULL);
        }
    }

cleanup:
    sr_release_data(output);
    sr_release_data(op_data);
    np_release_user_sess(user_sess);
    return reply;
}

/**
 * @brief Check SR schema context for all the required schemas and features.
 *
 * @param[in] sr_sess SR session to use.
 * @return 0 on success;
 * @return -1 on error.
 */
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

    ly_ctx = sr_session_acquire_context(sr_sess);

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
    NP2_CHECK_FEATURE("confirmed-commit");

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

    sr_session_release_context(sr_sess);
    return 0;
}

static char *
np2srv_content_id_cb(void *UNUSED(user_data))
{
    char buf[11];
    uint32_t content_id;

    content_id = sr_get_content_id(np2srv.sr_conn);
    sprintf(buf, "%" PRIu32, content_id);
    return strdup(buf);
}

/**
 * @brief SR operational get callback for schema-mounts data. They are obtained from the file provided
 * by a parameter.
 */
static int
np2srv_sm_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    const struct ly_ctx *ly_ctx = sr_session_acquire_context(session);
    struct lyd_node *data = NULL, *sm;

    /* parse the data file */
    if (lyd_parse_data_path(ly_ctx, np2srv.ext_data_path, 0, LYD_PARSE_STRICT, LYD_VALIDATE_PRESENT, &data)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* find the schema-mount data */
    if (lyd_find_path(data, "/ietf-yang-schema-mount:schema-mounts", 0, &sm)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* return them */
    lyd_unlink_tree(sm);
    if (sm == data) {
        data = data->next;
    }
    *parent = sm;

cleanup:
    lyd_free_siblings(data);
    sr_session_release_context(session);
    return rc;
}

/**
 * @brief Add subscription capabilities to a node
 * @param[in,out] node is a part of ietf-system-capabilities.
 * @param[in] ly_ctx a libyang context.
 */
static int
np2srv_add_subscription_capabilities(struct lyd_node *node, const struct ly_ctx *ly_ctx)
{
    const struct lys_module *notc_mod;
    struct lyd_node *subs_capas;
    int rc = SR_ERR_OK;
    uint32_t c;

    notc_mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-notification-capabilities");
    if (!notc_mod) {
        ERR("Module \"ietf-notification-capabilities\" not implemented in sysrepo.");
        rc = -1;
        goto cleanup;
    }

    /* subscription-capabilities */
    if (lyd_new_path(node, ly_ctx, "ietf-notification-capabilities:subscription-capabilities",
            NULL, 0, &subs_capas)) {
        ERR("Failed to create subscription-capabilities.");
        rc = -1;
        goto cleanup;
    }

    /* notification capabilities */
    for (c = 0; c < sizeof(notif_capas) / sizeof(*notif_capas); c++) {
        if (lyd_new_term(subs_capas, notc_mod, notif_capas[c].name, notif_capas[c].value, 0,
                NULL)) {
            ERR("Failed to create %s.", notif_capas[c].name);
            rc = -1;
            goto cleanup;
        }
    }
cleanup:
    return rc;
}

/**
 * @brief SR operational get callback for system-capabilities data.
 */
static int
np2srv_capabilities_oper_cb(sr_session_ctx_t *session, uint32_t sub_id,
        const char *module_name, const char *path, const char *request_xpath,
        uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct lyd_node *sys_capas = NULL, *datastore_capas, *per_node_capas;
    const struct ly_ctx *ly_ctx;
    int rc = SR_ERR_OK;
    uint32_t ds;

    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    /* context is locked while the callback is executing */
    ly_ctx = sr_session_acquire_context(session);
    if (!ly_ctx) {
        ERR("Failed to acquire sysrepo context.");
        rc = -1;
        goto cleanup;
    }

    if (lyd_new_path(NULL, ly_ctx, "/ietf-system-capabilities:system-capabilities",
            NULL, 0, &sys_capas)) {
        ERR("Failed to create system-capabilities.");
        rc = -1;
        goto cleanup;
    }

    /* datastore-capabilities */
    for (ds = 0; ds < SR_DS_COUNT; ds++) {
        if (lyd_new_list(sys_capas, NULL, "datastore-capabilities",
                0, &datastore_capas, sub_ntf_ds2ident(ds))) {
            ERR("Failed to create datastore-capabilities.");
            rc = -1;
            goto cleanup;
        }

        if (lyd_new_list(datastore_capas, NULL, "per-node-capabilities",
                0, &per_node_capas, '/')) {
            ERR("Failed to create per-node-capabilities.");
            rc = -1;
            goto cleanup;
        }

        /* per datastore capabilities */
        if (np2srv_add_subscription_capabilities(per_node_capas, ly_ctx)) {
            ERR("Failed to add per node subscription-capabilities.");
            rc = -1;
            goto cleanup;
        }
    }

    /* global capabilities */
    if (np2srv_add_subscription_capabilities(sys_capas, ly_ctx)) {
        ERR("Failed to add global subscription-capabilities.");
        rc = -1;
        goto cleanup;
    }

cleanup:
    if (rc) {
        lyd_free_tree(sys_capas);
    } else {
        *parent = sys_capas;
    }

    sr_session_release_context(session);
    return rc;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Callback for sending certificate expiration notifications generated by libnetconf2.
 */
static void
np2srv_cert_exp_notif_cb(const char *expiration_time, const char *xpath, void *user_data)
{
    sr_session_ctx_t *sr_sess = user_data;
    const struct ly_ctx *ly_ctx = NULL;
    int rc, stop_thread = 0;
    struct lyd_node *ntf = NULL;

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    if (!ly_ctx) {
        ERR("Failed to acquire sysrepo context.");
        stop_thread = 1;
        goto cleanup;
    }

    rc = lyd_new_path(NULL, ly_ctx, xpath, expiration_time, 0, &ntf);
    if (rc) {
        ERR("Failed to create certificate expiration notification data.");
        stop_thread = 1;
        goto cleanup;
    }

    rc = sr_notif_send_tree(sr_sess, ntf, 0, 0);
    if (rc) {
        ERR("Failed to send certificate expiration notification.");
        stop_thread = 1;
        goto cleanup;
    }

cleanup:
    lyd_free_tree(ntf);
    if (ly_ctx) {
        sr_release_context(np2srv.sr_conn);
    }
    if (stop_thread) {
        nc_server_notif_cert_expiration_thread_stop(1);
    }
}

/**
 * @brief Start the certificate expiration notification thread.
 *
 * The thread is started only if the 'certificate-expiration-notification' feature is enabled.
 *
 * @return 0 if the thread is successfully started or if the feature is disabled, -1 on error.
 */
static int
np2srv_start_cert_exp_notif_thread(void)
{
    int r, ret = 0;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    if (!ly_ctx) {
        ERR("Failed to acquire SR connection context.");
        return -1;
    }

    mod = ly_ctx_get_module_implemented(ly_ctx, "ietf-crypto-types");
    if (!mod) {
        ERR("Module \"ietf-crypto-types\" not implemented in sysrepo.");
        ret = -1;
        goto cleanup;
    }

    /* check if the feature is enabled and if so, then start the thread */
    r = lys_feature_value(mod, "certificate-expiration-notification");
    if (r == LY_SUCCESS) {
        if (nc_server_notif_cert_expiration_thread_start(np2srv_cert_exp_notif_cb, np2srv.sr_sess, NULL)) {
            ERR("Failed to start certificate expiration notification thread.");
            ret = -1;
            goto cleanup;
        }
    } else if (r == LY_ENOTFOUND) {
        ERR("Feature \"certificate-expiration-notification\" not found in module \"ietf-crypto-types\".");
        ret = -1;
        goto cleanup;
    }

cleanup:
    sr_release_context(np2srv.sr_conn);
    return ret;
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Initialize the server,
 *
 * @return 0 on succes;
 * @return -1 on error.
 */
static int
server_init(void)
{
    int rc;

    /* connect to sysrepo */
    if ((rc = sr_connect(SR_CONN_CACHE_RUNNING, &np2srv.sr_conn))) {
        ERR("Connecting to sysrepo failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* set the content-id callback */
    nc_server_set_content_id_clb(np2srv_content_id_cb, NULL, NULL);

    /* server session */
    if ((rc = sr_session_start(np2srv.sr_conn, SR_DS_RUNNING, &np2srv.sr_sess))) {
        ERR("Creating sysrepo session failed (%s).", sr_strerror(rc));
        goto error;
    }

    /* check libyang context */
    if (np2srv_check_schemas(np2srv.sr_sess)) {
        goto error;
    }

    /* init monitoring */
    ncm_init();

    /* init libnetconf2 */
    if (nc_server_init()) {
        goto error;
    }

    /* prepare poll session structure for libnetconf2 */
    np2srv.nc_ps = nc_ps_new();

    /* set with-defaults capability basic-mode */
    nc_server_set_capab_withdefaults(NC_WD_EXPLICIT, NC_WD_ALL | NC_WD_ALL_TAG | NC_WD_TRIM | NC_WD_EXPLICIT);

#ifdef NC_ENABLED_SSH_TLS
    /* set ln2 call home call backs and data */
    nc_server_ch_set_dispatch_data(np_acquire_ctx_cb, np_release_ctx_cb, np2srv.sr_conn, np_new_session_cb, NULL);

    /* if PAM is not supported, the function will return an error, but don't check it, because PAM is not required */
    nc_server_ssh_set_pam_conf_filename("netopeer2.conf");

    /* set authorized_keys path format to by default {client_home}/.ssh/authorized_keys */
    if (nc_server_ssh_set_authkey_path_format(NP2SRV_SSH_AUTHORIZED_KEYS_FORMAT)) {
        ERR("Setting authorized_keys path format failed.");
        goto error;
    }

    /* start certificate expiration notification thread if the certificate-expiration-notification feature is enabled */
    if (np2srv_start_cert_exp_notif_thread()) {
        ERR("Starting certificate expiration notification thread failed.");
        goto error;
    }
#endif /* NC_ENABLED_SSH_TLS */

    /* set capabilities for the NETCONF Notifications */
    nc_server_set_capability("urn:ietf:params:netconf:capability:notification:1.0");
    nc_server_set_capability("urn:ietf:params:netconf:capability:interleave:1.0");

    /* set URL capability */
    if (np_url_setcap()) {
        goto error;
    }

    /* set libnetconf2 global PRC callback */
    nc_set_global_rpc_clb(np2srv_rpc_cb);

    /* UNIX socket */
    if (np2srv.unix_path) {
        if (nc_server_add_endpt_unix_socket_listen("unix", np2srv.unix_path, np2srv.unix_mode,
                np2srv.unix_uid, np2srv.unix_gid)) {
            goto error;
        }
    }

    /* restore a previous confirmed commit if restore file exists */
    ncc_try_restore();

    return 0;

error:
    ERR("Server init failed.");
    return -1;
}

/**
 * @brief Destroy the server.
 */
static void
server_destroy(void)
{
    struct nc_session *sess;

#ifdef NC_ENABLED_SSH_TLS
    struct lyd_node *data = NULL, *node = NULL;
    const struct ly_ctx *ly_ctx;
    uint32_t temp_lo = 0;

    /* remove all CH clients so they do not reconnect */
    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    ly_temp_log_options(&temp_lo);
    if (!lyd_new_path2(NULL, ly_ctx, "/ietf-netconf-server:netconf-server/call-home", NULL, 0, 0, 0, &data, &node)) {
        lyd_new_meta(ly_ctx, data, NULL, "yang:operation", "none", 0, NULL);
        lyd_new_meta(ly_ctx, node, NULL, "yang:operation", "delete", 0, NULL);
        nc_server_config_setup_diff(data);
        lyd_free_tree(data);
    }
    ly_temp_log_options(NULL);
    sr_release_context(np2srv.sr_conn);
#endif

    /* stop notif read dispatched thread, if running */
    srsn_read_dispatch_destroy();

    /* close all open sessions */
    if (np2srv.nc_ps) {
        while (nc_ps_session_count(np2srv.nc_ps)) {
            sess = nc_ps_get_session(np2srv.nc_ps, 0);
            nc_session_set_term_reason(sess, NC_SESSION_TERM_OTHER);
            np2srv_del_session_cb(sess);
            sr_release_context(np2srv.sr_conn);
        }
        nc_ps_free(np2srv.nc_ps);
    }

    /* stop subscriptions */
    sr_unsubscribe(np2srv.sr_data_sub);
    sr_unsubscribe(np2srv.sr_nacm_stats_sub);
    sr_unsubscribe(np2srv.sr_notif_sub);

    /* libnetconf2 cleanup */
    nc_server_destroy();

    /* monitoring cleanup */
    ncm_destroy();

    /* NACM cleanup */
    sr_nacm_destroy();

    /* confirmed commit cleanup */
    ncc_commit_ctx_destroy();

    /* disconnects and clears all the sessions */
    sr_disconnect(np2srv.sr_conn);

    /* free dynamic members */
    free(np2srv.url_protocols);

    /* zero */
    memset(&np2srv, 0, sizeof np2srv);
}

/**
 * @brief Open the server PID file and write into it.
 *
 * @param[in] pidfile Path to the PID file.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
server_open_pidfile(const char *pidfile)
{
    int pidfd, len;
    char pid[8];
    struct flock fl;

    /* make sure we are the only instance - lock the PID file and write the PID */
    pidfd = open(pidfile, O_RDWR | O_CREAT, 00644);
    if (pidfd < 0) {
        ERR("Unable to open the PID file \"%s\" (%s).", pidfile, strerror(errno));
        return -1;
    }

    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 5;
    if (fcntl(pidfd, F_SETLK, &fl) < 0) {
        close(pidfd);
        if ((errno == EACCES) || (errno == EAGAIN)) {
            ERR("Another instance of the Netopeer2 server is running.");
        } else {
            ERR("Unable to lock the PID file \"%s\" (%s).", pidfile, strerror(errno));
        }
        return -1;
    }

    if (ftruncate(pidfd, 0)) {
        ERR("Failed to truncate PID file (%s).", strerror(errno));
        close(pidfd);
        return -1;
    }

    len = snprintf(pid, sizeof(pid), "%d\n", getpid());
    if ((len < 0) || (write(pidfd, pid, len) < len)) {
        ERR("Failed to write into PID file.");
        close(pidfd);
        return -1;
    }

    close(pidfd);
    return 0;
}

/**
 * @brief Callback for handling netconf-server, ietf-keystore and ietf-truststore data changes.
 *
 * The diff is given to libnetconf2, which then handles the changes.
 */
static int
np2srv_libnetconf2_config_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    int rc = 0;
    const struct lyd_node *diff = NULL;

    /* get diff and apply it */
    diff = sr_get_change_diff(session);
    rc = nc_server_config_setup_diff(diff);
    if (rc) {
        ERR("Configuring NETCONF server failed.");
        return rc;
    }

    return SR_ERR_OK;
}

#ifdef NC_ENABLED_SSH_TLS

/**
 * @brief Callback for providing SSH algorithms operational data.
 */
static int
np2srv_ssh_algs_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *module_name, const char *path,
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent,
        void *UNUSED(private_data))
{
    int ret = 0;
    const struct ly_ctx *ly_ctx;

    (void) path;

    /* context is locked by the callback anyway */
    ly_ctx = sr_session_acquire_context(session);
    sr_session_release_context(session);

    /* get oper data based on the module */
    if (!strcmp(module_name, "iana-ssh-public-key-algs")) {
        assert(!strcmp(path, "/iana-ssh-public-key-algs:supported-algorithms"));
        ret = nc_server_config_oper_get_hostkey_algs(ly_ctx, parent);
    } else if (!strcmp(module_name, "iana-ssh-key-exchange-algs")) {
        assert(!strcmp(path, "/iana-ssh-key-exchange-algs:supported-algorithms"));
        ret = nc_server_config_oper_get_kex_algs(ly_ctx, parent);
    } else if (!strcmp(module_name, "iana-ssh-encryption-algs")) {
        assert(!strcmp(path, "/iana-ssh-encryption-algs:supported-algorithms"));
        ret = nc_server_config_oper_get_encryption_algs(ly_ctx, parent);
    } else if (!strcmp(module_name, "iana-ssh-mac-algs")) {
        assert(!strcmp(path, "/iana-ssh-mac-algs:supported-algorithms"));
        ret = nc_server_config_oper_get_mac_algs(ly_ctx, parent);
    } else {
        ERR("Unable to get supported SSH algorithms (module %s not supported).", module_name);
        return SR_ERR_INTERNAL;
    }
    if (ret) {
        ERR("Getting supported SSH algorithms failed.");
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

#endif /* NC_ENABLED_SSH_TLS */

/**
 * @brief Subscribe to all the handled configuration and operational data by the server.
 *
 * @return 0 on success;
 * @return -1 on error.
 */
static int
server_data_subscribe(void)
{
    const char *mod_name, *xpath;
    int rc;

#define SR_OPER_SUBSCR(mod_name, xpath, cb) \
    rc = sr_oper_get_subscribe(np2srv.sr_sess, mod_name, xpath, cb, NULL, 0, &np2srv.sr_data_sub); \
    if (rc != SR_ERR_OK) { \
        ERR("Subscribing for providing \"%s\" state data failed (%s).", mod_name, sr_strerror(rc)); \
        goto error; \
    }

#define SR_CONFIG_SUBSCR(mod_name, xpath, cb) \
    rc = sr_module_change_subscribe(np2srv.sr_sess, mod_name, xpath, cb, NULL, 0, \
            SR_SUBSCR_DONE_ONLY | SR_SUBSCR_ENABLED, &np2srv.sr_data_sub); \
    if (rc != SR_ERR_OK) { \
        ERR("Subscribing for \"%s\" data changes failed (%s).", mod_name, sr_strerror(rc)); \
        goto error; \
    }

    /* subscribe for providing state data */
    if (np2srv.sr_data_sub) {
        EINT;
        goto error;
    }

    if (np2srv.ext_data_path) {
        mod_name = "ietf-yang-schema-mount";
        SR_OPER_SUBSCR(mod_name, "/ietf-yang-schema-mount:schema-mounts", np2srv_sm_oper_cb);
    }

    mod_name = "ietf-netconf-monitoring";
    SR_OPER_SUBSCR(mod_name, "/ietf-netconf-monitoring:netconf-state", np2srv_ncm_oper_cb);

    mod_name = "nc-notifications";
    SR_OPER_SUBSCR(mod_name, "/nc-notifications:netconf", np2srv_nc_ntf_oper_cb);

    mod_name = "ietf-system-capabilities";
    rc = sr_oper_get_subscribe(np2srv.sr_sess, mod_name,
            "/ietf-system-capabilities:system-capabilities", np2srv_capabilities_oper_cb, NULL,
            SR_SUBSCR_OPER_MERGE, &np2srv.sr_data_sub);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing for providing \"%s\" state data failed (%s).", mod_name, sr_strerror(rc));
        goto error;
    }

#ifdef NC_ENABLED_SSH_TLS
    /* set callbacks for supported algorithms oper data */
    mod_name = "iana-ssh-public-key-algs";
    SR_OPER_SUBSCR(mod_name, "/iana-ssh-public-key-algs:supported-algorithms", np2srv_ssh_algs_oper_cb);

    mod_name = "iana-ssh-key-exchange-algs";
    SR_OPER_SUBSCR(mod_name, "/iana-ssh-key-exchange-algs:supported-algorithms", np2srv_ssh_algs_oper_cb);

    mod_name = "iana-ssh-encryption-algs";
    SR_OPER_SUBSCR(mod_name, "/iana-ssh-encryption-algs:supported-algorithms", np2srv_ssh_algs_oper_cb);

    mod_name = "iana-ssh-mac-algs";
    SR_OPER_SUBSCR(mod_name, "/iana-ssh-mac-algs:supported-algorithms", np2srv_ssh_algs_oper_cb);
#endif /* NC_ENABLED_SSH_TLS */

    /*
     * ietf-subscribed-notifications
     */
    mod_name = "ietf-subscribed-notifications";
    xpath = "/ietf-subscribed-notifications:filters";
    rc = sr_module_change_subscribe(np2srv.sr_sess, mod_name, xpath, np2srv_config_sub_ntf_filters_cb, NULL, 0,
            SR_SUBSCR_DONE_ONLY, &np2srv.sr_data_sub);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing for \"%s\" data changes failed (%s).", mod_name, sr_strerror(rc));
        goto error;
    }

    /* operational data */
    SR_OPER_SUBSCR(mod_name, "/ietf-subscribed-notifications:streams", srsn_oper_data_streams_cb);
    rc = sr_oper_get_subscribe(np2srv.sr_sess, mod_name, "/ietf-subscribed-notifications:subscriptions",
            np2srv_oper_sub_ntf_subscriptions_cb, NULL, SR_SUBSCR_OPER_MERGE, &np2srv.sr_data_sub);
    if (rc != SR_ERR_OK) {
        ERR("Subscribing for providing \"%s\" state data failed (%s).", mod_name, sr_strerror(rc));
        goto error;
    }

    /*
     * ietf-netconf-server, ietf-keystore, ietf-trustore, and libnetconf2-netconf-server handled by ln2
     */
    SR_CONFIG_SUBSCR("ietf-netconf-server", NULL, np2srv_libnetconf2_config_cb);
    SR_CONFIG_SUBSCR("ietf-keystore", NULL, np2srv_libnetconf2_config_cb);
    SR_CONFIG_SUBSCR("ietf-truststore", NULL, np2srv_libnetconf2_config_cb);
    SR_CONFIG_SUBSCR("libnetconf2-netconf-server", NULL, np2srv_libnetconf2_config_cb);

    /*
     * ietf-netconf-acm
     */
    if (sr_nacm_init(np2srv.sr_sess, 0, &np2srv.sr_data_sub)) {
        goto error;
    }
    if (sr_nacm_glob_stats_subscribe(np2srv.sr_sess, 0, &np2srv.sr_nacm_stats_sub)) {
        goto error;
    }

    return 0;

error:
    ERR("Server data subscribe failed.");
    return -1;
}

/**
 * @brief Accept new NETCONF session.
 */
static void
server_accept_session(void)
{
    NC_MSG_TYPE msgtype;
    const struct ly_ctx *ly_ctx;
    struct nc_session *ncs = NULL;

    if (!nc_server_endpt_count()) {
        /* no listening endpoints */
        return;
    }

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    if (!ly_ctx) {
        ERR("Failed to acquire SR connection context.");
        return;
    }

    /* accept session */
    msgtype = nc_accept(0, ly_ctx, &ncs);
    if ((msgtype == NC_MSG_HELLO) && !np_new_session_cb(NULL, ncs, NULL)) {
        /* callback success, keep the session with the context lock */
        return;
    }

    /* no new session or callback fail, free the session, release context */
    nc_session_free(ncs, NULL);
    sr_release_context(np2srv.sr_conn);
}

/**
 * @brief Server worker thread function.
 *
 * @param[in] arg Worker index.
 * @return NULL.
 */
static void *
worker_thread(void *arg)
{
#ifdef NC_ENABLED_SSH_TLS
    NC_MSG_TYPE msgtype;
#endif /* NC_ENABLED_SSH_TLS */
    int rc, idx = *((int *)arg);
    struct nc_session *ncs;

#ifdef NC_ENABLED_SSH_TLS
    nc_libssh_thread_verbosity(np2_libssh_verbose_level);
#endif

    while (ATOMIC_LOAD_RELAXED(loop_continue)) {
        /* try to accept new NETCONF sessions */
        server_accept_session();

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
            sr_release_context(np2srv.sr_conn);
        }
#ifdef NC_ENABLED_SSH_TLS
        else if (rc & NC_PSPOLL_SSH_CHANNEL) {
            /* a new SSH channel on existing session was created */
            VRB("Session %d: thread %d event new SSH channel.", nc_session_get_id(ncs), idx);
            msgtype = nc_session_accept_ssh_channel(ncs, &ncs);
            if (msgtype == NC_MSG_HELLO) {
                if (np_new_session_cb(NULL, ncs, NULL)) {
                    nc_session_free(ncs, NULL);
                    continue;
                }

                /* for the new session */
                sr_acquire_context(np2srv.sr_conn);
            } else if (msgtype == NC_MSG_BAD_HELLO) {
                ncm_bad_hello(ncs);
            }
        }
#endif
    }

    /* cleanup */
    free(arg);
    return NULL;
}

static void
print_version(void)
{
    fprintf(stdout, "netopeer2-server %s\n", NP2SRV_VERSION);
}

static void
print_usage(char *progname)
{
    fprintf(stdout, "Usage: %s [-dFhV] [-p PATH] [-U[PATH]] [-m MODE] [-u UID] [-g GID] [-t TIMEOUT] [-x PATH]\n", progname);
    fprintf(stdout, "          [-v LEVEL] [-c CATEGORY]\n");
    fprintf(stdout, " -d         Debug mode (do not daemonize and print verbose messages to stderr instead of syslog).\n");
    fprintf(stdout, " -F         Run in foreground, like -d, but log to syslog.\n");
    fprintf(stdout, " -h         Display help.\n");
    fprintf(stdout, " -V         Show program version.\n");
    fprintf(stdout, " -p PATH    Path to pidfile (default path is \"%s\").\n", NP2SRV_PID_FILE_PATH);
    fprintf(stdout, " -f PATH    Path to netopeer2 server files directory (default path is \"%s\")\n", SERVER_DIR);
    fprintf(stdout, " -U[PATH]   Listen on a local UNIX socket (default path is \"%s\").\n", NP2SRV_UNIX_SOCK_PATH);
    fprintf(stdout, " -m MODE    Set mode for the listening UNIX socket.\n");
    fprintf(stdout, " -u UID     Set UID/user for the listening UNIX socket.\n");
    fprintf(stdout, " -g GID     Set GID/group for the listening UNIX socket.\n");
    fprintf(stdout, " -t TIMEOUT Timeout in seconds of all sysrepo functions (applying edit-config, reading data, ...),\n");
    fprintf(stdout, "            if 0 (default), the default sysrepo timeouts are used.\n");
    fprintf(stdout, " -x PATH    Path to a data file with data for libyang ext data callback. They are required for\n");
    fprintf(stdout, "            supporting some extensions such as schema-mount, in which case the ietf-yang-schema-mount\n");
    fprintf(stdout, "            operational data are expected to be in the file.\n");
    fprintf(stdout, " -v LEVEL   Verbose output level:\n");
    fprintf(stdout, "                0 - errors\n");
    fprintf(stdout, "                1 - errors and warnings\n");
    fprintf(stdout, "                2 - errors, warnings, and verbose messages\n");
    fprintf(stdout, " -c CATEGORY[,CATEGORY...]\n");
#ifndef NDEBUG
    fprintf(stdout, "            Verbose debug level, print only these debug message categories.\n");
# ifdef NC_ENABLED_SSH_TLS
    fprintf(stdout, "            Categories: DICT, YANG, YIN, XPATH, DIFF, MSG, LN2DBG, SSH, SYSREPO\n");
# else
    fprintf(stdout, "            Categories: DICT, YANG, YIN, XPATH, DIFF, MSG, LN2DBG, SYSREPO\n");
# endif
#else
    fprintf(stdout, "            Verbose debug level, NOT SUPPORTED in release build type.\n");
#endif
    fprintf(stdout, "\n");
}

int
main(int argc, char *argv[])
{
    int ret = EXIT_SUCCESS;
    int c, *idx, i;
    int daemonize = 1, verb = 0;
    const char *pidfile = NP2SRV_PID_FILE_PATH;
    char *ptr;
    struct passwd *pwd;
    struct group *grp;

#ifdef HAVE_SIGACTION
    struct sigaction action;
    sigset_t block_mask;
#endif

    /* reset control var */
    ATOMIC_STORE_RELAXED(loop_continue, 1);

    /* until daemonized, write messages to both syslog and stderr */
    openlog("netopeer2-server", LOG_PID, LOG_DAEMON);
    np2_stderr_log = 1;

#ifdef HAVE_SIGACTION
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
#endif

    /* default value */
    np2srv.server_dir = SERVER_DIR;

    /* process command line options */
    optind = 0;
    while ((c = getopt(argc, argv, "dFhVp:f:U::m:u:g:t:x:v:c:")) != -1) {
        switch (c) {
        case 'd':
            daemonize = 0;
            break;
        case 'F':
            daemonize = 0;
            np2_stderr_log = 0;
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
#ifdef NC_ENABLED_SSH_TLS
            nc_libssh_thread_verbosity(np2_libssh_verbose_level);
#endif
            break;
        case 'V':
            print_version();
            return EXIT_SUCCESS;
        case 'p':
            pidfile = optarg;
            break;
        case 'f':
            np2srv.server_dir = optarg;
            break;
        case 'U':
            /* optional argument */
            if (!optarg && (optind < argc) && (argv[optind][0] != '-')) {
                /* assume the parameter is the optional argument */
                optarg = argv[optind++];
            }
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
        case 'x':
            np2srv.ext_data_path = optarg;
            break;
        case 'c':
#ifndef NDEBUG
            if (verb) {
                ERR("Do not combine -v and -c parameters.");
                return EXIT_FAILURE;
            }

            /* set verbose for all, we change to debug later if requested */
            np2_sr_verbose_level = SR_LL_INF;
            np2_verbose_level = NC_VERB_VERBOSE;
            np2_libssh_verbose_level = 1;

            ptr = strtok(optarg, ",");
            do {
                if (!strcmp(ptr, "DICT")) {
                    verb |= LY_LDGDICT;
                } else if (!strcmp(ptr, "XPATH")) {
                    verb |= LY_LDGXPATH;
                } else if (!strcmp(ptr, "MSG")) {
                    /* NETCONF messages - only ln2 debug verbosity */
                    np2_verbose_level = NC_VERB_DEBUG;
                } else if (!strcmp(ptr, "LN2DBG")) {
                    np2_verbose_level = NC_VERB_DEBUG_LOWLVL;
# ifdef NC_ENABLED_SSH_TLS
                } else if (!strcmp(ptr, "SSH")) {
                    np2_libssh_verbose_level = 3;
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
# ifdef NC_ENABLED_SSH_TLS
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

    /* set printer callbacks for the used libraries and set proper log levels */
    nc_set_print_clb_session(np2log_cb_nc2); /* libnetconf2 */
    ly_set_log_clb(np2log_cb_ly); /* libyang */
    sr_log_set_cb(np2log_cb_sr); /* sysrepo, log level is checked by callback */

    /* initiate NETCONF server */
    if (server_init()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* subscribe to sysrepo for providing data */
    if (server_data_subscribe()) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

    /* open/create pidfile */
    if (server_open_pidfile(pidfile)) {
        ret = EXIT_FAILURE;
        goto cleanup;
    }

#ifdef NP2SRV_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "READY=1");
#endif

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

#ifdef NP2SRV_HAVE_SYSTEMD
    /* notify systemd */
    sd_notify(0, "STOPPING=1");
#endif

    /* wait for other worker threads to finish */
    for (i = 1; i < NP2SRV_THREAD_COUNT; ++i) {
        c = pthread_join(np2srv.workers[i], NULL);
        if (c) {
            ERR("Failed to join worker thread %d (%s).", i, strerror(c));
        }
    }

cleanup:
    VRB("Server terminated.");

    /* destroy the server */
    server_destroy();

    /* remove PID file */
    unlink(pidfile);

    return ret;
}
