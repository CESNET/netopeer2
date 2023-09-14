/**
 * @file netconf_monitoring.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-monitoring statistics and counters
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include "netconf_monitoring.h"

#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>
#include <nc_server.h>

#include "common.h"
#include "compat.h"
#include "err_netconf.h"
#include "log.h"

struct ncm stats;

void
ncm_init(void)
{
    stats.netconf_start_time = time(NULL);
    pthread_mutex_init(&stats.lock, NULL);
}

void
ncm_destroy(void)
{
    free(stats.sessions);
    free(stats.session_stats);
    pthread_mutex_destroy(&stats.lock);
}

static uint32_t
find_session_idx(struct nc_session *session)
{
    uint32_t i;

    for (i = 0; i < stats.session_count; ++i) {
        if (nc_session_get_id(stats.sessions[i]) == nc_session_get_id(session)) {
            return i;
        }
    }

    EINT;
    return 0;
}

static int
ncm_is_monitored(struct nc_session *session)
{
    switch (nc_session_get_ti(session)) {
#ifdef NC_ENABLED_SSH_TLS
    case NC_TI_LIBSSH:
        return 1;
    case NC_TI_OPENSSL:
        return 1;
#endif
    default:
        break;
    }

    return 0;
}

void
ncm_session_rpc(struct nc_session *session)
{
    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].in_rpcs;
    ++stats.global_stats.in_rpcs;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_bad_rpc(struct nc_session *session)
{
    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].in_bad_rpcs;
    ++stats.global_stats.in_bad_rpcs;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_rpc_reply_error(struct nc_session *session)
{
    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].out_rpc_errors;
    ++stats.global_stats.out_rpc_errors;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_notification(struct nc_session *session)
{
    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].out_notifications;
    ++stats.global_stats.out_notifications;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_add(struct nc_session *session)
{
    void *new;

    if (!ncm_is_monitored(session)) {
        WRN("Session %d uses a transport protocol not supported by ietf-netconf-monitoring, will not be monitored.",
                nc_session_get_id(session));
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.in_sessions;

    ++stats.session_count;
    new = realloc(stats.sessions, stats.session_count * sizeof *stats.sessions);
    if (!new) {
        EMEM;
        goto cleanup;
    }
    stats.sessions = new;
    new = realloc(stats.session_stats, stats.session_count * sizeof *stats.session_stats);
    if (!new) {
        EMEM;
        goto cleanup;
    }
    stats.session_stats = new;

    stats.sessions[stats.session_count - 1] = session;
    memset(&stats.session_stats[stats.session_count - 1], 0, sizeof *stats.session_stats);

cleanup:
    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_del(struct nc_session *session)
{
    uint32_t i;

    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    if (!nc_session_get_term_reason(session)) {
        EINT;
    }

    if (nc_session_get_term_reason(session) != NC_SESSION_TERM_CLOSED) {
        ++stats.dropped_sessions;
    }

    i = find_session_idx(session);
    --stats.session_count;
    if (stats.session_count && (i < stats.session_count)) {
        memmove(&stats.sessions[i], &stats.sessions[i + 1], (stats.session_count - i) * sizeof *stats.sessions);
        memmove(&stats.session_stats[i], &stats.session_stats[i + 1], (stats.session_count - i) * sizeof *stats.session_stats);
    }

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_bad_hello(struct nc_session *session)
{
    if (!ncm_is_monitored(session)) {
        return;
    }

    pthread_mutex_lock(&stats.lock);

    ++stats.in_bad_hellos;

    pthread_mutex_unlock(&stats.lock);
}

uint32_t
ncm_session_get_notification(struct nc_session *session)
{
    uint32_t count;

    if (!ncm_is_monitored(session)) {
        return 0;
    }

    pthread_mutex_lock(&stats.lock);

    count = stats.session_stats[find_session_idx(session)].out_notifications;

    pthread_mutex_unlock(&stats.lock);

    return count;
}

static void
ncm_data_add_ds_lock(sr_conn_ctx_t *conn, const char *ds_str, sr_datastore_t ds, struct lyd_node *parent)
{
    struct lyd_node *list, *cont, *cont2;
    char *buf, ncid_str[11];
    int rc, is_locked;
    uint32_t sid;
    struct timespec ts;
    struct nc_session *ncs;

    lyd_new_list(parent, NULL, "datastore", 0, &list, ds_str);
    rc = sr_get_lock(conn, ds, NULL, &is_locked, &sid, &ts);
    if (rc != SR_ERR_OK) {
        WRN("Failed to learn about %s lock (%s).", ds_str, sr_strerror(rc));
    } else if (is_locked) {
        lyd_new_inner(list, NULL, "locks", 0, &cont);
        lyd_new_inner(cont, NULL, "global-lock", 0, &cont2);

        np_get_nc_sess_by_id(sid, 0, __func__, &ncs);
        sprintf(ncid_str, "%" PRIu32, ncs ? nc_session_get_id(ncs) : 0);
        lyd_new_term(cont2, NULL, "locked-by-session", ncid_str, 0, NULL);

        ly_time_ts2str(&ts, &buf);
        lyd_new_term(cont2, NULL, "locked-time", buf, 0, NULL);
        free(buf);
    }
}

int
np2srv_ncm_oper_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root = NULL, *cont, *list;
    const struct lys_module *mod;
    sr_conn_ctx_t *conn;
    struct ly_ctx *ly_ctx;
    char **cpblts;
    char *time_str, buf[11];
    uint32_t i;

    /* context is locked while the callback is executed */
    conn = sr_session_get_connection(session);
    ly_ctx = (struct ly_ctx *)sr_acquire_context(conn);
    sr_release_context(conn);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-netconf-monitoring:netconf-state", NULL, 0, &root)) {
        goto error;
    }

    /* capabilities */
    lyd_new_inner(root, NULL, "capabilities", 0, &cont);

    cpblts = nc_server_get_cpblts_version(ly_ctx, LYS_VERSION_1_0);
    if (!cpblts) {
        goto error;
    }

    for (i = 0; cpblts[i]; ++i) {
        lyd_new_term(cont, NULL, "capability", cpblts[i], 0, NULL);
        free(cpblts[i]);
    }
    free(cpblts);

    /* datastore locks */
    lyd_new_inner(root, NULL, "datastores", 0, &cont);
    ncm_data_add_ds_lock(conn, "running", SR_DS_RUNNING, cont);
    ncm_data_add_ds_lock(conn, "startup", SR_DS_STARTUP, cont);
    ncm_data_add_ds_lock(conn, "candidate", SR_DS_CANDIDATE, cont);

    /* schemas */
    lyd_new_inner(root, NULL, "schemas", 0, &cont);

    i = 0;
    while ((mod = ly_ctx_get_module_iter(ly_ctx, &i))) {
        lyd_new_list(cont, NULL, "schema", 0, &list, mod->name, mod->revision ? mod->revision : "", "yang");
        lyd_new_term(list, NULL, "namespace", mod->ns, 0, NULL);
        lyd_new_term(list, NULL, "location", "NETCONF", 0, NULL);

        lyd_new_list(cont, NULL, "schema", 0, &list, mod->name, mod->revision ? mod->revision : "", "yin");
        lyd_new_term(list, NULL, "namespace", mod->ns, 0, NULL);
        lyd_new_term(list, NULL, "location", "NETCONF", 0, NULL);
    }

    /* sessions */
    pthread_mutex_lock(&stats.lock);

    if (stats.session_count) {
        lyd_new_inner(root, NULL, "sessions", 0, &cont);

        for (i = 0; i < stats.session_count; ++i) {
            sprintf(buf, "%u", nc_session_get_id(stats.sessions[i]));
            lyd_new_list(cont, NULL, "session", 0, &list, buf);

            switch (nc_session_get_ti(stats.sessions[i])) {
#ifdef NC_ENABLED_SSH_TLS
            case NC_TI_LIBSSH:
                lyd_new_term(list, NULL, "transport", "netconf-ssh", 0, NULL);
                break;
            case NC_TI_OPENSSL:
                lyd_new_term(list, NULL, "transport", "netconf-tls", 0, NULL);
                break;
#endif
            default: /* NC_TI_FD, NC_TI_NONE */
                ERR("ietf-netconf-monitoring unsupported session transport type.");
                pthread_mutex_unlock(&stats.lock);
                goto error;
            }
            lyd_new_term(list, NULL, "username", nc_session_get_username(stats.sessions[i]), 0, NULL);
            lyd_new_term(list, NULL, "source-host", nc_session_get_host(stats.sessions[i]), 0, NULL);
            ly_time_time2str(nc_session_get_start_time(stats.sessions[i]), NULL, &time_str);
            lyd_new_term(list, NULL, "login-time", time_str, 0, NULL);
            free(time_str);

            sprintf(buf, "%u", stats.session_stats[i].in_rpcs);
            lyd_new_term(list, NULL, "in-rpcs", buf, 0, NULL);
            sprintf(buf, "%u", stats.session_stats[i].in_bad_rpcs);
            lyd_new_term(list, NULL, "in-bad-rpcs", buf, 0, NULL);
            sprintf(buf, "%u", stats.session_stats[i].out_rpc_errors);
            lyd_new_term(list, NULL, "out-rpc-errors", buf, 0, NULL);
            sprintf(buf, "%u", stats.session_stats[i].out_notifications);
            lyd_new_term(list, NULL, "out-notifications", buf, 0, NULL);
        }
    }

    /* statistics */
    lyd_new_inner(root, NULL, "statistics", 0, &cont);

    ly_time_time2str(stats.netconf_start_time, NULL, &time_str);
    lyd_new_term(cont, NULL, "netconf-start-time", time_str, 0, NULL);
    free(time_str);
    sprintf(buf, "%u", stats.in_bad_hellos);
    lyd_new_term(cont, NULL, "in-bad-hellos", buf, 0, NULL);
    sprintf(buf, "%u", stats.in_sessions);
    lyd_new_term(cont, NULL, "in-sessions", buf, 0, NULL);
    sprintf(buf, "%u", stats.dropped_sessions);
    lyd_new_term(cont, NULL, "dropped-sessions", buf, 0, NULL);
    sprintf(buf, "%u", stats.global_stats.in_rpcs);
    lyd_new_term(cont, NULL, "in-rpcs", buf, 0, NULL);
    sprintf(buf, "%u", stats.global_stats.in_bad_rpcs);
    lyd_new_term(cont, NULL, "in-bad-rpcs", buf, 0, NULL);
    sprintf(buf, "%u", stats.global_stats.out_rpc_errors);
    lyd_new_term(cont, NULL, "out-rpc-errors", buf, 0, NULL);
    sprintf(buf, "%u", stats.global_stats.out_notifications);
    lyd_new_term(cont, NULL, "out-notifications", buf, 0, NULL);

    pthread_mutex_unlock(&stats.lock);

    if (lyd_validate_all(&root, NULL, LYD_VALIDATE_PRESENT, NULL)) {
        goto error;
    }

    *parent = root;
    return SR_ERR_OK;

error:
    lyd_free_tree(root);
    return SR_ERR_INTERNAL;
}

int
np2srv_rpc_getschema_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    const char *identifier = NULL, *revision = NULL, *format = NULL;
    const struct ly_ctx *ly_ctx = NULL;
    int rc = SR_ERR_OK;
    char *model_data = NULL;
    struct ly_out *out;
    const struct lys_module *module = NULL;
    const struct lysp_submodule *submodule = NULL;
    struct lyd_node *node;
    LYS_OUTFORMAT outformat = 0;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* identifier */
    if (!lyd_find_path(input, "identifier", 0, &node)) {
        identifier = lyd_get_value(node);
    }

    /* revision */
    if (!lyd_find_path(input, "version", 0, &node)) {
        revision = lyd_get_value(node);
        if (!strlen(revision)) {
            revision = NULL;
        }
    }

    /* format */
    if (!lyd_find_path(input, "format", 0, &node)) {
        /* get the identity name directly */
        format = ((struct lyd_node_term *)node)->value.ident->name;
    }
    VRB("Module \"%s@%s\" was requested.", identifier, revision ? revision : "<any>");

    /* check revision */
    if (revision && (strlen(revision) != 10) && strcmp(revision, "1.0")) {
        np_err_invalid_value(session, "The requested version is not supported.", NULL);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    if (revision) {
        /* get specific module */
        module = ly_ctx_get_module(ly_ctx, identifier, revision);
        if (!module) {
            submodule = ly_ctx_get_submodule(ly_ctx, identifier, revision);
        }
    } else {
        /* try to get implemented, then latest module */
        module = ly_ctx_get_module_implemented(ly_ctx, identifier);
        if (!module) {
            module = ly_ctx_get_module_latest(ly_ctx, identifier);
        }
        if (!module) {
            submodule = ly_ctx_get_submodule_latest(ly_ctx, identifier);
        }
    }
    if (!module && !submodule) {
        np_err_invalid_value(session, "The requested module was not found.", NULL);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* check format */
    if (!format || !strcmp(format, "yang")) {
        outformat = LYS_OUT_YANG;
    } else if (!strcmp(format, "yin")) {
        outformat = LYS_OUT_YIN;
    } else {
        np_err_invalid_value(session, "The requested format is not supported.", NULL);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* print */
    ly_out_new_memory(&model_data, 0, &out);
    if (module) {
        lys_print_module(out, module, outformat, 0, 0);
    } else {
        lys_print_submodule(out, submodule, outformat, 0, 0);
    }
    ly_out_free(out, NULL, 0);
    if (!model_data) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* add output */
    if (lyd_new_any(output, NULL, "data", model_data, 1, LYD_ANYDATA_STRING, 1, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    model_data = NULL;

cleanup:
    if (ly_ctx) {
        sr_release_context(np2srv.sr_conn);
    }
    free(model_data);
    return rc;
}
