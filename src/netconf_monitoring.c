/**
 * @file netconf_monitoring.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-monitoring statistics and counters
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include <libyang/libyang.h>
#include <nc_server.h>

#include "common.h"
#include "log.h"
#include "netconf_monitoring.h"

#define NCM_TIMEZONE "CET"

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
#ifdef NC_ENABLED_SSH
    case NC_TI_LIBSSH:
#endif
#ifdef NC_ENABLED_TLS
    case NC_TI_OPENSSL:
#endif
#if defined(NC_ENABLED_SSH) || defined(NC_ENABLED_TLS)
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
        return;
    }
    stats.sessions = new;
    new = realloc(stats.session_stats, stats.session_count * sizeof *stats.session_stats);
    if (!new) {
        EMEM;
        return;
    }
    stats.session_stats = new;

    stats.sessions[stats.session_count - 1] = session;
    memset(&stats.session_stats[stats.session_count - 1], 0, sizeof *stats.session_stats);

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

static uint32_t
ncm_sid2ncid(uint32_t sid)
{
    struct nc_session *nc_sess = NULL;
    struct np2_sess_data *sess_data;
    uint32_t i;

    for (i = 0; (nc_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        sess_data = nc_session_get_data(nc_sess);
        if (sr_session_get_id(sess_data->sr_sess) == sid) {
            break;
        }
    }
    if (!nc_sess) {
        return 0;
    }

    return nc_session_get_id(nc_sess);
}

struct lyd_node *
ncm_get_data(sr_conn_ctx_t *conn)
{
    struct lyd_node *root = NULL, *cont, *list, *cont2, *cont3;
    const struct lys_module *mod;
    struct ly_ctx *ly_ctx;
    const char **cpblts;
    char buf[26];
    uint32_t i, sid;
    int rc, is_locked;
    time_t ts;

    ly_ctx = (struct ly_ctx *)sr_get_context(conn);

    root = lyd_new_path(NULL, ly_ctx, "/ietf-netconf-monitoring:netconf-state", NULL, 0, 0);
    if (!root) {
        goto error;
    }

    /* capabilities */
    cont = lyd_new(root, NULL, "capabilities");

    cpblts = nc_server_get_cpblts_version(ly_ctx, LYS_VERSION_1);
    if (!cpblts) {
        goto error;
    }

    for (i = 0; cpblts[i]; ++i) {
        lyd_new_leaf(cont, NULL, "capability", cpblts[i]);
        lydict_remove(ly_ctx, cpblts[i]);
    }
    free(cpblts);

    cont = lyd_new(root, NULL, "datastores");

    list = lyd_new(cont, NULL, "datastore");
    lyd_new_leaf(list, NULL, "name", "running");
    rc = sr_get_lock(conn, SR_DS_RUNNING, NULL, &is_locked, &sid, NULL, &ts);
    if (rc != SR_ERR_OK) {
        WRN("Failed to learn about running lock (%s).", sr_strerror(rc));
    } else if (is_locked) {
        cont2 = lyd_new(list, NULL, "locks");
        cont3 = lyd_new(cont2, NULL, "global-lock");
        sprintf(buf, "%" PRIu32, ncm_sid2ncid(sid));
        lyd_new_leaf(cont3, NULL, "locked-by-session", buf);
        nc_time2datetime(ts, NCM_TIMEZONE, buf);
        lyd_new_leaf(cont3, NULL, "locked-time", buf);
    }

    list = lyd_new(cont, NULL, "datastore");
    lyd_new_leaf(list, NULL, "name", "startup");
    rc = sr_get_lock(conn, SR_DS_STARTUP, NULL, &is_locked, &sid, NULL, &ts);
    if (rc != SR_ERR_OK) {
        WRN("Failed to learn about startup lock (%s).", sr_strerror(rc));
    } else if (is_locked) {
        cont2 = lyd_new(list, NULL, "locks");
        cont3 = lyd_new(cont2, NULL, "global-lock");
        sprintf(buf, "%" PRIu32, ncm_sid2ncid(sid));
        lyd_new_leaf(cont3, NULL, "locked-by-session", buf);
        nc_time2datetime(ts, NCM_TIMEZONE, buf);
        lyd_new_leaf(cont3, NULL, "locked-time", buf);
    }

    list = lyd_new(cont, NULL, "datastore");
    lyd_new_leaf(list, NULL, "name", "candidate");
    rc = sr_get_lock(conn, SR_DS_CANDIDATE, NULL, &is_locked, &sid, NULL, &ts);
    if (rc != SR_ERR_OK) {
        WRN("Failed to learn about candidate lock (%s).", sr_strerror(rc));
    } else if (is_locked) {
        cont2 = lyd_new(list, NULL, "locks");
        cont3 = lyd_new(cont2, NULL, "global-lock");
        sprintf(buf, "%" PRIu32, ncm_sid2ncid(sid));
        lyd_new_leaf(cont3, NULL, "locked-by-session", buf);
        nc_time2datetime(ts, NCM_TIMEZONE, buf);
        lyd_new_leaf(cont3, NULL, "locked-time", buf);
    }

    /* schemas */
    cont = lyd_new(root, NULL, "schemas");

    i = 0;
    while ((mod = ly_ctx_get_module_iter(ly_ctx, &i))) {
        list = lyd_new(cont, NULL, "schema");
        lyd_new_leaf(list, NULL, "identifier", mod->name);
        lyd_new_leaf(list, NULL, "version", (mod->rev ? mod->rev[0].date : NULL));
        lyd_new_leaf(list, NULL, "format", "yang");
        lyd_new_leaf(list, NULL, "namespace", lys_main_module(mod)->ns);
        lyd_new_leaf(list, NULL, "location", "NETCONF");

        list = lyd_new(cont, NULL, "schema");
        lyd_new_leaf(list, NULL, "identifier", mod->name);
        lyd_new_leaf(list, NULL, "version", (mod->rev ? mod->rev[0].date : NULL));
        lyd_new_leaf(list, NULL, "format", "yin");
        lyd_new_leaf(list, NULL, "namespace", lys_main_module(mod)->ns);
        lyd_new_leaf(list, NULL, "location", "NETCONF");
    }

    /* sessions */
    pthread_mutex_lock(&stats.lock);

    if (stats.session_count) {
        cont = lyd_new(root, NULL, "sessions");

        for (i = 0; i < stats.session_count; ++i) {
            list = lyd_new(cont, NULL, "session");

            sprintf(buf, "%u", nc_session_get_id(stats.sessions[i]));
            lyd_new_leaf(list, NULL, "session-id", buf);
            switch (nc_session_get_ti(stats.sessions[i])) {
#ifdef NC_ENABLED_SSH
            case NC_TI_LIBSSH:
                lyd_new_leaf(list, NULL, "transport", "netconf-ssh");
                break;
#endif
#ifdef NC_ENABLED_TLS
            case NC_TI_OPENSSL:
                lyd_new_leaf(list, NULL, "transport", "netconf-tls");
                break;
#endif
            default: /* NC_TI_FD, NC_TI_NONE */
                ERR("ietf-netconf-monitoring unsupported session transport type.");
                pthread_mutex_unlock(&stats.lock);
                goto error;
            }
            lyd_new_leaf(list, NULL, "username", nc_session_get_username(stats.sessions[i]));
            lyd_new_leaf(list, NULL, "source-host", nc_session_get_host(stats.sessions[i]));
            nc_time2datetime(nc_session_get_start_time(stats.sessions[i]), NCM_TIMEZONE, buf);
            lyd_new_leaf(list, NULL, "login-time", buf);

            sprintf(buf, "%u", stats.session_stats[i].in_rpcs);
            lyd_new_leaf(list, NULL, "in-rpcs", buf);
            sprintf(buf, "%u", stats.session_stats[i].in_bad_rpcs);
            lyd_new_leaf(list, NULL, "in-bad-rpcs", buf);
            sprintf(buf, "%u", stats.session_stats[i].out_rpc_errors);
            lyd_new_leaf(list, NULL, "out-rpc-errors", buf);
            sprintf(buf, "%u", stats.session_stats[i].out_notifications);
            lyd_new_leaf(list, NULL, "out-notifications", buf);
        }
    }

    /* statistics */
    cont = lyd_new(root, NULL, "statistics");

    nc_time2datetime(stats.netconf_start_time, NCM_TIMEZONE, buf);
    lyd_new_leaf(cont, NULL, "netconf-start-time", buf);
    sprintf(buf, "%u", stats.in_bad_hellos);
    lyd_new_leaf(cont, NULL, "in-bad-hellos", buf);
    sprintf(buf, "%u", stats.in_sessions);
    lyd_new_leaf(cont, NULL, "in-sessions", buf);
    sprintf(buf, "%u", stats.dropped_sessions);
    lyd_new_leaf(cont, NULL, "dropped-sessions", buf);
    sprintf(buf, "%u", stats.global_stats.in_rpcs);
    lyd_new_leaf(cont, NULL, "in-rpcs", buf);
    sprintf(buf, "%u", stats.global_stats.in_bad_rpcs);
    lyd_new_leaf(cont, NULL, "in-bad-rpcs", buf);
    sprintf(buf, "%u", stats.global_stats.out_rpc_errors);
    lyd_new_leaf(cont, NULL, "out-rpc-errors", buf);
    sprintf(buf, "%u", stats.global_stats.out_notifications);
    lyd_new_leaf(cont, NULL, "out-notifications", buf);

    pthread_mutex_unlock(&stats.lock);

    if (lyd_validate(&root, LYD_OPT_NOSIBLINGS, NULL)) {
        goto error;
    }

    return root;

error:
    lyd_free(root);
    return NULL;
}
