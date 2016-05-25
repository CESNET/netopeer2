/**
 * @file netconf_monitoring.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server ietf-netconf-monitoring statistics and counters
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
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

#include "netconf_monitoring.h"
#include "common.h"
#include "log.h"

struct np_session_stats {
    uint32_t in_rpcs;
    uint32_t in_bad_rpcs;
    uint32_t out_rpc_errors;
    uint32_t out_notifications;
};

static struct {
    struct nc_session **sessions;
    struct np_session_stats *session_stats;
    uint32_t session_count;

    time_t netconf_start_time;
    uint32_t in_bad_hellos;
    uint32_t in_sessions;
    uint32_t dropped_sessions;
    struct np_session_stats global_stats;

    pthread_mutex_t lock;
} stats;

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

void
ncm_session_rpc(struct nc_session *session)
{
    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].in_rpcs;
    ++stats.global_stats.in_rpcs;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_bad_rpc(struct nc_session *session)
{
    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].in_bad_rpcs;
    ++stats.global_stats.in_bad_rpcs;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_rpc_reply_error(struct nc_session *session)
{
    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].out_rpc_errors;
    ++stats.global_stats.out_rpc_errors;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_notification(struct nc_session *session)
{
    pthread_mutex_lock(&stats.lock);

    ++stats.session_stats[find_session_idx(session)].out_notifications;
    ++stats.global_stats.out_notifications;

    pthread_mutex_unlock(&stats.lock);
}

void
ncm_session_add(struct nc_session *session)
{
    void *new;

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
ncm_session_del(struct nc_session *session, int dropped)
{
    uint32_t i;

    pthread_mutex_lock(&stats.lock);

    if (dropped) {
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
ncm_bad_hello(void)
{
    pthread_mutex_lock(&stats.lock);

    ++stats.in_bad_hellos;

    pthread_mutex_unlock(&stats.lock);
}

struct lyd_node *
ncm_get_data(void)
{
    struct lyd_node *yanglib, *root = NULL, *cont;
    const char **cpblts;
    int i;

    yanglib = ly_ctx_info(np2srv.ly_ctx);
    if (!yanglib) {
        goto error;
    }

    root = lyd_new_path(NULL, np2srv.ly_ctx, "/ietf-netconf-monitoring:netconf-state", NULL, 0);
    if (!root) {
        goto error;
    }

    /* capabilities */
    cont = lyd_new(root, NULL, "capabilities");

    cpblts = nc_server_get_cpblts(np2srv.ly_ctx);
    if (!cpblts) {
        goto error;
    }

    for (i = 0; cpblts[i]; ++i) {
        lyd_new_leaf(cont, NULL, "capability", cpblts[i]);
        lydict_remove(np2srv.ly_ctx, cpblts[i]);
    }
    free(cpblts);

    /* datastores */
    /* TODO */

    /* schemas */
    /* TODO */

    /* sessions */
    /* TODO */

    /* statistics */
    /* TODO */

    lyd_free(yanglib);
    return root;

error:
    lyd_free(yanglib);
    lyd_free(root);
    return NULL;
}
