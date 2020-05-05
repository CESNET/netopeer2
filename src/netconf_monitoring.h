/**
 * @file netconf_monitoring.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-monitoring statistics and counters header
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_MONITORING_H_
#define NP2SRV_NETCONF_MONITORING_H_

#include <pthread.h>

#include <nc_server.h>
#include <sysrepo.h>

struct ncm_session_stats {
    uint32_t in_rpcs;
    uint32_t in_bad_rpcs;
    uint32_t out_rpc_errors;
    uint32_t out_notifications;
};

struct ncm {
    struct nc_session **sessions;
    struct ncm_session_stats *session_stats;
    uint32_t session_count;

    time_t netconf_start_time;
    uint32_t in_bad_hellos;
    uint32_t in_sessions;
    uint32_t dropped_sessions;
    struct ncm_session_stats global_stats;

    pthread_mutex_t lock;
};

void ncm_init(void);
void ncm_destroy(void);

void ncm_session_rpc(struct nc_session *session);
void ncm_session_bad_rpc(struct nc_session *session);
void ncm_session_rpc_reply_error(struct nc_session *session);
void ncm_session_notification(struct nc_session *session);
void ncm_session_add(struct nc_session *session);
void ncm_session_del(struct nc_session *session);
void ncm_bad_hello(void);

struct lyd_node *ncm_get_data(sr_conn_ctx_t *conn);

#endif /* NP2SRV_NETCONF_MONITORING_H_ */
