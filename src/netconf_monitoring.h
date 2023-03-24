/**
 * @file netconf_monitoring.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-monitoring statistics and counters header
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_MONITORING_H_
#define NP2SRV_NETCONF_MONITORING_H_

#define _GNU_SOURCE

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
void ncm_bad_hello(struct nc_session *session);

uint32_t ncm_session_get_notification(struct nc_session *session);

int np2srv_ncm_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_rpc_getschema_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

#endif /* NP2SRV_NETCONF_MONITORING_H_ */
