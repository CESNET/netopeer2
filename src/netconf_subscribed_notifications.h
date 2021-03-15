/**
 * @file netconf_subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks header
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_
#define NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_

#include <libyang/libyang.h>
#include <sysrepo.h>

void np2srv_sub_ntf_destroy(void);

int np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_delete_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_sub_ntf_filters_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_sub_ntf_streams_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_sub_ntf_subscriptions_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

#endif /* NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_ */
