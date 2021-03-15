/**
 * @file netconf_server.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server callbacks header
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_SERVER_H_
#define NP2SRV_NETCONF_SERVER_H_

#include <sysrepo.h>
#include <nc_server.h>

int np2srv_sr_get_privkey(const struct lyd_node *asym_key, char **privkey_data, NC_SSH_KEY_TYPE *privkey_type);

int np2srv_idle_timeout_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_endpt_tcp_params_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_client_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_ch_client_endpt_tcp_params_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_connection_type_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_reconnect_strategy_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

#endif /* NP2SRV_NETCONF_SERVER_H_ */
