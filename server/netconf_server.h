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

int np2srv_idle_timeout_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_ch_client_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_ch_connection_type_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_reconnect_strategy_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

#endif /* NP2SRV_NETCONF_SERVER_H_ */
