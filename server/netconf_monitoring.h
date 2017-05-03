/**
 * @file netconf_monitoring.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-monitoring statistics and counters header
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_MONITORING_H_
#define NP2SRV_NETCONF_MONITORING_H_

#include <nc_server.h>

void ncm_init(void);
void ncm_destroy(void);

void ncm_session_rpc(struct nc_session *session);
void ncm_session_bad_rpc(struct nc_session *session);
void ncm_session_rpc_reply_error(struct nc_session *session);
void ncm_session_notification(struct nc_session *session);
void ncm_session_add(struct nc_session *session);
void ncm_session_del(struct nc_session *session);
void ncm_bad_hello(void);

struct lyd_node *ncm_get_data(void);

#endif /* NP2SRV_NETCONF_MONITORING_H_ */
