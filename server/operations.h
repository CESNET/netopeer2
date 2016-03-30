/**
 * @file operations.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Basic NETCONF operations
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_OPERATIONS_H_
#define NP2SRV_OPERATIONS_H_

#include <nc_server.h>

/**
 * @brief Use when the session is being terminated to 'release' all its locks
 * @param[in] ncs NETCONF session being terminated.
 */
void np2srv_clean_dslock(struct nc_session *ncs);

struct nc_server_reply *op_get(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_lock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_unlock(struct lyd_node *rpc, struct nc_session *ncs);

#endif /* NP2SRV_OPERATIONS_H_ */
