/**
 * @file operations.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Basic NETCONF operations
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

struct nc_server_reply *op_get(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_un_lock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_editconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_copyconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_deleteconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_validate(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_kill(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_commit(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_discardchanges(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_subscribe(struct lyd_node *rpc, struct nc_session *ncs);

struct nc_server_reply *op_generic(struct lyd_node *rpc, struct nc_session *ncs);

#endif /* NP2SRV_OPERATIONS_H_ */
