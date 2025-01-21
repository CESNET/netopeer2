/**
 * @file netconf.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf callbacks header
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_H_
#define NP2SRV_NETCONF_H_

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"

struct nc_server_reply *np2srv_rpc_get_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_editconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_copyconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_deleteconfig_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_un_lock_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_kill_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_commit_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_cancel_commit_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_discard_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_validate_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_subscribe_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

int np2srv_nc_ntf_oper_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

#endif /* NP2SRV_NETCONF_H_ */
