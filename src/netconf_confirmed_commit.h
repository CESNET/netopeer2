/**
 * @file netconf_confirmed_commit.h
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf confirmed-commit capability header
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

#ifndef NP2SRV_NETCONF_CONFIRMED_COMMIT_H_
#define NP2SRV_NETCONF_CONFIRMED_COMMIT_H_

#include <stdint.h>

#include <libyang/libyang.h>
#include <nc_server.h>

#include "common.h"

/**
 * @brief Destroy the commit_ctx_s structure.
 */
void ncc_commit_ctx_destroy(void);

/**
 * @brief Check whether there is an ongoing confirmed commit.
 *
 * @param[out] nc_sess NETCONF session that started the confirmed commit, if any.
 * @return Whether there is an ongoing confirmed commit or not.
 */
int ncc_ongoing_confirmed_commit(struct nc_session **nc_sess);

/**
 * @brief Try and restore a previous confirmed commit after server reboot.
 */
void ncc_try_restore(void);

/**
 * @brief Revert current confirmed commit, if any, if not persistent and this session started it.
 *
 * @param[in] user_sess User session with terminated NC session.
 * @param[in] sr_sess Sysrepo server session.
 */
void ncc_del_session(struct np_user_sess *user_sess, sr_session_ctx_t *sr_sess);

struct nc_server_reply *np2srv_rpc_commit_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_cancel_commit_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

#endif /* NP2SRV_NETCONF_CONFIRMED_COMMIT_H_ */
