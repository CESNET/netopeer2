/**
 * @file netconf_confirmed_commit.h
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf confirmed-commit capability header
 *
 * @copyright
 * Copyright (c) 2019 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2023 CESNET, z.s.p.o.
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
#include <sysrepo.h>

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
 * @param[in] nc_sess Terminated NC session.
 * @param[in] sr_sess Sysrepo server session.
 */
void ncc_del_session(const struct nc_session *nc_sess, sr_session_ctx_t *sr_sess);

int np2srv_rpc_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_cancel_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

#endif /* NP2SRV_NETCONF_CONFIRMED_COMMIT_H_ */
