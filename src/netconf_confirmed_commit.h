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
 * @brief Try and restore a previous confirmed commit after server reboot.
 */
void ncc_try_restore(void);

/**
 * @brief Revert current confirmed commit, if any, if not persistent and this session started it.
 *
 * @param[in] nc_id NC ID of a terminated NC session.
 */
void ncc_del_session(uint32_t nc_id);

int np2srv_rpc_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_cancel_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

#endif /* NP2SRV_NETCONF_CONFIRMED_COMMIT_H_ */
