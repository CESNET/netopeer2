/**
 * @file netconf_confirmed_commit.h
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief ietf-netconf confirmed-commit capability header
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

/**
 * @brief Destroy the commit_ctx_s structure.
 */
void ncc_commit_ctx_destroy(void);

/**
 * @brief Try and restore a previous confirmed commit after server stopping.
 */
void ncc_try_restore(void);

int np2srv_rpc_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id,
        struct lyd_node *output, void *private_data);

int np2srv_rpc_cancel_commit_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id,
        struct lyd_node *output, void *private_data);
