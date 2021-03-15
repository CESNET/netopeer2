/**
 * @file netconf_yang_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-yang-push callbacks
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include "netconf_yang_push.h"

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "log.h"
#include "common.h"

int
np2srv_rpc_establish_yang_push_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    return SR_ERR_OK;
}

int
np2srv_rpc_modify_yang_push_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    return SR_ERR_OK;
}
