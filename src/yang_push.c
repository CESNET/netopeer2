/**
 * @file yang_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications ietf-yang-push callbacks
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include "yang_push.h"

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "log.h"
#include "common.h"
#include "netconf_subscribed_notifications.h"

int
yang_push_rpc_establish_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, time_t stop, uint32_t **sub_ids,
        uint32_t *sub_id_count, void **data)
{

}

int
yang_push_rpc_modify_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, time_t stop, struct np2srv_sub_ntf *sub)
{

}

int
yang_push_notif_modified_append_data(struct lyd_node *ntf, void *data)
{

}

int
yang_push_config_filters(const struct lyd_node *filter, sr_change_oper_t op)
{

}

int
yang_push_oper_subscription(struct lyd_node *subscription, void *data)
{

}

uint32_t
yang_push_oper_receiver_excluded(struct np2srv_sub_ntf *sub)
{

}

int
yang_push_terminate_sr_sub(uint32_t sub_id)
{

}

void
yang_push_data_destroy(void *data)
{

}
