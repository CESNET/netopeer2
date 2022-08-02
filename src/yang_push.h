/**
 * @file yang_push.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications ietf-yang-push callbacks header
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

#ifndef NP2SRV_YANG_PUSH_H_
#define NP2SRV_YANG_PUSH_H_

#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

struct np2srv_sub_ntf;

/**
 * @brief Operations supported by yang-push.
 */
enum yang_push_op {
    YP_OP_CREATE,
    YP_OP_DELETE,
    YP_OP_INSERT,
    YP_OP_MOVE,
    YP_OP_REPLACE,
    YP_OP_OPERATION_COUNT   /* count of all the operations */
};

/**
 * @brief yang-push sysrepo change and timer callback argument.
 */
struct yang_push_cb_arg {
    struct nc_session *ncs;
    struct yang_push_data *yp_data;
    uint32_t nc_sub_id;
};

struct yang_push_data {
    /* parameters */
    sr_datastore_t datastore;
    char *selection_filter_ref;
    struct lyd_node *datastore_subtree_filter;
    char *datastore_xpath_filter;
    int periodic;

    union {
        struct {
            /* parameters */
            uint32_t period_ms;
            struct timespec anchor_time;

            /* internal data */
            timer_t update_timer;
        };
        struct {
            /* parameters */
            uint32_t dampening_period_ms;
            int sync_on_start;
            int excluded_change[YP_OP_OPERATION_COUNT];

            /* internal data */
            pthread_mutex_t notif_lock;
            sr_data_t *change_ntf;
            ATOMIC_T patch_id;
            ATOMIC_T edit_id;
            struct timespec last_notif;
            timer_t damp_timer;
            ATOMIC_T excluded_op_count; /* explicitly excluded changes */
        };
    };

    /* internal data */
    char *xpath;
    struct yang_push_cb_arg cb_arg;
    timer_t stop_timer;
};

/* for documentation, see subscribed_notifications.h */
int yang_push_rpc_establish_sub_prepare(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct np2srv_sub_ntf *sub);

int yang_push_rpc_establish_sub_start_async(sr_session_ctx_t *ev_sess, struct np2srv_sub_ntf *sub);

int yang_push_rpc_modify_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct timespec stop,
        struct np2srv_sub_ntf *sub);

int yang_push_notif_modified_append_data(struct lyd_node *ntf, void *data);

int yang_push_config_filters(const struct lyd_node *filter, sr_change_oper_t op);

int yang_push_oper_subscription(struct lyd_node *subscription, void *data);

uint32_t yang_push_oper_receiver_excluded(struct np2srv_sub_ntf *sub);

void yang_push_terminate_async(void *data);

void yang_push_data_destroy(void *data);

/*
 * for main.c
 */
int np2srv_rpc_resync_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

#endif /* NP2SRV_YANG_PUSH_H_ */
