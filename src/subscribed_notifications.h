/**
 * @file subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications sub-ntf callbacks header
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

#ifndef NP2SRV_SUBSCRIBED_NOTIFICATIONS_H_
#define NP2SRV_SUBSCRIBED_NOTIFICATIONS_H_

#include <stdint.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

struct np2srv_sub_ntf;

/**
 * @brief Sysrepo notification callback argument.
 */
struct sub_ntf_cb_arg {
    struct nc_session *ncs;
    struct sub_ntf_data *sn_data;
    uint32_t nc_sub_id;

    uint32_t sr_sub_count;          /* number of SR subscriptions made for this NC subscription */
    ATOMIC_T replay_complete_count; /* counter of special replay-complete notifications received */
};

/**
 * @brief Type-specific data for these subscriptions.
 */
struct sub_ntf_data {
    /* parameters */
    char *stream_filter_name;
    struct lyd_node *stream_subtree_filter;
    char *stream_xpath_filter;
    char *stream;
    struct timespec replay_start_time;

    /* internal data */
    struct sub_ntf_cb_arg cb_arg;
};

/**
 * @brief Called on establish-subscription RPC, should create any required sysrepo subscriptions and type-specific data.
 * sub-ntf lock NOT held, @p sub not yet in subscriptions.
 *
 * @param[in] ev_sess Event session.
 * @param[in] rpc RPC data.
 * @param[in,out] sub Subscription structure to prepare.
 * @return Sysrepo error value.
 */
int sub_ntf_rpc_establish_sub_prepare(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct np2srv_sub_ntf *sub);

/**
 * @brief Called on establish-subscription RPC, should start any asynchronous tasks.
 * sub-ntf lock held.
 *
 * @param[in] ev_sess Event session.
 * @param[in,out] sub Prepared subscription structure.
 * @return Sysrepo error value.
 */
int sub_ntf_rpc_establish_sub_start_async(sr_session_ctx_t *ev_sess, struct np2srv_sub_ntf *sub);

/**
 * @brief Called on modify-subscription RPC, should update sysrepo subscriptions and type-specific data accordingly.
 * sub-ntf lock held.
 *
 * @param[in] ev_sess Event session.
 * @param[in] rpc RPC data.
 * @param[in] stop New stop time, 0 if not modified.
 * @param[in,out] sub sub-ntf subscription to update.
 * @return Sysrepo error value.
 */
int sub_ntf_rpc_modify_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct timespec stop,
        struct np2srv_sub_ntf *sub);

/**
 * @brief Called on subscription-modified notification, should append type-specific YANG nodes.
 * sub-ntf lock held.
 *
 * @param[in] ntf Notification to append to.
 * @param[in] data Type-specific data.
 * @return Sysrepo error value.
 */
int sub_ntf_notif_modified_append_data(struct lyd_node *ntf, void *data);

/**
 * @brief Called for every configuration change in type-specific filters.
 * sub-ntf lock held.
 *
 * @param[in] filter Changed filter node.
 * @param[in] op Sysrepo operation.
 * @return Sysrepo error value.
 */
int sub_ntf_config_filters(const struct lyd_node *filter, sr_change_oper_t op);

/**
 * @brief Should append type-specific operational YANG nodes to "subscription" node.
 * sub-ntf lock held.
 *
 * @param[in] subscription Subscription to append to.
 * @param[in] data Type-specific data.
 * @return Sysrepo error value.
 */
int sub_ntf_oper_subscription(struct lyd_node *subscription, void *data);

/**
 * @brief Get excluded notification count for a subscription except for notifications denied by NACM.
 * sub-ntf lock held.
 *
 * @param[in] sub sub-ntf subscription to read from.
 * @return Number of excluded events because of non-matching fliter or denied NACM permission.
 */
uint32_t sub_ntf_oper_receiver_excluded(struct np2srv_sub_ntf *sub);

/**
 * @brief Terminate any asynchronous tasks (except for sysrepo subscriptions) so they cannot be executed
 * after this function ends. Case when they are being executed now is handled.
 *
 * @param[in] data Type-specific data to free.
 */
void sub_ntf_terminate_async(void *data);

/**
 * @brief Free type-specific data.
 *
 * @param[in] data Type-specific data to free.
 */
void sub_ntf_data_destroy(void *data);

#endif /* NP2SRV_SUBSCRIBED_NOTIFICATIONS_H_ */
