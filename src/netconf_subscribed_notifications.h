/**
 * @file netconf_subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks header
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_
#define NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

/**
 * @brief Type of a subscribed-notifications subscription.
 */
enum sub_ntf_type {
    SUB_TYPE_SUB_NTF,   /**< standard subscribed-notifications subscription */
    SUB_TYPE_YANG_PUSH, /**< yang-push subscription */
};

/**
 * @brief Complete operational information about the subscriptions.
 */
struct np2srv_sub_ntf_info {
    pthread_mutex_t lock;
    ATOMIC_T sub_id_lock;   /* subscription ID that holds the lock, if a notification callback is called with this ID,
                               it must not appempt locking and can access this structure directly */

    struct np2srv_sub_ntf {
        uint32_t nc_id;
        uint32_t sub_ntf_id;
        uint32_t *sub_ids;
        ATOMIC_T sub_id_count;
        const char *term_reason;
        time_t stop_time;

        uint32_t sent_count;    /* sent notifications counter */

        enum sub_ntf_type type;
        void *data;
    } *subs;
    uint32_t count;
};

/*
 * for specific subscriptions
 */

/**
 * @brief Find next matching sub-ntf subscription structure.
 *
 * @param[in] last Last found structure.
 * @param[in] sub_ntf_match_cb Callback for deciding a subscription match.
 * @param[in] match_data Data passed to @p sub_ntf_match_cb based on which a match is decided.
 * @return Next matching subscription.
 * @return NULL if no more matching subscriptions found.
 */
struct np2srv_sub_ntf *sub_ntf_find_next(struct np2srv_sub_ntf *last,
        int (*sub_ntf_match_cb)(struct np2srv_sub_ntf *sub, const void *match_data), const void *match_data);

/**
 * @brief Remove a subscription from internal subscriptions.
 * Only once all the sysrepo subscription of a sub-ntf subscription were removed, the actual sub-ntf subscription
 * is also removed.
 *
 * @param[in] sub_id Sysrepo subscription ID to remove.
 * @param[in] nc_id Receiver NETCONF SID.
 * @param[out] term_reason If was the last, set termination reason.
 * @return Whether the last sysrepo subscription was removed for a sub-ntf subscription.
 */
int sub_ntf_sr_del_is_last(uint32_t sub_id, uint32_t nc_id, const char **term_reason);

/**
 * @brief Get ntf-sub subscription ID from sysrepo subscription ID.
 *
 * @param[in] sub_id Sysrepo subscription ID.
 * @return sub-ntf subscription ID.
 */
uint32_t sub_ntf_sub_id_sr2sub_ntf(uint32_t sub_id);

/**
 * @brief Increase sent counter for a subscription.
 *
 * @param[in] sub_id Both sysrepo subscription ID and sub-ntf subscription ID of the subscription to update.
 */
void sub_ntf_inc_sent(uint32_t sub_id);

/**
 * @brief Create subscription-modified notification.
 *
 * @param[in] sub_id Both sysrepo and sub-ntf subscription ID.
 * @param[in] nc_id NETCONF SID.
 * @param[out] ly_ntf Created notification.
 * @return Sysrepo error value.
 */
int sub_ntf_notif_modified(uint32_t sub_id, uint32_t nc_id, struct lyd_node **ly_ntf);

/**
 * @brief If holding the sub-ntf lock, pass it to another callback that will be called by some following code.
 *
 * @param[in] sub_id Sysrepo subscription ID obtained in the callback.
 */
void sub_ntf_cb_lock_pass(uint32_t sub_id);

/**
 * @brief Correctly terminate a ntf-sub subscription.
 * ntf-sub lock is expected to be held.
 *
 * @param[in] sub Subscription to terminate, is freed on success!
 * @return Sysrepo error value.
 */
int sub_ntf_terminate_sub(struct np2srv_sub_ntf *sub);

/*
 * for main.c
 */
void np2srv_sub_ntf_destroy(void);

int np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_delete_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_oper_sub_ntf_streams_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

#endif /* NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_ */
