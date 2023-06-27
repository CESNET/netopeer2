/**
 * @file netconf_subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks header
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

#ifndef NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_
#define NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "receivers.h"

/**
 * @brief state of a configured subscribed-notifications.
 */
enum sub_cfg_state {
    SUB_CFG_STATE_NONE = 0,
    SUB_CFG_STATE_VALID,
    SUB_CFG_STATE_INVALID,
    SUB_CFG_STATE_CONCLUDED
};

/**
 * @brief Type of a subscribed-notifications subscription.
 */
enum sub_ntf_type {
    SUB_TYPE_DYN_SUB,       /**< standard subscribed-notifications subscription */
    SUB_TYPE_DYN_YANG_PUSH, /**< yang-push subscription */
    SUB_TYPE_CFG_SUB,       /**< configured subscriptions */
    SUB_TYPE_CFG_YANG_PUSH  /**< configured yang push */
};

/**
 * @brief Complete operational information about the subscriptions.
 */
struct np2srv_sub_ntf_info {
    pthread_rwlock_t lock;
    ATOMIC_T sub_id_lock;   /* subscription ID that holds the lock, if a notification callback is called with this ID,
                               it must not attempt locking and can access this structure directly */

    struct np2srv_sub_ntf {
        uint32_t nc_id;
        uint32_t nc_sub_id;
        uint32_t *sub_ids;
        ATOMIC_T sub_id_count;
        const char *term_reason;
        struct timespec stop_time;

        int terminating;        /* set flag means the WRITE lock for this subscription will not be granted */
        ATOMIC_T sent_count;    /* sent notifications counter */

        enum sub_ntf_type type;
        void *data;
    } *subs;
    uint32_t count;

    struct csn_receiver_config *recv_configs;
    uint32_t recv_cfg_count;
};

/*
 * for specific subscriptions
 */

/**
 * @brief Lock the sub-ntf lock, if possible, and return a subscription.
 *
 * @param[in] nc_sub_id NC sub ID of the subscription.
 * @param[in] sub_id SR subscription ID in a callback, 0 if not in callback.
 * @param[in] write Whether to write or read-lock.
 * @return Found subscription.
 * @return NULL if subscription was not found or it is terminating.
 */
struct np2srv_sub_ntf *sub_ntf_find_lock(uint32_t nc_sub_id, uint32_t sub_id, int write);

/**
 * @brief Unlock the sub-ntf lock.
 *
 * @param[in] sub_id SR subscription ID in a callback, 0 if not in callback.
 */
void sub_ntf_unlock(uint32_t sub_id);

/**
 * @brief Find the next matching sub-ntf subscription structure.
 *
 * @param[in] last Last found structure, NULL on first call.
 * @param[in] sub_ntf_match_cb Callback for deciding a subscription match.
 * @param[in] match_data Data passed to @p sub_ntf_match_cb based on which a match is decided.
 * @return Next matching subscription.
 * @return NULL if no more matching subscriptions found.
 */
struct np2srv_sub_ntf *sub_ntf_find_next(struct np2srv_sub_ntf *last,
        int (*sub_ntf_match_cb)(struct np2srv_sub_ntf *sub, const void *match_data), const void *match_data);

/**
 * @brief Send a notification.
 *
 * @param[in] ncs NETCONF session to use.
 * @param[in] nc_sub_id NETCONF sub ID of the subscription.
 * @param[in] timestamp Timestamp to use.
 * @param[in,out] ly_ntf Notification to send.
 * @param[in] use_ntf Whether to free @p ly_ntf and set to NULL or leave unchanged.
 * @return Sysrepo error value.
 */
int sub_ntf_send_notif(struct nc_session *ncs, uint32_t nc_sub_id, struct timespec timestamp, struct lyd_node **ly_ntf,
        int use_ntf);

/**
 * @brief If holding the sub-ntf lock, pass it to another callback that will be called by some following code.
 *
 * Clear with sub_ntf_cb_lock_clear().
 *
 * @param[in] sub_id Sysrepo subscription ID obtained in the callback.
 */
void sub_ntf_cb_lock_pass(uint32_t sub_id);

/**
 * @brief Clear the passed sub-ntf lock.
 *
 * @param[in] sub_id Sysrepo subscription ID that the lock was passed to.
 */
void sub_ntf_cb_lock_clear(uint32_t sub_id);

/**
 * @brief Correctly terminate a ntf-sub subscription.
 * ntf-sub lock is expected to be held.
 *
 * @param[in] sub Subscription to terminate, is freed.
 * @param[in] ncs NETCONF session.
 * @return Sysrepo error value.
 */
int sub_ntf_terminate_sub(struct np2srv_sub_ntf *sub, struct nc_session *ncs);

/**
 * @brief Send a subscription-modified notification.
 *
 * @param[in] sub Subscription structure that was modified.
 * @return Sysrepo error value.
 */
int sub_ntf_send_notif_modified(const struct np2srv_sub_ntf *sub);

/**
 * @brief Create a new function timer.
 *
 * @param[in] cb Callback to be called.
 * @param[in] arg Argument for @p cb.
 * @param[in] force_real Whether to force realtime clock ID or can be monotonic if available.
 * @param[out] timer_id Created timer ID.
 * @return Sysrepo error value.
 */
int sub_ntf_create_timer(void (*cb)(union sigval), void *arg, int force_real, timer_t *timer_id);

/*
 * for main.c
 */
void np2srv_sub_ntf_session_destroy(struct nc_session *ncs);

void np2srv_sub_ntf_destroy(void);

int np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_delete_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data);

int np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_oper_sub_ntf_streams_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_config_receivers_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_config_subscriptions_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_config_subscriptions_receivers_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_oper_sub_ntf_receivers_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_rpc_reset_receiver_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data);

/*
 * for configured subscribed notifications
 */

/**
 * @brief Send a notification.
 *
 * @param[in] receivers reference to receivers to use.
 * @param[in] receivers_count the number of receivers.
 * @param[in] nc_sub_id NETCONF sub ID of the subscription.
 * @param[in] timestamp Timestamp to use.
 * @param[in,out] ly_ntf Notification to send.
 * @param[in] use_ntf Whether to free @p ly_ntf and set to NULL or leave unchanged.
 * @return Sysrepo error value.
 */
int csn_send_notif(struct csn_receiver_info *recv_info, uint32_t nc_sub_id,
        struct timespec timestamp, struct lyd_node **ly_ntf, int use_ntf);

/**
 * @brief Destroy content of receiver info in a subscription
 *
 * @param[in] receiver_info in the subscription.
 */
void csn_receiver_info_destroy(struct csn_receiver_info *recv_info);

/**
 * @brief Destroy content of receiver in a subscription
 *
 * @param[in] receiver in the subscription in the receiver_info.
 */
void csn_receiver_destroy(struct csn_receiver *receiver, int keep_ref);

/**
 * @brief start a receiver
 *
 * @param[in] receiver in the subscription in the receiver_info.
 * @param[in] receiver_config is the global receiver config
 * @param[in] receiver_info in the subscription.
 * @return Sysrepo error value.
 */
int csn_receiver_start(struct csn_receiver *receiver, struct csn_receiver_config *recv_config,
        struct csn_receiver_info *recv_info);
/**
 * @brief add a receiver in the receiver_info list
 *
 * @param[in] receiver in the subscription in the receiver_info.
 * @param[in] receiver_info in the subscription.
 * @return Sysrepo error value.
 */
int csn_receiver_add(struct csn_receiver_info *recv_info, struct csn_receiver *receiver);

/**
 * @brief get a receiver configration from the list
 *
 * @param[in] name of a receiver configuration.
 * @return a config containing receiver connection parameters
 */
struct csn_receiver_config *csn_receiver_config_get_by_name(const char *name);

#endif /* NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_ */
