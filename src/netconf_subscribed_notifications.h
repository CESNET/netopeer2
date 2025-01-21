/**
 * @file netconf_subscribed_notifications.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks header
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

#ifndef NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_
#define NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"

/**
 * @brief Argument of the sysrepo notification dispatch callback.
 * */
struct np_sub_ntf_arg {
    struct nc_session *ncs;
    uint32_t sub_id;
};

/**
 * @brief Operational information about the subscriptions in addition to that provided by sysrepo.
 */
struct np_sub_ntf_state {
    pthread_rwlock_t lock;
    struct np2srv_sub_ntf {
        uint32_t nc_id;
        uint32_t sub_id;
        char *filter_name;
        struct lyd_node *subtree_filter;
        char *xpath_filter;
        int is_yp;
        int terminated;                     /**< subscription was terminated and will be freed once the notification is received */
        struct np_sub_ntf_arg *cb_arg;
    } *subs;
    uint32_t count;
};

void np_sub_ntf_session_destroy(struct nc_session *ncs);

struct nc_server_reply *np2srv_rpc_establish_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_modify_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_delete_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_kill_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_resync_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

int np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *path, const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

#endif /* NP2SRV_NETCONF_SUBSCRIBED_NOTIFICATIONS_H_ */
