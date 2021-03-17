/**
 * @file common.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief netopeer2-server common structures and functions
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_COMMON_H_
#define NP2SRV_COMMON_H_

#include <stdint.h>
#include <sys/types.h>
#include <time.h>
#include <pthread.h>

#include <nc_server.h>
#include <sysrepo.h>

#include "compat.h"
#include "config.h"

/* server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;         /**< sysrepo connection */
    sr_session_ctx_t *sr_sess;      /**< sysrepo server session */
    sr_subscription_ctx_t *sr_rpc_sub;  /**< sysrepo RPC subscription context */
    sr_subscription_ctx_t *sr_data_sub; /**< sysrepo data subscription context */
    sr_subscription_ctx_t *sr_notif_sub;    /**< sysrepo notification subscription context */

    const char *unix_path;          /**< path to the UNIX socket to listen on, if any */
    mode_t unix_mode;               /**< UNIX socket mode */
    uid_t unix_uid;                 /**< UNIX socket UID */
    gid_t unix_gid;                 /**< UNIX socket GID */
    uint32_t sr_timeout;            /**< timeout in ms for all sysrepo functions */

    struct nc_pollsession *nc_ps;   /**< libnetconf2 pollsession structure */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};
extern struct np2srv np2srv;

extern ATOMIC_T skip_nacm_sr_sid;

int np_sleep(uint32_t ms);

struct nc_session *np_get_nc_sess(uint32_t nc_id);

const char *np_get_nc_sess_user(sr_session_ctx_t *session);

sr_session_ctx_t *np_get_user_sess(sr_session_ctx_t *ev_sess);

int np_ly_mod_has_notif(const struct lys_module *mod);

void np2srv_new_session_cb(const char *client_name, struct nc_session *new_session);

int np2srv_url_setcap(void);

#ifdef NP2SRV_URL_CAPAB

struct lyd_node *op_parse_url(const char *url, uint32_t parse_options, int *rc, sr_session_ctx_t *sr_sess);

int op_export_url(const char *url, struct lyd_node *data, int options, int *rc, sr_session_ctx_t *sr_sess);

#endif

struct lyd_node *op_parse_config(struct lyd_node_any *config, uint32_t parse_options, int *rc, sr_session_ctx_t *sr_sess);

struct np2_filter {
    struct {
        char *str;
        int selection;  /**< selection or content filter */
    } *filters;
    uint32_t count;
};

int op_filter_subtree2xpath(const struct lyd_node *node, struct np2_filter *filter);

void op_filter_erase(struct np2_filter *filter);

int op_filter_filter2xpath(const struct np2_filter *filter, char **xpath);

/**
 * @brief Get all data matching the selection filters.
 */
int op_filter_data_get(sr_session_ctx_t *session, uint32_t max_depth, sr_get_oper_options_t get_opts,
        const struct np2_filter *filter, sr_session_ctx_t *ev_sess, struct lyd_node **data);

/**
 * @brief Filter out only the data matching the content filters.
 */
int op_filter_data_filter(struct lyd_node **data, const struct np2_filter *filter, int with_selection,
        struct lyd_node **filtered_data);

#endif /* NP2SRV_COMMON_H_ */
