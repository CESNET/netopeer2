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

#include <sysrepo.h>

#include "config.h"

#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

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

    pthread_mutex_t pending_sub_lock;
    struct np2srv_psub {
        struct nc_session *sess;
        char *stream;
        char *xpath;
        time_t start;
        time_t stop;
    } *pending_subs;
    uint16_t pending_sub_count;

    struct nc_pollsession *nc_ps;   /**< libnetconf2 pollsession structure */
    uint16_t nc_max_sessions;       /**< maximum number of running sessions */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};
extern struct np2srv np2srv;

void np2srv_new_session_cb(const char *client_name, struct nc_session *new_session);

#endif /* NP2SRV_COMMON_H_ */
