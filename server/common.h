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

#include <pthread.h>

#include "config.h"
#include "log.h"
#include "netconf.h"
#include "netconf_monitoring.h"
#include "netconf_server.h"

#define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))

/* server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;         /**< sysrepo connection */
    sr_session_ctx_t *sr_sess;      /**< sysrepo server session */
    sr_subscription_ctx_t *sr_data_sub; /**< sysrepo data subscription context */
    sr_subscription_ctx_t *sr_notif_sub;    /**< sysrepo notification sunscription context */

    const char *unix_path;          /**< path to the UNIX socket to listen on, if any */
    mode_t unix_mode;               /**< UNIX socket mode */
    uid_t unix_uid;                 /**< UNIX socket UID */
    gid_t unix_gid;                 /**< UNIX socket GID */

    struct nc_pollsession *nc_ps;   /**< libnetconf2 pollsession structure */
    uint16_t nc_max_sessions;       /**< maximum number of running sessions */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};
extern struct np2srv np2srv;

void np2srv_ntf_new_clb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data);

void np2srv_new_session_clb(const char *client_name, struct nc_session *new_session);

#endif /* NP2SRV_COMMON_H_ */
