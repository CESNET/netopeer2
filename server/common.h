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
#include "operations.h"
#include "log.h"
#include "netconf_monitoring.h"

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

/* Netopeer server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;        /**< sysrepo connection */
    sr_session_ctx_t *sr_sess;     /**< sysrepo server session */
    sr_subscription_ctx_t *sr_sub; /**< sysrepo subscription context */

    struct nc_pollsession *nc_ps;  /**< libnetconf2 pollsession structure */
    uint16_t nc_max_sessions;      /**< maximum number of running sessions */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */
};
extern struct np2srv np2srv;

#endif /* NP2SRV_COMMON_H_ */
