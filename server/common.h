/**
 * @file common.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief netopeer2-server common structures and functions
 *
 * Copyright (c) 2016 - 2017 CESNET, z.s.p.o.
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

#ifdef __GNUC__
#  define UNUSED(x) UNUSED_ ## x __attribute__((__unused__))
#else
#  define UNUSED(x) UNUSED_ ## x
#endif

/* NETCONF - SYSREPO connections */
struct np2_sessions {
    struct nc_session *ncs; /* NETCONF session */
    sr_session_ctx_t *srs;  /* SYSREPO session */
    sr_datastore_t ds;      /* current SYSREPO datastore */
    sr_sess_options_t opts; /* current SYSREPO session options */

    int flags;              /* various flags */
#define NP2S_CAND_CHANGED 0x01
};

/* Netopeer server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;        /**< sysrepo connection */
    int disconnected;              /**< flag marking that server is currently not connected to sysrepo */
    struct np2_sessions sr_sess;   /**< Netopeer's sysrepo sessions */
    sr_subscription_ctx_t *sr_subscr; /**< sysrepo subscription context */

    struct nc_pollsession *nc_ps;  /**< libnetconf2 pollsession structure */
    uint16_t nc_max_sessions;      /**< maximum number of running sessions */
    pthread_t workers[NP2SRV_THREAD_COUNT]; /**< worker threads handling sessions */

    struct ly_ctx *ly_ctx;         /**< libyang's context */
    pthread_rwlock_t ly_ctx_lock;  /**< libyang's context rwlock */
};
extern struct np2srv np2srv;

int np2srv_sr_reconnect(void);

int ietf_netconf_server_init(const struct lys_module *module);
int ietf_system_init(const struct lys_module *module);

void np2srv_new_session_clb(const char *UNUSED(client_name), struct nc_session *new_session);

#endif /* NP2SRV_COMMON_H_ */
