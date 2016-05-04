/**
 * @file common.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief netopeer2-server common structures and functions
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_COMMON_H_
#define NP2SRV_COMMON_H_

#include "config.h"
#include "log.h"

/* NETCONF session's sysrepo connections */
struct np2sr_sessions {
    sr_session_ctx_t *running;
    sr_session_ctx_t *running_config;
    sr_session_ctx_t *startup;
    sr_session_ctx_t *candidate;
    int flags;
    struct nc_session *ncs;
};

#define NP2SRV_CAND_MODIFIED 0x01  /**< candidate datastore modified (candidate is being committed explicitly) */

/* Netopeer server internal data */
struct np2srv {
    sr_conn_ctx_t *sr_conn;        /**< sysrepo connection */
    struct np2sr_sessions sr_sess; /**< Netopeer's sysrepo sessions */

    struct ly_ctx *ly_ctx;         /**< libyang's context */

    struct nc_pollsession *nc_ps;
};
extern struct np2srv np2srv;

#endif /* NP2SRV_COMMON_H_ */
