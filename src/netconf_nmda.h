/**
 * @file netconf_nmda.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-nmda callbacks header
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

#ifndef NP2SRV_NETCONF_NMDA_H_
#define NP2SRV_NETCONF_NMDA_H_

#include <libyang/libyang.h>
#include <nc_server.h>

#include "common.h"

struct nc_server_reply *np2srv_rpc_getdata_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

struct nc_server_reply *np2srv_rpc_editdata_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess);

#endif /* NP2SRV_NMDA_H_ */
