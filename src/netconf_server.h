/**
 * @file netconf_server.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server callbacks header
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

#ifndef NP2SRV_NETCONF_SERVER_H_
#define NP2SRV_NETCONF_SERVER_H_

#include <nc_server.h>
#include <sysrepo.h>

/**
 * @brief Callback for handling netconf-server, ietf-keystore and ietf-truststore data changes.
 *
 * The diff is given to libnetconf2, which then handles the changes.
 *
 * @param session sysrepo session.
 * @param[in] sub_id Subscription identifier.
 * @param[in] module_name Module's name.
 * @param[in] xpath XPath.
 * @param[in] event Event.
 * @param[in] request_id Request identifier.
 * @param private_data Private data.
 *
 * @return SR_ERR_OK on success, on error any other value.
 */
int np2srv_libnetconf2_config_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

#ifdef NC_ENABLED_SSH_TLS

int np2srv_pubkey_auth_cb(const struct nc_session *session, ssh_key key, void *user_data);

#endif /* NC_ENABLED_SSH_TLS */

#endif /* NP2SRV_NETCONF_SERVER_H_ */
