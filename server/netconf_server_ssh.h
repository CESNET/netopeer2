/**
 * @file netconf_server_ssh.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server SSH callbacks header
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_SERVER_SSH_H_
#define NP2SRV_NETCONF_SERVER_SSH_H_

#include <libssh/libssh.h>
#include <sysrepo.h>

int np2srv_hostkey_cb(const char *name, void *user_data, char **privkey_path, char **privkey_data,
        NC_SSH_KEY_TYPE *privkey_type);

int np2srv_pubkey_auth_cb(const struct nc_session *session, ssh_key key, void *user_data);

int np2srv_endpt_ssh_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data);

int np2srv_endpt_tcp_params_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_endpt_ssh_hostkey_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_endpt_ssh_auth_methods_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_endpt_ssh_keepalives_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_endpt_ssh_auth_users_oper_cb(sr_session_ctx_t *session, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data);

int np2srv_ch_client_endpt_ssh_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_client_endpt_tcp_params_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_endpt_ssh_hostkey_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_endpt_ssh_auth_methods_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

int np2srv_ch_endpt_ssh_keepalives_cb(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        uint32_t request_id, sr_event_t event, void *private_data);

#endif /* NP2SRV_NETCONF_SERVER_SSH_H_ */
