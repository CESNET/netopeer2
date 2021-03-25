/**
 * @file netconf_server_tks.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-server TLS callbacks header
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_NETCONF_SERVER_TLS_H_
#define NP2SRV_NETCONF_SERVER_TLS_H_

#include <sysrepo.h>
#include <nc_server.h>

int np2srv_cert_cb(const char *name, void *user_data, char **cert_path, char **cert_data, char **privkey_path,
        char **privkey_data, NC_SSH_KEY_TYPE *privkey_type);

int np2srv_cert_list_cb(const char *name, void *user_data, char ***cert_paths, int *cert_path_count, char ***cert_data,
        int *cert_data_count);

int np2srv_endpt_tls_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_endpt_tls_servercert_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_endpt_tls_client_auth_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_endpt_tls_client_ctn_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_ch_client_endpt_tls_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath,
        sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_ch_client_endpt_tls_servercert_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_ch_client_endpt_tls_client_auth_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

int np2srv_ch_client_endpt_tls_client_ctn_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name,
        const char *xpath, sr_event_t event, uint32_t request_id, void *private_data);

#endif /* NP2SRV_NETCONF_SERVER_TLS_H_ */
