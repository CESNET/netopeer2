/**
 * @file err_netconf.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF error header
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_ERR_NETCONF_H_
#define NP2SRV_ERR_NETCONF_H_

#include <sysrepo.h>

void np_err_nacm_access_denied(sr_session_ctx_t *ev_sess, const char *module_name, const char *user, const char *path);

void np_err_sr2nc_lock_denied(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info);

void np_err_sr2nc_in_use(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info);

void np_err_sr2nc_same_ds(sr_session_ctx_t *ev_sess, const char *err_msg);

void np_err_missing_element(sr_session_ctx_t *ev_sess, const char *elem_name);

void np_err_bad_element(sr_session_ctx_t *ev_sess, const char *elem_name, const char *description);

void np_err_invalid_value(sr_session_ctx_t *ev_sess, const char *description, const char *bad_elem_name);

void np_err_ntf_sub_no_such_sub(sr_session_ctx_t *ev_sess, const char *message);

#endif /* NP2SRV_ERR_NETCONF_H_ */
