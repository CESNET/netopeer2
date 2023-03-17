/**
 * @file err_netconf.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF error header
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
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

void np_err_sr2nc_lock_denied(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info);

void np_err_sr2nc_in_use(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info);

void np_err_sr2nc_same_ds(sr_session_ctx_t *ev_sess, const char *err_msg);

void np_err_in_use(sr_session_ctx_t *ev_sess, uint32_t sr_id);

void np_err_lock_denied(sr_session_ctx_t *ev_sess, const char *err_msg, uint32_t nc_id);

void np_err_missing_element(sr_session_ctx_t *ev_sess, const char *elem_name);

void np_err_bad_element(sr_session_ctx_t *ev_sess, const char *elem_name, const char *description);

void np_err_invalid_value(sr_session_ctx_t *ev_sess, const char *description, const char *bad_elem_name);

void np_err_operation_failed(sr_session_ctx_t *ev_sess, const char *description);

void np_err_ntf_sub_no_such_sub(sr_session_ctx_t *ev_sess, const char *message);

void np_err_sr2nc_edit(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess);

void np_err_sr2nc_get(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess);

#endif /* NP2SRV_ERR_NETCONF_H_ */
