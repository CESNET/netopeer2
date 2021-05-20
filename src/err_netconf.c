/**
 * @file err_netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF errors
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE /* asprintf */

#include "err_netconf.h"

#include <stdio.h>

#include "common.h"
#include "compat.h"

void
np_err_nacm_access_denied(sr_session_ctx_t *ev_sess, const char *module_name, const char *user, const char *path)
{
    const char *str;
    char *msg;
    int len;

    /* error format */
    sr_session_set_error_format(ev_sess, "NETCONF");

    /* error-type */
    str = "protocol";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    /* error-tag */
    str = "access-denied";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    /* error-message */
    len = asprintf(&msg, "Access to the data model \"%s\" is denied because \"%s\" NACM authorization failed.",
            module_name, user);
    sr_session_push_error_data(ev_sess, len + 1, msg);
    free(msg);

    /* error-app-tag */
    sr_session_push_error_data(ev_sess, 1, "");

    /* error-path */
    sr_session_push_error_data(ev_sess, strlen(path) + 1, path);
}

void
np_err_sr2nc_lock_denied(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info)
{
    struct nc_session *nc_sess;
    const char *str, *ptr;
    char buf[11];

    /* error format */
    sr_session_set_error_format(ev_sess, "NETCONF");

    /* error-type */
    str = "protocol";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    /* error-tag */
    str = "lock-denied";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    /* error-message */
    str = "Access to the requested lock is denied because the lock is currently held by another entity.";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    /* error-app-tag */
    sr_session_push_error_data(ev_sess, 1, "");

    /* error-path */
    sr_session_push_error_data(ev_sess, 1, "");

    /* error-info */
    str = "session-id";
    sr_session_push_error_data(ev_sess, strlen(str) + 1, str);

    str = "DS-locked by session ";
    ptr = strstr(err_info->err[0].message, str);
    if (!ptr) {
        return;
    }
    nc_sess = np_get_nc_sess_by_sr_id(atoi(ptr + strlen(str)));

    sprintf(buf, "%" PRIu32, nc_sess ? nc_session_get_id(nc_sess) : 0);
    sr_session_push_error_data(ev_sess, strlen(buf) + 1, buf);
}
