/**
 * @file err_netconf.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF errors
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
#define _GNU_SOURCE /* asprintf */

#include "err_netconf.h"

#include <stdio.h>

#include <sysrepo/error_format.h>

#include "common.h"
#include "compat.h"

void
np_err_sr2nc_lock_denied(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info)
{
    struct nc_session *nc_sess;
    const char *msg, *str, *ptr;
    char buf[11];

    /* message */
    msg = "Access to the requested lock is denied because the lock is currently held by another entity.";

    /* error info session ID */
    str = "DS-locked by session ";
    ptr = strstr(err_info->err[0].message, str);
    if (!ptr) {
        return;
    }
    np_get_nc_sess_by_id(atoi(ptr + strlen(str)), 0, &nc_sess);

    sprintf(buf, "%" PRIu32, nc_sess ? nc_session_get_id(nc_sess) : 0);

    /* set error */
    sr_session_set_netconf_error(ev_sess, "protocol", "lock-denied", NULL, NULL, msg, 1, "session-id", buf);
}

void
np_err_sr2nc_in_use(sr_session_ctx_t *ev_sess, const sr_error_info_t *err_info)
{
    struct nc_session *nc_sess;
    const char *msg, *str, *ptr;
    char buf[11];

    /* message */
    msg = "The request requires a resource that already is in use.";

    /* error info session ID */
    str = "DS-locked by session ";
    ptr = strstr(err_info->err[0].message, str);
    if (!ptr) {
        return;
    }
    np_get_nc_sess_by_id(atoi(ptr + strlen(str)), 0, &nc_sess);

    sprintf(buf, "%" PRIu32, nc_sess ? nc_session_get_id(nc_sess) : 0);

    /* set error */
    sr_session_set_netconf_error(ev_sess, "protocol", "in-use", NULL, NULL, msg, 1, "session-id", buf);
}

void
np_err_sr2nc_same_ds(sr_session_ctx_t *ev_sess, const char *err_msg)
{
    /* set error */
    sr_session_set_netconf_error(ev_sess, "application", "invalid-value", NULL, NULL, err_msg, 0);
}

void
np_err_missing_element(sr_session_ctx_t *ev_sess, const char *elem_name)
{
    const char *msg;

    /* message */
    msg = "An expected element is missing.";

    /* set error */
    sr_session_set_netconf_error(ev_sess, "protocol", "missing-element", NULL, NULL, msg, 1, "bad-element", elem_name);
}

void
np_err_bad_element(sr_session_ctx_t *ev_sess, const char *elem_name, const char *description)
{
    /* set error */
    sr_session_set_netconf_error(ev_sess, "protocol", "bad-element", NULL, NULL, description, 1, "bad-element", elem_name);
}

void
np_err_invalid_value(sr_session_ctx_t *ev_sess, const char *description, const char *bad_elem_name)
{
    if (bad_elem_name) {
        /* set error */
        sr_session_set_netconf_error(ev_sess, "application", "invalid-value", NULL, NULL, description, 1, "bad-element",
                bad_elem_name);
    } else {
        /* set error */
        sr_session_set_netconf_error(ev_sess, "application", "invalid-value", NULL, NULL, description, 0);
    }
}

void
np_err_ntf_sub_no_such_sub(sr_session_ctx_t *ev_sess, const char *message)
{
    /* set error */
    sr_session_set_netconf_error(ev_sess, "application", "invalid-value",
            "ietf-subscribed-notifications:no-such-subscription", NULL, message, 0);
}
