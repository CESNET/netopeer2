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

#include <assert.h>
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
    np_get_nc_sess_by_id(atoi(ptr + strlen(str)), 0, __func__, &nc_sess);

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
    np_get_nc_sess_by_id(atoi(ptr + strlen(str)), 0, __func__, &nc_sess);

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
np_err_operation_failed(sr_session_ctx_t *ev_sess, const char *description)
{
    /* set error */
    sr_session_set_netconf_error(ev_sess, "application", "operation-failed", NULL, NULL, description, 0);
}

void
np_err_ntf_sub_no_such_sub(sr_session_ctx_t *ev_sess, const char *message)
{
    /* set error */
    sr_session_set_netconf_error(ev_sess, "application", "invalid-value",
            "ietf-subscribed-notifications:no-such-subscription", NULL, message, 0);
}

void
np_err_sr2nc_edit(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess)
{
    const sr_error_info_t *err_info;
    const sr_error_info_err_t *err;
    const char *ptr, *ptr2;
    char *path = NULL, *str = NULL, *str2 = NULL;

    /* get the error */
    sr_session_get_error((sr_session_ctx_t *)err_sess, &err_info);
    assert(err_info);
    err = &err_info->err[0];

    /* get path */
    if ((ptr = strstr(err->message, "Data location \""))) {
        ptr += 15;
    }
    if (!ptr) {
        if ((ptr = strstr(err->message, "Schema location \""))) {
            ptr += 17;
        }
    }
    if (ptr) {
        path = strndup(ptr, strchr(ptr, '\"') - ptr);
    }

    if (!strncmp(err->message, "Unique data leaf(s)", 19)) {
        /* data-not-unique */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "operation-failed", "data-not-unique", NULL,
                "Unique constraint violated.", 1, "non-unique", path);
    } else if (!strncmp(err->message, "Too many", 8)) {
        /* too-many-elements */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "operation-failed", "too-many-elements", path,
                "Too many elements.", 0);
    } else if (!strncmp(err->message, "Too few", 7)) {
        /* too-few-elements */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "operation-failed", "too-few-elements", path,
                "Too few elements.", 0);
    } else if (!strncmp(err->message, "Must condition", 14)) {
        /* get the must condition error message */
        ptr = strrchr(err->message, '(');
        --ptr;
        str = strndup(err->message, ptr - err->message);

        /* must-violation */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "operation-failed", "must-violation", path, str, 0);
    } else if (!strncmp(err->message, "Invalid leafref value", 21) && strstr(err->message, "no target instance")) {
        /* get the value */
        assert(err->message[22] == '\"');
        ptr = strchr(err->message + 23, '\"');

        /* create error message */
        if (asprintf(&str, "Required leafref target with value \"%.*s\" missing.", (int)(ptr - (err->message + 23)),
                err->message + 23) == -1) {
            goto mem_error;
        }

        /* instance-required */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "data-missing", "instance-required", path, str, 0);
    } else if (!strncmp(err->message, "Invalid instance-identifier", 26) && strstr(err->message, "required instance not found")) {
        /* get the value */
        assert(err->message[28] == '\"');
        ptr = strchr(err->message + 29, '\"');

        /* create error message */
        if (asprintf(&str, "Required instance-identifier \"%.*s\" missing.", (int)(ptr - (err->message + 29)),
                err->message + 29) == -1) {
            goto mem_error;
        }

        /* instance-required */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "protocol", "data-missing", "instance-required", path, str, 0);
    } else if (!strncmp(err->message, "Mandatory choice", 16)) {
        /* get choice parent */
        assert(path);
        ptr = strrchr(path, '/');
        str = strndup(path, (ptr == path) ? 1 : ptr - path);

        /* missing-choice */
        sr_session_set_netconf_error(ev_sess, "protocol", "data-missing", "mandatory-choice", str,
                "Missing mandatory choice.", 1, "missing-choice", path);
    } else if (strstr(err->message, "instance to insert next to not found.")) {
        /* get the node name */
        assert(err->message[5] == '\"');
        ptr = strchr(err->message + 6, '\"');

        /* create error message */
        if (asprintf(&str, "Missing insert anchor \"%.*s\" instance.", (int)(ptr - (err->message + 6)),
                err->message + 6) == -1) {
            goto mem_error;
        }

        /* missing-instance */
        sr_session_set_netconf_error(ev_sess, "protocol", "bad-attribute", "missing-instance", NULL, str, 0);
    } else if (strstr(err->message, "to be created already exists.")) {
        /* data-exists */
        sr_session_set_netconf_error(ev_sess, "protocol", "data-exists", NULL, NULL, err->message, 0);
    } else if (strstr(err->message, "to be deleted does not exist.")) {
        /* data-missing */
        sr_session_set_netconf_error(ev_sess, "protocol", "data-missing", NULL, NULL, err->message, 0);
    } else if (strstr(err->message, "does not exist.")) {
        /* data-missing */
        sr_session_set_netconf_error(ev_sess, "protocol", "data-missing", NULL, NULL, err->message, 0);
    } else if (!strncmp(err->message, "Invalid type", 12) || !strncmp(err->message, "Unsatisfied range", 17) ||
            !strncmp(err->message, "Unsatisfied pattern", 19)) {
        /* create error message */
        str = strndup(err->message, (strchr(err->message, '.') + 1) - err->message);

        /* bad-element */
        assert(path);
        sr_session_set_netconf_error(ev_sess, "application", "bad-element", NULL, NULL, str, 1, "bad-element", path);
    } else if (!strncmp(err->message, "Node \"", 6) && strstr(err->message, " not found")) {
        /* get the node name */
        assert(err->message[5] == '\"');
        ptr = strchr(err->message + 6, '\"');
        str = strndup(err->message + 6, ptr - (err->message + 6));

        /* unknown-element */
        sr_session_set_netconf_error(ev_sess, "application", "unknown-element", NULL, NULL, err->message, 1,
                "bad-element", str);
    } else if (!strncmp(err->message, "No (implemented) module with namespace", 38)) {
        /* get the namespace */
        ptr = strchr(err->message, '\"') + 1;
        ptr2 = strchr(ptr, '\"');
        str = strndup(ptr, ptr2 - ptr);

        /* get the node name */
        ptr = strchr(ptr2 + 1, '\"') + 1;
        ptr2 = strchr(ptr, '\"');
        str2 = strndup(ptr, ptr2 - ptr);

        /* unknown-namespace */
        sr_session_set_netconf_error(ev_sess, "application", "unknown-namespace", NULL, NULL,
                "An unexpected namespace is present.", 2, "bad-element", str2, "bad-namespace", str);
    } else {
        /* other error */
        sr_session_dup_error((sr_session_ctx_t *)err_sess, ev_sess);
    }

    free(path);
    free(str);
    free(str2);
    return;

mem_error:
    sr_session_set_error_message(ev_sess, "Memory allocation failed.");

    free(path);
    free(str);
    free(str2);
}

void
np_err_sr2nc_get(sr_session_ctx_t *ev_sess, const sr_session_ctx_t *err_sess)
{
    const sr_error_info_t *err_info;
    const sr_error_info_err_t *err;

    /* get the error */
    sr_session_get_error((sr_session_ctx_t *)err_sess, &err_info);
    assert(err_info);
    err = &err_info->err[0];

    if (strstr(err->message, " result is not a node set.")) {
        /* invalid-value */
        np_err_invalid_value(ev_sess, err->message, NULL);
    } else {
        /* other error */
        sr_session_dup_error((sr_session_ctx_t *)err_sess, ev_sess);
    }
}
