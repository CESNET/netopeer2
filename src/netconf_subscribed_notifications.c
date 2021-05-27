/**
 * @file netconf_subscribed_notifications.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks
 *
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#define _POSIX_SOURCE

#include "netconf_subscribed_notifications.h"

#include <assert.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "netconf_acm.h"
#include "netconf_monitoring.h"
#include "subscribed_notifications.h"
#include "yang_push.h"

static struct np2srv_sub_ntf_info info = {
    .lock = PTHREAD_RWLOCK_INITIALIZER
};

static ATOMIC_T new_nc_sub_id = 1;

/**
 * @brief Find an internal subscription structure.
 *
 * @param[in] nc_sub_id NETCONF sub ID.
 * @param[in] nc_id Optional NETCONF ID of the specific subscriber.
 * @param[in] wlock Whether to write-lock subscriptions when a subscription was found or not.
 * @param[in] rlock Whether to read-lock subscriptions when a subscription was found or not.
 * @return Found subscription.
 */
static struct np2srv_sub_ntf *
sub_ntf_find(uint32_t nc_sub_id, uint32_t nc_id, int wlock, int rlock)
{
    uint32_t i;

    assert(!wlock || !rlock);

    if (wlock) {
        /* WRITE LOCK */
        pthread_rwlock_wrlock(&info.lock);
    } else if (rlock) {
        /* READ LOCK */
        pthread_rwlock_rdlock(&info.lock);
    }

    for (i = 0; i < info.count; ++i) {
        if (nc_id && (info.subs[i].nc_id != nc_id)) {
            continue;
        }

        if (info.subs[i].nc_sub_id == nc_sub_id) {
            return &info.subs[i];
        }
    }

    if (wlock || rlock) {
        /* UNLOCK */
        pthread_rwlock_unlock(&info.lock);
    }
    return NULL;
}

struct np2srv_sub_ntf *
sub_ntf_find_lock(uint32_t nc_sub_id, int write)
{
    struct np2srv_sub_ntf *sub;

    /* LOCK */
    if (write) {
        pthread_rwlock_wrlock(&info.lock);
    } else {
        pthread_rwlock_rdlock(&info.lock);
    }

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        /* not found */
        goto error;
    }

    if (sub->terminating) {
        /* this subscription cannot be used */
        goto error;
    }

    return sub;

error:
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);
    return NULL;
}

void
sub_ntf_unlock(void)
{
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);
}

struct np2srv_sub_ntf *
sub_ntf_find_next(struct np2srv_sub_ntf *last, int (*sub_ntf_match_cb)(struct np2srv_sub_ntf *sub, const void *match_data),
        const void *match_data)
{
    uint32_t i, last_idx = last ? (((char *)last) - ((char *)info.subs)) / sizeof *last : 0;

    for (i = last_idx ? last_idx + 1 : 0; i < info.count; ++i) {
        if (sub_ntf_match_cb(&info.subs[i], match_data)) {
            return &info.subs[i];
        }
    }

    return NULL;
}

int
sub_ntf_send_notif(struct nc_session *ncs, uint32_t nc_sub_id, struct timespec timestamp, struct lyd_node **ly_ntf, int use_ntf)
{
    struct np2srv_sub_ntf *sub;
    struct nc_server_notif *nc_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char *datetime;
    int rc;

    /* find the subscription structure */
    sub = sub_ntf_find(nc_sub_id, nc_session_get_id(ncs), 0, 0);
    if (!sub) {
        if (use_ntf) {
            /* free the notification since we are not using it */
            lyd_free_tree(*ly_ntf);
            *ly_ntf = NULL;
        }
        EINT;
        return SR_ERR_INTERNAL;
    }

    /* check NACM of the notification itself */
    if (ncac_check_operation(*ly_ntf, nc_session_get_username(ncs))) {
        /* denied */
        ATOMIC_INC_RELAXED(sub->denied_count);

        if (use_ntf) {
            /* free the notification since we are not using it */
            lyd_free_tree(*ly_ntf);
            *ly_ntf = NULL;
        }
        return SR_ERR_OK;
    }

    /* create the notification object */
    ly_time_ts2str(&timestamp, &datetime);
    if (use_ntf) {
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_FREE);
        *ly_ntf = NULL;
    } else {
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_CONST);
        free(datetime);
    }

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs),
                msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        rc = (msg_type == NC_MSG_ERROR) ? SR_ERR_OPERATION_FAILED : SR_ERR_TIME_OUT;
    } else {
        ncm_session_notification(ncs);
        ATOMIC_INC_RELAXED(sub->sent_count);
        rc = SR_ERR_OK;
    }

    nc_server_notif_free(nc_ntf);
    return rc;
}

void
sub_ntf_cb_lock_pass(uint32_t sub_id)
{
    ATOMIC_STORE_RELAXED(info.sub_id_lock, sub_id);
}

void
sub_ntf_inc_denied(uint32_t nc_sub_id)
{
    struct np2srv_sub_ntf *sub;

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        EINT;
        return;
    }

    ATOMIC_INC_RELAXED(sub->denied_count);
}

/**
 * @brief Add a subscription into internal subscriptions.
 *
 * @param[in] nc_id NETCONF SID of the session creating this subscription.
 * @param[in] nc_sub_id NETCONF subscription ID.
 * @param[in] term_reason Default termination reason.
 * @param[in] stop_time Subscription stop time.
 * @param[in] type Subscription type.
 * @param[out] sub_p Created subscription.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_new(uint32_t nc_id, uint32_t nc_sub_id, const char *term_reason, struct timespec stop_time, enum sub_ntf_type type,
        struct np2srv_sub_ntf **sub_p)
{
    void *mem;
    struct np2srv_sub_ntf *sub;

    mem = realloc(info.subs, (info.count + 1) * sizeof *info.subs);
    if (!mem) {
        return -1;
    }
    info.subs = mem;
    sub = &info.subs[info.count];
    memset(sub, 0, sizeof *sub);

    /* fill known members */
    sub->nc_id = nc_id;
    sub->nc_sub_id = nc_sub_id;
    sub->term_reason = term_reason;
    sub->stop_time = stop_time;
    sub->type = type;

    ++info.count;
    *sub_p = sub;

    return 0;
}

void
np2srv_sub_ntf_session_destroy(struct nc_session *ncs)
{
    uint32_t i;

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&info.lock);

    for (i = 0; i < info.count; ++i) {
        if (info.subs[i].nc_id == nc_session_get_id(ncs)) {
            sub_ntf_terminate_sub(&info.subs[i], ncs);
        }
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);
}

void
np2srv_sub_ntf_destroy(void)
{
    uint32_t i;

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&info.lock);

    for (i = 0; i < info.count; ++i) {
        switch (info.subs[i].type) {
        case SUB_TYPE_SUB_NTF:
            sub_ntf_terminate_async(info.subs[i].data);
            break;
        case SUB_TYPE_YANG_PUSH:
            yang_push_terminate_async(info.subs[i].data);
            break;
        }

        free(info.subs[i].sub_ids);
        switch (info.subs[i].type) {
        case SUB_TYPE_SUB_NTF:
            sub_ntf_data_destroy(info.subs[i].data);
            break;
        case SUB_TYPE_YANG_PUSH:
            yang_push_data_destroy(info.subs[i].data);
            break;
        }
    }
    free(info.subs);
    info.subs = NULL;
    info.count = 0;

    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);
}

int
np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct nc_session *ncs;
    struct np2srv_sub_ntf *sub;
    char id_str[11];
    struct timespec stop = {0};
    int rc, ntf_status = 0;
    uint32_t nc_sub_id, *nc_id;
    enum sub_ntf_type type;
    void *data = NULL;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* find this NETCONF session */
    if ((rc = np_get_user_sess(session, &ncs, NULL))) {
        goto error;
    }

    /* stop time */
    lyd_find_path(input, "stop-time", 0, &node);
    if (node) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* encoding */
    lyd_find_path(input, "encoding", 0, &node);
    if (node && strcmp(((struct lyd_node_term *)node)->value.ident->name, "encode-xml")) {
        ERR("Unsupported encoding \"%s\".", lyd_get_value(node));
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    /* detect type */
    if (!lyd_find_path(input, "stream", 0, NULL)) {
        type = SUB_TYPE_SUB_NTF;
    } else if (!lyd_find_path(input, "ietf-yang-push:datastore", 0, NULL)) {
        type = SUB_TYPE_YANG_PUSH;
    } else {
        ERR("Missing mandatory \"stream\" or \"datastore\" leaves.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    /* set ongoing notifications flag */
    nc_session_inc_notif_status(ncs);
    ntf_status = 1;

    /* get new NC sub ID */
    nc_sub_id = ATOMIC_INC_RELAXED(new_nc_sub_id);

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&info.lock);

    /* allocate a new subscription */
    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    if (sub_ntf_new(*nc_id, nc_sub_id, "ietf-subscribed-notifications:no-such-subscription", stop, type, &sub)) {
        rc = SR_ERR_INTERNAL;
        goto error_unlock;
    }

    /* create sysrepo subscriptions and type-specific data */
    switch (type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_rpc_establish_sub(session, input, sub);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_rpc_establish_sub(session, input, sub);
        break;
    }
    if (rc != SR_ERR_OK) {
        goto error_unlock;
    }

    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    /* generate output */
    sprintf(id_str, "%" PRIu32, nc_sub_id);
    if (lyd_new_term(output, NULL, "id", id_str, 1, NULL)) {
        rc = SR_ERR_LY;
        goto error;
    }
    /* TODO "replay-start-time-revision" - sent only if the earliest (theoretical) stored notif is later than start-time */

    return SR_ERR_OK;

error_unlock:
    --info.count;

    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

error:
    if (data) {
        switch (type) {
        case SUB_TYPE_SUB_NTF:
            sub_ntf_data_destroy(data);
            break;
        case SUB_TYPE_YANG_PUSH:
            yang_push_data_destroy(data);
            break;
        }
    }
    if (ntf_status) {
        nc_session_dec_notif_status(ncs);
    }
    return rc;
}

/**
 * @brief Create a subscription-modified notification.
 *
 * @param[in] sub Subscription structure.
 * @param[out] ly_ntf Created notification.
 * @return Sysrepo error value.
 */
static int
sub_ntf_notif_modified(struct np2srv_sub_ntf *sub, struct lyd_node **ly_ntf)
{
    int rc = SR_ERR_OK;
    char buf[11], *datetime = NULL;

    *ly_ntf = NULL;

    if (lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:subscription-modified", NULL,
            0, ly_ntf)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* id */
    sprintf(buf, "%" PRIu32, sub->nc_sub_id);
    if (lyd_new_term(*ly_ntf, NULL, "id", buf, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* stop-time */
    if (sub->stop_time.tv_sec) {
        ly_time_ts2str(&sub->stop_time, &datetime);
        if (lyd_new_term(*ly_ntf, NULL, "stop-time", datetime, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* type-specific data */
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_notif_modified_append_data(*ly_ntf, sub->data);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_notif_modified_append_data(*ly_ntf, sub->data);
        break;
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    free(datetime);
    if (rc) {
        lyd_free_tree(*ly_ntf);
        *ly_ntf = NULL;
    }
    return rc;
}

int
np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct lyd_node *node, *ly_ntf;
    struct np2srv_sub_ntf *sub;
    char *xp = NULL;
    struct timespec stop = {0};
    struct nc_session *ncs;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id, *nc_id;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* stop time */
    lyd_find_path(input, "stop-time", 0, &node);
    if (node) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, *nc_id, 1, 0);
    if (!sub) {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "Subscription with ID %" PRIu32 " for the current receiver does not exist.",
                nc_sub_id);
        goto cleanup;
    }

    /* update type-specific operational data */
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_rpc_modify_sub(session, input, stop, sub);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_rpc_modify_sub(session, input, stop, sub);
        break;
    }
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

    /* update the generic subscription operational data */
    if (stop.tv_sec) {
        sub->stop_time = stop;
    }

    /* create the notification */
    rc = sub_ntf_notif_modified(sub, &ly_ntf);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get NETCONF session */
    if ((rc = np_get_user_sess(session, &ncs, NULL))) {
        goto cleanup;
    }

    /* send the notification */
    rc = sub_ntf_send_notif(ncs, nc_sub_id, np_gettimespec(), &ly_ntf, 1);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

cleanup_unlock:
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

cleanup:
    free(xp);
    return rc;
}

int
sub_ntf_terminate_sub(struct np2srv_sub_ntf *sub, struct nc_session *ncs)
{
    int r, rc = SR_ERR_OK;
    struct lyd_node *ly_ntf;
    char buf[11];
    uint32_t i, idx;

    /* unsubscribe all sysrepo subscriptions */
    for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
        r = sr_unsubscribe_sub(np2srv.sr_notif_sub, sub->sub_ids[i]);
        if (r != SR_ERR_OK) {
            rc = r;
        }
    }

    /* terminate any asynchronous tasks */
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        sub_ntf_terminate_async(sub->data);
        break;
    case SUB_TYPE_YANG_PUSH:
        yang_push_terminate_async(sub->data);
        break;
    }

    /* handle corner cases when the asynchronous tasks have already started and are waiting for the lock */
    sub->terminating = 1;

    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    /* give the tasks a chance to wake up */
    np_sleep(NP2SRV_SUB_NTF_TERMINATE_YIELD_SLEEP);

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&info.lock);

    if (nc_session_get_status(ncs) == NC_STATUS_RUNNING) {
        /* send the subscription-terminated notification */
        sprintf(buf, "%" PRIu32, sub->nc_sub_id);
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:subscription-terminated/id",
                buf, 0, &ly_ntf);
        lyd_new_path(ly_ntf, NULL, "reason", sub->term_reason, 0, NULL);

        r = sub_ntf_send_notif(ncs, sub->nc_sub_id, np_gettimespec(), &ly_ntf, 1);
        if (r != SR_ERR_OK) {
            rc = r;
        }
    }

    /* subscription terminated */
    nc_session_dec_notif_status(ncs);

    /* free the sub */
    idx = (((char *)sub) - ((char *)info.subs)) / sizeof *sub;

    free(sub->sub_ids);
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        sub_ntf_data_destroy(sub->data);
        break;
    case SUB_TYPE_YANG_PUSH:
        yang_push_data_destroy(sub->data);
        break;
    }

    --info.count;
    if (idx < info.count) {
        memmove(sub, sub + 1, (info.count - idx) * sizeof *sub);
    } else if (!info.count) {
        free(info.subs);
        info.subs = NULL;
    }

    return rc;
}

int
np2srv_rpc_delete_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    struct nc_session *ncs;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id, *nc_id;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, *nc_id, 1, 0);
    if (!sub) {
        sr_session_set_error_message(session, "Subscription with ID %" PRIu32 " for the current receiver does not exist.",
                nc_sub_id);
        return SR_ERR_INVAL_ARG;
    }

    /* get NETCONF session */
    if ((rc = np_get_user_sess(session, &ncs, NULL))) {
        goto cleanup_unlock;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub, ncs);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    return rc;
}

int
np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    struct nc_session *ncs;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, 0, 1, 0);
    if (!sub) {
        sr_session_set_error_message(session, "Subscription with ID %" PRIu32 " does not exist.", nc_sub_id);
        return SR_ERR_INVAL_ARG;
    }

    /* get the user session */
    if ((rc = np_get_user_sess(session, &ncs, NULL))) {
        goto cleanup_unlock;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub, ncs);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* WRITE UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    return rc;
}

int
np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    int r, rc = SR_ERR_OK;

    /* WRITE LOCK */
    pthread_rwlock_wrlock(&info.lock);

    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        rc = sub_ntf_config_filters(session, node, op);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }
    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    sr_free_change_iter(iter);
    iter = NULL;

    /* yang-push */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        rc = yang_push_config_filters(session, node, op);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }
    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

cleanup:
    ATOMIC_STORE_RELAXED(info.sub_id_lock, 0);
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    sr_free_change_iter(iter);
    return rc;
}

int
np2srv_oper_sub_ntf_streams_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream, *sr_data = NULL, *sr_mod, *rep_sup;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    const char *mod_name;
    char *buf;
    int rc;

    conn = sr_session_get_connection(session);
    ly_ctx = sr_get_context(conn);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:streams", NULL, 0, &root)) {
        goto error;
    }

    /* generic stream */
    if (lyd_new_path(root, NULL, "/ietf-subscribed-notifications:streams/stream[name='NETCONF']", NULL, 0, &stream)) {
        goto error;
    }
    if (lyd_new_term(stream, stream->schema->module, "description",
            "Default NETCONF stream containing notifications from all the modules."
            " Replays only notifications for modules that support replay.", 0, NULL)) {
        goto error;
    }
    if (lyd_new_term(stream, stream->schema->module, "replay-support", NULL, 0, NULL)) {
        goto error;
    }

    /* go through all the sysrepo modules for individual streams */
    rc = sr_get_module_info(conn, &sr_data);
    if (rc != SR_ERR_OK) {
        ERR("Failed to get sysrepo module info data (%s).", sr_strerror(rc));
        goto error;
    }
    LY_LIST_FOR(lyd_child(sr_data), sr_mod) {
        if (strcmp(sr_mod->schema->name, "module")) {
            continue;
        }

        mod_name = lyd_get_value(lyd_child(sr_mod));

        /* get the module */
        mod = ly_ctx_get_module_implemented(ly_ctx, mod_name);
        assert(mod);

        if (!np_ly_mod_has_notif(mod)) {
            /* no notifications in the module so do not consider it a stream */
            continue;
        }

        /* generate information about the stream/module */
        if (lyd_new_list(root, NULL, "stream", 0, &stream, mod_name)) {
            goto error;
        }
        if (lyd_new_term(stream, NULL, "description", "Stream with all notifications of a module.", 0, NULL)) {
            goto error;
        }

        lyd_find_path(sr_mod, "replay-support", 0, &rep_sup);
        if (rep_sup) {
            if (lyd_new_term(stream, NULL, "replay-support", NULL, 0, NULL)) {
                goto error;
            }
            ly_time_time2str(((struct lyd_node_term *)rep_sup)->value.uint64, NULL, &buf);
            if (lyd_new_term(stream, NULL, "replay-log-creation-time", buf, 0, NULL)) {
                free(buf);
                goto error;
            }
            free(buf);
        }
    }

    lyd_free_siblings(sr_data);
    *parent = root;
    return SR_ERR_OK;

error:
    lyd_free_tree(root);
    lyd_free_siblings(sr_data);
    return SR_ERR_INTERNAL;
}

int
np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *list, *receiver, *root;
    struct np2srv_sub_ntf *sub;
    char buf[26], *path = NULL, *datetime = NULL;
    uint32_t i, excluded_count;
    int rc = SR_ERR_OK;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    /* READ LOCK */
    pthread_rwlock_rdlock(&info.lock);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscriptions", NULL, 0, &root)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* go through all the subscriptions */
    for (i = 0; i < info.count; ++i) {
        sub = &info.subs[i];

        /* subscription with id */
        sprintf(buf, "%" PRIu32, sub->nc_sub_id);
        if (lyd_new_list(root, NULL, "subscription", 0, &list, buf)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* subscription type-specific data */
        switch (sub->type) {
        case SUB_TYPE_SUB_NTF:
            rc = sub_ntf_oper_subscription(list, sub->data);
            break;
        case SUB_TYPE_YANG_PUSH:
            rc = yang_push_oper_subscription(list, sub->data);
            break;
        }
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }

        /* stop-time */
        if (sub->stop_time.tv_sec) {
            ly_time_ts2str(&sub->stop_time, &datetime);
            if (lyd_new_term(list, NULL, "stop-time", datetime, 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        /* receivers */
        if (asprintf(&path, "receivers/receiver[name='NETCONF session %u']", sub->nc_id) == -1) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        if (lyd_new_path(list, NULL, path, NULL, 0, &receiver)) {
            free(path);
            rc = SR_ERR_LY;
            goto cleanup;
        }
        free(path);
        receiver = lyd_child(receiver);

        /* sent-event-records */
        sprintf(buf, "%" PRIu32, (uint32_t)ATOMIC_LOAD_RELAXED(sub->sent_count));
        if (lyd_new_term(receiver, NULL, "sent-event-records", buf, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* excluded-event-records, type-specific */
        switch (sub->type) {
        case SUB_TYPE_SUB_NTF:
            excluded_count = sub_ntf_oper_receiver_excluded(sub);
            break;
        case SUB_TYPE_YANG_PUSH:
            excluded_count = yang_push_oper_receiver_excluded(sub);
            break;
        }

        /* add denied */
        excluded_count += ATOMIC_LOAD_RELAXED(sub->denied_count);

        sprintf(buf, "%" PRIu32, excluded_count);
        if (lyd_new_term(receiver, NULL, "excluded-event-records", buf, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* state */
        if (lyd_new_term(receiver, NULL, "state", "active", 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    /* UNLOCK */
    pthread_rwlock_unlock(&info.lock);

    free(datetime);
    if (rc) {
        lyd_free_tree(root);
    } else {
        *parent = root;
    }
    return rc;
}
