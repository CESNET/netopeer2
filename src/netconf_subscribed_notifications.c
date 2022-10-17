/**
 * @file netconf_subscribed_notifications.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications callbacks
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
#include "err_netconf.h"
#include "log.h"
#include "netconf_monitoring.h"
#include "subscribed_notifications.h"
#include "yang_push.h"

static struct np2srv_sub_ntf_info info = {
    .lock = PTHREAD_RWLOCK_INITIALIZER
};

static ATOMIC_T new_nc_sub_id = 1;

#define INFO_RLOCK if ((r = pthread_rwlock_rdlock(&info.lock))) ELOCK(r)
#define INFO_WLOCK if ((r = pthread_rwlock_wrlock(&info.lock))) ELOCK(r)
#define INFO_UNLOCK if ((r = pthread_rwlock_unlock(&info.lock))) EUNLOCK(r)

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
    int r;

    assert(!wlock || !rlock);

    if (wlock) {
        /* WRITE LOCK */
        INFO_WLOCK;
    } else if (rlock) {
        /* READ LOCK */
        INFO_RLOCK;
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
        INFO_UNLOCK;
    }
    return NULL;
}

struct np2srv_sub_ntf *
sub_ntf_find_lock(uint32_t nc_sub_id, uint32_t sub_id, int write)
{
    struct np2srv_sub_ntf *sub;
    int r;

    /* LOCK */
    if (!sub_id || (ATOMIC_LOAD_RELAXED(info.sub_id_lock) != sub_id)) {
        if (write) {
            INFO_WLOCK;
        } else {
            INFO_RLOCK;
        }
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
    if (!sub_id || (ATOMIC_LOAD_RELAXED(info.sub_id_lock) != sub_id)) {
        INFO_UNLOCK;
    }
    return NULL;
}

void
sub_ntf_unlock(uint32_t sub_id)
{
    int r;

    /* UNLOCK */
    if (!sub_id || (ATOMIC_LOAD_RELAXED(info.sub_id_lock) != sub_id)) {
        INFO_UNLOCK;
    }
}

struct np2srv_sub_ntf *
sub_ntf_find_next(struct np2srv_sub_ntf *last, int (*sub_ntf_match_cb)(struct np2srv_sub_ntf *sub, const void *match_data),
        const void *match_data)
{
    uint32_t i, last_idx = last ? (((char *)last) - ((char *)info.subs)) / sizeof *last : 0;

    for (i = last ? last_idx + 1 : 0; i < info.count; ++i) {
        if (sub_ntf_match_cb(&info.subs[i], match_data)) {
            return &info.subs[i];
        }
    }

    return NULL;
}

int
sub_ntf_send_notif(struct nc_session *ncs, uint32_t nc_sub_id, struct timespec timestamp, struct lyd_node **ly_ntf,
        int use_ntf)
{
    struct np2srv_sub_ntf *sub;
    struct nc_server_notif *nc_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char *datetime = NULL;
    int rc = SR_ERR_OK;

    /* find the subscription structure */
    sub = sub_ntf_find(nc_sub_id, nc_session_get_id(ncs), 0, 0);
    if (!sub) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* create the notification object */
    ly_time_ts2str(&timestamp, &datetime);
    if (use_ntf) {
        /* take ownership of the objects */
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_FREE);
        *ly_ntf = NULL;
        datetime = NULL;
    } else {
        /* objects const, their lifetime must last until the notif is sent */
        nc_ntf = nc_server_notif_new(*ly_ntf, datetime, NC_PARAMTYPE_CONST);
    }

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs),
                msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        rc = (msg_type == NC_MSG_ERROR) ? SR_ERR_OPERATION_FAILED : SR_ERR_TIME_OUT;
        goto cleanup;
    } else {
        ncm_session_notification(ncs);
        ATOMIC_INC_RELAXED(sub->sent_count);
    }

cleanup:
    if (use_ntf) {
        lyd_free_tree(*ly_ntf);
        *ly_ntf = NULL;
    }
    free(datetime);
    nc_server_notif_free(nc_ntf);
    return rc;
}

void
sub_ntf_cb_lock_pass(uint32_t sub_id)
{
    assert(!ATOMIC_LOAD_RELAXED(info.sub_id_lock));

    ATOMIC_STORE_RELAXED(info.sub_id_lock, sub_id);
}

void
sub_ntf_cb_lock_clear(uint32_t sub_id)
{
    assert(ATOMIC_LOAD_RELAXED(info.sub_id_lock) == sub_id);
    (void)sub_id;

    ATOMIC_STORE_RELAXED(info.sub_id_lock, 0);
}

/**
 * @brief Add a prepared and valid subscription into internal subscriptions.
 *
 * @param[in] sub Subscription to add.
 * @param[out] sub_p Pointer to the stored subscription.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_add(const struct np2srv_sub_ntf *sub, struct np2srv_sub_ntf **sub_p)
{
    void *mem;

    *sub_p = NULL;

    mem = realloc(info.subs, (info.count + 1) * sizeof *info.subs);
    if (!mem) {
        return -1;
    }
    info.subs = mem;

    info.subs[info.count] = *sub;
    *sub_p = &info.subs[info.count];
    ++info.count;

    return 0;
}

void
np2srv_sub_ntf_session_destroy(struct nc_session *ncs)
{
    int r;
    uint32_t i = 0;

    /* WRITE LOCK */
    INFO_WLOCK;

    while (i < info.count) {
        if (info.subs[i].nc_id == nc_session_get_id(ncs)) {
            /* terminate the subscription, the following ones are moved */
            sub_ntf_terminate_sub(&info.subs[i], ncs);
        } else {
            /* skip */
            ++i;
        }
    }

    /* UNLOCK */
    INFO_UNLOCK;
}

void
np2srv_sub_ntf_destroy(void)
{
    int r;
    uint32_t i;

    /* WRITE LOCK */
    INFO_WLOCK;

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
    INFO_UNLOCK;
}

int
np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct nc_session *ncs;
    struct np2srv_sub_ntf sub = {0}, *sub_p;
    char id_str[11];
    struct timespec stop = {0};
    int r, rc = SR_ERR_OK, ntf_status = 0;
    uint32_t nc_sub_id, *nc_id;
    enum sub_ntf_type type;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* find this NETCONF session */
    if ((rc = np_get_user_sess(session, __func__, &ncs, NULL))) {
        goto error;
    }

    /* stop time */
    if (!lyd_find_path(input, "stop-time", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* encoding */
    if (!lyd_find_path(input, "encoding", 0, &node) &&
            strcmp(((struct lyd_node_term *)node)->value.ident->name, "encode-xml")) {
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

    /* prepare a new subscription */
    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    sub.nc_id = *nc_id;
    sub.nc_sub_id = nc_sub_id;
    sub.term_reason = "ietf-subscribed-notifications:no-such-subscription";
    sub.stop_time = stop;
    sub.type = type;

    /* create sysrepo subscriptions and type-specific data */
    switch (type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_rpc_establish_sub_prepare(session, input, &sub);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_rpc_establish_sub_prepare(session, input, &sub);
        break;
    }
    if (rc) {
        goto error;
    }

    /* WRITE LOCK */
    INFO_WLOCK;

    /* add into subscriptions, is not accessible before */
    sub_ntf_add(&sub, &sub_p);

    /* start even asynchronous tasks that may access subscriptions and require lock to be held now */
    switch (type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_rpc_establish_sub_start_async(session, sub_p);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_rpc_establish_sub_start_async(session, sub_p);
        break;
    }
    if (rc) {
        goto error_unlock;
    }

    /* UNLOCK */
    INFO_UNLOCK;

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
    INFO_UNLOCK;

error:
    if (ntf_status) {
        nc_session_dec_notif_status(ncs);
    }
    return rc;
}

int
sub_ntf_send_notif_modified(const struct np2srv_sub_ntf *sub)
{
    int rc = SR_ERR_OK;
    char buf[11], *datetime = NULL;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *ly_ntf = NULL;
    struct nc_session *ncs;

    ly_ctx = sr_acquire_context(np2srv.sr_conn);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-modified", NULL, 0, &ly_ntf)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* id */
    sprintf(buf, "%" PRIu32, sub->nc_sub_id);
    if (lyd_new_term(ly_ntf, NULL, "id", buf, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* stop-time */
    if (sub->stop_time.tv_sec) {
        ly_time_ts2str(&sub->stop_time, &datetime);
        if (lyd_new_term(ly_ntf, NULL, "stop-time", datetime, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* type-specific data */
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_notif_modified_append_data(ly_ntf, sub->data);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_notif_modified_append_data(ly_ntf, sub->data);
        break;
    }
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get NETCONF session */
    if ((rc = np_get_nc_sess_by_id(0, sub->nc_id, __func__, &ncs))) {
        goto cleanup;
    }

    /* send the notification */
    rc = sub_ntf_send_notif(ncs, sub->nc_sub_id, np_gettimespec(1), &ly_ntf, 1);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    free(datetime);
    lyd_free_tree(ly_ntf);
    sr_release_context(np2srv.sr_conn);
    return rc;
}

int
np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    char *xp = NULL, *message;
    struct timespec stop = {0};
    int r, rc = SR_ERR_OK;
    uint32_t nc_sub_id, *nc_id;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* stop time */
    if (!lyd_find_path(input, "stop-time", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, *nc_id, 1, 0);
    if (!sub) {
        if (asprintf(&message, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", nc_sub_id) == -1) {
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        np_err_ntf_sub_no_such_sub(session, message);
        free(message);
        rc = SR_ERR_INVAL_ARG;
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
    rc = sub_ntf_send_notif_modified(sub);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    INFO_UNLOCK;

cleanup:
    free(xp);
    return rc;
}

int
sub_ntf_terminate_sub(struct np2srv_sub_ntf *sub, struct nc_session *ncs)
{
    int r, rc = SR_ERR_OK;
    struct lyd_node *ly_ntf;
    const struct ly_ctx *ly_ctx;
    char buf[11];
    uint32_t idx, sub_id_count, sub_id, nc_sub_id;
    enum sub_ntf_type sub_type = sub->type;

    if (sub->terminating) {
        /* already terminating for some other reason */
        return SR_ERR_OK;
    }

    /* unsubscribe all sysrepo subscriptions */
    switch (sub_type) {
    case SUB_TYPE_SUB_NTF:
        sub_id_count = ATOMIC_LOAD_RELAXED(sub->sub_id_count);
        for (idx = 0; idx < sub_id_count; ++idx) {
            /* pass the lock to the notification CB, which removes its sub ID, the final one the whole sub */
            sub_id = sub->sub_ids[0];
            sub_ntf_cb_lock_pass(sub_id);
            r = sr_unsubscribe_sub(np2srv.sr_notif_sub, sub_id);
            sub_ntf_cb_lock_clear(sub_id);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }

        if (sub_id_count) {
            /* this subscription item was already freed as part of unsubscribe terminate notification */
            return rc;
        }
        break;
    case SUB_TYPE_YANG_PUSH:
        for (idx = 0; idx < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++idx) {
            r = sr_unsubscribe_sub(np2srv.sr_data_sub, sub->sub_ids[idx]);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }
        break;
    }

    /* terminate any asynchronous tasks */
    switch (sub_type) {
    case SUB_TYPE_SUB_NTF:
        sub_ntf_terminate_async(sub->data);
        break;
    case SUB_TYPE_YANG_PUSH:
        yang_push_terminate_async(sub->data);
        break;
    }

    /* handle corner cases when the asynchronous tasks have already started and are waiting for the lock */
    sub->terminating = 1;

    /* remember the unique nc_sub_id */
    nc_sub_id = sub->nc_sub_id;

    /* UNLOCK */
    INFO_UNLOCK;

    /* give the tasks a chance to wake up */
    np_sleep(NP2SRV_SUB_NTF_TERMINATE_YIELD_SLEEP);

    /* WRITE LOCK */
    INFO_WLOCK;

    /* find the same subscription again */
    sub = NULL;
    for (idx = 0; idx < info.count; ++idx) {
        if (info.subs[idx].nc_sub_id == nc_sub_id) {
            sub = &info.subs[idx];
            break;
        }
    }
    assert(sub);

    if (nc_session_get_status(ncs) == NC_STATUS_RUNNING) {
        ly_ctx = sr_acquire_context(np2srv.sr_conn);

        /* send the subscription-terminated notification */
        sprintf(buf, "%" PRIu32, sub->nc_sub_id);
        lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-terminated/id", buf, 0, &ly_ntf);
        lyd_new_path(ly_ntf, NULL, "reason", sub->term_reason, 0, NULL);

        r = sub_ntf_send_notif(ncs, sub->nc_sub_id, np_gettimespec(1), &ly_ntf, 1);
        if (r != SR_ERR_OK) {
            rc = r;
        }

        sr_release_context(np2srv.sr_conn);
    }

    /* subscription terminated */
    nc_session_dec_notif_status(ncs);

    /* free the sub */
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
    char *message;
    int r, rc = SR_ERR_OK;
    uint32_t nc_sub_id, *nc_id;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, *nc_id, 1, 0);
    if (!sub) {
        if (asprintf(&message, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", nc_sub_id) == -1) {
            return SR_ERR_NO_MEMORY;
        }
        np_err_ntf_sub_no_such_sub(session, message);
        free(message);
        return SR_ERR_INVAL_ARG;
    }

    /* get NETCONF session */
    if ((rc = np_get_user_sess(session, __func__, &ncs, NULL))) {
        goto cleanup_unlock;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub, ncs);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    INFO_UNLOCK;

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
    char *message;
    int r, rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, 0, 1, 0);
    if (!sub) {
        if (asprintf(&message, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", nc_sub_id) == -1) {
            return SR_ERR_NO_MEMORY;
        }
        np_err_ntf_sub_no_such_sub(session, message);
        free(message);
        return SR_ERR_INVAL_ARG;
    }

    /* get the user session */
    if ((rc = np_get_user_sess(session, __func__, &ncs, NULL))) {
        goto cleanup_unlock;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub, ncs);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* WRITE UNLOCK */
    INFO_UNLOCK;

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
    INFO_WLOCK;

    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter/*", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        rc = sub_ntf_config_filters(lyd_parent(node), op);
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
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter/*", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        rc = yang_push_config_filters(lyd_parent(node), op);
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
    /* UNLOCK */
    INFO_UNLOCK;

    sr_free_change_iter(iter);
    return rc;
}

int
np2srv_oper_sub_ntf_streams_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    uint32_t idx = 0;
    char *buf;
    int enabled;
    struct timespec earliest_notif;

    /* context locked while the callback is executing */
    conn = sr_session_get_connection(session);
    ly_ctx = sr_acquire_context(conn);
    sr_release_context(conn);

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

    /* go through all the modules */
    while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
        if (!ly_mod->implemented || !np_ly_mod_has_notif(ly_mod)) {
            /* not implemented or no notifications in the module so do not consider it a stream */
            continue;
        }

        /* generate information about the stream/module */
        if (lyd_new_list(root, NULL, "stream", 0, &stream, ly_mod->name)) {
            goto error;
        }
        if (lyd_new_term(stream, NULL, "description", "Stream with all notifications of a module.", 0, NULL)) {
            goto error;
        }

        /* learn whether replay is supported */
        if (sr_get_module_replay_support(conn, ly_mod->name, &earliest_notif, &enabled)) {
            goto error;
        }
        if (enabled) {
            if (lyd_new_term(stream, NULL, "replay-support", NULL, 0, NULL)) {
                goto error;
            }
            ly_time_ts2str(&earliest_notif, &buf);
            if (lyd_new_term(stream, NULL, "replay-log-creation-time", buf, 0, NULL)) {
                free(buf);
                goto error;
            }
            free(buf);
        }
    }

    *parent = root;
    return SR_ERR_OK;

error:
    lyd_free_tree(root);
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
    uint32_t i, excluded_count = 0;
    int r, rc = SR_ERR_OK;

    /* context is locked while the callback is executing */
    ly_ctx = sr_session_acquire_context(session);
    sr_session_release_context(session);

    /* READ LOCK */
    INFO_RLOCK;

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
    INFO_UNLOCK;

    free(datetime);
    if (rc) {
        lyd_free_tree(root);
    } else {
        *parent = root;
    }
    return rc;
}
