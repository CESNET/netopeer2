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

#include "netconf_subscribed_notifications.h"

#include <assert.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "log.h"
#include "common.h"
#include "subscribed_notifications.h"
#include "yang_push.h"

static struct np2srv_sub_ntf_info info = {
    .lock = PTHREAD_MUTEX_INITIALIZER
};

/**
 * @brief Find an internal subscription structure.
 *
 * @param[in] sub_id Subscription ID of the subscription.
 * @param[in] nc_id Receiver NETCONF SID, 0 for any.
 * @param[in] lock Whether to lock subscriptions when a subscription was found or not.
 * @return Found subscription.
 */
static struct np2srv_sub_ntf *
sub_ntf_find(uint32_t sub_id, uint32_t nc_id, int lock)
{
    uint32_t i, j;

    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&info.lock);
    }

    for (i = 0; i < info.count; ++i) {
        if (nc_id && (info.subs[i].nc_id != nc_id)) {
            continue;
        }

        for (j = 0; j < ATOMIC_LOAD_RELAXED(info.subs[i].sub_id_count); ++j) {
            if (info.subs[i].sub_ids[j] == sub_id) {
                return &info.subs[i];
            }
        }
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
    }
    return NULL;
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
sub_ntf_sr_del_is_last(uint32_t sub_id, uint32_t nc_id, const char **term_reason)
{
    int lock = ATOMIC_LOAD_RELAXED(info.sub_id_lock) == sub_id ? 0 : 1, last = 0;
    struct np2srv_sub_ntf *sub;
    uint32_t i, idx;

    /* LOCK */
    sub = sub_ntf_find(sub_id, nc_id, lock);
    if (!sub) {
        EINT;
        return last;
    }

    if (ATOMIC_LOAD_RELAXED(sub->sub_id_count) > 1) {
        /* not the last subscription, remove just this sub_id */
        for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
            if (sub->sub_ids[i] == sub_id) {
                break;
            }
        }
        assert(i < ATOMIC_LOAD_RELAXED(sub->sub_id_count));

        if (i < ATOMIC_LOAD_RELAXED(sub->sub_id_count) - 1) {
            sub->sub_ids[i] = sub->sub_ids[ATOMIC_LOAD_RELAXED(sub->sub_id_count) - 1];
        }
        ATOMIC_DEC_RELAXED(sub->sub_id_count);
        goto cleanup;
    }

    /* remember term reason */
    *term_reason = sub->term_reason;

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
    }

    /* last subscription was removed */
    last = 1;

cleanup:
    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
    }
    return last;
}

uint32_t
sub_ntf_sub_id_sr2sub_ntf(uint32_t sub_id)
{
    int lock;
    uint32_t i, j, sub_ntf_id = 0;

    lock = ATOMIC_LOAD_RELAXED(info.sub_id_lock) == sub_id ? 0 : 1;
    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&info.lock);
    }

    for (i = 0; i < info.count; ++i) {
        for (j = 0; j < ATOMIC_LOAD_RELAXED(info.subs[i].sub_id_count); ++j) {
            if (info.subs[i].sub_ids[j] == sub_id) {
                sub_ntf_id = info.subs[i].sub_ntf_id;
                break;
            }
        }

        if (sub_ntf_id) {
            break;
        }
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
    }

    if (!sub_ntf_id) {
        EINT;
    }
    return sub_ntf_id;
}

void
sub_ntf_inc_sent(uint32_t sub_id)
{
    int lock;
    uint32_t i;

    lock = ATOMIC_LOAD_RELAXED(info.sub_id_lock) == sub_id ? 0 : 1;
    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&info.lock);
    }

    for (i = 0; i < info.count; ++i) {
        if (info.subs[i].sub_ntf_id == sub_id) {
            ++info.subs[i].sent_count;
            break;
        }
    }
    if (i == info.count) {
        EINT;
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
    }
}

int
sub_ntf_notif_modified(uint32_t sub_id, uint32_t nc_id, struct lyd_node **ly_ntf)
{
    int rc = SR_ERR_OK, lock;
    struct np2srv_sub_ntf *sub;
    char buf[26];

    *ly_ntf = NULL;

    /* get the subscription */
    lock = ATOMIC_LOAD_RELAXED(info.sub_id_lock) == sub_id ? 0 : 1;

    /* LOCK */
    sub = sub_ntf_find(sub_id, nc_id, lock);
    if (!sub) {
        rc = SR_ERR_INTERNAL;
        lock = 0;
        goto cleanup;
    }

    if (lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:subscription-modified", NULL,
            0, ly_ntf)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* id */
    sprintf(buf, "%" PRIu32, sub->sub_ntf_id);
    if (lyd_new_term(*ly_ntf, NULL, "id", buf, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* stop-time */
    if (sub->stop_time) {
        nc_time2datetime(sub->stop_time, NULL, buf);
        if (lyd_new_term(*ly_ntf, NULL, "stop-time", buf, 0, NULL)) {
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
    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
    }

    if (rc) {
        lyd_free_tree(*ly_ntf);
        *ly_ntf = NULL;
    }
    return rc;
}

void
sub_ntf_cb_lock_pass(uint32_t sub_id)
{
    ATOMIC_STORE_RELAXED(info.sub_id_lock, sub_id);
}

/**
 * @brief Add a subscription into internal subscriptions.
 *
 * @param[in] nc_id NETCONF SID of the session creating this subscription.
 * @param[in] sub_ids Array of generated sysrepo subscription IDs.
 * @param[in] sub_id_count Number of @p sub_ids.
 * @param[in] term_reason Default termination reason.
 * @param[in] stop_time Subscription stop time.
 * @param[in] type Subscription type.
 * @param[in] data Data specific for @p type.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_new(uint32_t nc_id, uint32_t *sub_ids, uint32_t sub_id_count, const char *term_reason, time_t stop_time,
        enum sub_ntf_type type, void *data)
{
    void *mem;
    struct np2srv_sub_ntf *sub;

    assert(sub_ids && sub_id_count);

    /* LOCK */
    pthread_mutex_lock(&info.lock);

    mem = realloc(info.subs, (info.count + 1) * sizeof *info.subs);
    if (!mem) {
        /* UNLOCK */
        pthread_mutex_unlock(&info.lock);
        return -1;
    }
    info.subs = mem;
    sub = &info.subs[info.count];

    /* fill all members */
    sub->nc_id = nc_id;
    sub->sub_ntf_id = sub_ids[0];
    sub->sub_ids = sub_ids;
    ATOMIC_STORE_RELAXED(sub->sub_id_count, sub_id_count);
    sub->term_reason = term_reason;
    sub->stop_time = stop_time;

    sub->sent_count = 0;

    sub->type = type;
    sub->data = data;

    ++info.count;

    /* UNLOCK */
    pthread_mutex_unlock(&info.lock);
    return 0;
}

void
np2srv_sub_ntf_destroy(void)
{
    uint32_t i;

    /* LOCK */
    pthread_mutex_lock(&info.lock);

    for (i = 0; i < info.count; ++i) {
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
    pthread_mutex_unlock(&info.lock);
}

int
np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct nc_session *ncs;
    char id_str[11];
    time_t stop = 0;
    int rc;
    uint32_t *sub_ids = NULL, sub_id_count = 0;
    enum sub_ntf_type type;
    void *data = NULL;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* find this NETCONF session */
    ncs = np_get_nc_sess(sr_session_get_event_nc_id(session));
    if (!ncs) {
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    /* stop time */
    lyd_find_path(input, "stop-time", 0, &node);
    if (node) {
        stop = nc_datetime2time(LYD_CANON_VALUE(node));
    }

    /* encoding */
    lyd_find_path(input, "encoding", 0, &node);
    if (node && strcmp(((struct lyd_node_term *)node)->value.ident->name, "encode-xml")) {
        ERR("Unsupported encoding \"%s\".", LYD_CANON_VALUE(node));
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
    nc_session_set_notif_status(ncs, 1);

    /* get type-specific data */
    switch (type) {
    case SUB_TYPE_SUB_NTF:
        rc = sub_ntf_rpc_establish_sub(session, input, stop, &sub_ids, &sub_id_count, &data);
        break;
    case SUB_TYPE_YANG_PUSH:
        rc = yang_push_rpc_establish_sub(session, input, stop, &sub_ids, &sub_id_count, &data);
        break;
    }
    if (rc != SR_ERR_OK) {
        goto error;
    }

    /* generate output */
    sprintf(id_str, "%" PRIu32, sub_ids[0]);
    if (lyd_new_term(output, NULL, "id", id_str, 1, NULL)) {
        rc = SR_ERR_LY;
        goto error;
    }
    /* TODO "replay-start-time-revision" - sent only if the earliest (theoretical) stored notif is later than start-time */

    /* add a new subscription into our subscription information */
    if (sub_ntf_new(sr_session_get_event_nc_id(session), sub_ids, sub_id_count,
            "ietf-subscribed-notifications:no-such-subscription", stop, type, data)) {
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    return SR_ERR_OK;

error:
    free(sub_ids);
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
    if (ncs) {
        nc_session_set_notif_status(ncs, 0);
    }
    return rc;
}

int
np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    char *xp = NULL;
    time_t stop = 0;
    int rc = SR_ERR_OK;
    uint32_t sub_ntf_id;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    sub_ntf_id = ((struct lyd_node_term *)node)->value.uint32;

    /* stop time */
    lyd_find_path(input, "stop-time", 0, &node);
    if (node) {
        stop = nc_datetime2time(LYD_CANON_VALUE(node));
    }

    /* LOCK */
    sub = sub_ntf_find(sub_ntf_id, sr_session_get_event_nc_id(session), 1);
    if (!sub || (sub->sub_ntf_id != sub_ntf_id)) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", sub_ntf_id);
        if (sub) {
            goto cleanup_unlock;
        }
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
    if (stop) {
        sub->stop_time = stop;
    }

cleanup_unlock:
    /* UNLOCK */
    pthread_mutex_unlock(&info.lock);

cleanup:
    free(xp);
    return rc;
}

int
sub_ntf_terminate_sub(struct np2srv_sub_ntf *sub)
{
    int r, rc = SR_ERR_OK;

    /* terminate all the subscriptions, they delete themselves */
    while (ATOMIC_LOAD_RELAXED(sub->sub_id_count) > 1) {
        switch (sub->type) {
        case SUB_TYPE_SUB_NTF:
            r = sub_ntf_terminate_sr_sub(sub->sub_ids[0]);
            break;
        case SUB_TYPE_YANG_PUSH:
            r = yang_push_terminate_sr_sub(sub->sub_ids[0]);
            break;
        }
        if (r != SR_ERR_OK) {
            rc = r;
        }
    }

    /* last unsubscribe, will free sub */
    switch (sub->type) {
    case SUB_TYPE_SUB_NTF:
        r = sub_ntf_terminate_sr_sub(sub->sub_ids[0]);
        break;
    case SUB_TYPE_YANG_PUSH:
        r = yang_push_terminate_sr_sub(sub->sub_ids[0]);
        break;
    }
    if (r != SR_ERR_OK) {
        rc = r;
    }

    return rc;
}

int
np2srv_rpc_delete_sub_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    int rc = SR_ERR_OK;
    uint32_t sub_ntf_id;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    sub_ntf_id = ((struct lyd_node_term *)node)->value.uint32;

    /* LOCK */
    sub = sub_ntf_find(sub_ntf_id, sr_session_get_event_nc_id(session), 1);
    if (!sub || (sub->sub_ntf_id != sub_ntf_id)) {
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", sub_ntf_id);
        if (sub) {
            rc = SR_ERR_INVAL_ARG;
            goto cleanup_unlock;
        }
        return SR_ERR_INVAL_ARG;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    pthread_mutex_unlock(&info.lock);

    return rc;
}

int
np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    int rc = SR_ERR_OK;
    uint32_t sub_ntf_id;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    sub_ntf_id = ((struct lyd_node_term *)node)->value.uint32;

    /* LOCK */
    sub = sub_ntf_find(sub_ntf_id, 0, 1);
    if (!sub || (sub->sub_ntf_id != sub_ntf_id)) {
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " does not exist.", sub_ntf_id);
        if (sub) {
            rc = SR_ERR_INVAL_ARG;
            goto cleanup_unlock;
        }
        return SR_ERR_INVAL_ARG;
    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    pthread_mutex_unlock(&info.lock);

    return rc;
}

int
np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(xpath),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_val, *prev_list;
    bool prev_dflt;
    int r, rc = SR_ERR_OK;

    /* LOCK */
    pthread_mutex_lock(&info.lock);

    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        rc = sub_ntf_config_filters(node, op);
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

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        rc = yang_push_config_filters(node, op);
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
    pthread_mutex_unlock(&info.lock);

    sr_free_change_iter(iter);
    return rc;
}

int
np2srv_oper_sub_ntf_streams_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(path),
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream, *sr_data = NULL, *sr_mod, *rep_sup;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *mod;
    const char *mod_name;
    char buf[26];
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
        mod_name = LYD_CANON_VALUE(lyd_child(sr_mod));

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
            nc_time2datetime(((struct lyd_node_term *)rep_sup)->value.uint64, NULL, buf);
            if (lyd_new_term(stream, NULL, "replay-log-creation-time", buf, 0, NULL)) {
                goto error;
            }
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
np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(path),
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    const struct ly_ctx *ly_ctx;
    struct lyd_node *list, *receiver, *root;
    struct np2srv_sub_ntf *sub;
    char buf[26], *path = NULL;
    uint32_t i, excluded_count;
    int rc = SR_ERR_OK;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    /* LOCK */
    pthread_mutex_lock(&info.lock);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscriptions", NULL, 0, &root)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* go through all the subscriptions */
    for (i = 0; i < info.count; ++i) {
        sub = &info.subs[i];

        /* subscription with id */
        sprintf(buf, "%" PRIu32, sub->sub_ntf_id);
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
        if (sub->stop_time) {
            nc_time2datetime(sub->stop_time, NULL, buf);
            if (lyd_new_term(list, NULL, "stop-time", buf, 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        /* receivers */
        if (asprintf(&path, "receivers/receiver[name='NETCONF session %u']", sub->nc_id) == -1) {
            EMEM;
            rc = SR_ERR_NOMEM;
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
        sprintf(buf, "%" PRIu32, sub->sent_count);
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
    pthread_mutex_unlock(&info.lock);

    if (rc) {
        lyd_free_tree(root);
    } else {
        *parent = root;
    }
    return rc;
}
