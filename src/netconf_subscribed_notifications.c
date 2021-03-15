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
#include "netconf_acm.h"
#include "netconf_monitoring.h"
#include "netconf_yang_push.h"

/**
 * @brief Complete operational information about the subscriptions.
 */
static struct {
    pthread_mutex_t lock;
    ATOMIC_T sub_id_lock;   /* subscription ID that holds the lock, if a notification callback is called with this ID,
                               it must not appempt locking and can access this structure directly */

    struct np2srv_ntf_sub {
        uint32_t nc_id;
        struct np2srv_ntf_sub_sr {
            uint32_t sub_id;
            uint32_t denied_count;  /* number of notifications denied by NACM */
        } *sub_ids;
        uint32_t ntf_sub_id;
        ATOMIC_T sub_id_count;
        const char *term_reason;

        char *stream_filter_name;
        struct lyd_node *stream_subtree_filter;
        char *stream_xpath_filter;

        char *stream;
        time_t replay_start_time;
        time_t stop_time;
    } *subs;
    uint32_t count;
} ntf_subs = { .lock = PTHREAD_MUTEX_INITIALIZER };

static int sub_ntf_oper_sub_add(struct np2srv_ntf_sub *sub, struct lyd_node *root);

/**
 * @brief Add a subscription into internal subscriptions.
 *
 * @param[in] nc_id NETCONF SID of the session creating this subscription.
 * @param[in] sub_ids Array of generated sysrepo subscription IDs.
 * @param[in] sub_id_count Number of @p sub_ids.
 * @param[in] term_reason Default termination reason.
 * @param[in] stream_filter_name Value of stream-filter-name, if any.
 * @param[in] stream_subtree_filter Node stream-subtree-filter, if any.
 * @param[in] stream_xpath_filter Value of stream-xpath-filter, if any.
 * @param[in] stream Name of the subscribed stream.
 * @param[in] replay_start_time Replay start time of the subscription.
 * @param[in] stop_time Subscription stop time.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_new(uint32_t nc_id, struct np2srv_ntf_sub_sr *sub_ids, uint32_t sub_id_count, const char *term_reason,
        const char *stream_filter_name, const struct lyd_node *stream_subtree_filter, const char *stream_xpath_filter,
        const char *stream, time_t replay_start_time, time_t stop_time)
{
    void *mem;
    struct np2srv_ntf_sub *sub;

    assert(sub_ids && sub_id_count);
    assert(stream);

    /* LOCK */
    pthread_mutex_lock(&ntf_subs.lock);

    mem = realloc(ntf_subs.subs, (ntf_subs.count + 1) * sizeof *ntf_subs.subs);
    if (!mem) {
        /* UNLOCK */
        pthread_mutex_unlock(&ntf_subs.lock);
        return -1;
    }
    ntf_subs.subs = mem;
    sub = &ntf_subs.subs[ntf_subs.count];

    /* fill all members */
    sub->nc_id = nc_id;
    sub->sub_ids = sub_ids;
    ATOMIC_STORE_RELAXED(sub->sub_id_count, sub_id_count);
    sub->ntf_sub_id = sub_ids[0].sub_id;
    sub->term_reason = term_reason;

    sub->stream_filter_name = stream_filter_name ? strdup(stream_filter_name) : NULL;
    if (stream_subtree_filter) {
        lyd_dup_single(stream_subtree_filter, NULL, 0, &sub->stream_subtree_filter);
    } else {
        sub->stream_subtree_filter = NULL;
    }
    sub->stream_xpath_filter = stream_xpath_filter ? strdup(stream_xpath_filter) : NULL;

    sub->stream = strdup(stream);
    sub->replay_start_time = replay_start_time;
    sub->stop_time = stop_time;

    ++ntf_subs.count;

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);
    return 0;
}

/**
 * @brief Get ntf-sub subscription ID from sysrepo subscription ID.
 *
 * @param[in] sub_id Sysrepo subscription ID.
 * @return ntf-sub subscription ID.
 */
static uint32_t
sub_ntf_sub_id_sr2ntf_sub(uint32_t sub_id)
{
    int lock;
    uint32_t i, j, ntf_sub_id = 0;

    lock = ATOMIC_LOAD_RELAXED(ntf_subs.sub_id_lock) == sub_id ? 0 : 1;
    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&ntf_subs.lock);
    }

    for (i = 0; i < ntf_subs.count; ++i) {
        for (j = 0; j < ATOMIC_LOAD_RELAXED(ntf_subs.subs[i].sub_id_count); ++j) {
            if (ntf_subs.subs[i].sub_ids[j].sub_id == sub_id) {
                ntf_sub_id = ntf_subs.subs[i].ntf_sub_id;
                break;
            }
        }

        if (ntf_sub_id) {
            break;
        }
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&ntf_subs.lock);
    }

    if (!ntf_sub_id) {
        EINT;
    }
    return ntf_sub_id;
}

/**
 * @brief Find an internal subscription structure.
 *
 * @param[in] sub_id Subscription ID of the subscription.
 * @param[in] nc_id Receiver NETCONF SID, 0 for any.
 * @param[in] lock Whether to lock subscriptions when a subscription was found or not.
 * @return Found subscription.
 */
static struct np2srv_ntf_sub *
sub_ntf_find(uint32_t sub_id, uint32_t nc_id, int lock)
{
    uint32_t i, j;

    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&ntf_subs.lock);
    }

    for (i = 0; i < ntf_subs.count; ++i) {
        if (nc_id && (ntf_subs.subs[i].nc_id != nc_id)) {
            continue;
        }

        for (j = 0; j < ATOMIC_LOAD_RELAXED(ntf_subs.subs[i].sub_id_count); ++j) {
            if (ntf_subs.subs[i].sub_ids[j].sub_id == sub_id) {
                return &ntf_subs.subs[i];
            }
        }
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&ntf_subs.lock);
    }
    return NULL;
}

/**
 * @brief Find next matching internal subscription structure.
 *
 * @param[in] last Last found structure.
 * @param[in] stream_filter_name Stream filter name of the matching subscription.
 * @return Next matching subscription.
 * @return NULL if no more matching subscriptions found.
 */
static struct np2srv_ntf_sub *
sub_ntf_find_next(struct np2srv_ntf_sub *last, const char *stream_filter_name)
{
    uint32_t i, last_idx = last ? (((char *)last) - ((char *)ntf_subs.subs)) / sizeof *last : 0;

    for (i = last_idx ? last_idx + 1 : 0; i < ntf_subs.count; ++i) {
        if (ntf_subs.subs[i].stream_filter_name && !strcmp(ntf_subs.subs[i].stream_filter_name, stream_filter_name)) {
            return &ntf_subs.subs[i];
        }
    }

    return NULL;
}

/**
 * @brief Increase the denied notification counter.
 *
 * @param[in] sub_id Subscription ID of the subscription.
 */
static void
sub_ntf_inc_denied(uint32_t sub_id)
{
    int lock, found = 0;
    uint32_t i, j;

    lock = ATOMIC_LOAD_RELAXED(ntf_subs.sub_id_lock) == sub_id ? 0 : 1;
    if (lock) {
        /* LOCK */
        pthread_mutex_lock(&ntf_subs.lock);
    }

    for (i = 0; i < ntf_subs.count; ++i) {
        for (j = 0; j < ATOMIC_LOAD_RELAXED(ntf_subs.subs[i].sub_id_count); ++j) {
            if (ntf_subs.subs[i].sub_ids[j].sub_id == sub_id) {
                ++ntf_subs.subs[i].sub_ids[j].denied_count;
                found = 1;
                break;
            }
        }

        if (found) {
            break;
        }
    }

    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&ntf_subs.lock);
    }

    if (!found) {
        EINT;
    }
}

/**
 * @brief Remove a subscription from internal subscriptions.
 * Only once all the sysrepo subscription of a ntf-sub subscription were removed, the actual ntf-sub subscription
 * is also removed.
 *
 * @param[in] sub_id Sysrepo subscription ID to remove.
 * @param[in] nc_id Receiver NETCONF SID.
 * @param[out] term_reason If was the last, set termination reason.
 * @return Whether the last sysrepo subscription was removed for a ntf-sub subscription.
 */
static int
sub_ntf_sr_del_is_last(uint32_t sub_id, uint32_t nc_id, const char **term_reason)
{
    int lock = ATOMIC_LOAD_RELAXED(ntf_subs.sub_id_lock) == sub_id ? 0 : 1, last = 0;
    struct np2srv_ntf_sub *sub;
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
            if (sub->sub_ids[i].sub_id == sub_id) {
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

    idx = (((char *)sub) - ((char *)ntf_subs.subs)) / sizeof *sub;

    free(sub->sub_ids);
    free(sub->stream_filter_name);
    lyd_free_tree(sub->stream_subtree_filter);
    free(sub->stream_xpath_filter);
    free(sub->stream);

    --ntf_subs.count;
    if (idx < ntf_subs.count) {
        memmove(sub, sub + 1, (ntf_subs.count - idx) * sizeof *sub);
    }

    /* last subscription was removed */
    last = 1;

cleanup:
    if (lock) {
        /* UNLOCK */
        pthread_mutex_unlock(&ntf_subs.lock);
    }
    return last;
}

void
np2srv_sub_ntf_destroy(void)
{
    uint32_t i;

    /* LOCK */
    pthread_mutex_lock(&ntf_subs.lock);

    for (i = 0; i < ntf_subs.count; ++i) {
        free(ntf_subs.subs[i].sub_ids);
        free(ntf_subs.subs[i].stream_filter_name);
        lyd_free_tree(ntf_subs.subs[i].stream_subtree_filter);
        free(ntf_subs.subs[i].stream_xpath_filter);
        free(ntf_subs.subs[i].stream);
    }
    free(ntf_subs.subs);
    ntf_subs.subs = NULL;
    ntf_subs.count = 0;

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);
}

static LY_ERR
sub_ntf_lysc_has_notif_clb(struct lysc_node *node, void *UNUSED(data), ly_bool *UNUSED(dfs_continue))
{
    if (node->nodetype == LYS_NOTIF) {
        return LY_EEXIST;
    }

    return LY_SUCCESS;
}

/**
 * @brief Create oper data for a specific subscription.
 *
 * @param[in] ly_ctx libyang context to use.
 * @param[in] sub_id Subscription ID of the specific subscription.
 * @param[in] nc_id Receiver NETCONF ID.
 * @param[out] root Oper subscriptions data tree with information about the subscription.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_oper_sub_get(const struct ly_ctx *ly_ctx, uint32_t sub_id, uint32_t nc_id, struct lyd_node **root)
{
    struct np2srv_ntf_sub *sub;

    /* LOCK */
    sub = sub_ntf_find(sub_id, nc_id, 1);
    if (!sub) {
        EINT;
        return -1;
    }

    lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscriptions", NULL, 0, root);

    /* add sub oper data */
    sub_ntf_oper_sub_add(sub, *root);

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);
    return 0;
}

/**
 * @brief New notification callback used for notifications received on subscription made by \<establish-subscription\> RPC.
 */
static void
np2srv_rpc_establish_sub_ntf_cb(sr_session_ctx_t *session, const sr_ev_notif_type_t notif_type, uint32_t sub_id,
        const struct lyd_node *notif, time_t timestamp, void *private_data)
{
    struct nc_server_notif *nc_ntf = NULL;
    struct nc_session *ncs = (struct nc_session *)private_data;
    struct lyd_node *ly_ntf = NULL, *oper_data = NULL, *child;
    NC_MSG_TYPE msg_type;
    uint32_t ntf_sub_id;
    char buf[26], *datetime;
    const char *reason = NULL;

    if (notif_type == SR_EV_NOTIF_TERMINATED) {
        /* use ntf-sub sub_id (we must get it before it is all removed) */
        ntf_sub_id = sub_ntf_sub_id_sr2ntf_sub(sub_id);

        if (!sub_ntf_sr_del_is_last(sub_id, sr_session_get_event_nc_id(session), &reason)) {
            /* wait for the last subscription */
            return;
        }
    } else {
        if (sub_id != sub_ntf_sub_id_sr2ntf_sub(sub_id)) {
            /* event on one of the sysrepo subscriptions among several for one sub-ntf subscription,
            * we want to send only one NETCONF notification so wait for the "main" sysrepo subscription */
            return;
        }

        ntf_sub_id = sub_id;
    }

    if (nc_session_get_status(ncs) != NC_STATUS_RUNNING) {
        /* we cannot send any notification on the NETCONF session for whatever reason (client disconnected) */
        goto cleanup;
    }

    /* create these notifications, sysrepo only emulates them */
    if (notif_type == SR_EV_NOTIF_REPLAY_COMPLETE) {
        sprintf(buf, "%" PRIu32, ntf_sub_id);
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:replay-completed/id",
                buf, 0, &ly_ntf);
        notif = ly_ntf;
    } else if (notif_type == SR_EV_NOTIF_MODIFIED) {
        /* get information about the subscription (oper data) */
        if (sub_ntf_oper_sub_get(sr_get_context(np2srv.sr_conn), ntf_sub_id, sr_session_get_event_nc_id(session), &oper_data)) {
            goto cleanup;
        }

        /* create the notification with its data copied from the oper data */
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:subscription-modified", NULL,
                0, &ly_ntf);
        LY_LIST_FOR(lyd_child(oper_data), child) {
            if (np_ly_schema_dup_r(ly_ntf, child, 0)) {
                goto cleanup;
            }
        }
        notif = ly_ntf;
    } else if (notif_type == SR_EV_NOTIF_TERMINATED) {
        if (!reason) {
            EINT;
            goto cleanup;
        }

        sprintf(buf, "%" PRIu32, ntf_sub_id);
        lyd_new_path(NULL, sr_get_context(np2srv.sr_conn), "/ietf-subscribed-notifications:subscription-terminated/id",
                buf, 0, &ly_ntf);
        lyd_new_path(ly_ntf, NULL, "reason", reason, 0, NULL);
        notif = ly_ntf;
    } else if ((notif_type == SR_EV_NOTIF_RESUMED) || (notif_type == SR_EV_NOTIF_SUSPENDED)) {
        /* should never be generated by the server */
        EINT;
        goto cleanup;
    }

    /* find the top-level node */
    while (notif->parent) {
        notif = lyd_parent(notif);
    }

    /* check NACM */
    if (ncac_check_operation(notif, nc_session_get_username(ncs))) {
        /* denied */
        sub_ntf_inc_denied(sub_id);
        goto cleanup;
    }

    /* create the notification object */
    datetime = nc_time2datetime(timestamp, NULL, buf);
    nc_ntf = nc_server_notif_new((struct lyd_node *)notif, datetime, NC_PARAMTYPE_CONST);

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs),
                msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        goto cleanup;
    }
    ncm_session_notification(ncs);

cleanup:
    if (notif_type == SR_EV_NOTIF_TERMINATED) {
        /* subscription finished */
        nc_session_set_notif_status(ncs, 0);
    }

    nc_server_notif_free(nc_ntf);
    lyd_free_tree(oper_data);
    lyd_free_all(ly_ntf);
}

/**
 * @brief Create all sysrepo subscriptions for a single sub-ntf subscription.
 *
 * @param[in] user_sess User session to use for sysrepo calls.
 * @param[in] stream Stream to subscribe to.
 * @param[in] xpath Filter to use.
 * @param[in] start Replay start time.
 * @param[in] stop Subscription stop time.
 * @param[in] private_data User data to set when subscribing.
 * @param[in] ev_sess Event session for reporting errors.
 * @param[out] sub_ids Generated sysrepo subscription IDs, the first one is used as sub-ntf subscription ID.
 * @param[out] sub_id_count Number of @p sub_ids.
 * @return Sysrepo error value.
 */
static int
sub_ntf_sr_subscribe(sr_session_ctx_t *user_sess, const char *stream, const char *xpath, time_t start,
        time_t stop, void *private_data, sr_session_ctx_t *ev_sess, struct np2srv_ntf_sub_sr **sub_ids,
        uint32_t *sub_id_count)
{
    const struct ly_ctx *ly_ctx = sr_get_context(sr_session_get_connection(user_sess));
    const struct lys_module *ly_mod;
    int rc;
    const sr_error_info_t *err_info;
    uint32_t idx;
    void *mem;

    *sub_ids = NULL;
    *sub_id_count = 0;

    /* sysrepo API */
    if (!strcmp(stream, "NETCONF")) {
        /* subscribe to all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            if (!ly_mod->implemented) {
                continue;
            }

            if (lysc_module_dfs_full(ly_mod, sub_ntf_lysc_has_notif_clb, NULL) == LY_EEXIST) {
                /* allocate a new sub ID */
                mem = realloc(*sub_ids, (*sub_id_count + 1) * sizeof **sub_ids);
                if (!mem) {
                    EMEM;
                    rc = SR_ERR_NOMEM;
                    goto error;
                }
                *sub_ids = mem;

                /* a notification was found, subscribe to the module */
                rc = sr_event_notif_subscribe_tree(user_sess, ly_mod->name, xpath, start, stop, np2srv_rpc_establish_sub_ntf_cb,
                        private_data, SR_SUBSCR_CTX_REUSE, &np2srv.sr_notif_sub);
                if (rc != SR_ERR_OK) {
                    sr_get_error(user_sess, &err_info);
                    sr_set_error(ev_sess, err_info->err[0].xpath, err_info->err[0].message);
                    goto error;
                }

                /* add new sub ID */
                (*sub_ids)[*sub_id_count].sub_id = sr_event_notif_sub_id_get_last(np2srv.sr_notif_sub);
                (*sub_ids)[*sub_id_count].denied_count = 0;
                ++(*sub_id_count);
            }
        }
    } else {
        /* allocate a new single sub ID */
        *sub_ids = malloc(sizeof **sub_ids);
        if (!*sub_ids) {
            goto error;
        }

        /* subscribe to the specific module (stream) */
        rc = sr_event_notif_subscribe_tree(user_sess, stream, xpath, start, stop, np2srv_rpc_establish_sub_ntf_cb, private_data,
                SR_SUBSCR_CTX_REUSE, &np2srv.sr_notif_sub);
        if (rc != SR_ERR_OK) {
            sr_get_error(user_sess, &err_info);
            sr_set_error(ev_sess, err_info->err[0].xpath, err_info->err[0].message);
            goto error;
        }

        /* add new sub ID */
        (*sub_ids)[0].sub_id = sr_event_notif_sub_id_get_last(np2srv.sr_notif_sub);
        (*sub_ids)[0].denied_count = 0;
        *sub_id_count = 1;
    }

    return SR_ERR_OK;

error:
    for (idx = 0; idx < *sub_id_count; ++idx) {
        sr_event_notif_sub_unsubscribe(np2srv.sr_notif_sub, (*sub_ids)[idx].sub_id);
    }
    free(*sub_ids);
    *sub_ids = NULL;
    *sub_id_count = 0;
    return rc;
}

/**
 * @brief Transform all filter specifications into a single XPath filter.
 *
 * @param[in] user_sess User session to use for sysrepo calls.
 * @param[in] rpc Parent of the filter nodes.
 * @param[in] ev_sess Event session for reporting errors.
 * @param[out] xpath Created xpath filter.
 * @param[out] stream_filter_name Node value, if this filter was present.
 * @param[out] stream_subtree_silter Duplicated node, if this filter was present.
 * @param[out] stream_xpath_filter Node value, if this filter was present.
 * @return Sysrepo error value.
 */
static int
sub_ntf_rpc_filter2xpath(sr_session_ctx_t *user_sess, const struct lyd_node *rpc, sr_session_ctx_t *ev_sess,
        char **xpath, const char **stream_filter_name, struct lyd_node **stream_subtree_filter,
        const char **stream_xpath_filter)
{
    struct lyd_node *node = NULL, *subtree = NULL;
    struct ly_set *nodeset;
    const sr_error_info_t *err_info;
    struct np2_filter filter = {0};
    char *str;
    int rc = SR_ERR_OK;

    assert(rpc && xpath);

    *xpath = NULL;
    if (stream_filter_name) {
        *stream_filter_name = NULL;
    }
    if (stream_subtree_filter) {
        *stream_subtree_filter = NULL;
    }
    if (stream_xpath_filter) {
        *stream_xpath_filter = NULL;
    }

    /* find the filter node */
    lyd_find_xpath(rpc, "stream-filter-name | stream-subtree-filter | stream-xpath-filter", &nodeset);
    if (nodeset->count) {
        node = nodeset->dnodes[0];
    }
    ly_set_free(nodeset, NULL);

    if (!node) {
        /* nothing to do */
        return SR_ERR_OK;
    }

    /* first remember the exact filter used */
    if (!strcmp(node->schema->name, "stream-filter-name")) {
        if (stream_filter_name) {
            *stream_filter_name = LYD_CANON_VALUE(node);
        }
    } else if (!strcmp(node->schema->name, "stream-subtree-filter")) {
        if (stream_subtree_filter) {
            *stream_subtree_filter = node;
        }
    } else {
        assert(!strcmp(node->schema->name, "stream-xpath-filter"));
        if (stream_xpath_filter) {
            *stream_xpath_filter = LYD_CANON_VALUE(node);
        }
    }

    if (!strcmp(node->schema->name, "stream-filter-name")) {
        /* first get this filter from sysrepo */
        if (asprintf(&str, "/ietf-subscribed-notifications:filters/stream-filter[name='%s']", LYD_CANON_VALUE(node)) == -1) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }

        sr_session_switch_ds(user_sess, SR_DS_OPERATIONAL);
        rc = sr_get_subtree(user_sess, str, 0, &subtree);
        free(str);
        if (rc != SR_ERR_OK) {
            sr_get_error(user_sess, &err_info);
            sr_set_error(ev_sess, err_info->err[0].xpath, err_info->err[0].message);
            goto cleanup;
        }

        if (!lyd_child(subtree)->next) {
            ERR("Filter \"%s\" does not define any actual filter.", LYD_CANON_VALUE(node));
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        node = lyd_child(subtree)->next;
    }

    if (!strcmp(node->schema->name, "stream-subtree-filter")) {
        /* subtree */
        if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
            if (op_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, &filter)) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if (op_filter_filter2xpath(&filter, xpath)) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
        }
    } else {
        /* xpath */
        assert(!strcmp(node->schema->name, "stream-xpath-filter"));
        if (strlen(LYD_CANON_VALUE(node))) {
            *xpath = strdup(LYD_CANON_VALUE(node));
            if (*xpath) {
                EMEM;
                rc = SR_ERR_NOMEM;
                goto cleanup;
            }
        }
    }

cleanup:
    lyd_free_tree(subtree);
    op_filter_erase(&filter);
    return rc;
}

int
np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input,
        sr_event_t event, uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct lyd_node *node, *stream_subtree_filter = NULL;
    struct nc_session *ncs;
    sr_session_ctx_t *user_sess;
    const char *stream, *stream_filter_name = NULL, *stream_xpath_filter = NULL;
    char *xp = NULL, buf[26];
    time_t start = 0, stop = 0;
    int rc = SR_ERR_OK;
    struct np2srv_ntf_sub_sr *sub_ids = NULL;
    uint32_t sub_id_count = 0;

    /* datastore */
    if (!lyd_find_path(input, "ietf-yang-push:datastore", 0, NULL)) {
        /* ietf-yang-push subscription, handled separately */
        return np2srv_rpc_establish_yang_push_cb(session, op_path, input, event, request_id, output, private_data);
    }

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* find this NETCONF session */
    ncs = np_get_nc_sess(sr_session_get_event_nc_id(session));
    if (!ncs) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    user_sess = nc_session_get_data(ncs);

    /* filter, join all into one xpath */
    rc = sub_ntf_rpc_filter2xpath(user_sess, input, session, &xp, &stream_filter_name, &stream_subtree_filter,
            &stream_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* stream */
    lyd_find_path(input, "stream", 0, &node);
    stream = LYD_CANON_VALUE(node);

    /* replay start time */
    lyd_find_path(input, "replay-start-time", 0, &node);
    if (node) {
        start = nc_datetime2time(LYD_CANON_VALUE(node));
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
        goto cleanup;
    }

    /* set ongoing notifications flag */
    nc_session_set_notif_status(ncs, 1);

    /* subscribe to sysrepo notifications */
    rc = sub_ntf_sr_subscribe(user_sess, stream, xp, start, stop, ncs, session, &sub_ids, &sub_id_count);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* add a new subscription into our subscription information */
    if (sub_ntf_new(sr_session_get_event_nc_id(session), sub_ids, sub_id_count,
            "ietf-subscribed-notifications:no-such-subscription", stream_filter_name, stream_subtree_filter,
            stream_xpath_filter, stream, start, stop)) {
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }
    sprintf(buf, "%" PRIu32, sub_ids[0].sub_id);
    sub_ids = NULL;

    /* generate output */
    if (lyd_new_term(output, NULL, "id", buf, 1, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    /* TODO "replay-start-time-revision" - sent only if the earliest (theoretical) stored notif is later than start-time */

    /* success */

cleanup:
    free(sub_ids);
    free(xp);
    if (ncs && rc) {
        nc_session_set_notif_status(ncs, 0);
    }
    return rc;
}

int
np2srv_rpc_modify_sub_cb(sr_session_ctx_t *session, const char *op_path, const struct lyd_node *input, sr_event_t event,
        uint32_t request_id, struct lyd_node *output, void *private_data)
{
    struct lyd_node *node, *stream_subtree_filter = NULL;
    struct np2srv_ntf_sub *sub;
    sr_session_ctx_t *user_sess;
    const char *cur_xp, *stream_filter_name = NULL, *stream_xpath_filter = NULL;
    char *xp = NULL;
    time_t stop = 0, cur_stop;
    int rc = SR_ERR_OK;
    uint32_t i, ntf_sub_id;

    /* datastore */
    if (!lyd_find_path(input, "ietf-yang-push:datastore", 0, NULL)) {
        /* ietf-yang-push handled separately */
        return np2srv_rpc_modify_yang_push_cb(session, op_path, input, event, request_id, output, private_data);
    }

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    ntf_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* filter, join all into one xpath */
    rc = sub_ntf_rpc_filter2xpath(user_sess, input, session, &xp, &stream_filter_name, &stream_subtree_filter,
            &stream_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* stop time */
    lyd_find_path(input, "stop-time", 0, &node);
    if (node) {
        stop = nc_datetime2time(LYD_CANON_VALUE(node));
    }

    /* LOCK */
    sub = sub_ntf_find(ntf_sub_id, sr_session_get_event_nc_id(session), 1);
    if (!sub || (sub->sub_ids[0].sub_id != ntf_sub_id)) {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", ntf_sub_id);
        if (sub) {
            goto cleanup_unlock;
        }
        goto cleanup;
    }

    /* learn the current filter */
    rc = sr_event_notif_sub_get_info(np2srv.sr_notif_sub, ntf_sub_id, NULL, &cur_xp, NULL, &cur_stop, NULL);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

    if (strcmp(cur_xp, xp)) {
        /* update the filter */
        for (i = 0; i < sub->sub_id_count; ++i) {
            /* "pass" the lock to the callback */
            ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, sub->sub_ids[i].sub_id);
            rc = sr_event_notif_sub_modify_filter(np2srv.sr_notif_sub, sub->sub_ids[i].sub_id, xp);
            if (rc != SR_ERR_OK) {
                goto cleanup_unlock;
            }
        }
    }
    if (stop && (cur_stop != stop)) {
        /* update stop time */
        for (i = 0; i < sub->sub_id_count; ++i) {
            /* "pass" the lock to the callback */
            ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, sub->sub_ids[i].sub_id);
            rc = sr_event_notif_sub_modify_stop_time(np2srv.sr_notif_sub, sub->sub_ids[i].sub_id, stop);
            if (rc != SR_ERR_OK) {
                goto cleanup_unlock;
            }
        }
    }

    /* update the subscription operational data */
    sub->stream_filter_name = stream_filter_name ? strdup(stream_filter_name) : NULL;
    if (stream_subtree_filter) {
        lyd_dup_single(stream_subtree_filter, NULL, 0, &sub->stream_subtree_filter);
    } else {
        sub->stream_subtree_filter = NULL;
    }
    sub->stream_xpath_filter = stream_xpath_filter ? strdup(stream_xpath_filter) : NULL;
    if (stop) {
        sub->stop_time = stop;
    }

cleanup_unlock:
    ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, 0);

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);

cleanup:
    free(xp);
    return rc;
}

/**
 * @brief Correctly terminate a ntf-sub subscription.
 * ntf-sub lock is expected to be held.
 *
 * @param[in] sub Subscription to terminate, is freed on success!
 * @return Sysrepo error value.
 */
static int
np2srv_rpc_terminate_sub(struct np2srv_ntf_sub *sub)
{
    int r, rc = SR_ERR_OK;

    /* terminate all the subscriptions, they delete themselves */
    while (ATOMIC_LOAD_RELAXED(sub->sub_id_count) > 1) {
        /* "pass" the lock to the callback */
        ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, sub->sub_ids[0].sub_id);
        r = sr_event_notif_sub_unsubscribe(np2srv.sr_notif_sub, sub->sub_ids[0].sub_id);
        if (r != SR_ERR_OK) {
            /* continue on error */
            rc = r;
        }
    }

    /* last unsubscribe, will free sub */
    ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, sub->sub_ids[0].sub_id);
    r = sr_event_notif_sub_unsubscribe(np2srv.sr_notif_sub, sub->sub_ids[0].sub_id);
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
    struct np2srv_ntf_sub *sub;
    int rc = SR_ERR_OK;
    uint32_t ntf_sub_id;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    ntf_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* LOCK */
    sub = sub_ntf_find(ntf_sub_id, sr_session_get_event_nc_id(session), 1);
    if (!sub || (sub->sub_ids[0].sub_id != ntf_sub_id)) {
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", ntf_sub_id);
        if (sub) {
            rc = SR_ERR_INVAL_ARG;
            goto cleanup_unlock;
        }
        return SR_ERR_INVAL_ARG;
    }

    /* terminate the subscription */
    rc = np2srv_rpc_terminate_sub(sub);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, 0);

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);

    return rc;
}

int
np2srv_rpc_kill_sub_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_ntf_sub *sub;
    int rc = SR_ERR_OK;
    uint32_t ntf_sub_id;

    if (event == SR_EV_ABORT) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    ntf_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* LOCK */
    sub = sub_ntf_find(ntf_sub_id, 0, 1);
    if (!sub || (sub->sub_ids[0].sub_id != ntf_sub_id)) {
        sr_set_error(session, NULL, "Subscription with ID %" PRIu32 " does not exist.", ntf_sub_id);
        if (sub) {
            rc = SR_ERR_INVAL_ARG;
            goto cleanup_unlock;
        }
        return SR_ERR_INVAL_ARG;
    }

    /* terminate the subscription */
    rc = np2srv_rpc_terminate_sub(sub);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, 0);

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);

    return rc;
}

int
np2srv_sub_ntf_filters_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(xpath),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter;
    sr_change_oper_t op;
    const struct lyd_node *node;
    struct np2srv_ntf_sub *sub;
    const char *prev_val, *prev_list;
    bool prev_dflt;
    int r, rc = SR_ERR_OK;
    uint32_t i;
    char *xp;

    r = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter", &iter);
    if (r != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(r));
        return r;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, &prev_val, &prev_list, &prev_dflt)) == SR_ERR_OK) {
        if (op == SR_OP_MODIFIED) {
            /* construct the new filter */
            r = sub_ntf_rpc_filter2xpath(NULL, node, NULL, &xp, NULL, NULL, NULL);
            if (r != SR_ERR_OK) {
                rc = r;
                r = SR_ERR_NOT_FOUND;
                break;
            }

            /* LOCK */
            pthread_mutex_lock(&ntf_subs.lock);

            /* update all the relevant subscriptions */
            sub = NULL;
            while ((sub = sub_ntf_find_next(sub, LYD_CANON_VALUE(lyd_child(node))))) {
                /* modify the filter of the subscription(s) */
                for (i = 0; i < sub->sub_id_count; ++i) {
                    /* "pass" the lock to the callback */
                    ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, sub->sub_ids[i].sub_id);
                    r = sr_event_notif_sub_modify_filter(np2srv.sr_notif_sub, sub->sub_ids[i].sub_id, xp);
                    if (r != SR_ERR_OK) {
                        rc = r;
                    }
                }
            }

            ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, 0);
            /* UNLOCK */
            pthread_mutex_unlock(&ntf_subs.lock);

            free(xp);
        } else if (op == SR_OP_DELETED) {
            /* LOCK */
            pthread_mutex_lock(&ntf_subs.lock);

            /* update all the relevant subscriptions */
            sub = NULL;
            while ((sub = sub_ntf_find_next(sub, LYD_CANON_VALUE(lyd_child(node))))) {
                /* terminate the subscription with the specific term reason */
                sub->term_reason = "ietf-subscribed-notifications:filter-unavailable";
                r = np2srv_rpc_terminate_sub(sub);
                if (r != SR_ERR_OK) {
                    rc = r;
                }
            }

            ATOMIC_STORE_RELAXED(ntf_subs.sub_id_lock, 0);
            /* UNLOCK */
            pthread_mutex_unlock(&ntf_subs.lock);
        }
    }
    sr_free_change_iter(iter);
    if (r != SR_ERR_NOT_FOUND) {
        ERR("Getting next change failed (%s).", sr_strerror(r));
        return r;
    }

    return rc;
}

int
np2srv_sub_ntf_streams_oper_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(path),
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root, *stream, *sr_data = NULL, *sr_mod, *rep_sup;
    sr_conn_ctx_t *conn;
    const struct ly_ctx *ly_ctx;
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

/**
 * @brief Add oper data for a specific subscription into operational data.
 *
 * @param[in] sub Subscription whose information to add.
 * @param[in] root Root node to add to.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_oper_sub_add(struct np2srv_ntf_sub *sub, struct lyd_node *root)
{
    struct lyd_node *list, *receiver;
    struct nc_session *ncs;
    char buf[26], *path = NULL;
    uint32_t i, excluded_count, filtered_out;

    /* subscription with id */
    sprintf(buf, "%" PRIu32, sub->sub_ids[0].sub_id);
    if (lyd_new_list(root, NULL, "subscription", 0, &list, buf)) {
        goto error;
    }

    /* filter */
    if (sub->stream_filter_name) {
        if (lyd_new_term(list, NULL, "stream-filter-name", sub->stream_filter_name, 0, NULL)) {
            goto error;
        }
    } else if (sub->stream_subtree_filter) {
        if (np_ly_schema_dup_r(list, sub->stream_subtree_filter, 1)) {
            goto error;
        }
    } else if (sub->stream_xpath_filter) {
        if (lyd_new_term(list, NULL, "stream-xpath-filter", sub->stream_xpath_filter, 0, NULL)) {
            goto error;
        }
    }

    /* stream */
    if (lyd_new_term(list, NULL, "stream", sub->stream, 0, NULL)) {
        goto error;
    }

    /* replay-start-time */
    if (sub->replay_start_time) {
        nc_time2datetime(sub->replay_start_time, NULL, buf);
        if (lyd_new_term(list, NULL, "replay-start-time", buf, 0, NULL)) {
            goto error;
        }
    }

    /* stop-time */
    if (sub->stop_time) {
        nc_time2datetime(sub->stop_time, NULL, buf);
        if (lyd_new_term(list, NULL, "stop-time", buf, 0, NULL)) {
            goto error;
        }
    }

    /* receivers */
    if (asprintf(&path, "receivers/receiver[name='NETCONF session %u']", sub->nc_id) == -1) {
        EMEM;
        goto error;
    }
    if (lyd_new_path(list, NULL, path, NULL, 0, &receiver)) {
        goto error;
    }
    receiver = lyd_child(receiver);
    free(path);
    path = NULL;

    /* sent-event-records, read from netconf-monitoring for the NETCONF session */
    ncs = np_get_nc_sess(sub->nc_id);
    sprintf(buf, "%u", ncm_session_get_notification(ncs));
    if (lyd_new_term(receiver, NULL, "sent-event-records", buf, 0, NULL)) {
        goto error;
    }

    /* excluded-event-records */
    excluded_count = 0;
    for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
        /* get filter-out count for the subscription */
        if (sr_event_notif_sub_get_info(np2srv.sr_notif_sub, sub->sub_ids[i].sub_id, NULL, NULL, NULL, NULL,
                &filtered_out)) {
            goto error;
        }
        excluded_count += filtered_out;

        /* add denied */
        excluded_count += sub->sub_ids[i].denied_count;
    }
    sprintf(buf, "%u", excluded_count);
    if (lyd_new_term(receiver, NULL, "excluded-event-records", buf, 0, NULL)) {
        goto error;
    }

    /* state */
    if (lyd_new_term(receiver, NULL, "state", "active", 0, NULL)) {
        goto error;
    }

    free(path);
    return 0;

error:
    free(path);
    return -1;
}

int
np2srv_sub_ntf_subscriptions_oper_cb(sr_session_ctx_t *session, const char *UNUSED(module_name), const char *UNUSED(path),
        const char *UNUSED(request_xpath), uint32_t UNUSED(request_id), struct lyd_node **parent, void *UNUSED(private_data))
{
    struct lyd_node *root;
    const struct ly_ctx *ly_ctx;
    uint32_t i;

    ly_ctx = sr_get_context(sr_session_get_connection(session));

    /* LOCK */
    pthread_mutex_lock(&ntf_subs.lock);

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscriptions", NULL, 0, &root)) {
        goto error;
    }

    /* go through all the subscriptions */
    for (i = 0; i < ntf_subs.count; ++i) {
        if (sub_ntf_oper_sub_add(&ntf_subs.subs[i], root)) {
            goto error;
        }
    }

    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);

    *parent = root;
    return SR_ERR_OK;

error:
    /* UNLOCK */
    pthread_mutex_unlock(&ntf_subs.lock);

    lyd_free_tree(root);
    return SR_ERR_INTERNAL;
}
