/**
 * @file subscribed_notifications.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications sub-ntf callbacks
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

#include "subscribed_notifications.h"

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
#include "netconf_subscribed_notifications.h"

/**
 * @brief Remove this SR subscription and check whether it was the last.
 *
 * @param[in,out] sub Subscription structure to use.
 * @param[in] sub_id SR sub ID to delete.
 * @return Whether it was the last SR subscription or not.
 */
static int
sub_ntf_del_sr_sub_is_last(struct np2srv_sub_ntf *sub, uint32_t sub_id)
{
    uint32_t i, count;
    int last = 0;

    /* find SR subscription */
    for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
        if (sub->sub_ids[i] == sub_id) {
            break;
        }
    }
    if (i == ATOMIC_LOAD_RELAXED(sub->sub_id_count)) {
        EINT;
        return 0;
    }

    /* remove it */
    ATOMIC_DEC_RELAXED(sub->sub_id_count);
    count = ATOMIC_LOAD_RELAXED(sub->sub_id_count);
    if (i < count) {
        memmove(sub->sub_ids + i, sub->sub_ids + i + 1, (count - i) * sizeof *sub->sub_ids);
    } else if (!count) {
        free(sub->sub_ids);
        sub->sub_ids = NULL;

        last = 1;
    }

    return last;
}

/**
 * @brief New notification callback used for notifications received on subscription made by \<establish-subscription\> RPC.
 */
static void
np2srv_rpc_establish_sub_ntf_cb(sr_session_ctx_t *UNUSED(session), uint32_t sub_id, const sr_ev_notif_type_t notif_type,
        const struct lyd_node *notif, struct timespec *timestamp, void *private_data)
{
    struct np_sub_ntf_arg *arg = private_data;
    struct lyd_node *ly_ntf;
    const struct ly_ctx *ly_ctx;
    struct np2srv_sub_ntf *sub;
    char buf[26];
    uint32_t i;

    if (notif) {
        /* find the top-level node */
        while (notif->parent) {
            notif = lyd_parent(notif);
        }
    }

    switch (notif_type) {
    case SR_EV_NOTIF_REPLAY_COMPLETE:
        if (ATOMIC_INC_RELAXED(arg->replay_complete_count) + 1 < arg->sr_sub_count) {
            /* wait until all the subscriptions finish their replay */
            break;
        }

        /* context lock is held while the callback is executing */
        ly_ctx = sr_acquire_context(np2srv.sr_conn);
        sr_release_context(np2srv.sr_conn);

        sprintf(buf, "%" PRIu32, arg->nc_sub_id);
        lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:replay-completed/id", buf, 0, &ly_ntf);

        if (arg->ncs) {
            sub_ntf_send_notif(arg->ncs, arg->nc_sub_id, *timestamp, &ly_ntf, 1);

            /* now send all the buffered notifications */
            for (i = 0; i < arg->rt_notif_count; ++i) {
                np_ntf_send(arg->ncs, &arg->rt_notifs[i].timestamp, &arg->rt_notifs[i].notif, 1);
            }
        } else {
            csn_send_notif(&arg->recv_info, arg->nc_sub_id, *timestamp, &ly_ntf, 1);

            /* now send all the buffered notifications */
            for (i = 0; i < arg->rt_notif_count; ++i) {
                csn_send_notif(&arg->recv_info, arg->nc_sub_id, arg->rt_notifs[i].timestamp,
                        &arg->rt_notifs[i].notif, 1);
            }
        }

        break;
    case SR_EV_NOTIF_TERMINATED:
    case SR_EV_NOTIF_STOP_TIME:
        /* WRITE LOCK on sub */
        sub = sub_ntf_find_lock(arg->nc_sub_id, sub_id, 1);
        if (!sub) {
            EINT;
            break;
        }

        if (sub_ntf_del_sr_sub_is_last(sub, sub_id)) {
            /* last SR subscription terminated, remove the whole NC subscription */
            sub_ntf_terminate_sub(sub, arg->ncs);
        }

        /* UNLOCK */
        sub_ntf_unlock(sub_id);

        /* subscription-terminated notif was already sent */
        break;
    case SR_EV_NOTIF_REALTIME:
        if (ATOMIC_LOAD_RELAXED(arg->replay_complete_count) < arg->sr_sub_count) {
            /* realtime notification received before replay has been completed, store in buffer */
            np_ntf_add_dup(notif, timestamp, &arg->rt_notifs, &arg->rt_notif_count);
        } else {
            /* send the realtime notification */
            if (arg->ncs) {
                sub_ntf_send_notif(arg->ncs, arg->nc_sub_id, *timestamp, (struct lyd_node **)&notif, 0);
            } else {
                csn_send_notif(&arg->recv_info, arg->nc_sub_id, *timestamp,
                        (struct lyd_node **)&notif, 0);
            }
        }
        break;
    case SR_EV_NOTIF_REPLAY:
        /* send the replayed notification */
        if (arg->ncs) {
            sub_ntf_send_notif(arg->ncs, arg->nc_sub_id, *timestamp, (struct lyd_node **)&notif, 0);
        } else {
            csn_send_notif(&arg->recv_info, arg->nc_sub_id, *timestamp,
                    (struct lyd_node **)&notif, 0);
        }
        break;
    case SR_EV_NOTIF_MODIFIED:
        /* handled elsewhere */
        break;
    case SR_EV_NOTIF_RESUMED:
    case SR_EV_NOTIF_SUSPENDED:
        /* should never be generated by the server */
        EINT;
        break;
    }
}

/**
 * @brief Create all sysrepo subscriptions for a single sub-ntf subscription.
 *
 * @param[in] user_sess User session to use for sysrepo calls.
 * @param[in] stream Stream to subscribe to.
 * @param[in] xpath Filter to use.
 * @param[in] start Replay start time.
 * @param[in] stop Subscription stop time.
 * @param[in] cb_arg Callback argument to set when subscribing.
 * @param[in] ev_sess Event session for reporting errors.
 * @param[out] sub_ids Generated sysrepo subscription IDs, the first one is used as sub-ntf subscription ID.
 * @param[out] sub_id_count Number of @p sub_ids.
 * @param[in] sr_sub_ctx is the sysrepo context.
 * @return Sysrepo error value.
 */
static int
sub_ntf_sr_subscribe(sr_session_ctx_t *user_sess, const char *stream, const char *xpath, const struct timespec *start,
        const struct timespec *stop, struct np_sub_ntf_arg *cb_arg, sr_session_ctx_t *ev_sess, uint32_t **sub_ids,
        uint32_t *sub_id_count, sr_subscription_ctx_t **sr_sub_ctx)
{
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    int rc = SR_ERR_OK, suspended = 0;
    const sr_error_info_t *err_info;
    struct ly_set mod_set = {0};
    uint32_t idx;

    ly_ctx = sr_session_acquire_context(user_sess);

    *sub_ids = NULL;
    *sub_id_count = 0;

    if (!strcmp(stream, "NETCONF")) {
        /* collect all modules with notifications */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            if (!ly_mod->implemented) {
                continue;
            }

            if (np_ly_mod_has_notif(ly_mod)) {
                if (ly_set_add(&mod_set, (void *)ly_mod, 1, NULL)) {
                    EINT;
                    rc = SR_ERR_INTERNAL;
                    goto error;
                }
            }
        }

        /* allocate all sub IDs */
        *sub_ids = malloc(mod_set.count * sizeof **sub_ids);
        if (!*sub_ids) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto error;
        }

        /* set SR sub count and replayed count */
        cb_arg->sr_sub_count = mod_set.count;
        cb_arg->replay_complete_count = start ? 0 : cb_arg->sr_sub_count;

        /* subscribe to all the modules */
        for (idx = 0; idx < mod_set.count; ++idx) {
            ly_mod = mod_set.objs[idx];

            /* subscribe to the module */
            rc = sr_notif_subscribe_tree(user_sess, ly_mod->name, xpath, start, stop, np2srv_rpc_establish_sub_ntf_cb,
                    cb_arg, SR_SUBSCR_THREAD_SUSPEND, sr_sub_ctx);
            if (rc != SR_ERR_OK) {
                sr_session_get_error(user_sess, &err_info);
                sr_session_set_error_message(ev_sess, err_info->err[0].message);
                goto error;
            }
            suspended = 1;

            /* add new sub ID */
            (*sub_ids)[*sub_id_count] = sr_subscription_get_last_sub_id(*sr_sub_ctx);
            ++(*sub_id_count);
        }
    } else {
        /* allocate a new single sub ID */
        *sub_ids = malloc(sizeof **sub_ids);
        if (!*sub_ids) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto error;
        }

        /* set SR sub count and replayed count */
        cb_arg->sr_sub_count = 1;
        cb_arg->replay_complete_count = start ? 0 : 1;

        /* subscribe to the specific module (stream) */
        rc = sr_notif_subscribe_tree(user_sess, stream, xpath, start, stop, np2srv_rpc_establish_sub_ntf_cb,
                cb_arg, SR_SUBSCR_THREAD_SUSPEND, sr_sub_ctx);
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(ev_sess, err_info->err[0].message);
            goto error;
        }
        suspended = 1;

        /* add new sub ID */
        (*sub_ids)[*sub_id_count] = sr_subscription_get_last_sub_id(*sr_sub_ctx);
        ++(*sub_id_count);
    }

    goto cleanup;

error:
    for (idx = 0; idx < *sub_id_count; ++idx) {
        sr_unsubscribe_sub(*sr_sub_ctx, (*sub_ids)[idx]);
    }
    if (suspended) {
        /* resume subscription thread */
        sr_subscription_thread_resume(*sr_sub_ctx);
    }
    free(*sub_ids);
    *sub_ids = NULL;
    *sub_id_count = 0;

cleanup:
    sr_session_release_context(user_sess);
    ly_set_erase(&mod_set, NULL);
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
    struct lyd_node *node = NULL;
    sr_data_t *subtree = NULL;
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
            *stream_filter_name = lyd_get_value(node);
        }
    } else if (!strcmp(node->schema->name, "stream-subtree-filter")) {
        if (stream_subtree_filter) {
            *stream_subtree_filter = node;
        }
    } else {
        assert(!strcmp(node->schema->name, "stream-xpath-filter"));
        if (stream_xpath_filter) {
            *stream_xpath_filter = lyd_get_value(node);
        }
    }

    if (!strcmp(node->schema->name, "stream-filter-name")) {
        /* first get this filter from sysrepo */
        if (asprintf(&str, "/ietf-subscribed-notifications:filters/stream-filter[name='%s']", lyd_get_value(node)) == -1) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }

        sr_session_switch_ds(user_sess, SR_DS_OPERATIONAL);
        rc = sr_get_subtree(user_sess, str, 0, &subtree);
        free(str);
        if (rc != SR_ERR_OK) {
            sr_session_get_error(user_sess, &err_info);
            sr_session_set_error_message(ev_sess, err_info->err[0].message);
            goto cleanup;
        }

        if (!lyd_child(subtree->tree)->next) {
            ERR("Stream filter \"%s\" does not define any actual filter.", lyd_get_value(node));
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        node = lyd_child(subtree->tree)->next;
    }

    if (!strcmp(node->schema->name, "stream-subtree-filter")) {
        /* subtree */
        if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
            if ((rc = op_filter_create_subtree(((struct lyd_node_any *)node)->value.tree, ev_sess, &filter))) {
                goto cleanup;
            }
            if ((rc = op_filter_filter2xpath(&filter, xpath))) {
                goto cleanup;
            }
        }
    } else {
        /* xpath */
        assert(!strcmp(node->schema->name, "stream-xpath-filter"));
        if (strlen(lyd_get_value(node))) {
            *xpath = strdup(lyd_get_value(node));
            if (!*xpath) {
                EMEM;
                rc = SR_ERR_NO_MEMORY;
                goto cleanup;
            }
        }
    }

cleanup:
    sr_release_data(subtree);
    op_filter_erase(&filter);
    return rc;
}

/**
 * @brief Timer callback for stopping configured yang-push subscriptions.
 */
static void
sub_ntf_stop_timer_cb(union sigval sval)
{
    struct np_sub_ntf_arg *arg = sval.sival_ptr;
    struct np2srv_sub_ntf *sub;

    /* WRITE LOCK */
    sub = sub_ntf_find_lock(arg->nc_sub_id, 0, 1);
    if (!sub) {
        return;
    }

    arg->sn_data->state = SUB_CFG_STATE_CONCLUDED;

    /* terminate the subscription */
    sub_ntf_terminate_sub(sub, NULL);

    /* UNLOCK */
    sub_ntf_unlock(0);
}

int
sub_ntf_rpc_establish_sub_prepare(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct np2srv_sub_ntf *sub)
{
    struct lyd_node *node, *stream_subtree_filter = NULL;
    struct nc_session *ncs;
    struct np2_user_sess *user_sess = NULL;
    struct sub_ntf_data *sn_data = NULL;
    struct timespec stop, cur_ts;
    const char *stream, *stream_filter_name = NULL, *stream_xpath_filter = NULL;
    char *xp = NULL;
    struct timespec start = {0};
    uint32_t sub_id_count;
    int rc = SR_ERR_OK;
    sr_subscription_ctx_t **sr_sub_ctx;
    const char *local_address = NULL;
    const char *interface = NULL;
    sr_session_ctx_t *sess;

    if (sub->type == SUB_TYPE_DYN_SUB) {
        /* get the NETCONF session and user session */
        if ((rc = np_find_user_sess(ev_sess, __func__, &ncs, &user_sess))) {
            goto cleanup;
        }
        sess = user_sess->sess;
        sr_sub_ctx = &np2srv.sr_notif_sub;
    } else {
        /* SUB_TYPE_CFG_SUB */
        ncs = NULL;
        sess = np2srv.sr_sess_cfg;
        if (!lyd_find_path(rpc, "source-address", 0, &node)) {
            local_address = lyd_get_value(node);
        }

        /* interface */
        if (!lyd_find_path(rpc, "interface", 0, &node)) {
            interface = lyd_get_value(node);
        }

        sr_sub_ctx = &np2srv.sr_cfg_notif_sub;
    }

    /* filter, join all into one xpath */
    rc = sub_ntf_rpc_filter2xpath(sess, rpc, ev_sess, &xp, &stream_filter_name, &stream_subtree_filter,
            &stream_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* stream */
    lyd_find_path(rpc, "stream", 0, &node);
    stream = lyd_get_value(node);

    /* replay start time */
    if (!lyd_find_path(rpc, "replay-start-time", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &start);
    }

    stop = sub->stop_time;

    /* check parameters */
    cur_ts = np_gettimespec(1);
    if (start.tv_sec && (np_difftimespec(&start, &cur_ts) < 0)) {
        np_err_bad_element(ev_sess, "replay-start-time", "Specified \"replay-start-time\" is in future.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (!start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &cur_ts) > 0)) {
        np_err_bad_element(ev_sess, "stop-time", "Specified \"stop-time\" is in the past.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    } else if (start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &start) > 0)) {
        np_err_bad_element(ev_sess, "stop-time", "Specified \"stop-time\" is earlier than \"replay-start-time\".");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* allocate specific data */
    sub->data = sn_data = calloc(1, sizeof *sn_data);
    if (!sn_data) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    sn_data->stream_filter_name = stream_filter_name ? strdup(stream_filter_name) : NULL;
    if (stream_subtree_filter) {
        lyd_dup_single(stream_subtree_filter, NULL, 0, &sn_data->stream_subtree_filter);
    } else {
        sn_data->stream_subtree_filter = NULL;
    }
    sn_data->stream_xpath_filter = stream_xpath_filter ? strdup(stream_xpath_filter) : NULL;
    sn_data->stream = strdup(stream);

    if (local_address) {
        sn_data->cb_arg.recv_info.local_address = strdup(local_address);
    }

    if (interface) {
        sn_data->cb_arg.recv_info.interface = strdup(interface);
    }

    sn_data->replay_start_time = start;
    if ((stream_filter_name && !sn_data->stream_filter_name) || (stream_subtree_filter && !sn_data->stream_subtree_filter) ||
            (stream_xpath_filter && !sn_data->stream_xpath_filter) || !sn_data->stream) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /* fill cb argument */
    /* NETCONF session could not be accessed from the callback normally because it may not be in nc_ps anymore */
    sn_data->cb_arg.ncs = ncs;
    /* no API to get these data in the callback, so they are accessible directly this way, the lock must always be held */
    sn_data->cb_arg.sn_data = sn_data;
    sn_data->cb_arg.nc_sub_id = sub->nc_sub_id;

    if (!ncs && sub->stop_time.tv_sec) {
        /* create stop timer for SUB_TYPE_CFG_SUB */
        rc = sub_ntf_create_timer(sub_ntf_stop_timer_cb,
                &sn_data->cb_arg, 1,
                &sn_data->stop_timer);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    /* subscribe to sysrepo notifications, cb_arg is managed (freed) by the callback */
    rc = sub_ntf_sr_subscribe(sess, stream, xp, start.tv_sec ? &start : NULL,
            sub->stop_time.tv_sec ? &sub->stop_time : NULL, &sn_data->cb_arg, ev_sess, &sub->sub_ids, &sub_id_count,
            sr_sub_ctx);
    ATOMIC_STORE_RELAXED(sub->sub_id_count, sub_id_count);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (!ncs) {
        sn_data->state = SUB_CFG_STATE_VALID;
    }

cleanup:
    free(xp);
    np_release_user_sess(user_sess);
    if (rc) {
        sub_ntf_data_destroy(sn_data);
    }
    return rc;
}

int
sub_ntf_rpc_establish_sub_start_async(sr_session_ctx_t *UNUSED(ev_sess), struct np2srv_sub_ntf *sub)
{
    /* resume subscription thread */
    if (sub->type == SUB_TYPE_DYN_SUB) {
        sr_subscription_thread_resume(np2srv.sr_notif_sub);
    } else {
        sr_subscription_thread_resume(np2srv.sr_cfg_notif_sub);
    }

    return 0;
}

int
sub_ntf_rpc_modify_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct timespec stop,
        struct np2srv_sub_ntf *sub)
{
    struct lyd_node *stream_subtree_filter = NULL;
    struct np2_user_sess *user_sess = NULL;
    struct sub_ntf_data *sn_data;
    struct lyd_node *node;
    const char *cur_xp, *stream_filter_name = NULL, *stream_xpath_filter = NULL;
    char *xp = NULL;
    struct timespec cur_stop;
    int rc = SR_ERR_OK;
    uint32_t i;

    /* get the user session */
    if ((rc = np_find_user_sess(ev_sess, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* datastore */
    if (!lyd_find_path(rpc, "ietf-yang-push:datastore", 0, &node)) {
        sr_session_set_error_message(ev_sess, "Subscription with ID %" PRIu32 " is not yang-push but \"datastore\""
                " is set.", sub->nc_sub_id);
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    /* filter, join all into one xpath */
    rc = sub_ntf_rpc_filter2xpath(user_sess->sess, rpc, ev_sess, &xp, &stream_filter_name, &stream_subtree_filter,
            &stream_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* learn the current filter */
    rc = sr_notif_sub_get_info(np2srv.sr_notif_sub, sub->sub_ids[0], NULL, &cur_xp, NULL, &cur_stop, NULL);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (!cur_xp || strcmp(cur_xp, xp)) {
        /* update the filter */
        for (i = 0; i < sub->sub_id_count; ++i) {
            /* "pass" the lock to the callback */
            sub_ntf_cb_lock_pass(sub->sub_ids[i]);
            rc = sr_notif_sub_modify_xpath(np2srv.sr_notif_sub, sub->sub_ids[i], xp);
            sub_ntf_cb_lock_clear(sub->sub_ids[i]);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }
    if (np_difftimespec(&cur_stop, &stop) != 0) {
        /* update stop time */
        for (i = 0; i < sub->sub_id_count; ++i) {
            /* "pass" the lock to the callback */
            sub_ntf_cb_lock_pass(sub->sub_ids[i]);
            rc = sr_notif_sub_modify_stop_time(np2srv.sr_notif_sub, sub->sub_ids[i], stop.tv_sec ? &stop : NULL);
            sub_ntf_cb_lock_clear(sub->sub_ids[i]);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }

    /* update our type-specific data */
    sn_data = sub->data;
    free(sn_data->stream_filter_name);
    lyd_free_tree(sn_data->stream_subtree_filter);
    free(sn_data->stream_xpath_filter);

    sn_data->stream_filter_name = stream_filter_name ? strdup(stream_filter_name) : NULL;
    if (stream_subtree_filter) {
        lyd_dup_single(stream_subtree_filter, NULL, 0, &sn_data->stream_subtree_filter);
    } else {
        sn_data->stream_subtree_filter = NULL;
    }
    sn_data->stream_xpath_filter = stream_xpath_filter ? strdup(stream_xpath_filter) : NULL;
    if ((stream_filter_name && !sn_data->stream_filter_name) || (stream_subtree_filter && !sn_data->stream_subtree_filter) ||
            (stream_xpath_filter && !sn_data->stream_xpath_filter)) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    free(xp);
    np_release_user_sess(user_sess);
    return rc;
}

int
sub_ntf_notif_modified_append_data(struct lyd_node *ntf, void *data)
{
    struct sub_ntf_data *sn_data = data;
    struct lyd_node_any *any;

    if (sn_data->stream_filter_name) {
        /* stream-filter-name */
        if (lyd_new_term(ntf, NULL, "stream-filter-name", sn_data->stream_filter_name, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (sn_data->stream_subtree_filter) {
        /* stream-subtree-filter */
        any = (struct lyd_node_any *)sn_data->stream_subtree_filter;
        if (lyd_new_any(ntf, NULL, "stream-subtree-filter", any->value.tree, 0, any->value_type, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (sn_data->stream_xpath_filter) {
        /* stream-xpath-filter */
        if (lyd_new_term(ntf, NULL, "stream-xpath-filter", sn_data->stream_xpath_filter, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Stream-filter-name match callback.
 */
static int
sub_ntf_stream_filter_match_cb(struct np2srv_sub_ntf *sub, const void *match_data)
{
    const char *stream_filter_name = match_data;
    struct sub_ntf_data *sn_data = sub->data;

    if (sub->type != SUB_TYPE_DYN_SUB) {
        return 0;
    }

    if (sn_data->stream_filter_name && !strcmp(sn_data->stream_filter_name, stream_filter_name)) {
        return 1;
    }
    return 0;
}

int
sub_ntf_config_filters(const struct lyd_node *filter, sr_change_oper_t op)
{
    int rc = SR_ERR_OK, r;
    struct np2srv_sub_ntf *sub;
    struct nc_session *ncs;
    char *xp;
    uint32_t i;

    if (op == SR_OP_MODIFIED) {
        /* construct the new filter */
        r = sub_ntf_rpc_filter2xpath(NULL, filter, NULL, &xp, NULL, NULL, NULL);
        if (r != SR_ERR_OK) {
            return r;
        }

        /* update all the relevant subscriptions */
        sub = NULL;
        while ((sub = sub_ntf_find_next(sub, sub_ntf_stream_filter_match_cb, lyd_get_value(lyd_child(filter))))) {
            /* modify the filter of the subscription(s) */
            for (i = 0; i < sub->sub_id_count; ++i) {
                /* callback ignores this event */
                r = sr_notif_sub_modify_xpath(np2srv.sr_notif_sub, sub->sub_ids[i], xp);
                if (r != SR_ERR_OK) {
                    rc = r;
                }
            }

            /* send subscription-modified notif */
            r = sub_ntf_send_notif_modified(sub);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }

        free(xp);
    } else if (op == SR_OP_DELETED) {
        /* update all the relevant subscriptions */
        sub = NULL;
        while ((sub = sub_ntf_find_next(sub, sub_ntf_stream_filter_match_cb, lyd_get_value(lyd_child(filter))))) {
            /* get NETCONF session */
            if ((rc = np_get_nc_sess_by_id(0, sub->nc_id, __func__, &ncs))) {
                return rc;
            }

            /* terminate the subscription with the specific term reason */
            sub->term_reason = "ietf-subscribed-notifications:filter-unavailable";
            r = sub_ntf_terminate_sub(sub, ncs);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }
    }

    return rc;
}

int
sub_ntf_oper_subscription(struct lyd_node *subscription, void *data)
{
    struct sub_ntf_data *sn_data = data;
    struct lyd_node_any *any;
    char *buf;

    if (sn_data->stream_filter_name) {
        /* stream-filter-name */
        if (lyd_new_term(subscription, NULL, "stream-filter-name", sn_data->stream_filter_name, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (sn_data->stream_subtree_filter) {
        /* stream-subtree-filter */
        any = (struct lyd_node_any *)sn_data->stream_subtree_filter;
        if (lyd_new_any(subscription, NULL, "stream-subtree-filter", any->value.tree, 0, any->value_type, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (sn_data->stream_xpath_filter) {
        /* stream-xpath-filter */
        if (lyd_new_term(subscription, NULL, "stream-xpath-filter", sn_data->stream_xpath_filter, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    /* stream */
    if (lyd_new_term(subscription, NULL, "stream", sn_data->stream, 0, NULL)) {
        return SR_ERR_LY;
    }

    /* replay-start-time */
    if (sn_data->replay_start_time.tv_sec) {
        ly_time_ts2str(&sn_data->replay_start_time, &buf);
        if (lyd_new_term(subscription, NULL, "replay-start-time", buf, 0, NULL)) {
            free(buf);
            return SR_ERR_LY;
        }
        free(buf);
    }

    if (!sn_data->cb_arg.ncs) {
        /* configured-subscription-state of SUB_TYPE_CFG_SUB */
        switch (sn_data->state) {
        case SUB_CFG_STATE_CONCLUDED:
            buf = "concluded";
            break;
        default:
            buf = "valid";
            break;
        }

        if (lyd_new_term(subscription, NULL, "configured-subscription-state", buf, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    return SR_ERR_OK;
}

uint32_t
sub_ntf_oper_receiver_excluded(struct np2srv_sub_ntf *sub)
{
    uint32_t i, excluded_count = 0, filtered_out;
    int r;

    /* excluded-event-records */
    for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
        /* get filter-out count for the subscription */
        if (sub->type == SUB_TYPE_DYN_SUB) {
            r = sr_notif_sub_get_info(np2srv.sr_notif_sub, sub->sub_ids[i], NULL, NULL, NULL, NULL, &filtered_out);
        } else {
            r = sr_notif_sub_get_info(np2srv.sr_cfg_notif_sub, sub->sub_ids[i], NULL, NULL, NULL, NULL, &filtered_out);
        }
        if (r != SR_ERR_OK) {
            return r;
        }
        excluded_count += filtered_out;
    }

    return excluded_count;
}

void
sub_ntf_terminate_async(void *data)
{
    struct sub_ntf_data *sn_data = data;
    struct itimerspec tspec = {0};
    const struct ly_ctx *ly_ctx;
    struct lyd_node *ly_ntf;
    char buf[26];

    if (!sn_data->stop_timer) {
        return;
    }

    timer_settime(sn_data->stop_timer, TIMER_ABSTIME, &tspec, NULL);

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    sr_release_context(np2srv.sr_conn);

    sprintf(buf, "%" PRIu32, sn_data->cb_arg.nc_sub_id);
    lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-completed/id",
            buf, 0, &ly_ntf);
    csn_send_notif(&sn_data->cb_arg.recv_info, sn_data->cb_arg.nc_sub_id,
            np_gettimespec(1), &ly_ntf, 1);
}

void
sub_ntf_data_destroy(void *data)
{
    struct sub_ntf_data *sn_data = data;
    struct csn_receiver_info *recv_info;
    uint32_t i;

    if (!sn_data) {
        return;
    }

    recv_info = &sn_data->cb_arg.recv_info;

    free(sn_data->stream_filter_name);
    lyd_free_tree(sn_data->stream_subtree_filter);
    free(sn_data->stream_xpath_filter);
    free(sn_data->stream);
    for (i = 0; i < sn_data->cb_arg.rt_notif_count; ++i) {
        lyd_free_tree(sn_data->cb_arg.rt_notifs[i].notif);
    }

    if (sn_data->stop_timer) {
        timer_delete(sn_data->stop_timer);
    }

    csn_receiver_info_destroy(recv_info);

    free(sn_data);
}

struct csn_receiver_info *
sub_ntf_receivers_info_get(void *data)
{
    struct sub_ntf_data *sn_data = data;

    if (!sn_data) {
        return NULL;
    }

    return &sn_data->cb_arg.recv_info;
}
