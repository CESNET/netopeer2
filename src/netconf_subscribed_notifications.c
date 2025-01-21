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

#include "netconf_subscribed_notifications.h"

#include <assert.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/subscribed_notifications.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "netconf_monitoring.h"

static struct np_sub_ntf_state state = {
    .lock = PTHREAD_RWLOCK_INITIALIZER
};

#define STATE_RLOCK { int _r; if ((_r = pthread_rwlock_rdlock(&state.lock))) ELOCK(_r); }
#define STATE_WLOCK { int _r; if ((_r = pthread_rwlock_wrlock(&state.lock))) ELOCK(_r); }
#define STATE_UNLOCK { int _r; if ((_r = pthread_rwlock_unlock(&state.lock))) EUNLOCK(_r); }

/**
 * @brief Print and set error for a SR event session.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] sr_err SR error code.
 * @param[in] fmt Message format.
 * @param[in] ... Message arguments.
 * @return Server reply structure.
 */
static struct nc_server_reply *
sub_ntf_error(const struct ly_ctx *ly_ctx, int sr_err, const char *fmt, ...)
{
    struct lyd_node *e;
    char *msg;
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vasprintf(&msg, fmt, ap);
    va_end(ap);

    if (r == -1) {
        EMEM;
        return NULL;
    }

    ERR("%s", msg);

    switch (sr_err) {
    case SR_ERR_INVAL_ARG:
        e = nc_err(ly_ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
        break;
    case SR_ERR_OPERATION_FAILED:
        e = nc_err(ly_ctx, NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        break;
    }
    nc_err_set_msg(e, msg, NULL);
    free(msg);

    return nc_server_reply_err(e);
}

/**
 * @brief Print and set no-such-subscription error for a SR event session.
 *
 * @param[in] ly_ctx Context to use.
 * @param[in] fmt Message format.
 * @param[in] ... Message arguments.
 * @return Server reply structure.
 */
static struct nc_server_reply *
sub_ntf_error_no_sub(const struct ly_ctx *ly_ctx, const char *fmt, ...)
{
    struct lyd_node *e;
    char *msg;
    va_list ap;
    int r;

    va_start(ap, fmt);
    r = vasprintf(&msg, fmt, ap);
    va_end(ap);

    if (r == -1) {
        EMEM;
        return NULL;
    }

    ERR("%s", msg);

    e = nc_err(ly_ctx, NC_ERR_INVALID_VALUE, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, msg, NULL);
    nc_err_set_app_tag(e, "ietf-subscribed-notifications:no-such-subscription");
    free(msg);

    return nc_server_reply_err(e);
}

/**
 * @brief Delete a subscription.
 *
 * @param[in] sub_id Subscription ID of the subscription to delete.
 * @return Sysrepo error value.
 */
static int
sub_ntf_del(uint32_t sub_id)
{
    struct np2srv_sub_ntf *sub = NULL;
    uint32_t i;

    /* find the subscription */
    for (i = 0; i < state.count; ++i) {
        if (state.subs[i].sub_id == sub_id) {
            sub = &state.subs[i];
            break;
        }
    }
    if (!sub) {
        return SR_ERR_NOT_FOUND;
    }

    /* free members */
    free(sub->filter_name);
    lyd_free_siblings(sub->subtree_filter);
    free(sub->xpath_filter);
    free(sub->cb_arg);

    /* adjust the global array */
    --state.count;
    if (i < state.count) {
        memmove(sub, sub + 1, (state.count - i) * sizeof *state.subs);
    } else if (!state.count) {
        free(state.subs);
        state.subs = NULL;
    }

    return SR_ERR_OK;
}

/**
 * @brief Sysrepo notification dispatch callback.
 */
static void
np2srv_srsn_notif_cb(const struct lyd_node *notif, const struct timespec *timestamp, void *cb_data)
{
    struct np_sub_ntf_arg *arg = cb_data;
    struct nc_session *ncs;
    struct nc_server_notif *nc_ntf = NULL;
    NC_MSG_TYPE msg_type;
    char *datetime = NULL;

    /* remember the NC session in case the subscription is removed */
    ncs = arg->ncs;

    if (!strcmp(LYD_NAME(notif), "subscription-terminated") &&
            !strcmp(notif->schema->module->name, "ietf-subscribed-notifications")) {
        /* WRITE LOCK */
        STATE_WLOCK;

        /* subscription has terminated, free it */
        sub_ntf_del(arg->sub_id);

        /* UNLOCK */
        STATE_UNLOCK;
    }

    if (nc_session_get_status(ncs) != NC_STATUS_RUNNING) {
        /* is being closed */
        goto cleanup;
    }

    /* create the notification object */
    ly_time_ts2str(timestamp, &datetime);
    nc_ntf = nc_server_notif_new((struct lyd_node *)notif, datetime, NC_PARAMTYPE_CONST);

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        ERR("Sending a notification to session %d %s.", nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ?
                "failed" : "timed out");
        goto cleanup;
    }

    /* NETCONF monitoring notification counter */
    ncm_session_notification(ncs);

cleanup:
    free(datetime);
    nc_server_notif_free(nc_ntf);
}

/**
 * @brief Add a subscription and add into dispatched notifications.
 *
 * @param[in] ly_ctx Context for errors.
 * @param[in] ncs NETCONF session.
 * @param[in] sub_id SRSN ID.
 * @param[in] filter_name Subsription filter name, if any.
 * @param[in] subtree_filter Subscription subtree filter, if any.
 * @param[in] xpath_filter Subscription XPath filter, if any.
 * @param[in] is_yp Whether it is a yang-push subscription or not.
 * @param[in] fd Subscription FD to read from.
 * @return Error reply on error, NULL on success.
 */
static struct nc_server_reply *
sub_ntf_add(const struct ly_ctx *ly_ctx, struct nc_session *ncs, uint32_t sub_id, const char *filter_name,
        const struct lyd_node *subtree_filter, const char *xpath_filter, int is_yp, int fd)
{
    struct nc_server_reply *reply = NULL;
    struct np2srv_sub_ntf *sub;
    void *mem;

    /* add into subscriptions */
    mem = realloc(state.subs, (state.count + 1) * sizeof *state.subs);
    if (!mem) {
        reply = np_reply_err_op_failed(NULL, ly_ctx, "Memory allocation failed.");
        goto cleanup;
    }
    state.subs = mem;
    sub = &state.subs[state.count];

    sub->nc_id = nc_session_get_id(ncs);
    sub->sub_id = sub_id;
    sub->filter_name = filter_name ? strdup(filter_name) : NULL;
    if (subtree_filter) {
        if (lyd_dup_single(subtree_filter, NULL, 0, &sub->subtree_filter)) {
            reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            goto cleanup;
        }
    } else {
        sub->subtree_filter = NULL;
    }
    sub->xpath_filter = xpath_filter ? strdup(xpath_filter) : NULL;
    sub->is_yp = is_yp;
    sub->terminated = 0;
    sub->cb_arg = malloc(sizeof *sub->cb_arg);
    if (!sub->cb_arg) {
        reply = np_reply_err_op_failed(NULL, ly_ctx, "Memory allocation failed.");
        goto cleanup;
    }
    sub->cb_arg->ncs = ncs;
    sub->cb_arg->sub_id = sub_id;

    ++state.count;

    /* add to dispatch */
    if (srsn_read_dispatch_add(fd, sub->cb_arg)) {
        reply = sub_ntf_error(ly_ctx, SR_ERR_OPERATION_FAILED, "Failed to add a FD to SR sub-ntf dispatch.");
        goto cleanup;
    }

cleanup:
    return reply;
}

void
np_sub_ntf_session_destroy(struct nc_session *ncs)
{
    uint32_t i = 0;

    /* WRITE LOCK */
    STATE_WLOCK;

    while (i < state.count) {
        if (state.subs[i].nc_id == nc_session_get_id(ncs)) {
            /* terminate the subscription (without a notification being sent, so remove it manually) */
            srsn_terminate(state.subs[i].sub_id, NULL);
            sub_ntf_del(state.subs[i].sub_id);
        } else {
            /* skip */
            ++i;
        }
    }

    /* UNLOCK */
    STATE_UNLOCK;
}

/**
 * @brief Get the filter specification from an RPC.
 *
 * @param[in] rpc Parent of the filter nodes.
 * @param[in] filter_name_str Name of @p filter_name node.
 * @param[out] filter_name Node value, if this filter was present.
 * @param[in] subtree_filter_str Name of @p subtree_filter node.
 * @param[out] subtree_filter Duplicated node, if this filter was present.
 * @param[in] xpath_filter_str Name of @p xpath_filter node.
 * @param[out] xpath_filter Node value, if this filter was present.
 * @return Error reply on error, NULL on success.
 */
static struct nc_server_reply *
sub_ntf_rpc_get_filter(const struct lyd_node *rpc, const char *filter_name_str, const char **filter_name,
        const char *subtree_filter_str, const struct lyd_node **subtree_filter, const char *xpath_filter_str,
        const char **xpath_filter)
{
    struct lyd_node *node = NULL;
    struct ly_set *nodeset;
    char *str = NULL;
    const char *ptr;
    LY_ERR r;

    *filter_name = NULL;
    *subtree_filter = NULL;
    *xpath_filter = NULL;

    /* find the filter node */
    if (asprintf(&str, "%s | %s | %s", filter_name_str, subtree_filter_str, xpath_filter_str) == -1) {
        return np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Memory allocation failed.");
    }
    r = lyd_find_xpath(rpc, str, &nodeset);
    free(str);
    if (r) {
        return np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
    }
    if (nodeset->count) {
        node = nodeset->dnodes[0];
    }
    ly_set_free(nodeset, NULL);

    if (!node) {
        /* nothing to do */
        return NULL;
    }

    /* get schema node names */
    if ((ptr = strchr(filter_name_str, ':'))) {
        filter_name_str = ptr + 1;
    }
    if ((ptr = strchr(subtree_filter_str, ':'))) {
        subtree_filter_str = ptr + 1;
    }
    if ((ptr = strchr(xpath_filter_str, ':'))) {
        xpath_filter_str = ptr + 1;
    }

    /* remember the exact filter used */
    if (!strcmp(node->schema->name, filter_name_str)) {
        *filter_name = lyd_get_value(node);
    } else if (!strcmp(node->schema->name, subtree_filter_str)) {
        *subtree_filter = node;
    } else {
        assert(!strcmp(node->schema->name, xpath_filter_str));
        *xpath_filter = lyd_get_value(node);
    }

    return NULL;
}

/**
 * @brief Transform filter into a single XPath filter.
 *
 * @param[in] session Session to use.
 * @param[in] filter_name_search_fmt Format string with a single '%s' for @p filter_name to retrieve the actual filter
 * from sysrepo.
 * @param[in] filter_name Filter name value, if any.
 * @param[in] subtree_filter Subtree data node, if any.
 * @param[in] xpath_filter XPath filer value, if any.
 * @param[out] xpath Created XPath filter.
 * @param[in,out] err_reply If set, generates an error reply on error.
 * @param[in,out] err_sess If set, is used for storing error information.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
sub_ntf_filter2xpath(sr_session_ctx_t *session, const char *filter_name_search_fmt, const char *filter_name,
        const struct lyd_node *subtree_filter, const char *xpath_filter, char **xpath, struct nc_server_reply **err_reply,
        sr_session_ctx_t *err_sess)
{
    int rc = 0;
    sr_data_t *subtree = NULL;
    char *str = NULL;

    if (filter_name) {
        /* first get this filter from sysrepo */
        if (asprintf(&str, filter_name_search_fmt, filter_name) == -1) {
            if (err_reply) {
                *err_reply = np_reply_err_op_failed(session, NULL, "Memory allocation failed.");
            } else if (err_sess) {
                sr_session_set_error(err_sess, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
            }
            rc = -1;
            goto cleanup;
        }

        sr_session_switch_ds(session, SR_DS_OPERATIONAL);
        if (sr_get_subtree(session, str, 0, &subtree)) {
            if (err_reply) {
                *err_reply = np_reply_err_sr(session, "get");
            } else if (err_sess) {
                sr_session_dup_error(session, err_sess);
            }
            rc = -1;
            goto cleanup;
        }

        if (!lyd_child(subtree->tree)->next) {
            if (err_reply) {
                *err_reply = sub_ntf_error(LYD_CTX(subtree->tree), SR_ERR_INVAL_ARG,
                        "Filter \"%s\" does not define any actual filter.", filter_name);
            } else if (err_sess) {
                sr_session_set_error(err_sess, NULL, SR_ERR_INVAL_ARG, "Filter \"%s\" does not define any actual filter.",
                        filter_name);
            }
            rc = -1;
            goto cleanup;
        }
        if (lyd_child(subtree->tree)->next->schema->nodetype == LYS_ANYDATA) {
            /* subtree */
            subtree_filter = lyd_child(subtree->tree)->next;
        } else {
            /* xpath */
            assert(lyd_child(subtree->tree)->next->schema->nodetype == LYS_LEAF);
            xpath_filter = lyd_get_value(lyd_child(subtree->tree)->next);
        }
    }

    if (subtree_filter) {
        /* subtree */
        if (((struct lyd_node_any *)subtree_filter)->value_type == LYD_ANYDATA_DATATREE) {
            if (srsn_filter_subtree2xpath(((struct lyd_node_any *)subtree_filter)->value.tree, session, xpath)) {
                if (err_reply) {
                    *err_reply = np_reply_err_sr(session, "get");
                } else if (err_sess) {
                    sr_session_dup_error(session, err_sess);
                }
                rc = -1;
                goto cleanup;
            }
        }
    } else if (xpath_filter) {
        /* xpath */
        if (strlen(xpath_filter)) {
            *xpath = strdup(xpath_filter);
            if (!*xpath) {
                if (err_reply) {
                    *err_reply = np_reply_err_op_failed(session, NULL, "Memory allocation failed.");
                } else if (err_sess) {
                    sr_session_set_error(err_sess, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
                }
                rc = -1;
                goto cleanup;
            }
        }
    }

cleanup:
    free(str);
    sr_release_data(subtree);
    return rc;
}

/**
 * @brief Transform a string identity into a datastore.
 *
 * @param[in] str Identity.
 * @param[out] ds Datastore.
 * @return Sysrepo error value.
 */
static int
sub_ntf_ident2ds(const char *str, sr_datastore_t *ds)
{
    if (!strcmp(str, "ietf-datastores:startup")) {
        *ds = SR_DS_STARTUP;
        return SR_ERR_OK;
    } else if (!strcmp(str, "ietf-datastores:running")) {
        *ds = SR_DS_RUNNING;
        return SR_ERR_OK;
    } else if (!strcmp(str, "ietf-datastores:candidate")) {
        *ds = SR_DS_CANDIDATE;
        return SR_ERR_OK;
    } else if (!strcmp(str, "ietf-datastores:operational")) {
        *ds = SR_DS_OPERATIONAL;
        return SR_ERR_OK;
    } else if (!strcmp(str, "ietf-factory-default:factory-default")) {
        *ds = SR_DS_FACTORY_DEFAULT;
        return SR_ERR_OK;
    }

    return SR_ERR_UNSUPPORTED;
}

/**
 * @brief Transform string into a yang-push operation.
 *
 * @param[in] str Operation string.
 * @return yang-push operation.
 */
static srsn_yp_change_t
sub_ntf_str2op(const char *str)
{
    if (!strcmp(str, "create")) {
        return SRSN_YP_CHANGE_CREATE;
    } else if (!strcmp(str, "delete")) {
        return SRSN_YP_CHANGE_DELETE;
    } else if (!strcmp(str, "insert")) {
        return SRSN_YP_CHANGE_INSERT;
    } else if (!strcmp(str, "move")) {
        return SRSN_YP_CHANGE_MOVE;
    } else if (!strcmp(str, "replace")) {
        return SRSN_YP_CHANGE_REPLACE;
    }

    EINT;
    return SRSN_YP_CHANGE_INVALID;
}

struct nc_server_reply *
np2srv_rpc_establish_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    int fd = -1, sync_on_start, is_yp, excluded_change[SRSN_COUNT_YP_CHANGE] = {0};
    struct lyd_node *node, *node2, *output = NULL;
    const struct lyd_node *subtree_filter;
    struct ly_set *set;
    char id_str[11], *xp = NULL, *replay_start_str = NULL;
    srsn_yp_change_t chg;
    struct timespec cur_ts, stop = {0}, start = {0}, replay_start = {0}, anchor_time = {0};
    sr_datastore_t datastore;
    uint32_t i, sub_id, period, dampening_period;
    const char *stream, *filter_name, *xpath_filter;

    /* get lock to prevent SRSN subscriptions calling our notif callback before the subscription was added */

    /* WRITE LOCK */
    STATE_WLOCK;

    /* init dispatch params, can be called repeatedly */
    if (srsn_read_dispatch_init(np2srv.sr_conn, np2srv_srsn_notif_cb)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to initialize SRSN dispatch.");
        goto cleanup;
    }

    /* stop time */
    if (!lyd_find_path(rpc, "stop-time", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    /* encoding */
    if (!lyd_find_path(rpc, "encoding", 0, &node) &&
            strcmp(((struct lyd_node_term *)node)->value.ident->name, "encode-xml")) {
        reply = sub_ntf_error(LYD_CTX(rpc), SR_ERR_INVAL_ARG, "Unsupported encoding \"%s\".", lyd_get_value(node));
        goto cleanup;
    }

    if (!lyd_find_path(rpc, "stream", 0, &node)) {
        is_yp = 0;

        /* stream */
        stream = lyd_get_value(node);

        /* filter */
        if ((reply = sub_ntf_rpc_get_filter(rpc, "stream-filter-name", &filter_name, "stream-subtree-filter",
                &subtree_filter, "stream-xpath-filter", &xpath_filter))) {
            goto cleanup;
        }
        if (sub_ntf_filter2xpath(user_sess->sess, "/ietf-subscribed-notifications:filters/stream-filter[name='%s']",
                filter_name, subtree_filter, xpath_filter, &xp, &reply, NULL)) {
            goto cleanup;
        }

        /* replay start time */
        if (!lyd_find_path(rpc, "replay-start-time", 0, &node)) {
            ly_time_str2ts(lyd_get_value(node), &start);
        }

        /* check timestamp parameters */
        cur_ts = np_gettimespec(1);
        if (start.tv_sec && (np_difftimespec(&start, &cur_ts) < 0)) {
            reply = np_reply_err_bad_elem(LYD_CTX(rpc), "Specified \"replay-start-time\" is in future.",
                    "replay-start-time");
            goto cleanup;
        } else if (!start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &cur_ts) > 0)) {
            reply = np_reply_err_bad_elem(LYD_CTX(rpc), "Specified \"stop-time\" is in the past.", "stop-time");
            goto cleanup;
        } else if (start.tv_sec && stop.tv_sec && (np_difftimespec(&stop, &start) > 0)) {
            reply = np_reply_err_bad_elem(LYD_CTX(rpc),
                    "Specified \"stop-time\" is earlier than \"replay-start-time\".", "stop-time");
            goto cleanup;
        }

        /* SRSN subscribe */
        if (srsn_subscribe(user_sess->sess, stream, xp, stop.tv_sec ? &stop : NULL, start.tv_sec ? &start : NULL, 0,
                NULL, &replay_start, &fd, &sub_id)) {
            reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
            goto cleanup;
        }
    } else if (!lyd_find_path(rpc, "ietf-yang-push:datastore", 0, &node)) {
        is_yp = 1;

        /* datastore */
        if (sub_ntf_ident2ds(lyd_get_value(node), &datastore)) {
            reply = sub_ntf_error(LYD_CTX(rpc), SR_ERR_INVAL_ARG, "Unsupported datastore \"%s\".", lyd_get_value(node));
            goto cleanup;
        }

        /* filter */
        if ((reply = sub_ntf_rpc_get_filter(rpc, "ietf-yang-push:selection-filter-ref", &filter_name,
                "ietf-yang-push:datastore-subtree-filter", &subtree_filter, "ietf-yang-push:datastore-xpath-filter",
                &xpath_filter))) {
            goto cleanup;
        }
        if (sub_ntf_filter2xpath(user_sess->sess,
                "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter[filter-id='%s']",
                filter_name, subtree_filter, xpath_filter, &xp, &reply, NULL)) {
            goto cleanup;
        }

        /* update-trigger */
        if (!lyd_find_path(rpc, "ietf-yang-push:periodic", 0, &node)) {
            /* period */
            lyd_find_path(node, "period", 0, &node2);
            period = ((struct lyd_node_term *)node2)->value.uint32;

            /* anchor-time */
            if (!lyd_find_path(node, "anchor-time", 0, &node2)) {
                ly_time_str2ts(lyd_get_value(node2), &anchor_time);
            }

            /* SRSN subscribe */
            if (srsn_yang_push_periodic(user_sess->sess, datastore, xp, period * 10, anchor_time.tv_sec ? &anchor_time : NULL,
                    stop.tv_sec ? &stop : NULL, &fd, &sub_id)) {
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                goto cleanup;
            }
        } else if (!lyd_find_path(rpc, "ietf-yang-push:on-change", 0, &node)) {
            /* dampening-period */
            lyd_find_path(node, "dampening-period", 0, &node2);
            dampening_period = ((struct lyd_node_term *)node2)->value.uint32;

            /* sync-on-start */
            lyd_find_path(node, "sync-on-start", 0, &node2);
            sync_on_start = ((struct lyd_node_term *)node2)->value.boolean ? 1 : 0;

            /* excluded-change* */
            if (lyd_find_xpath(node, "excluded-change", &set)) {
                reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
                goto cleanup;
            }
            for (i = 0; i < set->count; ++i) {
                chg = sub_ntf_str2op(lyd_get_value(set->dnodes[i]));
                if (chg > SRSN_YP_CHANGE_INVALID) {
                    excluded_change[chg] = 1;
                }
            }
            ly_set_free(set, NULL);

            /* SRSN subscribe */
            if (srsn_yang_push_on_change(user_sess->sess, datastore, xp, dampening_period * 10, sync_on_start,
                    excluded_change, stop.tv_sec ? &stop : NULL, 0, NULL, &fd, &sub_id)) {
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                goto cleanup;
            }
        } else {
            reply = sub_ntf_error(LYD_CTX(rpc), SR_ERR_OPERATION_FAILED,
                    "Unknown update trigger for the yang-push subscription.");
            goto cleanup;
        }
    } else {
        reply = sub_ntf_error(LYD_CTX(rpc), SR_ERR_INVAL_ARG, "Missing mandatory \"stream\" or \"datastore\" leaves.");
        goto cleanup;
    }

    /* generate output */
    if (lyd_dup_single(rpc, NULL, LYD_DUP_WITH_PARENTS, &output)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    sprintf(id_str, "%" PRIu32, sub_id);
    if (lyd_new_term(output, NULL, "id", id_str, 1, NULL)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    if (np_difftimespec(&start, &replay_start) > 0) {
        ly_time_ts2str(&replay_start, &replay_start_str);
        if (lyd_new_term(output, NULL, "replay-start-time-revision", replay_start_str, 1, NULL)) {
            reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
            goto cleanup;
        }
    }

    /* add a new subscription */
    if ((reply = sub_ntf_add(LYD_CTX(rpc), user_sess->ntf_arg.nc_sess, sub_id, filter_name, subtree_filter,
            xpath_filter, is_yp, fd))) {
        goto cleanup;
    }

    /* param spent */
    fd = -1;

    /* set ongoing notifications flag */
    nc_session_inc_notif_status(user_sess->ntf_arg.nc_sess);

    /* data reply */
    reply = np_reply_success(rpc, output);
    output = NULL;

cleanup:
    /* UNLOCK */
    STATE_UNLOCK;

    if (fd > -1) {
        close(fd);
    }
    free(xp);
    free(replay_start_str);
    lyd_free_siblings(output);
    return reply;
}

/**
 * @brief Append filter specification data nodes.
 *
 * @param[in] parent Parent node to append to.
 * @param[in] sub Subscription to use.
 * @param[in,out] err_reply If set, generates an error reply on error.
 * @param[in,out] err_sess If set, is used for storing error information.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
sub_ntf_append_params_filter(struct lyd_node *parent, const struct np2srv_sub_ntf *sub,
        struct nc_server_reply **err_reply, sr_session_ctx_t *err_sess)
{
    int rc = 0;
    struct lyd_node_any *any;
    const struct lys_module *yp_mod;

    yp_mod = ly_ctx_get_module_implemented(LYD_CTX(parent), "ietf-yang-push");

    if (!sub->is_yp) {
        if (sub->filter_name) {
            /* stream-filter-name */
            if (lyd_new_term(parent, NULL, "stream-filter-name", sub->filter_name, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        } else if (sub->subtree_filter) {
            /* stream-subtree-filter */
            any = (struct lyd_node_any *)sub->subtree_filter;
            if (lyd_new_any(parent, NULL, "stream-subtree-filter", any->value.tree, any->value_type, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        } else if (sub->xpath_filter) {
            /* stream-xpath-filter */
            if (lyd_new_term(parent, NULL, "stream-xpath-filter", sub->xpath_filter, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        }
    } else {
        if (sub->filter_name) {
            /* selection-filter-ref */
            if (lyd_new_term(parent, yp_mod, "selection-filter-ref", sub->filter_name, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        } else if (sub->subtree_filter) {
            /* datastore-subtree-filter */
            any = (struct lyd_node_any *)sub->subtree_filter;
            if (lyd_new_any(parent, yp_mod, "datastore-subtree-filter", any->value.tree, any->value_type, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        } else if (sub->xpath_filter) {
            /* datastore-xpath-filter */
            if (lyd_new_term(parent, yp_mod, "datastore-xpath-filter", sub->xpath_filter, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        }
    }

cleanup:
    if (rc) {
        if (err_reply) {
            *err_reply = np_reply_err_op_failed(NULL, LYD_CTX(parent), ly_last_logmsg());
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_LY, ly_last_logmsg());
        }
    }
    return rc;
}

/**
 * @brief Transform a datastore into a string identity.
 *
 * @param[in] str Identity.
 * @param[out] ds Datastore.
 * @return Sysrepo error value.
 */
static const char *
sub_ntf_ds2ident(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_STARTUP:
        return "ietf-datastores:startup";
    case SR_DS_RUNNING:
        return "ietf-datastores:running";
    case SR_DS_CANDIDATE:
        return "ietf-datastores:candidate";
    case SR_DS_OPERATIONAL:
        return "ietf-datastores:operational";
    case SR_DS_FACTORY_DEFAULT:
        return "ietf-factory-default:factory-default";
    }

    return NULL;
}

/**
 * @brief Transform yang-push operation into string.
 *
 * @param[in] chg yang-push change.
 * @return String change name.
 */
static const char *
sub_ntf_change2str(srsn_yp_change_t chg)
{
    switch (chg) {
    case SRSN_YP_CHANGE_INVALID:
        break;
    case SRSN_YP_CHANGE_CREATE:
        return "create";
    case SRSN_YP_CHANGE_DELETE:
        return "delete";
    case SRSN_YP_CHANGE_INSERT:
        return "insert";
    case SRSN_YP_CHANGE_MOVE:
        return "move";
    case SRSN_YP_CHANGE_REPLACE:
        return "replace";
    case SRSN_COUNT_YP_CHANGE:
        break;
    }

    EINT;
    return NULL;
}

/**
 * @brief Append yang-push data nodes.
 *
 * @param[in] parent Parent node to append to.
 * @param[in] sub SRSN subscription to use.
 * @param[in,out] err_reply If set, generates an error reply on error.
 * @param[in,out] err_sess If set, is used for storing error information.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
sub_ntf_append_params_yang_push(struct lyd_node *parent, const srsn_state_sub_t *sub, struct nc_server_reply **err_reply,
        sr_session_ctx_t *err_sess)
{
    int rc = 0;
    const struct lys_module *yp_mod;
    struct lyd_node *cont;
    srsn_yp_change_t chg;
    char *datetime = NULL, buf[26];

    yp_mod = ly_ctx_get_module_implemented(LYD_CTX(parent), "ietf-yang-push");

    switch (sub->type) {
    case SRSN_SUB_NOTIF:
        /* nothing to do */
        break;
    case SRSN_YANG_PUSH_PERIODIC:
        /* datastore */
        if (lyd_new_term(parent, yp_mod, "datastore", sub_ntf_ds2ident(sub->yp_periodic.ds), 0, NULL)) {
            rc = -1;
            goto cleanup;
        }

        /* periodic */
        if (lyd_new_inner(parent, yp_mod, "periodic", 0, &cont)) {
            rc = -1;
            goto cleanup;
        }

        /* period */
        sprintf(buf, "%" PRIu32, sub->yp_periodic.period);
        if (lyd_new_term(cont, NULL, "period", buf, 0, NULL)) {
            rc = -1;
            goto cleanup;
        }

        /* anchor-time */
        if (sub->yp_periodic.anchor_time.tv_sec) {
            ly_time_ts2str(&sub->yp_periodic.anchor_time, &datetime);
            if (lyd_new_term(cont, NULL, "anchor-time", datetime, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        }
        break;
    case SRSN_YANG_PUSH_ON_CHANGE:
        /* datastore */
        if (lyd_new_term(parent, yp_mod, "datastore", sub_ntf_ds2ident(sub->yp_periodic.ds), 0, NULL)) {
            rc = -1;
            goto cleanup;
        }

        /* on-change */
        if (lyd_new_inner(parent, yp_mod, "on-change", 0, &cont)) {
            rc = -1;
            goto cleanup;
        }

        /* dampening-period */
        if (sub->yp_on_change.dampening_period) {
            sprintf(buf, "%" PRIu32, sub->yp_on_change.dampening_period);
            if (lyd_new_term(cont, NULL, "dampening-period", buf, 0, NULL)) {
                rc = -1;
                goto cleanup;
            }
        }

        /* sync-on-start */
        if (lyd_new_term(cont, NULL, "sync-on-start", sub->yp_on_change.sync_on_start ? "true" : "false", 0, NULL)) {
            rc = -1;
            goto cleanup;
        }

        /* excluded-change* */
        for (chg = 0; chg < SRSN_COUNT_YP_CHANGE; ++chg) {
            if (sub->yp_on_change.excluded_change[chg]) {
                if (lyd_new_term(cont, NULL, "excluded-change", sub_ntf_change2str(chg), 0, NULL)) {
                    rc = -1;
                    goto cleanup;
                }
            }
        }
        break;
    }

cleanup:
    free(datetime);
    if (rc) {
        if (err_reply) {
            *err_reply = np_reply_err_op_failed(NULL, LYD_CTX(parent), ly_last_logmsg());
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_LY, ly_last_logmsg());
        }
    }
    return rc;
}

/**
 * @brief Send a 'subscription-modified' notification.
 *
 * @param[in] ncs NC session to use.
 * @param[in] sub Subscription to use.
 * @param[in] use_stop Whether to use @p stop or the SRSN stop-time.
 * @param[in] stop Stop-time to use.
 * @param[in,out] err_reply If set, generates an error reply on error.
 * @param[in,out] err_sess If set, is used for storing error information.
 * @return 0 on success;
 * @return -1 on error.
 */
static int
sub_ntf_send_notif_modified(struct nc_session *ncs, const struct np2srv_sub_ntf *sub,
        int use_stop, const struct timespec *stop, struct nc_server_reply **err_reply, sr_session_ctx_t *err_sess)
{
    int rc = 0;
    const struct ly_ctx *ly_ctx;
    srsn_state_sub_t *sr_sub = NULL;
    char buf[11], *datetime = NULL;
    struct lyd_node *ly_ntf = NULL;
    struct timespec ts;
    struct nc_server_notif *nc_ntf = NULL;
    NC_MSG_TYPE msg_type;
    struct timespec stop_time = {0};

    ly_ctx = nc_session_get_ctx(ncs);

    /* get SRSN subscription state */
    if (srsn_oper_data_sub(sub->sub_id, &sr_sub)) {
        if (err_reply) {
            *err_reply = np_reply_err_op_failed(NULL, ly_ctx, "Failed to get subscription state.");
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_OPERATION_FAILED, "Failed to get subscription state.");
        }
        rc = -1;
        goto cleanup;
    }

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-modified", NULL, 0, &ly_ntf)) {
        if (err_reply) {
            *err_reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_LY, ly_last_logmsg());
        }
        rc = -1;
        goto cleanup;
    }

    /* id */
    sprintf(buf, "%" PRIu32, sub->sub_id);
    if (lyd_new_term(ly_ntf, NULL, "id", buf, 0, NULL)) {
        if (err_reply) {
            *err_reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_LY, ly_last_logmsg());
        }
        rc = -1;
        goto cleanup;
    }

    /* stop-time */
    if (use_stop) {
        if (stop) {
            stop_time = *stop;
        }
    } else {
        stop_time = sr_sub->stop_time;
    }
    if (stop_time.tv_sec) {
        ly_time_ts2str(&stop_time, &datetime);
        if (lyd_new_term(ly_ntf, NULL, "stop-time", datetime, 0, NULL)) {
            if (err_reply) {
                *err_reply = np_reply_err_op_failed(NULL, ly_ctx, ly_last_logmsg());
            } else if (err_sess) {
                sr_session_set_error(err_sess, NULL, SR_ERR_LY, ly_last_logmsg());
            }
            rc = -1;
            goto cleanup;
        }
        free(datetime);
        datetime = NULL;
    }

    /* filter parameters */
    if (sub_ntf_append_params_filter(ly_ntf, sub, err_reply, err_sess)) {
        rc = -1;
        goto cleanup;
    }

    /* yang-push parameters */
    if (sub_ntf_append_params_yang_push(ly_ntf, sr_sub, err_reply, err_sess)) {
        rc = -1;
        goto cleanup;
    }

    /* create the notification object, will free the parameters */
    ts = np_gettimespec(1);
    ly_time_ts2str(&ts, &datetime);
    nc_ntf = nc_server_notif_new(ly_ntf, datetime, NC_PARAMTYPE_FREE);
    ly_ntf = NULL;
    datetime = NULL;

    /* send the notification */
    msg_type = nc_server_notif_send(ncs, nc_ntf, NP2SRV_NOTIF_SEND_TIMEOUT);
    if ((msg_type == NC_MSG_ERROR) || (msg_type == NC_MSG_WOULDBLOCK)) {
        if (err_reply) {
            *err_reply = sub_ntf_error(ly_ctx, SR_ERR_OPERATION_FAILED, "Sending a notification to session %d %s.",
                    nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        } else if (err_sess) {
            sr_session_set_error(err_sess, NULL, SR_ERR_OPERATION_FAILED, "Sending a notification to session %d %s.",
                    nc_session_get_id(ncs), msg_type == NC_MSG_ERROR ? "failed" : "timed out");
        }
        rc = -1;
        goto cleanup;
    }

    /* increase sent notifications counter */
    srsn_notif_sent(sub->sub_id);

    /* NETCONF monitoring notification counter */
    ncm_session_notification(ncs);

cleanup:
    srsn_oper_data_subscriptions_free(sr_sub, 1);
    free(datetime);
    lyd_free_tree(ly_ntf);
    nc_server_notif_free(nc_ntf);
    return rc;
}

struct nc_server_reply *
np2srv_rpc_modify_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    int is_yp;
    struct lyd_node *node, *node2;
    const struct lyd_node *subtree_filter;
    char *xp = NULL;
    const char *filter_name, *xpath_filter;
    struct timespec stop = {0}, anchor_time = {0};
    struct np2srv_sub_ntf *sub = NULL;
    uint32_t i, sub_id, period, dampening_period;

    /* id */
    lyd_find_path(rpc, "id", 0, &node);
    sub_id = ((struct lyd_node_term *)node)->value.uint32;

    if (!lyd_find_path(rpc, "ietf-yang-push:datastore", 0, NULL)) {
        is_yp = 1;
    } else {
        is_yp = 0;
    }

    /* WRITE LOCK */
    STATE_WLOCK;

    /* find the subscription */
    for (i = 0; i < state.count; ++i) {
        if ((state.subs[i].sub_id == sub_id) && (state.subs[i].nc_id == nc_session_get_id(user_sess->ntf_arg.nc_sess)) &&
                (state.subs[i].is_yp == is_yp)) {
            sub = &state.subs[i];
            break;
        }
    }

    if (!sub) {
        reply = sub_ntf_error_no_sub(LYD_CTX(rpc), "%s subscription with ID %" PRIu32 " for the current receiver does not exist.",
                is_yp ? "YANG-push" : "Standard", sub_id);
        goto cleanup;
    }

    /* stop time */
    if (!lyd_find_path(rpc, "stop-time", 0, &node)) {
        ly_time_str2ts(lyd_get_value(node), &stop);
    }

    if (!is_yp) {
        /* filter */
        if ((reply = sub_ntf_rpc_get_filter(rpc, "stream-filter-name", &filter_name, "stream-subtree-filter",
                &subtree_filter, "stream-xpath-filter", &xpath_filter))) {
            goto cleanup;
        }
        if (sub_ntf_filter2xpath(user_sess->sess, "/ietf-subscribed-notifications:filters/stream-filter[name='%s']",
                filter_name, subtree_filter, xpath_filter, &xp, &reply, NULL)) {
            goto cleanup;
        }
    } else {
        /* filter */
        if ((reply = sub_ntf_rpc_get_filter(rpc, "ietf-yang-push:selection-filter-ref", &filter_name,
                "ietf-yang-push:datastore-subtree-filter", &subtree_filter, "ietf-yang-push:datastore-xpath-filter",
                &xpath_filter))) {
            goto cleanup;
        }
        if (sub_ntf_filter2xpath(user_sess->sess,
                "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter[filter-id='%s']",
                filter_name, subtree_filter, xpath_filter, &xp, &reply, NULL)) {
            goto cleanup;
        }

        /* update-trigger */
        if (!lyd_find_path(rpc, "ietf-yang-push:periodic", 0, &node)) {
            /* period */
            lyd_find_path(node, "period", 0, &node2);
            period = ((struct lyd_node_term *)node2)->value.uint32;

            /* anchor-time */
            if (!lyd_find_path(node, "anchor-time", 0, &node2)) {
                ly_time_str2ts(lyd_get_value(node2), &anchor_time);
            }

            /* SRSN modify */
            if (srsn_yang_push_modify_periodic(sub_id, period * 10, anchor_time.tv_sec ? &anchor_time : NULL)) {
                reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to modify a periodic subscription.");
                goto cleanup;
            }
        } else if (!lyd_find_path(rpc, "ietf-yang-push:on-change", 0, &node)) {
            /* dampening-period */
            lyd_find_path(node, "dampening-period", 0, &node2);
            dampening_period = ((struct lyd_node_term *)node2)->value.uint32;

            /* SRSN modify */
            if (srsn_yang_push_modify_on_change(sub_id, dampening_period * 10)) {
                reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to modify an on-change subscription.");
                goto cleanup;
            }
        } else {
            reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Unknown update trigger for the yang-push subscription.");
            goto cleanup;
        }
    }

    /* SRSN generic modify */
    if (srsn_modify_xpath_filter(sub_id, xp)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to modify an xpath filter of a subscription.");
        goto cleanup;
    }

    /* modify the subscription */
    free(sub->filter_name);
    sub->filter_name = filter_name ? strdup(filter_name) : NULL;

    lyd_free_siblings(sub->subtree_filter);
    sub->subtree_filter = NULL;
    if (subtree_filter && lyd_dup_siblings(subtree_filter, NULL, LYD_DUP_RECURSIVE, &sub->subtree_filter)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }

    free(sub->xpath_filter);
    sub->xpath_filter = xpath_filter ? strdup(xpath_filter) : NULL;

    /* create the 'subscription-modified' notification */
    if (sub_ntf_send_notif_modified(user_sess->ntf_arg.nc_sess, sub, 1, stop.tv_sec ? &stop : NULL, &reply, NULL)) {
        goto cleanup;
    }

    /* modify stop-time last in case it is in the past, the 'subscription-terminated' is not delivered before
     * 'subscription-modified' notif */
    if (srsn_modify_stop_time(sub_id, stop.tv_sec ? &stop : NULL)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to modify stop time of a subscription.");
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    /* UNLOCK */
    STATE_UNLOCK;

    free(xp);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_delete_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    int found = 0;
    struct lyd_node *node;
    uint32_t i, sub_id, nc_id;

    /* id */
    lyd_find_path(rpc, "id", 0, &node);
    sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* NC ID */
    nc_id = nc_session_get_id(user_sess->ntf_arg.nc_sess);

    /* WRITE LOCK */
    STATE_WLOCK;

    /* remove the subscription */
    for (i = 0; i < state.count; ++i) {
        if ((state.subs[i].sub_id == sub_id) && (state.subs[i].nc_id == nc_id) && !state.subs[i].terminated) {
            state.subs[i].terminated = 1;
            found = 1;
            break;
        }
    }

    /* UNLOCK */
    STATE_UNLOCK;

    if (found) {
        srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription");
    } else {
        reply = sub_ntf_error_no_sub(LYD_CTX(rpc), "Subscription with ID %" PRIu32 " for the current receiver does not exist.",
                sub_id);
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_kill_sub_cb(const struct lyd_node *rpc, struct np_user_sess *UNUSED(user_sess))
{
    struct nc_server_reply *reply = NULL;
    int found = 0;
    struct lyd_node *node;
    uint32_t i, sub_id;

    /* id */
    lyd_find_path(rpc, "id", 0, &node);
    sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* WRITE LOCK */
    STATE_WLOCK;

    /* remove the subscription */
    for (i = 0; i < state.count; ++i) {
        if ((state.subs[i].sub_id == sub_id) && !state.subs[i].terminated) {
            state.subs[i].terminated = 1;
            found = 1;
            break;
        }
    }

    /* UNLOCK */
    STATE_UNLOCK;

    if (found) {
        srsn_terminate(sub_id, "ietf-subscribed-notifications:no-such-subscription");
    } else {
        reply = sub_ntf_error_no_sub(LYD_CTX(rpc), "Subscription with ID %" PRIu32 " does not exist.", sub_id);
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

struct nc_server_reply *
np2srv_rpc_resync_sub_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    int found = 0;
    struct lyd_node *node;
    uint32_t i, sub_id, nc_id;

    /* id */
    lyd_find_path(rpc, "id", 0, &node);
    sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* NC ID */
    nc_id = nc_session_get_id(user_sess->ntf_arg.nc_sess);

    /* READ LOCK */
    STATE_RLOCK;

    /* resync the subscription */
    for (i = 0; i < state.count; ++i) {
        if ((state.subs[i].sub_id == sub_id) && (state.subs[i].nc_id == nc_id) && state.subs[i].is_yp &&
                !state.subs[i].terminated) {
            if (srsn_yang_push_on_change_resync(sub_id)) {
                reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "Failed to resync the subscription.");
            }
            found = 1;
            break;
        }
    }

    /* UNLOCK */
    STATE_UNLOCK;

    if (reply) {
        goto cleanup;
    }

    if (!found) {
        reply = sub_ntf_error_no_sub(LYD_CTX(rpc), "YANG-push subscription with ID %" PRIu32
                " for the current receiver does not exist.", sub_id);
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    return reply;
}

/**
 * @brief Process a filter change in the configuration.
 *
 * @param[in] ev_sess Event SR session for errors.
 * @param[in] filter_name Name of the changed filter.
 * @param[in] is_yp Whether a yang-push or subscribed-notifications filter was changed.
 * @param[in] op Change operation.
 * @return SR error value.
 */
static int
sub_ntf_config_filters(sr_session_ctx_t *ev_sess, const char *filter_name, int is_yp, sr_change_oper_t op)
{
    int rc = SR_ERR_OK, r;
    struct nc_session *ncs;
    char *xp = NULL;
    const char *search_fmt;
    uint32_t i, sub_id;

    if (is_yp) {
        search_fmt = "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter[filter-id='%s']";
    } else {
        search_fmt = "/ietf-subscribed-notifications:filters/stream-filter[name='%s']";
    }

    if (op == SR_OP_MODIFIED) {
        /* construct the new filter */
        if (sub_ntf_filter2xpath(ev_sess, search_fmt, filter_name, NULL, NULL, &xp, NULL, ev_sess)) {
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup;
        }

        /* WRITE LOCK */
        STATE_WLOCK;

        /* update all the relevant subscriptions */
        for (i = 0; i < state.count; ++i) {
            if ((state.subs[i].is_yp == is_yp) && state.subs[i].filter_name &&
                    !strcmp(state.subs[i].filter_name, filter_name)) {
                /* SRSN modify filter */
                if ((r = srsn_modify_xpath_filter(state.subs[i].sub_id, xp))) {
                    rc = r;
                }

                /* find this NETCONF session */
                np_get_nc_sess_by_id(0, state.subs[i].nc_id, __func__, &ncs);
                if (!ncs) {
                    ERR("NC session %" PRIu32 " not found.", state.subs[i].nc_id);
                    continue;
                }

                /* send the 'subscription-modified' notification */
                if (sub_ntf_send_notif_modified(ncs, &state.subs[i], 0, NULL, NULL, ev_sess)) {
                    rc = SR_ERR_OPERATION_FAILED;
                }
            }
        }

        /* UNLOCK */
        STATE_UNLOCK;
    } else if (op == SR_OP_DELETED) {
        /* WRITE LOCK */
        STATE_WLOCK;

        /* remove the subscriptions */
        i = 0;
        while (i < state.count) {
            if ((state.subs[i].is_yp == is_yp) && state.subs[i].filter_name &&
                    !strcmp(state.subs[i].filter_name, filter_name) && !state.subs[i].terminated) {
                /* free the subscription, needs the lock */
                sub_id = state.subs[i].sub_id;
                state.subs[i].terminated = 1;

                /* UNLOCK */
                STATE_UNLOCK;

                srsn_terminate(sub_id, "ietf-subscribed-notifications:filter-unavailable");

                /* WRITE LOCK */
                STATE_WLOCK;
            } else {
                ++i;
            }
        }

        /* UNLOCK */
        STATE_UNLOCK;
    }

cleanup:
    free(xp);
    return rc;
}

int
np2srv_config_sub_ntf_filters_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    int r, rc = SR_ERR_OK;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *filter_name;

    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter/*", &iter);
    if (rc) {
        sr_session_set_error(session, NULL, rc, "Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        filter_name = lyd_get_value(lyd_child(lyd_parent(node)));
        if ((rc = sub_ntf_config_filters(session, filter_name, 0, op))) {
            goto cleanup;
        }
    }
    if (r != SR_ERR_NOT_FOUND) {
        sr_session_set_error(session, NULL, rc, "Getting next change failed (%s).", sr_strerror(r));
        rc = r;
        goto cleanup;
    }

    sr_free_change_iter(iter);
    iter = NULL;

    /* yang-push */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter/*", &iter);
    if (rc) {
        sr_session_set_error(session, NULL, rc, "Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        filter_name = lyd_get_value(lyd_child(lyd_parent(node)));
        if ((rc = sub_ntf_config_filters(session, filter_name, 1, op))) {
            goto cleanup;
        }
    }
    if (r != SR_ERR_NOT_FOUND) {
        sr_session_set_error(session, NULL, rc, "Getting next change failed (%s).", sr_strerror(r));
        rc = r;
        goto cleanup;
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

int
np2srv_oper_sub_ntf_subscriptions_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), const char *UNUSED(request_xpath), uint32_t UNUSED(request_id),
        struct lyd_node **parent, void *UNUSED(private_data))
{
    int rc = SR_ERR_OK;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *list, *receiver, *root;
    srsn_state_sub_t *sr_subs = NULL, *sr_sub;
    struct np2srv_sub_ntf *sub;
    char buf[26], *path, *datetime;
    uint32_t i, sr_sub_count = 0, sr_sub_i = 0;
    LY_ERR lyrc;

    /* context is locked while the callback is executing */
    ly_ctx = sr_session_acquire_context(session);
    sr_session_release_context(session);

    /* READ LOCK */
    STATE_RLOCK;

    if (lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscriptions", NULL, 0, &root)) {
        sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* get SRSN subscription state */
    if ((rc = srsn_oper_data_subscriptions(&sr_subs, &sr_sub_count))) {
        goto cleanup;
    }

    /* go through all the subscriptions */
    for (i = 0; i < state.count; ++i) {
        sub = &state.subs[i];

        /* find the SRSN subscription */
        do {
            sr_sub = &sr_subs[sr_sub_i];
            ++sr_sub_i;

            if (sr_sub->sub_id == sub->sub_id) {
                break;
            }
        } while (sr_sub_i <= sr_sub_count);
        if (sr_sub_i > sr_sub_count) {
            sr_session_set_error(session, NULL, SR_ERR_INTERNAL, "Internal error (%s:%d).", __func__, __LINE__);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        /* subscription with id */
        sprintf(buf, "%" PRIu32, sub->sub_id);
        if (lyd_new_list(root, NULL, "subscription", 0, &list, buf)) {
            sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* filter parameters */
        if (sub_ntf_append_params_filter(list, sub, NULL, session)) {
            rc = SR_ERR_OPERATION_FAILED;
            goto cleanup;
        }

        switch (sr_sub->type) {
        case SRSN_SUB_NOTIF:
            /* stream */
            if (lyd_new_term(list, NULL, "stream", sr_sub->sub_notif.stream, 0, NULL)) {
                sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
                rc = SR_ERR_LY;
                goto cleanup;
            }

            /* replay-start-time */
            if (sr_sub->sub_notif.start_time.tv_sec) {
                ly_time_ts2str(&sr_sub->sub_notif.start_time, &datetime);
                lyrc = lyd_new_term(list, NULL, "replay-start-time", datetime, 0, NULL);
                free(datetime);
                if (lyrc) {
                    sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
                    rc = SR_ERR_LY;
                    goto cleanup;
                }
            }
            break;
        case SRSN_YANG_PUSH_PERIODIC:
        case SRSN_YANG_PUSH_ON_CHANGE:
            /* yang-push parameters */
            if (sub_ntf_append_params_yang_push(list, sr_sub, NULL, session)) {
                rc = SR_ERR_OPERATION_FAILED;
                goto cleanup;
            }
            break;
        }

        /* stop-time */
        if (sr_sub->stop_time.tv_sec) {
            ly_time_ts2str(&sr_sub->stop_time, &datetime);
            lyrc = lyd_new_term(list, NULL, "stop-time", datetime, 0, NULL);
            free(datetime);
            if (lyrc) {
                sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        /* receivers */
        if (asprintf(&path, "receivers/receiver[name='NETCONF session %" PRIu32 "']", sub->nc_id) == -1) {
            sr_session_set_error(session, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        lyrc = lyd_new_path(list, NULL, path, NULL, 0, &receiver);
        free(path);
        if (lyrc) {
            sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
            rc = SR_ERR_LY;
            goto cleanup;
        }
        receiver = lyd_child(receiver);

        /* sent-event-records */
        sprintf(buf, "%" PRIu32, sr_sub->sent_count);
        if (lyd_new_term(receiver, NULL, "sent-event-records", buf, 0, NULL)) {
            sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* excluded-event-records */
        sprintf(buf, "%" PRIu32, sr_sub->excluded_count);
        if (lyd_new_term(receiver, NULL, "excluded-event-records", buf, 0, NULL)) {
            sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* state */
        if (lyd_new_term(receiver, NULL, "state", "active", 0, NULL)) {
            sr_session_set_error(session, NULL, SR_ERR_LY, "%s", ly_last_logmsg());
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    /* UNLOCK */
    STATE_UNLOCK;

    srsn_oper_data_subscriptions_free(sr_subs, sr_sub_count);
    if (rc) {
        lyd_free_tree(root);
    } else {
        *parent = root;
    }
    return rc;
}
