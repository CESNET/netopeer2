/**
 * @file op_generic.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Implementation of NETCONF Event Notifications handling
 *
 * Copyright (c) 2016-2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"
#include "netconf_monitoring.h"

struct np_subscriber {
    struct nc_session *session;
    sr_subscription_ctx_t *sr_subscr;
    int subscr_count;
    char **filters;
    int filter_count;
    struct nc_server_notif **replay_notifs;
    uint16_t replay_notif_count;
    uint16_t replay_complete_count;
    uint16_t notif_complete_count;
    int subscr_ietf_yang_library;
};

struct {
    uint16_t size;
    uint16_t num;
    /* we use an array of pointers to the subscribers so that if we pass individual subscribers to np2srv_ntf_clb
     * and then call realloc() on this array, the pointers will remain the same */
    struct np_subscriber **list;
    pthread_mutex_t lock;
} subscribers = {0, 0, NULL, PTHREAD_MUTEX_INITIALIZER};

static int
np2srv_ntf_time_cmp(const void *ntf1, const void *ntf2)
{
    struct nc_server_notif *notif1, *notif2;

    notif1 = *(struct nc_server_notif **)ntf1;
    notif2 = *(struct nc_server_notif **)ntf2;

    return strcmp(nc_server_notif_get_time(notif1), nc_server_notif_get_time(notif2));
}

static void
np2srv_ntf_replay_sort_send(struct np_subscriber *subscriber)
{
    const struct lys_module *mod;
    struct lyd_node *event;
    struct nc_server_notif *notif;
    uint16_t i;

    assert(subscriber->replay_complete_count == subscriber->subscr_count);

    if (subscriber->replay_notif_count > 1) {
        /* sort replay notifications */
        qsort(subscriber->replay_notifs, subscriber->replay_notif_count, sizeof *subscriber->replay_notifs, np2srv_ntf_time_cmp);
    }

    /* send all the replay notifications */
    for (i = 0; i < subscriber->replay_notif_count; ++i) {
        nc_server_notif_send(subscriber->session, subscriber->replay_notifs[i], 5000);
        nc_server_notif_free(subscriber->replay_notifs[i]);
        ncm_session_notification(subscriber->session);
    }
    free(subscriber->replay_notifs);

    subscriber->replay_notif_count = 0;
    subscriber->replay_notifs = NULL;

    /* send replayComplete at the end */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "nc-notifications", NULL, 1);
    event = lyd_new(NULL, mod, "replayComplete");
    notif = nc_server_notif_new(event, nc_time2datetime(time(NULL), NULL, NULL), NC_PARAMTYPE_FREE);
    nc_server_notif_send(subscriber->session, notif, 5000);
    nc_server_notif_free(notif);
    ncm_session_notification(subscriber->session);
}

static void
np2srv_ntf_send(struct np_subscriber *subscriber, struct lyd_node *ntf, time_t timestamp, const sr_ev_notif_type_t notif_type)
{
    int i;
    const struct lys_module *mod;
    char *datetime = NULL;
    struct lyd_node *filtered_ntf;
    struct nc_server_notif *ntf_msg = NULL;

    switch (notif_type) {
    case SR_EV_NOTIF_T_REPLAY_COMPLETE:
        if (subscriber->replay_complete_count >= subscriber->subscr_count) {
            EINT;
        }

        ++subscriber->replay_complete_count;
        if (subscriber->replay_complete_count == subscriber->subscr_count) {
            np2srv_ntf_replay_sort_send(subscriber);
        }
        break;
    case SR_EV_NOTIF_T_REPLAY_STOP:
        if (subscriber->notif_complete_count >= subscriber->subscr_count) {
            EINT;
        }

        ++subscriber->notif_complete_count;
        if (subscriber->notif_complete_count == subscriber->subscr_count) {
            /* send notificationComplete */
            mod = ly_ctx_get_module(np2srv.ly_ctx, "nc-notifications", NULL, 1);
            if (mod) {
                filtered_ntf = lyd_new(NULL, mod, "notificationComplete");
                ntf_msg = nc_server_notif_new(filtered_ntf, nc_time2datetime(time(NULL), NULL, NULL), NC_PARAMTYPE_FREE);
                nc_server_notif_send(subscriber->session, ntf_msg, 5000);
                nc_server_notif_free(ntf_msg);
                ncm_session_notification(subscriber->session);
            } else {
                EINT;
            }

            op_ntf_unsubscribe(subscriber->session);
        }
        break;
    case SR_EV_NOTIF_T_REALTIME:
    case SR_EV_NOTIF_T_REPLAY:
        assert(ntf);
        datetime = nc_time2datetime(timestamp, NULL, NULL);

        if (subscriber->filters) {
            filtered_ntf = NULL;
            for (i = 0; i < subscriber->filter_count; ++i) {
                if (op_filter_get_tree_from_data(&filtered_ntf, ntf, subscriber->filters[i])) {
                    free(datetime);
                    lyd_free(filtered_ntf);
                    return;
                }
            }
            if (!filtered_ntf) {
                /* it is completely filtered out */
                break;
            }

            ntf_msg = nc_server_notif_new(filtered_ntf, datetime, NC_PARAMTYPE_DUP_AND_FREE);
            lyd_free(filtered_ntf);
        } else {
            ntf_msg = nc_server_notif_new(ntf, datetime, NC_PARAMTYPE_DUP_AND_FREE);
        }
        if (!ntf_msg) {
            break;
        }

        if (notif_type == SR_EV_NOTIF_T_REALTIME) {
            nc_server_notif_send(subscriber->session, ntf_msg, 5000);
            nc_server_notif_free(ntf_msg);
            ncm_session_notification(subscriber->session);
        } else {
            ++subscriber->replay_notif_count;
            subscriber->replay_notifs = realloc(subscriber->replay_notifs,
                        subscriber->replay_notif_count * sizeof *subscriber->replay_notifs);
            subscriber->replay_notifs[subscriber->replay_notif_count - 1] = ntf_msg;
        }
        break;
    }

    free(datetime);
}

static void
np2srv_ntf_clb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_val_t *vals, const size_t val_cnt,
               time_t timestamp, void *private_ctx)
{
    struct np_subscriber *subscriber = (struct np_subscriber *)private_ctx;
    struct lyd_node *ntf = NULL, *node;
    size_t i;
    const char *ntf_type_str = NULL;

    switch (notif_type) {
    case SR_EV_NOTIF_T_REALTIME:
        ntf_type_str = "realtime";
        break;
    case SR_EV_NOTIF_T_REPLAY:
        ntf_type_str = "replay";
        break;
    case SR_EV_NOTIF_T_REPLAY_COMPLETE:
        ntf_type_str = "replay complete";
        break;
    case SR_EV_NOTIF_T_REPLAY_STOP:
        ntf_type_str = "replay stop";
        break;
    }
    VRB("Session %d received a %s notification \"%s\" (%d).",
        nc_session_get_id(subscriber->session), ntf_type_str, xpath, timestamp);

    /* for special notifications the notif container is useless, they have no data */
    if ((notif_type == SR_EV_NOTIF_T_REALTIME) || (notif_type == SR_EV_NOTIF_T_REPLAY)) {
        ntf = lyd_new_path(NULL, np2srv.ly_ctx, xpath, NULL, 0, 0);
        if (!ntf) {
            ERR("Creating notification \"%s\" failed.", xpath);
            goto error;
        }

        for (i = 0; i < val_cnt; i++) {
            if (op_sr_val_to_lyd_node(ntf, &vals[i], &node)) {
                ERR("Creating notification (%s) data (%s) failed.", xpath, vals[i].xpath);
                goto error;
            }
        }
    }

    /* send the notification */
    np2srv_ntf_send(subscriber, ntf, timestamp, notif_type);

error:
    lyd_free(ntf);
}

static int
ntf_module_sr_subscribe(const struct lys_module *mod, struct np_subscriber *subscr)
{
    struct lys_node *next, *snode, *top;
    int rc;

    LY_TREE_FOR(mod->data, top) {
        LY_TREE_DFS_BEGIN(top, next, snode) {
            if (snode->nodetype == LYS_NOTIF) {
                if (subscr->sr_subscr) {
                    rc = np2srv_sr_event_notif_subscribe(np2srv.sr_sess.srs, mod->name, np2srv_ntf_clb, subscr,
                                                SR_SUBSCR_NOTIF_REPLAY_FIRST | SR_SUBSCR_CTX_REUSE, &subscr->sr_subscr, NULL);
                } else {
                    rc = np2srv_sr_event_notif_subscribe(np2srv.sr_sess.srs, mod->name, np2srv_ntf_clb, subscr,
                                                SR_SUBSCR_NOTIF_REPLAY_FIRST, &subscr->sr_subscr, NULL);
                }
                if (rc) {
                    return -1;
                }
                return 1;
            }

            LY_TREE_DFS_END(top, next, snode);
        }
    }

    return 0;
}

static void
np2srv_subscriber_free(struct np_subscriber *subscriber)
{
    int i;

    if (!subscriber) {
        return;
    }

    if (subscriber->sr_subscr) {
        np2srv_sr_unsubscribe(np2srv.sr_sess.srs, subscriber->sr_subscr, NULL);
    }
    for (i = 0; i < subscriber->filter_count; ++i) {
        free(subscriber->filters[i]);
    }
    free(subscriber->filters);
    for (i = 0; i < subscriber->replay_notif_count; ++i) {
        nc_server_notif_free(subscriber->replay_notifs[i]);
    }
    free(subscriber->replay_notifs);
    free(subscriber);
}

struct nc_server_reply *
op_ntf_subscribe(struct lyd_node *rpc, struct nc_session *ncs)
{
    int ret, filter_count = 0;
    uint16_t i;
    uint32_t idx;
    time_t now = time(NULL), start = 0, stop = 0;
    const char *stream;
    char **filters = NULL;
    void *mem;
    struct lyd_node *node;
    struct np_subscriber *new = NULL;
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    const struct lys_module *mod;
    struct np2_sessions *sessions;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/notifications:create-subscription", &ereply)) {
        goto error;
    }

    /* stream is always present - as explicit or default node */
    stream = ((struct lyd_node_leaf_list *)rpc->child)->value_str;

    /* get optional parameters */
    LY_TREE_FOR(rpc->child->next, node) {
        if (strcmp(node->schema->module->ns, "urn:ietf:params:xml:ns:netconf:notification:1.0")) {
            /* ignore */
            continue;
        } else if (!strcmp(node->schema->name, "startTime")) {
            start = nc_datetime2time(((struct lyd_node_leaf_list *)node)->value_str);
        } else if (!strcmp(node->schema->name, "stopTime")) {
            stop = nc_datetime2time(((struct lyd_node_leaf_list *)node)->value_str);
        } else if (!strcmp(node->schema->name, "filter")) {
            if (op_filter_create(node, &filters, &filter_count)) {
                e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "filter");
                nc_err_set_msg(e, "Failed to process filter.", "en");
                ereply = nc_server_reply_err(e);
                goto error;
            }
        }
    }

    /* check for the correct time boundaries */
    if (start > now) {
        /* it is not valid to specify future start time */
        e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "startTime");
        nc_err_set_msg(e, "Requested startTime is later than the current time.", "en");
        ereply = nc_server_reply_err(e);
        goto error;
    } else if (!start && stop) {
        /* stopTime must be used with startTime */
        e = nc_err(NC_ERR_MISSING_ELEM, NC_ERR_TYPE_PROT, "startTime");
        nc_err_set_msg(e, "The stopTime element must be used with the startTime element.", "en");
        ereply = nc_server_reply_err(e);
        goto error;
    } else if (stop && (start > stop)) {
        /* stopTime must be later than startTime */
        e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "stopTime");
        nc_err_set_msg(e, "Requested stopTime is earlier than the specified startTime.", "en");
        ereply = nc_server_reply_err(e);
        goto error;
    }

    pthread_mutex_lock(&subscribers.lock);

    /* check that the session is not in the current subscribers list */
    for (i = 0; i < subscribers.num; i++) {
        if (subscribers.list[i]->session == ncs) {
            /* already subscribed */
            e = nc_err(NC_ERR_IN_USE, NC_ERR_TYPE_PROT);
            nc_err_set_msg(e, "Already subscribed.", "en");
            ereply = nc_server_reply_err(e);
            goto unlock_error;
        }
    }

    /* new subscriber, make place for the pointer */
    if (subscribers.num == subscribers.size) {
        subscribers.size += 4;
        mem = realloc(subscribers.list, subscribers.size * sizeof *subscribers.list);
        if (!mem) {
            /* realloc failed */
            subscribers.size -= 4;
            EMEM;
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            ereply = nc_server_reply_err(e);
            goto unlock_error;
        }
        subscribers.list = mem;
    }
    /* allocate place for the subscriber structure itself */
    new = subscribers.list[subscribers.num] = malloc(sizeof *new);
    if (!new) {
        EMEM;
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        ereply = nc_server_reply_err(e);
        goto unlock_error;
    }
    subscribers.num++;

    /* store information about the new subscriber */
    new->session = ncs;
    new->sr_subscr = NULL;
    new->subscr_count = 0;
    new->filters = filters;
    filters = NULL;
    new->filter_count = filter_count;
    filter_count = 0;
    new->replay_notifs = NULL;
    new->replay_notif_count = 0;
    new->replay_complete_count = 0;
    new->notif_complete_count = 0;
    new->subscr_ietf_yang_library = 0;

    /* subscribe to all the notifications */
    if (!strcmp(stream, "NETCONF")) {
        /* default stream (all models) */
        idx = 0;
        while ((mod = ly_ctx_get_module_iter(np2srv.ly_ctx, &idx))) {
            if (!strcmp(mod->name, "nc-notifications")) {
                /* do not subscribe to replayComplete and notificationComplete,
                 * they are generated by sysrepo itself */
                continue;
            } else if (!strcmp(mod->name, "ietf-yang-library")) {
                /* remember that this subscriber wants this notification, we handle it on our own and
                 * ignore it if sysrepo also implements this model */
                new->subscr_ietf_yang_library = 1;
                continue;
            }

            ret = ntf_module_sr_subscribe(mod, new);
            if (ret == -1) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(np2srv.ly_ctx), "en");
                ereply = nc_server_reply_err(e);
                goto unlock_error;
            }

            new->subscr_count += ret;
        }

        if (!new->subscr_count) {
            /* weird */
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, "No modules with notifications to subscribe to.", "en");
            ereply = nc_server_reply_err(e);
            goto unlock_error;
        }
    } else {
        /* stream name is supposed to match the name of an implemented schema in the context having some
         * notifications defined */
        mod = ly_ctx_get_module(np2srv.ly_ctx, stream, NULL, 1);
        if (!strcmp(stream, "ietf-yang-library")) {
            /* handled internally */
            new->subscr_ietf_yang_library = 1;
            /* it does not support replay */
            ret = 0;
            if (start) {
                e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "stream");
                nc_err_set_msg(e, "Requested stream does not support replay.", "en");
                ereply = nc_server_reply_err(e);
                goto unlock_error;
            }
        } else if (!mod || !(ret = ntf_module_sr_subscribe(mod, new))) {
            /* requested stream does not match any schema with a notification */
            e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "stream");
            nc_err_set_msg(e, "Requested stream name does not match any of the provided streams.", "en");
            ereply = nc_server_reply_err(e);
            goto unlock_error;
        } else if (ret == -1) {
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, np2log_lasterr(np2srv.ly_ctx), "en");
            ereply = nc_server_reply_err(e);
            goto unlock_error;
        }

        new->subscr_count += ret;
    }

    pthread_mutex_unlock(&subscribers.lock);

    /* subscribe for replay */
    if (start) {
        if (np2srv_sr_event_notif_replay(np2srv.sr_sess.srs, new->sr_subscr, start, stop, &ereply)) {
            goto error;
        }
    }

    nc_session_set_notif_status(ncs, 1);
    return nc_server_reply_ok();

unlock_error:
    pthread_mutex_unlock(&subscribers.lock);
error:
    np2srv_subscriber_free(new);
    for (i = 0; i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);
    return ereply;
}

void
op_ntf_unsubscribe(struct nc_session *session)
{
    unsigned int i;

    pthread_mutex_lock(&subscribers.lock);

    for (i = 0; i < subscribers.num; i++) {
        if (subscribers.list[i]->session == session) {
            break;
        }
    }
    assert(i < subscribers.num);

    np2srv_subscriber_free(subscribers.list[i]);

    subscribers.num--;
    if (i < subscribers.num) {
        /* move here the subscriber pointer from the end of the list */
        subscribers.list[i] = subscribers.list[subscribers.num];
    }
    nc_session_set_notif_status(session, 0);

    if (!subscribers.num) {
        free(subscribers.list);
        subscribers.list = NULL;
        subscribers.size = 0;
    }

    pthread_mutex_unlock(&subscribers.lock);
}

void
op_ntf_yang_lib_change(const struct lyd_node *ylib_info)
{
    const char *setid;
    struct lyd_node *ntf;
    struct ly_set *set;
    int i;

    set = lyd_find_path(ylib_info, "/ietf-yang-library:modules-state/module-set-id");
    if (!set || (set->number != 1)) {
        ly_set_free(set);
        EINT;
        return;
    }
    setid = ((struct lyd_node_leaf_list *)set->set.d[0])->value_str;
    ly_set_free(set);

    ntf = lyd_new_path(NULL, np2srv.ly_ctx, "/ietf-yang-library:yang-library-change/module-set-id", (void *)setid, 0, 0);
    if (lyd_validate(&ntf, LYD_OPT_NOTIF, (void *)ylib_info)) {
        lyd_free(ntf);
        EINT;
        return;
    }

    /* send notifications */
    for (i = 0; i < subscribers.num; ++i) {
        if (subscribers.list[i]->subscr_ietf_yang_library) {
            np2srv_ntf_send(subscribers.list[i], ntf, time(NULL), SR_EV_NOTIF_T_REALTIME);
        }
    }
    lyd_free(ntf);
}

struct lyd_node *
ntf_get_data(void)
{
    uint32_t idx = 0;
    struct lyd_node *root, *stream;
    struct lys_node *snode;
    const struct lys_module *mod;
    const char *replay_sup;

    root = lyd_new_path(NULL, np2srv.ly_ctx, "/nc-notifications:netconf/streams", NULL, 0, 0);
    if (!root || !root->child) {
        goto error;
    }

    /* generic stream */
    stream = lyd_new_path(root, np2srv.ly_ctx, "/nc-notifications:netconf/streams/stream[name='NETCONF']", NULL, 0, 0);
    if (!stream) {
        goto error;
    }
    if (!lyd_new_leaf(stream, stream->schema->module, "description",
                      "Default NETCONF stream containing all the Event Notifications.")) {
        goto error;
    }
    if (!lyd_new_leaf(stream, stream->schema->module, "replaySupport", "true")) {
        goto error;
    }

    /* local streams - matching a module specifying a notifications */
    while ((mod = ly_ctx_get_module_iter(np2srv.ly_ctx, &idx))) {
        LY_TREE_FOR(mod->data, snode) {
            if (snode->nodetype == LYS_NOTIF) {
                break;
            }
        }
        if (!snode) {
            /* module has no notification */
            continue;
        }

        /* generate information about the stream/module */
        stream = lyd_new(root->child, root->schema->module, "stream");
        if (!stream) {
            goto error;
        }
        if (!lyd_new_leaf(stream, stream->schema->module, "name", mod->name)) {
            goto error;
        }
        if (!strcmp(mod->name, "ietf-yang-library")) {
            /* we generate the notification locally, we do not store it */
            replay_sup = "false";
        } else {
            replay_sup = "true";
        }
        if (!lyd_new_leaf(stream, stream->schema->module, "replaySupport", replay_sup)) {
            goto error;
        }
    }

    return root;

error:
    lyd_free(root);
    return NULL;
}
