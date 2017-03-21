/**
 * @file op_generic.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Implementation of NETCONF Event Notifications handling
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
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

uint16_t sr_subsc_count;

struct subscriber_s {
    struct nc_session *session;
    const struct lys_module *stream;
    time_t start;
    time_t stop;
    struct nc_server_notif **replay_notifs;
    uint16_t replay_notif_count;
    uint16_t replay_complete_count;
    uint16_t notif_complete_count;
};

struct {
    uint16_t size;
    uint16_t num;
    struct subscriber_s *list;
    pthread_mutex_t lock;
} subscribers = {0, 0, NULL, PTHREAD_MUTEX_INITIALIZER};

struct nc_server_reply *
op_ntf_subscribe(struct lyd_node *rpc, struct nc_session *ncs)
{
    int ret;
    uint16_t i;
    uint32_t idx;
    time_t now = time(NULL), start = 0, stop = 0;
    const char *stream;
    struct lyd_node *node;
    struct lys_node *snode;
    struct subscriber_s *new = NULL;
    struct nc_server_error *e = NULL;
    const struct lys_module *mod, *pstream;

    /*
     * parse RPC to get params
     */
    /* stream is always present - as explicit or default node */
    stream = ((struct lyd_node_leaf_list *)rpc->child)->value_str;

    /* check for the correct stream name */
    if (!strcmp(stream, "NETCONF")) {
        /* default stream */
        pstream = NULL;
    } else {
        /* stream name is supposed to match the name of a schema in the context having some
         * notifications defined */
        idx = 0;
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

            if (!strcmp(stream, mod->name)) {
                /* we have a match */
                pstream = mod;
                break;
            }
        }
        if (!mod) {
            /* requested stream does not match any schema with a notification */
            e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "stream");
            nc_err_set_msg(e, "Requested stream name does not match any of the provided streams.", "en");
            goto error;
        }
    }

    /* get optional parameters */
    LY_TREE_FOR(rpc->child->next, node) {
        if (strcmp(node->schema->module->ns, "urn:ietf:params:xml:ns:netconf:notification:1.0")) {
            /* ignore */
            continue;
        } else if (!strcmp(node->schema->name, "startTime")) {
            start = nc_datetime2time(((struct lyd_node_leaf_list *)node)->value_str);
        } else if (!strcmp(node->schema->name, "stopTime")) {
            stop = nc_datetime2time(((struct lyd_node_leaf_list *)node)->value_str);
        }
        /* TODO support subtree and XPath filters */
    }

    /* check for the correct time boundaries */
    if (start > now) {
        /* it is not valid to specify future start time */
        e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "startTime");
        nc_err_set_msg(e, "Requested startTime is later than the current time.", "en");
        goto error;
    } else if (!start && stop) {
        /* stopTime must be used with startTime */
        e = nc_err(NC_ERR_MISSING_ELEM, NC_ERR_TYPE_PROT, "startTime");
        nc_err_set_msg(e, "The stopTime element must be used with the startTime element.", "en");
        goto error;
    } else if (stop && (start > stop)) {
        /* stopTime must be later than startTime */
        e = nc_err(NC_ERR_BAD_ELEM, NC_ERR_TYPE_PROT, "stopTime");
        nc_err_set_msg(e, "Requested stopTime is earlier than the specified startTime.", "en");
        goto error;
    }

    pthread_mutex_lock(&subscribers.lock);

    /* check that the session is not in the current subscribers list */
    for (i = 0; i < subscribers.num; i++) {
        if (subscribers.list[i].session == ncs) {
            /* already subscribed */
            pthread_mutex_unlock(&subscribers.lock);
            e = nc_err(NC_ERR_IN_USE, NC_ERR_TYPE_PROT);
            nc_err_set_msg(e, "Already subscribed.", "en");
            goto error;
        }
    }

    /* new subscriber, add it into the list */
    if (subscribers.num == subscribers.size) {
        subscribers.size += 4;
        new = realloc(subscribers.list, subscribers.size * sizeof *subscribers.list);
        if (!new) {
            /* realloc failed */
            pthread_mutex_unlock(&subscribers.lock);
            EMEM;
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            subscribers.size -= 4;
            goto error;
        }
        subscribers.list = new;
    }
    new = &subscribers.list[subscribers.num];
    subscribers.num++;

    /* store information about the new subscriber */
    new->session = ncs;
    new->stream = pstream;
    new->start = start;
    new->stop = stop;
    new->replay_notifs = NULL;
    new->replay_notif_count = 0;
    new->replay_complete_count = 0;
    new->notif_complete_count = 0;

    pthread_mutex_unlock(&subscribers.lock);

    nc_session_set_notif_status(ncs, 1);

    /* subscribe for replay */
    if (start) {
        ret = sr_event_notif_replay(np2srv.sr_sess.srs, np2srv.sr_subscr, start, stop);
        if (ret) {
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, sr_strerror(ret), "en");
            goto error;
        }
    }

    return nc_server_reply_ok();

error:
    return nc_server_reply_err(e);
}

void
op_ntf_unsubscribe(struct nc_session *session, int have_lock)
{
    unsigned int i, j;
    const struct lys_module *mod;
    struct lyd_node *event;
    struct nc_server_notif *notif;

    if (!have_lock) {
        pthread_mutex_lock(&subscribers.lock);
    }

    for (i = 0; i < subscribers.num; i++) {
        if (subscribers.list[i].session == session) {
            break;
        }
    }

    assert(i < subscribers.num);

    /* send notificationComplete */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "nc-notifications", NULL);
    event = lyd_new(NULL, mod, "notificationComplete");
    notif = nc_server_notif_new(event, nc_time2datetime(time(NULL), NULL, NULL), NC_PARAMTYPE_FREE);
    nc_server_notif_send(session, notif, 5000);
    nc_server_notif_free(notif);

    /* free the subscriber */
    for (j = 0; j < subscribers.list[i].replay_notif_count; ++j) {
        nc_server_notif_free(subscribers.list[i].replay_notifs[j]);
    }
    free(subscribers.list[i].replay_notifs);

    subscribers.num--;
    if (i < subscribers.num) {
        /* move here the subscriber from the end of the list */
        memcpy(&subscribers.list[i], &subscribers.list[subscribers.num], sizeof *subscribers.list);
    }
    nc_session_set_notif_status(session, 0);

    if (!subscribers.num) {
        free(subscribers.list);
        subscribers.list = NULL;
        subscribers.size = 0;
    }

    if (!have_lock) {
        pthread_mutex_unlock(&subscribers.lock);
    }
}

static int
op_notif_time_cmp(const void *ntf1, const void *ntf2)
{
    struct nc_server_notif *notif1, *notif2;

    notif1 = *(struct nc_server_notif **)ntf1;
    notif2 = *(struct nc_server_notif **)ntf2;

    return strcmp(nc_server_notif_get_time(notif1), nc_server_notif_get_time(notif2));
}

static void
op_notif_replay_send(struct subscriber_s *subscriber)
{
    const struct lys_module *mod;
    struct lyd_node *event;
    struct nc_server_notif *notif;
    uint16_t i;

    assert(subscriber->replay_complete_count == sr_subsc_count);

    if (subscriber->replay_notif_count > 1) {
        /* sort replay notifications */
        qsort(subscriber->replay_notifs, subscriber->replay_notif_count, sizeof *subscriber->replay_notifs, op_notif_time_cmp);
    }

    /* send all the replay notifications */
    for (i = 0; i < subscriber->replay_notif_count; ++i) {
        nc_server_notif_send(subscriber->session, subscriber->replay_notifs[i], 5000);
        nc_server_notif_free(subscriber->replay_notifs[i]);
    }
    free(subscriber->replay_notifs);

    subscriber->replay_notif_count = 0;
    subscriber->replay_notifs = NULL;

    /* send replayComplete at the end */
    mod = ly_ctx_get_module(np2srv.ly_ctx, "nc-notifications", NULL);
    event = lyd_new(NULL, mod, "replayComplete");
    notif = nc_server_notif_new(event, nc_time2datetime(time(NULL), NULL, NULL), NC_PARAMTYPE_FREE);
    nc_server_notif_send(subscriber->session, notif, 5000);
    nc_server_notif_free(notif);
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

void
np2srv_ntf_send(struct lyd_node *ntf, const char *xpath, time_t timestamp, const sr_ev_notif_type_t notif_type)
{
    int i;
    char *datetime;
    struct nc_server_notif *ntf_msg = NULL;

    datetime = nc_time2datetime(timestamp, NULL, NULL);

    /* send the notification */
    pthread_mutex_lock(&subscribers.lock);

    for (i = 0; i < subscribers.num; ++i) {
        if (subscribers.list[i].stream && (subscribers.list[i].stream != ntf->schema->module)) {
            /* wrong stream */
            continue;
        }
        if ((notif_type == SR_EV_NOTIF_T_REALTIME) && (subscribers.list[i].stop && (timestamp > subscribers.list[i].stop))) {
            /* replay subscription that will finish before this notification's timestamp */
            continue;
        }
        if ((notif_type == SR_EV_NOTIF_T_REPLAY) && (!subscribers.list[i].start || (subscribers.list[i].start > timestamp)
                || (subscribers.list[i].stop && (subscribers.list[i].stop < timestamp)))) {
            /* notification not relevant for this subscription */
            continue;
        }

        if (!strcmp(xpath, "/nc-notifications:replayComplete")) {
            if (subscribers.list[i].start && (subscribers.list[i].replay_complete_count < sr_subsc_count)) {
                ++subscribers.list[i].replay_complete_count;
                if (subscribers.list[i].replay_complete_count == sr_subsc_count) {
                    op_notif_replay_send(&subscribers.list[i]);
                }
            }
            continue;
        } else if (!strcmp(xpath, "/nc-notifications:notificationComplete")) {
            if ((subscribers.list[i].stop == timestamp) && (subscribers.list[i].notif_complete_count < sr_subsc_count)) {
                ++subscribers.list[i].notif_complete_count;
                if (subscribers.list[i].notif_complete_count == sr_subsc_count) {
                    op_ntf_unsubscribe(subscribers.list[i].session, 1);
                    --i;
                }
            }
            continue;
        }

        assert(ntf);
        ntf_msg = nc_server_notif_new(ntf, datetime, NC_PARAMTYPE_DUP_AND_FREE);
        if (!ntf_msg) {
            free(datetime);
            lyd_free(ntf);
            return;
        }

        if (notif_type == SR_EV_NOTIF_T_REALTIME) {
            nc_server_notif_send(subscribers.list[i].session, ntf_msg, 5000);
            nc_server_notif_free(ntf_msg);
        } else {
            ++subscribers.list[i].replay_notif_count;
            subscribers.list[i].replay_notifs =
                realloc(subscribers.list[i].replay_notifs,
                        subscribers.list[i].replay_notif_count * sizeof *subscribers.list[i].replay_notifs);
            subscribers.list[i].replay_notifs[subscribers.list[i].replay_notif_count - 1] = ntf_msg;
        }
    }

    pthread_mutex_unlock(&subscribers.lock);

    free(datetime);
    lyd_free(ntf);
}

void
np2srv_ntf_clb(const sr_ev_notif_type_t notif_type, const char *xpath, const sr_node_t *trees, const size_t tree_cnt,
               time_t timestamp, void *UNUSED(private_ctx))
{
    const struct lys_node *snode;
    struct lyd_node *ntf = NULL, *parent, *node;
    const sr_node_t *srnode, *srnext;
    const struct lys_module *mod;
    size_t i;
    char numstr[21];

    VRB("Received a %s notification \"%s\" (%d).",
        (notif_type == SR_EV_NOTIF_T_REPLAY ? "replay" : "realtime"), xpath, timestamp);

    /* if we have no subscribers, it is not needed to do anything here */
    if (!subscribers.num) {
        assert(notif_type == SR_EV_NOTIF_T_REALTIME);
        return;
    }

    /* for special notifications the notif container is useless, they have no data */
    if (strcmp(xpath, "/nc-notifications:replayComplete") && strcmp(xpath, "/nc-notifications:notificationComplete")) {
        ntf = lyd_new_path(NULL, np2srv.ly_ctx, xpath, NULL, 0, 0);
        if (!ntf) {
            ERR("Creating notification \"%s\" failed.", xpath);
            goto error;
        }

        for (i = 0; i < tree_cnt; i++) {
            parent = ntf;

            for (srnode = srnext = &trees[i]; srnode; srnode = srnext) {
                mod = ly_ctx_get_module(np2srv.ly_ctx, srnode->module_name, NULL);
                if (!mod) {
                    ERR("Data from unknown module (%s%s) received in sysrepo notification \"%s\"", srnode->module_name,
                        srnode->name, xpath);
                    goto error;
                } else if (!mod->implemented) {
                    mod = lys_implemented_module(mod);
                    if (!mod->implemented) {
                        ERR("Non-implemented data (%s:%s) received in sysrepo notification \"%s\"", srnode->module_name,
                            srnode->name, xpath);
                        goto error;
                    }
                }

                snode = NULL;
                while ((snode = lys_getnext(snode, parent->schema, mod, 0))) {
                    if (strcmp(srnode->name, snode->name) || strcmp(srnode->module_name, snode->module->name)) {
                        continue;
                    }
                    /* match */
                    break;
                }
                if (!snode) {
                    ERR("Unknown data (%s:%s) received in sysrepo notification \"%s\"", srnode->module_name,
                        srnode->name, xpath);
                    goto error;
                }
                switch (snode->nodetype) {
                case LYS_LEAFLIST:
                case LYS_LEAF:
                    node = lyd_new_leaf(parent, mod, srnode->name, op_get_srval(np2srv.ly_ctx, (sr_val_t *)srnode, numstr));
                    break;
                case LYS_CONTAINER:
                case LYS_LIST:
                    node = lyd_new(parent, mod, srnode->name);
                    break;
                case LYS_ANYXML:
                case LYS_ANYDATA:
                    node = lyd_new_anydata(parent, mod, srnode->name,
                                        op_get_srval(np2srv.ly_ctx, (sr_val_t *)srnode, numstr), LYD_ANYDATA_SXML);
                    break;
                default:
                    ERR("Invalid node type (%d) received in sysrepo notification \"%s\"", snode->nodetype, xpath);
                    goto error;
                }

                if (!node) {
                    ERR("Creating notification (%s) data (%d: %s:%s) failed.", xpath, snode->nodetype, srnode->module_name,
                        srnode->name);
                    goto error;
                }

                /* select element for the next run - children first */
                srnext = srnode->first_child;
                if (!srnext) {
                    /* no children, try siblings */
                    srnext = srnode->next;
                } else {
                    parent = node;
                }
                while (!srnext) {
                    /* parent is already processed, go to its sibling */
                    srnode = srnode->parent;

                    if (srnode == trees->parent) {
                        /* we are done, no next element to process */
                        break;
                    }
                    srnext = srnode->next;
                    parent = parent->parent;
                }
            }
        }
    }

    /* send the notification */
    np2srv_ntf_send(ntf, xpath, timestamp, notif_type);
    return;

error:
    lyd_free(ntf);
}
