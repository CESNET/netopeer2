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
#include <errno.h>
#include <pthread.h>
#include <signal.h>
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

/**
 * @brief Build a notification.
 *
 * @param[in] timestamp any timestamp, mainly the current time.
 * @param[in] ly_ntf the notification content to add to the message.
 * @return a pointer to a new unyte message on success, NULL on failure.
 */
static unyte_message_t *
csn_build_notification(struct timespec timestamp, struct lyd_node **ly_ntf)
{
    unyte_message_t *message = NULL;
    static uint32_t message_id = 0;
    char *string_to_send = NULL;
    char *eventtime = NULL;
    int rc = 0;

    ly_time_ts2str(&timestamp, &eventtime);
    message = (unyte_message_t *)malloc(sizeof *message);
    if (!message) {
        EMEM;
        goto cleanup;
    }

    lyd_print_mem(&string_to_send, *ly_ntf, LYD_XML, LYD_PRINT_WD_ALL | LY_PRINT_SHRINK);
    if ((rc = asprintf((char **)&message->buffer,
            "<notification xmlns:\""NC_NS_NOTIF "\">"
            "<eventTime>%s</eventTime>"
            "%s"
            "</notification>",
            eventtime, string_to_send)) < 0) {
        EMEM;
        goto cleanup;
    }

    message->buffer_len = rc;

    /* UDP-notif */
    message->version = 0;
    message->space = 0;

    /* xml string */
    message->media_type = 2;
    message->observation_domain_id = 0;

    message->message_id = message_id;
    message_id = (message_id + 1) % UINT32_MAX;

    message->options = NULL;
    message->options_len = 0;

cleanup:
    if (rc < 0) {
        free(message);
        message = NULL;
    }

    free(eventtime);
    free(string_to_send);
    return message;
}

int
csn_send_notif(struct csn_receiver_info *recv_info, uint32_t nc_sub_id,
        struct timespec timestamp, struct lyd_node **ly_ntf, int use_ntf)
{
    unyte_message_t *message = NULL;
    struct np2srv_sub_ntf *sub;
    int rc = SR_ERR_OK;
    uint32_t r;

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    message = csn_build_notification(timestamp, ly_ntf);
    if (!message) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /* search transport */
    for (r = 0; r < recv_info->count; r++) {
        unyte_send(recv_info->receivers[r].udp.sender, message);
        ATOMIC_INC_RELAXED(sub->sent_count);
    }

cleanup:
    if (message) {
        free(message->buffer);
        free(message);
    }

    if (use_ntf) {
        lyd_free_tree(*ly_ntf);
        *ly_ntf = NULL;
    }
    return rc;
}

/**
 * @brief Send a notification to a receiver.
 *
 * @param[in] receiver the receiver to send the notif.
 * @param[in] nc_sub_id the configured subscription id.
 * @param[in] type may be started or terminated.
 * @return Sysrepo error value.
 */
static int
csn_send_notif_one(struct csn_receiver *receiver, uint32_t nc_sub_id, const char *type)
{
    unyte_message_t *message = NULL;
    const struct ly_ctx *ly_ctx;
    struct np2srv_sub_ntf *sub;
    struct lyd_node *ly_ntf;
    char notif_string[128];
    int rc = SR_ERR_OK;
    char buf[11];

    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    sr_release_context(np2srv.sr_conn);

    sprintf(buf, "%" PRIu32, nc_sub_id);
    sprintf(notif_string, "/ietf-subscribed-notifications:subscription-%s/id", type);
    lyd_new_path(NULL, ly_ctx, notif_string, buf, 0, &ly_ntf);

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    message = csn_build_notification(np_gettimespec(1), &ly_ntf);
    if (!message) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    unyte_send(receiver->udp.sender, message);

    ATOMIC_INC_RELAXED(sub->sent_count);

cleanup:
    if (message) {
        free(message->buffer);
        free(message);
    }

    lyd_free_tree(ly_ntf);
    return rc;
}

int
sub_ntf_send_notif(struct nc_session *ncs, uint32_t nc_sub_id, struct timespec timestamp, struct lyd_node **ly_ntf,
        int use_ntf)
{
    int rc = SR_ERR_OK;
    struct np2srv_sub_ntf *sub;

    /* find the subscription structure */
    sub = sub_ntf_find(nc_sub_id, nc_session_get_id(ncs), 0, 0);
    if (!sub) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* send the notification */
    if ((rc = np_ntf_send(ncs, &timestamp, ly_ntf, use_ntf))) {
        goto cleanup;
    }

    ATOMIC_INC_RELAXED(sub->sent_count);

cleanup:
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
 * @return 0 on success.
 * @return -1 on error.
 */
static int
sub_ntf_add(const struct np2srv_sub_ntf *sub)
{
    void *mem;

    mem = realloc(info.subs, (info.count + 1) * sizeof *info.subs);
    if (!mem) {
        return -1;
    }
    info.subs = mem;

    info.subs[info.count] = *sub;
    ++info.count;

    return 0;
}

/**
 * @brief Add receiver config to the list of receivers.
 *
 * @param[in] recv_config receiver config to add to the list.
 * @return 0 on success.
 * @return -1 on error.
 */
static int
csn_receiver_config_add(const struct csn_receiver_config *recv_config)
{
    void *mem;

    mem = realloc(info.recv_configs, (info.recv_cfg_count + 1) * sizeof *info.recv_configs);
    if (!mem) {
        return -1;
    }

    info.recv_configs = mem;

    info.recv_configs[info.recv_cfg_count] = *recv_config;
    ++info.recv_cfg_count;

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
        case SUB_TYPE_CFG_SUB:
        case SUB_TYPE_DYN_SUB:
            sub_ntf_terminate_async(info.subs[i].data);
            break;
        case SUB_TYPE_CFG_YANG_PUSH:
        case SUB_TYPE_DYN_YANG_PUSH:
            yang_push_terminate_async(info.subs[i].data);
            break;
        }

        free(info.subs[i].sub_ids);
        switch (info.subs[i].type) {
        case SUB_TYPE_CFG_SUB:
        case SUB_TYPE_DYN_SUB:
            sub_ntf_data_destroy(info.subs[i].data);
            break;
        case SUB_TYPE_CFG_YANG_PUSH:
        case SUB_TYPE_DYN_YANG_PUSH:
            yang_push_data_destroy(info.subs[i].data);
            break;
        }
    }
    free(info.subs);
    info.subs = NULL;
    info.count = 0;

    for (i = 0; i < info.recv_cfg_count; ++i) {
        if (info.recv_configs[i].instance_name) {
            free(info.recv_configs[i].instance_name);
        }
        if (info.recv_configs[i].udp.address) {
            free(info.recv_configs[i].udp.address);
        }
        if (info.recv_configs[i].udp.port) {
            free(info.recv_configs[i].udp.port);
        }
    }

    free(info.recv_configs);
    info.recv_configs = NULL;
    info.recv_cfg_count = 0;

    /* UNLOCK */
    INFO_UNLOCK;
}

/**
 * @brief Establish a new subscription either configured or not.
 *
 * @param[in] session sysrepo session.
 * @param[in] input the data containing the subscription info.
 * @param[out] output to return to the netconf subscriber.
 * @param[in] ncs the NETCONF session to use.
 * @return Sysrepo error value.
 */
static int
np2srv_establish_sub(sr_session_ctx_t *session, const struct lyd_node *input, struct lyd_node *output,
        struct nc_session *ncs)
{
    struct lyd_node *node;
    struct np2srv_sub_ntf sub = {0}, *sub_p;
    char id_str[11];
    struct timespec stop = {0};
    int r, rc = SR_ERR_OK, ntf_status = 0;
    uint32_t nc_sub_id, *nc_id;
    enum sub_ntf_type type;

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
    if (ncs) {
        if (!lyd_find_path(input, "stream", 0, NULL)) {
            type = SUB_TYPE_DYN_SUB;
        } else if (!lyd_find_path(input, "ietf-yang-push:datastore", 0, NULL)) {
            type = SUB_TYPE_DYN_YANG_PUSH;
        } else {
            ERR("Missing mandatory \"stream\" or \"datastore\" leaves.");
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }
        nc_session_inc_notif_status(ncs);
        ntf_status = 1;
        sr_session_get_orig_data(session, 0, NULL, (const void **)&nc_id);
        sub.nc_id = *nc_id;
        /* get new NC sub ID */
        do {
            nc_sub_id = ATOMIC_INC_RELAXED(new_nc_sub_id);
        } while (sub_ntf_find(nc_sub_id, 0, 0, 0));

    } else {
        sub.nc_id = 0;

        if (!lyd_find_path(input, "stream", 0, NULL)) {
            type = SUB_TYPE_CFG_SUB;
        } else if (!lyd_find_path(input, "ietf-yang-push:datastore", 0, NULL)) {
            type = SUB_TYPE_CFG_YANG_PUSH;
        } else {
            ERR("Missing mandatory \"stream\" leaves.");
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }

        if (lyd_find_path(input, "id", 0, &node)) {
            ERR("id not found.");
            rc = SR_ERR_INVAL_ARG;
            goto error;
        }

        nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

        if (sub_ntf_find(nc_sub_id, 0, 0, 0)) {
            ERR("id already exists.");
            rc = SR_ERR_INTERNAL;
            goto error;
        }
    }

    /* prepare a new subscription */
    sub.nc_sub_id = nc_sub_id;
    sub.term_reason = "ietf-subscribed-notifications:no-such-subscription";
    sub.stop_time = stop;
    sub.type = type;

    /* create sysrepo subscriptions and type-specific data */
    switch (type) {
    case SUB_TYPE_CFG_SUB:
    case SUB_TYPE_DYN_SUB:
        rc = sub_ntf_rpc_establish_sub_prepare(session, input, &sub);
        break;
    case SUB_TYPE_CFG_YANG_PUSH:
    case SUB_TYPE_DYN_YANG_PUSH:
        rc = yang_push_rpc_establish_sub_prepare(session, input, &sub);
        break;
    }
    if (rc) {
        goto error;
    }

    /* WRITE LOCK */
    INFO_WLOCK;

    /* add into subscriptions, is not accessible before */
    sub_ntf_add(&sub);

    /* UNLOCK */
    INFO_UNLOCK;

    /* READ LOCK */
    INFO_RLOCK;

    /* find the subscription in case it moved when the lock was released */
    sub_p = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub_p) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto error_unlock;
    }

    /* start even asynchronous tasks that may access subscriptions and require read lock to be held now */
    switch (type) {
    case SUB_TYPE_CFG_SUB:
    case SUB_TYPE_DYN_SUB:
        rc = sub_ntf_rpc_establish_sub_start_async(session, sub_p);
        break;
    case SUB_TYPE_CFG_YANG_PUSH:
    case SUB_TYPE_DYN_YANG_PUSH:
        rc = yang_push_rpc_establish_sub_start_async(session, sub_p);
        break;
    }
    if (rc) {
        goto error_unlock;
    }

    /* UNLOCK */
    INFO_UNLOCK;

    /* generate output */
    if (output) {
        sprintf(id_str, "%" PRIu32, nc_sub_id);
        if (lyd_new_term(output, NULL, "id", id_str, 1, NULL)) {
            rc = SR_ERR_LY;
            goto error;
        }
    }
    /* TODO "replay-start-time-revision" - sent only if the earliest (theoretical) stored notif is later than start-time */

    return SR_ERR_OK;

error_unlock:
    --info.count;

    /* UNLOCK */
    INFO_UNLOCK;

error:
    if (ntf_status && ncs) {
        nc_session_dec_notif_status(ncs);
    }
    return rc;
}

/**
 * @brief Return the receiver info found with its name.
 *
 * @param[in] recv_info the receiver info of a subscription.
 * @param[in] name the name of the receiver.
 * @return the found receiver info or NULL.
 */
static struct csn_receiver *
csn_receiver_get_by_name(struct csn_receiver_info *recv_info, const char *name)
{
    uint32_t r;

    for (r = 0; r < recv_info->count; r++) {
        if (!strcmp(name, recv_info->receivers[r].name)) {
            return &recv_info->receivers[r];
        }
    }

    return NULL;
}

/**
 * @brief Destroy content of receiver in a subscription
 *
 * @param[in] receiver in the subscription in the receiver_info.
 * @param[in] keep_ref 0: only the udp connection is destroyed, for restart, 1: everything is deleted.
 */
static void
csn_receiver_destroy(struct csn_receiver *receiver, int keep_ref)
{
    if (!receiver) {
        return;
    }

    if (!keep_ref) {
        free(receiver->name);
        receiver->name = NULL;

        free(receiver->instance_ref);
        receiver->instance_ref = NULL;
    }

    free_sender_socket(receiver->udp.sender);
    receiver->udp.sender = NULL;

    free(receiver->udp.options.address);
    receiver->udp.options.address = NULL;

    free(receiver->udp.options.port);
    receiver->udp.options.port = NULL;

    free(receiver->udp.options.interface);
    receiver->udp.options.interface = NULL;

    free(receiver->udp.options.local_address);
    receiver->udp.options.local_address = NULL;
}

/**
 * @brief Start a receiver to send udp notification
 *
 * @param[in,out] receiver the receiver to configure and start.
 * @param[in] recv_config the configuration of this receiver.
 * @param[in] recv_info, the receiver info structure in the subscription.
 * @return 0 on success, -1 on error.
 */
static int
csn_receiver_start(struct csn_receiver *receiver, struct csn_receiver_config *recv_config,
        struct csn_receiver_info *recv_info)
{
    receiver->state = CSN_RECEIVER_STATE_CONNECTING;
    receiver->reset_time = np_gettimespec(1);

    receiver->udp.options.default_mtu = 1500;
    receiver->udp.options.address = strdup(recv_config->udp.address);
    if (!receiver->udp.options.address) {
        EMEM;
        goto error;
    }

    receiver->udp.options.port = strdup(recv_config->udp.port);
    if (!receiver->udp.options.port) {
        EMEM;
        goto error;
    }

    if (recv_info->local_address) {
        receiver->udp.options.local_address = strdup(recv_info->local_address);
        if (!receiver->udp.options.local_address) {
            EMEM;
            goto error;
        }
    }

    if (recv_info->interface) {
        receiver->udp.options.interface = strdup(recv_info->interface);
        if (!receiver->udp.options.interface) {
            EMEM;
            goto error;
        }
    }

    receiver->udp.sender = unyte_start_sender(&receiver->udp.options);
    if (!receiver->udp.sender) {
        ERR("Cannot create udp sender: (%s).", strerror(errno));
        goto error;
    }

    receiver->state = CSN_RECEIVER_STATE_ACTIVE;

    return 0;

error:
    free(receiver->udp.options.address);
    free(receiver->udp.options.port);
    free(receiver->udp.options.interface);
    free(receiver->udp.options.local_address);
    return -1;
}

/**
 * @brief add a receiver in the receiver_info list
 *
 * @param[in] receiver in the subscription in the receiver_info.
 * @param[in] receiver_info in the subscription.
 * @return 0 on success, -1 on error.
 */
static int
csn_receiver_add(struct csn_receiver_info *recv_info, struct csn_receiver *receiver)
{
    void *mem;

    mem = realloc(recv_info->receivers, (recv_info->count + 1) * sizeof *receiver);
    if (!mem) {
        return -1;
    }

    recv_info->receivers = mem;

    recv_info->receivers[recv_info->count] = *receiver;
    ++recv_info->count;

    return 0;
}

/**
 * @brief Look for a receiver config according to its name.
 *
 * @param[in] name the name of the receiver config.
 * @return the found receiver config or NULL.
 */
static struct csn_receiver_config *
csn_receiver_config_get_by_name(const char *name)
{
    uint32_t r;

    for (r = 0; r < info.recv_cfg_count; r++) {
        if (!strcmp(name, info.recv_configs[r].instance_name)) {
            return &info.recv_configs[r];
        }
    }

    return NULL;
}

/**
 * @brief Add a receiver to a subscription.
 *
 * @param[in] node_receiver the configuration of the receiver.
 * @param[in] recv_info the receivers info of this subscription.
 * @param[in] nc_sub_id the subscription id of this configured subscription.
 * @return Sysrepo error value.
 */
static int
csn_add_sub_receivers_prepare(const struct lyd_node *node_receiver,
        struct csn_receiver_info *recv_info, uint32_t nc_sub_id)
{
    struct csn_receiver_config *recv_config = NULL;
    struct csn_receiver *receiver_search = NULL;
    struct lyd_node *node_receiver_name;
    struct lyd_node *node_receiver_ref;
    struct csn_receiver receiver = {0};
    int rc = SR_ERR_OK;

    if (lyd_find_path(node_receiver, "name", 0, &node_receiver_name)) {
        ERR("Missing receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (lyd_find_path(node_receiver, "ietf-subscribed-notif-receivers:receiver-instance-ref", 0, &node_receiver_ref)) {
        ERR("Missing receiver instance ref.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    receiver_search = csn_receiver_get_by_name(recv_info, lyd_get_value(node_receiver_name));
    if (receiver_search) {
        WRN("Receiver already existing.");
        goto cleanup;
    }

    receiver.name = strdup(lyd_get_value(node_receiver_name));
    if (!receiver.name) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    receiver.instance_ref = strdup(lyd_get_value(node_receiver_ref));
    if (!receiver.instance_ref) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    recv_config = csn_receiver_config_get_by_name(lyd_get_value(node_receiver_ref));
    if (!recv_config) {
        ERR("Cannot get receiver config.");
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    rc = csn_receiver_start(&receiver, recv_config, recv_info);
    if (rc) {
        ERR("Cannot init receiver.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (csn_send_notif_one(&receiver, nc_sub_id, "started")) {
        WRN("Could not send notification <subscription-started>.");
    }

    rc = csn_receiver_add(recv_info, &receiver);
    if (rc) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

cleanup:
    if (rc) {
        csn_receiver_destroy(&receiver, 0);
    }

    return rc;
}

/**
 * @brief Modify a receiver of a subscription.
 *
 * @param[in] node_receiver the configuration of the receiver.
 * @return Sysrepo error value.
 */
static int
csn_modify_sub_receiver(const struct lyd_node *node_receiver)
{
    const struct lyd_node *input = lyd_parent(lyd_parent(node_receiver));
    struct csn_receiver_info *recv_info = NULL;
    struct csn_receiver_config *recv_config;
    struct lyd_node *node_receiver_ref;
    struct csn_receiver *receiver;
    struct np2srv_sub_ntf *sub;
    struct lyd_node *node;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (lyd_find_path(input, "id", 0, &node)) {
        ERR("id not found.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;
    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        ERR("no such subscription.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (sub->type == SUB_TYPE_CFG_SUB) {
        recv_info = sub_ntf_receivers_info_get(sub->data);
    } else if (sub->type == SUB_TYPE_CFG_YANG_PUSH) {
        recv_info = yang_push_receivers_info_get(sub->data);
    }

    if (!recv_info) {
        ERR("no receivers info.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    if (lyd_find_path(node_receiver, "ietf-subscribed-notif-receivers:receiver-instance-ref", 0, &node_receiver_ref)) {
        ERR("Missing receiver instance ref.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (lyd_find_path(node_receiver, "name", 0, &node)) {
        ERR("Could not find receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    receiver = csn_receiver_get_by_name(recv_info, lyd_get_value(node));
    if (!receiver) {
        ERR("Receiver not found.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    recv_config = csn_receiver_config_get_by_name(lyd_get_value(node_receiver_ref));
    if (!recv_config) {
        ERR("Cannot get receiver config.");
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    if (strcmp(lyd_get_value(node_receiver_ref), receiver->instance_ref)) {

        free(receiver->instance_ref);
        receiver->instance_ref = strdup(lyd_get_value(node_receiver_ref));

        if (csn_send_notif_one(receiver, nc_sub_id, "terminated")) {
            WRN("Could not send notification <subscription-terminated>.");
        }

        csn_receiver_destroy(receiver, 1);

        rc = csn_receiver_start(receiver, recv_config, recv_info);
        if (rc) {
            ERR("Cannot init receiver.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        if (csn_send_notif_one(receiver, nc_sub_id, "started")) {
            WRN("Could not send notification <subscription-started>.");
        }
    }

cleanup:
    return rc;
}

/**
 * @brief add a receiver of a subscription.
 *
 * @param[in] node_receiver the configuration of the receiver.
 * @return Sysrepo error value.
 */
static int
csn_add_sub_receiver(const struct lyd_node *node_receiver)
{
    const struct lyd_node *input = lyd_parent(lyd_parent(node_receiver));
    struct csn_receiver_info *recv_info = NULL;
    struct np2srv_sub_ntf *sub;
    struct lyd_node *node;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (lyd_find_path(input, "id", 0, &node)) {
        ERR("id not found.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;
    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        ERR("no such subscription.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    if (sub->type == SUB_TYPE_CFG_SUB) {
        recv_info = sub_ntf_receivers_info_get(sub->data);
    } else if (sub->type == SUB_TYPE_CFG_YANG_PUSH) {
        recv_info = yang_push_receivers_info_get(sub->data);
    }

    if (!recv_info) {
        ERR("no receivers info.");
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    rc = csn_add_sub_receivers_prepare(node_receiver, recv_info, nc_sub_id);

error:
    return rc;
}

/**
 * @brief Remove a receiver from a subscription using its name.
 *
 * @param[in] recv_info the receivers in the subscription.
 * @param[in] name the name of the receiver.
 * @param[in] nc_sub_id the configured subscription id.
 * @return Sysrepo error value.
 */
static int
csn_receiver_remove_by_name(struct csn_receiver_info *recv_info, const char *name, uint32_t nc_sub_id)
{
    uint32_t r;

    for (r = 0; r < recv_info->count; r++) {

        if (strcmp(name, recv_info->receivers[r].name)) {
            continue;
        }

        if (csn_send_notif_one(&recv_info->receivers[r], nc_sub_id, "terminated")) {
            WRN("Could not send notification <subscription-terminated>.");
        }

        csn_receiver_destroy(&recv_info->receivers[r], 0);

        recv_info->count--;
        if (r < recv_info->count) {
            memmove(&recv_info->receivers[r], &recv_info->receivers[r + 1], (recv_info->count - r) * sizeof *recv_info->receivers);
        } else if (recv_info->count) {
            free(recv_info->receivers);
            recv_info->receivers = NULL;
        }
        return SR_ERR_OK;
    }

    return SR_ERR_INTERNAL;
}

/**
 * @brief Remove a receiver from a subscription.
 *
 * @param[in] node_receiver the information regarding the receiver.
 * @return Sysrepo error value.
 */
static int
csn_delete_sub_receiver(const struct lyd_node *node_receiver)
{
    const struct lyd_node *input = lyd_parent(lyd_parent(node_receiver));
    struct csn_receiver_info *recv_info = NULL;
    struct np2srv_sub_ntf *sub;
    const char *receiver_name;
    struct lyd_node *node;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (lyd_find_path(input, "id", 0, &node)) {
        ERR("id not found.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    if (lyd_find_path(node_receiver, "name", 0, &node)) {
        ERR("Could not find receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    receiver_name = lyd_get_value(node);

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        ERR("no such subscription.");
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    if (sub->type == SUB_TYPE_CFG_SUB) {
        recv_info = sub_ntf_receivers_info_get(sub->data);
    } else if (sub->type == SUB_TYPE_CFG_YANG_PUSH) {
        recv_info = yang_push_receivers_info_get(sub->data);
    }

    if (!recv_info) {
        ERR("no receivers info.");
        rc = SR_ERR_INTERNAL;
        goto error;
    }

    rc = csn_receiver_remove_by_name(recv_info, receiver_name, nc_sub_id);

error:
    return rc;
}

int
np2srv_rpc_establish_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    struct nc_session *ncs;
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* find this NETCONF session */
    if ((rc = np_find_user_sess(session, __func__, &ncs, NULL))) {
        return rc;
    }

    return np2srv_establish_sub(session, input, output, ncs);
}

/**
 * @brief Helpers to get the actual configured subscription config.
 *
 * @param[in] session sysrepo session.
 * @param[in] nc_sub_id the configured subscription id.
 * @return tree of the subscription config on success, NULL on error.
 */
static sr_data_t *
get_sr_config_sub_ntf(sr_session_ctx_t *session, uint32_t nc_sub_id)
{
    sr_data_t *data_node;
    char *xpath;

    if (asprintf(&xpath, "/ietf-subscribed-notifications:subscriptions/subscription[id=%" PRIu32 "]", nc_sub_id) == -1) {
        EMEM;
        return NULL;
    }

    sr_get_subtree(session, xpath, 0, &data_node);
    free(xpath);

    return data_node;
}

/**
 * @brief Establish a new confgured subscription
 *
 * @param[in] session sysrepo session.
 * @param[in] input the data containing the subscription info.
 * @return Sysrepo error value.
 */
static int
csn_add_sub(sr_session_ctx_t *session, const struct lyd_node *input)
{
    return np2srv_establish_sub(session, input, NULL, NULL);
}

/**
 * @brief Delete a receiver config from the list.
 *
 * @param[in] name of the receiver config to remove.
 * @return 0 on success, -1 on error.
 */
static int
csn_receiver_config_remove_by_name(const char *name)
{
    uint32_t r;

    for (r = 0; r < info.recv_cfg_count; r++) {
        if (strcmp(name, info.recv_configs[r].instance_name)) {
            continue;
        }

        if (info.recv_configs[r].udp.address) {
            free(info.recv_configs[r].udp.address);
        }
        if (info.recv_configs[r].udp.port) {
            free(info.recv_configs[r].udp.port);
        }

        --info.recv_cfg_count;
        if (r < info.recv_cfg_count) {
            memmove(&info.recv_configs[r], &info.recv_configs[r + 1],
                    (info.recv_cfg_count - r) * sizeof *info.recv_configs);
        }

        return 0;
    }

    return -1;
}

/**
 * @brief Delete a receiver config from the list.
 *
 * @param[in] input the information regarding the receiver.
 * @return 0 on success, -1 on error.
 */
static int
csn_receiver_config_delete(const struct lyd_node *input)
{
    struct lyd_node *name_node;
    int rc = SR_ERR_OK;

    if (lyd_find_path(input, "name", 0, &name_node)) {
        ERR("Missing receiver name.");
        return SR_ERR_INVAL_ARG;
    }

    /* remove from receivers */
    rc = csn_receiver_config_remove_by_name(lyd_get_value(name_node));
    if (rc) {
        ERR("Cannot remove receiver.");
        return SR_ERR_INTERNAL;
    }

    return rc;
}

/**
 * @brief restart a receiver of all the subscriptions using it.
 *
 * @param[in] recv_config the information regarding the receiver.
 * @return Sysrepo error value.
 */
static int
csn_receivers_restart(struct csn_receiver_config *recv_config)
{
    int rc = SR_ERR_OK;
    uint32_t s;

    /* iterate over all the subscriptions */
    for (s = 0; s < info.count; s++) {
        struct csn_receiver_info *recv_info = NULL;
        uint32_t r;

        if (info.subs[s].type == SUB_TYPE_CFG_SUB) {
            recv_info = sub_ntf_receivers_info_get(info.subs[s].data);
        } else if (info.subs[s].type == SUB_TYPE_CFG_YANG_PUSH) {
            recv_info = yang_push_receivers_info_get(info.subs[s].data);
        }

        if (!recv_info) {
            continue;
        }

        /* restart receivers of this subscription if they match the name */
        for (r = 0; r < recv_info->count; r++) {
            struct csn_receiver *receiver = &recv_info->receivers[r];

            if (strcmp(receiver->instance_ref, recv_config->instance_name)) {
                continue;
            }

            if (csn_send_notif_one(receiver, info.subs[s].nc_sub_id, "terminated")) {
                WRN("Could not send notification <subscription-terminated>.");
            }

            csn_receiver_destroy(receiver, 1);
            rc = csn_receiver_start(receiver, recv_config, recv_info);
            if (rc) {
                ERR("Cannot init receiver.");
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }

            if (csn_send_notif_one(receiver, info.subs[s].nc_sub_id, "started")) {
                WRN("Could not send notification <subscription-started>.");
            }
        }
    }

cleanup:
    return rc;
}

/**
 * @brief Modify a receiver configuration.
 *
 * @param[in] input the information regarding the receiver.
 * @return Sysrepo error value.
 */
static int
csn_receiver_config_modify(const struct lyd_node *input)
{
    struct lyd_node *remote_address_node = NULL;
    struct lyd_node *remote_port_node = NULL;
    struct csn_receiver_config *recv_config;
    struct lyd_node *receiver_node = NULL;
    struct lyd_node *name_node = NULL;
    int rc = SR_ERR_OK;

    if (lyd_find_path(input, "name", 0, &name_node)) {
        ERR("Missing receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    /* get from receivers */
    recv_config = csn_receiver_config_get_by_name(lyd_get_value(name_node));
    if (!recv_config) {
        ERR("Cannot get receiver config.");
        rc = SR_ERR_NOT_FOUND;
        goto error;
    }

    if (lyd_find_path(input, "ietf-udp-notif-transport:udp-notif-receiver", 0, &receiver_node)) {
        ERR("Missing mandatory \"udp-notif-receiver\" leave.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    if (!lyd_find_path(receiver_node, "remote-address", 0, &remote_address_node)) {
        free(recv_config->udp.address);
        recv_config->udp.address = strdup(lyd_get_value(remote_address_node));
        if (!recv_config->udp.address) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto error;
        }
    }

    if (!lyd_find_path(receiver_node, "remote-port", 0, &remote_port_node)) {
        free(recv_config->udp.port);
        recv_config->udp.port = strdup(lyd_get_value(remote_port_node));
        if (!recv_config->udp.port) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            goto error;
        }
    }

    rc = csn_receivers_restart(recv_config);
    if (rc) {
        ERR("Cannot init receivers.");
        goto error;
    }

error:
    return rc;
}

void
csn_receiver_info_destroy(struct csn_receiver_info *recv_info)
{
    uint32_t i;

    if (!recv_info) {
        return;
    }

    free(recv_info->local_address);
    recv_info->local_address = NULL;

    free(recv_info->interface);
    recv_info->interface = NULL;

    if (!recv_info->receivers) {
        return;
    }

    for (i = 0; i < recv_info->count; ++i) {
        csn_receiver_destroy(&recv_info->receivers[i], 0);
    }

    free(recv_info->receivers);
    recv_info->receivers = NULL;
    recv_info->count = 0;
}

/**
 * @brief reset a receiver.
 *
 * @param[in] receiver the receiver to restart.
 * @return 0 on success, -1 on failure.
 */
static int
csn_receiver_reset(struct csn_receiver *receiver)
{
    free_sender_socket(receiver->udp.sender);
    receiver->state = CSN_RECEIVER_STATE_CONNECTING;
    receiver->reset_time = np_gettimespec(1);

    receiver->udp.sender = unyte_start_sender(&receiver->udp.options);
    if (!receiver->udp.sender) {
        ERR("Cannot create udp sender: (%s).", strerror(errno));
        goto error;
    }

    receiver->state = CSN_RECEIVER_STATE_ACTIVE;

    return 0;

error:
    return -1;
}

/**
 * @brief Create a receiver configuration.
 *
 * @param[in] input the information regarding the receiver config.
 * @return Sysrepo error value.
 */
static int
csn_receiver_config_start(const struct lyd_node *input)
{
    struct csn_receiver_config recv_config = {0};
    struct lyd_node *remote_address_node = NULL;
    struct lyd_node *remote_port_node = NULL;
    struct lyd_node *receiver_node = NULL;
    struct lyd_node *name_node = NULL;
    int rc = SR_ERR_OK;

    if (lyd_find_path(input, "name", 0, &name_node)) {
        ERR("Missing receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    recv_config.instance_name = strdup(lyd_get_value(name_node));
    if (!recv_config.instance_name) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto error;
    }

    /* detect type */
    if (lyd_find_path(input, "ietf-udp-notif-transport:udp-notif-receiver", 0, &receiver_node)) {
        ERR("Missing mandatory \"udp-notif-receiver\" leave.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    recv_config.type = CSN_TRANSPORT_UDP;

    if (lyd_find_path(receiver_node, "remote-address", 0, &remote_address_node)) {
        ERR("Missing receiver remote address.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    recv_config.udp.address = strdup(lyd_get_value(remote_address_node));
    if (!recv_config.udp.address) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto error;
    }

    if (lyd_find_path(receiver_node, "remote-port", 0, &remote_port_node)) {
        ERR("Missing receiver remote port.");
        rc = SR_ERR_INVAL_ARG;
        goto error;
    }

    recv_config.udp.port = strdup(lyd_get_value(remote_port_node));
    if (!recv_config.udp.port) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto error;
    }

    /* add into receivers, is not accessible before */
    rc = csn_receiver_config_add(&recv_config);
    if (rc) {
        EMEM;
        rc = SR_ERR_NO_MEMORY;
        goto error;
    }

    return SR_ERR_OK;

error:
    if (recv_config.instance_name) {
        free(recv_config.instance_name);
    }
    if (recv_config.udp.address) {
        free(recv_config.udp.address);
    }
    if (recv_config.udp.port) {
        free(recv_config.udp.port);
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
    case SUB_TYPE_DYN_SUB:
        rc = sub_ntf_notif_modified_append_data(ly_ntf, sub->data);
        break;
    case SUB_TYPE_DYN_YANG_PUSH:
        rc = yang_push_notif_modified_append_data(ly_ntf, sub->data);
        break;
    default:
        rc = SR_ERR_INTERNAL;
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
    case SUB_TYPE_DYN_SUB:
        rc = sub_ntf_rpc_modify_sub(session, input, stop, sub);
        break;
    case SUB_TYPE_DYN_YANG_PUSH:
        rc = yang_push_rpc_modify_sub(session, input, stop, sub);
        break;
    default:
        rc = SR_ERR_INVAL_ARG;
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
    case SUB_TYPE_CFG_SUB:
    case SUB_TYPE_DYN_SUB:
        sub_id_count = ATOMIC_LOAD_RELAXED(sub->sub_id_count);
        for (idx = 0; idx < sub_id_count; ++idx) {
            /* pass the lock to the notification CB, which removes its sub ID, the final one the whole sub */
            sub_id = sub->sub_ids[0];
            sub_ntf_cb_lock_pass(sub_id);
            if (ncs) {
                r = sr_unsubscribe_sub(np2srv.sr_notif_sub, sub_id);
            } else {
                r = sr_unsubscribe_sub(np2srv.sr_cfg_notif_sub, sub_id);
            }
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
    case SUB_TYPE_CFG_YANG_PUSH:
    case SUB_TYPE_DYN_YANG_PUSH:
        for (idx = 0; idx < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++idx) {
            if (ncs) {
                r = sr_unsubscribe_sub(np2srv.sr_data_sub, sub->sub_ids[idx]);
            } else {
                r = sr_unsubscribe_sub(np2srv.sr_cfg_data_sub, sub->sub_ids[idx]);
            }
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }
        break;
    }

    /* terminate any asynchronous tasks */
    switch (sub_type) {
    case SUB_TYPE_CFG_SUB:
    case SUB_TYPE_DYN_SUB:
        sub_ntf_terminate_async(sub->data);
        break;
    case SUB_TYPE_CFG_YANG_PUSH:
    case SUB_TYPE_DYN_YANG_PUSH:
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

    ly_ctx = sr_acquire_context(np2srv.sr_conn);

    /* send the subscription-terminated notification */
    sprintf(buf, "%" PRIu32, sub->nc_sub_id);
    lyd_new_path(NULL, ly_ctx, "/ietf-subscribed-notifications:subscription-terminated/id", buf, 0, &ly_ntf);
    lyd_new_path(ly_ntf, NULL, "reason", sub->term_reason, 0, NULL);

    if (ncs) {
        /* subscription terminated */
        if (nc_session_get_status(ncs) == NC_STATUS_RUNNING) {
            /* send the subscription-terminated notification */
            r = sub_ntf_send_notif(ncs, sub->nc_sub_id, np_gettimespec(1), &ly_ntf, 1);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }
        nc_session_dec_notif_status(ncs);
    } else {
        struct csn_receiver_info *recv_info = NULL;

        /* configured subscription terminated */
        switch (sub_type) {
        case SUB_TYPE_CFG_SUB:
            recv_info = sub_ntf_receivers_info_get(sub->data);
            break;
        case SUB_TYPE_CFG_YANG_PUSH:
            recv_info = yang_push_receivers_info_get(sub->data);
            break;
        default:
            break;
        }

        if (recv_info) {
            r = csn_send_notif(recv_info, sub->nc_sub_id, np_gettimespec(1), &ly_ntf, 1);
            if (r != SR_ERR_OK) {
                rc = r;
            }
        }
    }

    sr_release_context(np2srv.sr_conn);

    /* free the sub */
    free(sub->sub_ids);
    switch (sub->type) {
    case SUB_TYPE_CFG_SUB:
    case SUB_TYPE_DYN_SUB:
        sub_ntf_data_destroy(sub->data);
        break;
    case SUB_TYPE_CFG_YANG_PUSH:
    case SUB_TYPE_DYN_YANG_PUSH:
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
    if ((rc = np_find_user_sess(session, __func__, &ncs, NULL))) {
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

/**
 * @brief Delete a configured subscription.
 *
 * @param[in] session sysrepo session.
 * @param[in] input the information regarding the subscription.
 * @return Sysrepo error value.
 */
static int
csn_delete_sub(sr_session_ctx_t *session, const struct lyd_node *input)
{
    struct np2srv_sub_ntf *sub;
    struct lyd_node *node;
    int r, rc = SR_ERR_OK;
    char *message = NULL;
    uint32_t nc_sub_id;

    /* id */
    if (lyd_find_path(input, "id", 0, &node)) {
        ERR("Could not find subscription id.");
        return SR_ERR_INVAL_ARG;
    }

    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* WRITE LOCK */
    sub = sub_ntf_find(nc_sub_id, 0, 1, 0);
    if (!sub) {
        if (asprintf(&message, "Subscription with ID %" PRIu32 " for the current receiver does not exist.", nc_sub_id) == -1) {
            EMEM;
            rc = SR_ERR_NO_MEMORY;
            return rc;
        }

        np_err_ntf_sub_no_such_sub(session, message);
        ERR("No such subscription.");
        rc = SR_ERR_INVAL_ARG;
        return rc;

    }

    /* terminate the subscription */
    rc = sub_ntf_terminate_sub(sub, NULL);
    if (rc != SR_ERR_OK) {
        ERR("Error on subscription termination.");
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    INFO_UNLOCK;

    free(message);

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
    if ((rc = np_find_user_sess(session, __func__, &ncs, NULL))) {
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
np2srv_config_receivers_cb(sr_session_ctx_t *session,
        uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *UNUSED(path),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter = NULL;
    const struct lyd_node *node;
    int r, rc = SR_ERR_OK;
    sr_change_oper_t op;

    /* WRITE LOCK */
    INFO_WLOCK;
    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/receiver-instances/receiver-instance", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {

        if (op == SR_OP_CREATED) {
            rc = csn_receiver_config_start(node);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        } else if (op == SR_OP_DELETED) {
            rc = csn_receiver_config_delete(node);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }

    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    sr_free_change_iter(iter);

    rc = sr_get_changes_iter(session,
            "/ietf-subscribed-notifications:subscriptions/receiver-instances/receiver-instance/udp-notif-receiver/*",
            &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (op == SR_OP_MODIFIED) {
            rc = csn_receiver_config_modify(lyd_parent(lyd_parent(node)));
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
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
np2srv_config_subscriptions_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(path), sr_event_t event, uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter = NULL;
    const struct lyd_node *node;
    uint32_t last_nc_sub_id = 0;
    sr_data_t *data_node = NULL;
    int r, rc = SR_ERR_OK;
    sr_change_oper_t op;

    if (event != SR_EV_CHANGE) {
        return SR_ERR_OK;
    }

    /* subscribed-notifications */
    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (op == SR_OP_CREATED) {
            rc = csn_add_sub(session, node);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        } else if (op == SR_OP_DELETED) {
            rc = csn_delete_sub(session, node);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }
    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    sr_free_change_iter(iter);

    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription/*", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        struct lyd_node *node_receivers;
        struct lyd_node *node_receiver;
        struct lyd_node *id_node;
        struct lyd_node *config;
        uint32_t nc_sub_id;

        /* handle subscription modification or subscription subset create or delete */
        if (op != SR_OP_MODIFIED) {
            struct lyd_meta *meta = lyd_find_meta(lyd_parent(node)->meta, NULL, "yang:operation");
            if (!meta || (meta->value.enum_item->name[0] != 'n')) {
                continue;
            }
        }

        lyd_find_path(lyd_parent(node), "id", 0, &id_node);
        nc_sub_id = ((struct lyd_node_term *)id_node)->value.uint32;
        if (nc_sub_id == last_nc_sub_id) {
            continue;
        }

        /* restart subscription with actual config */
        data_node = get_sr_config_sub_ntf(session, nc_sub_id);
        if (!data_node || !data_node->tree) {
            ERR("Could not find sub config %" PRIu32 ".", nc_sub_id);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        config = data_node->tree;

        /* delete and create the subscriptions */
        if ((rc = csn_delete_sub(session, lyd_parent(node)))) {
            goto cleanup;
        }
        if ((rc = csn_add_sub(session, config))) {
            goto cleanup;
        }
        if (!lyd_find_path(config, "receivers", 0, &node_receivers)) {
            LY_LIST_FOR(lyd_child(node_receivers), node_receiver) {
                rc = csn_add_sub_receiver(node_receiver);
                if (rc != SR_ERR_OK) {
                    goto cleanup;
                }
            }
        }

        /* save id of modified subscription */
        last_nc_sub_id = nc_sub_id;
        sr_release_data(data_node);
        data_node = NULL;
    }

    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

cleanup:
    sr_release_data(data_node);
    sr_free_change_iter(iter);
    return rc;
}

int
np2srv_config_subscriptions_receivers_cb(sr_session_ctx_t *session,
        uint32_t UNUSED(sub_id), const char *UNUSED(module_name), const char *UNUSED(path),
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *UNUSED(private_data))
{
    sr_change_iter_t *iter = NULL;
    const struct lyd_node *node;
    int r, rc = SR_ERR_OK;
    sr_change_oper_t op;

    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (op == SR_OP_CREATED) {
            rc = csn_add_sub_receiver(node);
            if (rc) {
                goto cleanup;
            }
        } else if (op == SR_OP_DELETED) {
            rc = csn_delete_sub_receiver(node);
            if (rc) {
                goto cleanup;
            }
        }
    }

    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    sr_free_change_iter(iter);

    rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver/*", &iter);
    if (rc != SR_ERR_OK) {
        ERR("Getting changes iter failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

    while ((r = sr_get_change_tree_next(session, iter, &op, &node, NULL, NULL, NULL)) == SR_ERR_OK) {
        if (op == SR_OP_MODIFIED) {
            rc = csn_modify_sub_receiver(lyd_parent(node));
            if (rc) {
                goto cleanup;
            }
        }
    }

    if (r != SR_ERR_NOT_FOUND) {
        rc = r;
        ERR("Getting next change failed (%s).", sr_strerror(rc));
        goto cleanup;
    }

cleanup:

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
    char *name = NULL;
    uint32_t id;

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
        case SUB_TYPE_CFG_SUB:
        case SUB_TYPE_DYN_SUB:
            rc = sub_ntf_oper_subscription(list, sub->data);
            break;
        case SUB_TYPE_CFG_YANG_PUSH:
        case SUB_TYPE_DYN_YANG_PUSH:
            rc = yang_push_oper_subscription(list, sub->data);
            break;
        default:
            rc = SR_ERR_NOT_FOUND;
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

        switch (sub->type) {
        case SUB_TYPE_CFG_SUB:
        case SUB_TYPE_CFG_YANG_PUSH:
            id = sub->nc_sub_id;
            name = "CONFIG notif";
            break;
        case SUB_TYPE_DYN_SUB:
        case SUB_TYPE_DYN_YANG_PUSH:
        default:
            id = sub->nc_id;
            name = "NETCONF session";
            break;
        }

        /* receivers */
        if (asprintf(&path, "receivers/receiver[name='%s %u']", name, id) == -1) {
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
        case SUB_TYPE_CFG_SUB:
        case SUB_TYPE_DYN_SUB:
            excluded_count = sub_ntf_oper_receiver_excluded(sub);
            break;
        case SUB_TYPE_CFG_YANG_PUSH:
        case SUB_TYPE_DYN_YANG_PUSH:
            excluded_count = yang_push_oper_receiver_excluded(sub);
            break;
        default:
            rc = SR_ERR_NOT_FOUND;
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

int
sub_ntf_create_timer(void (*cb)(union sigval), void *arg, int force_real, timer_t *timer_id)
{
    struct sigevent sevp = {0};

    sevp.sigev_notify = SIGEV_THREAD;
    sevp.sigev_value.sival_ptr = arg;
    sevp.sigev_notify_function = cb;
    if (force_real) {
        if (timer_create(CLOCK_REALTIME, &sevp, timer_id) == -1) {
            return SR_ERR_SYS;
        }
    } else {
        if (timer_create(COMPAT_CLOCK_ID, &sevp, timer_id) == -1) {
            return SR_ERR_SYS;
        }
    }

    return SR_ERR_OK;
}

int
np2srv_rpc_reset_receiver_cb(sr_session_ctx_t *UNUSED(session), uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    struct csn_receiver_info *recv_info = NULL;
    struct csn_receiver *receiver = NULL;
    struct np2srv_sub_ntf *sub;
    const char *receiver_name;
    struct lyd_node *node;
    char *time_str = NULL;
    int r, rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    /* WLOCK */
    INFO_WLOCK;

    if (lyd_find_path(lyd_parent(input), "name", 0, &node)) {
        ERR("Could not find receiver name.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    receiver_name = lyd_get_value(node);

    input = lyd_parent(lyd_parent(lyd_parent(input)));

    if (lyd_find_path(input, "id", 0, &node)) {
        ERR("Could not find subscription id.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    sub = sub_ntf_find(nc_sub_id, 0, 0, 0);
    if (!sub) {
        ERR("Subscription not found.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    switch (sub->type) {
    case SUB_TYPE_CFG_SUB:
        recv_info = sub_ntf_receivers_info_get(sub->data);
        break;
    case SUB_TYPE_CFG_YANG_PUSH:
        recv_info = yang_push_receivers_info_get(sub->data);
        break;
    default:
        ERR("Bad subscription type.");
        break;
    }

    if (!recv_info) {
        ERR("Receiver info not found.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    receiver = csn_receiver_get_by_name(recv_info, receiver_name);
    if (!receiver) {
        ERR("Receiver not found.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (csn_send_notif_one(receiver, nc_sub_id, "terminated")) {
        WRN("Could not send notification <subscription-terminated>.");
    }

    if (csn_receiver_reset(receiver)) {
        ERR("Receiver could not be reset.");
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    if (csn_send_notif_one(receiver, nc_sub_id, "started")) {
        WRN("Could not send notification <subscription-started>.");
    }

    if (output) {
        ly_time_ts2str(&receiver->reset_time, &time_str);
        if (lyd_new_term(output, NULL, "time", time_str, 1, NULL)) {
            ERR("Could not add time.");
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    free(time_str);
    /* UNLOCK */
    INFO_UNLOCK;

    return rc;
}

