/**
 * @file yang_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications ietf-yang-push callbacks
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

#include "yang_push.h"

#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "netconf_acm.h"
#include "netconf_subscribed_notifications.h"

/**
 * @brief Transform yang-push operation into string.
 *
 * @param[in] op yang-push operation.
 * @return String operation name.
 */
static const char *
yang_push_op2str(enum yang_push_op op)
{
    switch (op) {
    case YP_OP_CREATE:
        return "create";
    case YP_OP_DELETE:
        return "delete";
    case YP_OP_INSERT:
        return "insert";
    case YP_OP_MOVE:
        return "move";
    case YP_OP_REPLACE:
        return "replace";
    case YP_OP_OPERATION_COUNT:
        break;
    }

    EINT;
    return NULL;
}

/**
 * @brief Transform string into a yang-push operation.
 *
 * @param[in] str Operation string.
 * @return yang-push operation.
 */
static enum yang_push_op
yang_push_str2op(const char *str)
{
    if (!strcmp(str, "create")) {
        return YP_OP_CREATE;
    } else if (!strcmp(str, "delete")) {
        return YP_OP_DELETE;
    } else if (!strcmp(str, "insert")) {
        return YP_OP_INSERT;
    } else if (!strcmp(str, "move")) {
        return YP_OP_MOVE;
    } else if (!strcmp(str, "replace")) {
        return YP_OP_REPLACE;
    }

    EINT;
    return 0;
}

/**
 * @brief Transform a string identity into a datastore.
 *
 * @param[in] str Identity.
 * @param[out] ds Datastore.
 * @return Sysrepo error value.
 */
static int
yang_push_ident2ds(const char *str, sr_datastore_t *ds)
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
    }

    return SR_ERR_UNSUPPORTED;
}

/**
 * @brief Transform a datastore into a string identity.
 *
 * @param[in] str Identity.
 * @param[out] ds Datastore.
 * @return Sysrepo error value.
 */
static const char *
yang_push_ds2ident(sr_datastore_t ds)
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
    }

    return NULL;
}

/**
 * @brief Transform operation from sysrepo to yang-push.
 *
 * @param[in] op Sysrepo operation.
 * @param[in] node Changed node returned by sysrepo.
 * @return yang-push operation.
 */
static enum yang_push_op
yang_push_op_sr2yp(sr_change_oper_t op, const struct lyd_node *node)
{
    switch (op) {
    case SR_OP_CREATED:
        if (lysc_is_userordered(node->schema)) {
            return YP_OP_INSERT;
        }
        return YP_OP_CREATE;
    case SR_OP_MODIFIED:
        return YP_OP_REPLACE;
    case SR_OP_DELETED:
        return YP_OP_DELETE;
    case SR_OP_MOVED:
        return YP_OP_MOVE;
    }

    EINT;
    return 0;
}

/**
 * @brief Remove any previous edits in a YANG patch of a target.
 *
 * @param[in] ly_yp YANG patch node.
 * @param[in] target Target edits to remove.
 * @return Sysrepo error value.
 */
static int
yang_push_notif_change_edit_clear_target(struct lyd_node *ly_yp, const char *target)
{
    int rc = SR_ERR_OK;
    struct ly_set *set = NULL;
    char quot, *xpath = NULL;

    /* find the edit of this target, be careful with the quotes in the XPath */
    quot = strchr(target, '\'') ? '\"' : '\'';
    if (asprintf(&xpath, "/ietf-yang-push:push-change-update/datastore-changes/yang-patch/edit[target=%c%s%c]",
            quot, target, quot) == -1) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if (lyd_find_xpath(ly_yp, xpath, &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    assert((set->count == 0) || (set->count == 1));

    /* remove the previous change of this target */
    if (set->count) {
        lyd_free_tree(set->dnodes[0]);
    }

cleanup:
    free(xpath);
    ly_set_free(set, NULL);
    return rc;
}

/**
 * @brief Append a new edit (change) to a YANG patch.
 *
 * @param[in] ly_yp YANG patch node to append to.
 * @param[in] yp_op yang-push operation.
 * @param[in] node Changed node.
 * @param[in] prev_value Previous leaf-list value, if any.
 * @param[in] prev_list Previous list value, if any.
 * @param[in] yp_data yang-push data.
 * @return Sysrepo error value.
 */
static int
yang_push_notif_change_edit_append(struct lyd_node *ly_yp, enum yang_push_op yp_op, const struct lyd_node *node,
        const char *prev_value, const char *prev_list, struct yang_push_data *yp_data)
{
    struct lyd_node *ly_edit, *ly_target, *value_tree;
    char buf[26], *path = NULL, *point = NULL, quot;
    uint32_t edit_id;
    int rc = SR_ERR_OK;

    /* get the edit target path */
    path = lyd_path(node, LYD_PATH_STD, NULL, 0);
    if (!path) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* remove any previous change of this target */
    if ((rc = yang_push_notif_change_edit_clear_target(ly_yp, path))) {
        goto cleanup;
    }

    /* generate new edit ID */
    edit_id = ATOMIC_INC_RELAXED(yp_data->edit_id);

    /* edit with edit-id */
    sprintf(buf, "edit-%" PRIu32, edit_id);
    if (lyd_new_list(ly_yp, NULL, "edit", 0, &ly_edit, buf)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* operation */
    if (lyd_new_term(ly_edit, NULL, "operation", yang_push_op2str(yp_op), 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* target */
    if (lyd_new_term(ly_edit, NULL, "target", path, 0, &ly_target)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* remember the node schema */
    ly_target->priv = (void *)node->schema;

    if ((yp_op == YP_OP_INSERT) || (yp_op == YP_OP_MOVE)) {
        /* point */
        if (node->schema->nodetype == LYS_LEAFLIST) {
            assert(prev_value);
            if (prev_value[0]) {
                quot = strchr(prev_value, '\'') ? '\"' : '\'';
                if (asprintf(&point, "%s[.=%c%s%c]", path, quot, prev_value, quot) == -1) {
                    rc = SR_ERR_NO_MEMORY;
                    goto cleanup;
                }
            }
        } else {
            if (prev_list[0]) {
                if (asprintf(&point, "%s%s", path, prev_list) == -1) {
                    rc = SR_ERR_NO_MEMORY;
                    goto cleanup;
                }
            }
        }
        if (point && lyd_new_term(ly_edit, NULL, "point", point, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* where */
        if (((node->schema->nodetype == LYS_LEAFLIST) && !prev_value[0]) ||
                ((node->schema->nodetype == LYS_LIST) && !prev_list[0])) {
            if (lyd_new_term(ly_edit, NULL, "where", "first", 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        } else {
            if (lyd_new_term(ly_edit, NULL, "where", "after", 0, NULL)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }
    }

    if ((yp_op == YP_OP_INSERT) || (yp_op == YP_OP_CREATE) || (yp_op == YP_OP_REPLACE)) {
        /* duplicate value tree without metadata */
        if (lyd_dup_single(node, NULL, LYD_DUP_RECURSIVE | LYD_DUP_NO_META | LYD_DUP_WITH_FLAGS, &value_tree)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }

        /* value */
        if (lyd_new_any(ly_edit, NULL, "value", value_tree, 1, LYD_ANYDATA_DATATREE, 0, NULL)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(point);
    if (rc) {
        ERR("Failed to store data edit for an on-change notification.");
    }
    return rc;
}

/**
 * @brief Send an on-change push-change-update yang-push notification.
 *
 * @param[in] ncs NETCONF session.
 * @param[in] yp_data yang-push data with the notification.
 * @param[in] nc_sub_id NC sub ID of the subscription.
 * @return Sysrepo error value.
 */
static int
yang_push_notif_change_send(struct nc_session *ncs, struct yang_push_data *yp_data, uint32_t nc_sub_id)
{
    struct ly_set *set = NULL;
    int all_removed = 0;
    int rc = SR_ERR_OK;

    assert(yp_data->change_ntf);

    /* NACM filtering */
    if (lyd_find_xpath(yp_data->change_ntf->tree, "/ietf-yang-push:push-change-update/datastore-changes/yang-patch/edit",
            &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    ncac_check_yang_push_update_notif(nc_session_get_username(ncs), set, &all_removed);

    if (all_removed) {
        /* no change is actually readable, notification denied */
        sub_ntf_inc_denied(nc_sub_id);
        goto cleanup;
    }

    /* send the notification */
    rc = sub_ntf_send_notif(ncs, nc_sub_id, np_gettimespec(1), &yp_data->change_ntf->tree, 1);

    if (rc == SR_ERR_OK) {
        /* set last_notif timestamp */
        yp_data->last_notif = np_gettimespec(1);
    }

cleanup:
    ly_set_free(set, NULL);
    sr_release_data(yp_data->change_ntf);
    yp_data->change_ntf = NULL;
    return rc;
}

/**
 * @brief Timer callback for dampened on-change yang-push changes.
 */
static void
yang_push_damp_timer_cb(union sigval sval)
{
    struct yang_push_cb_arg *arg = sval.sival_ptr;

    /* READ LOCK */
    if (!sub_ntf_find_lock(arg->nc_sub_id, 0, 0)) {
        return;
    }

    /* NOTIF LOCK */
    pthread_mutex_lock(&arg->yp_data->notif_lock);

    /* send the postponed on-change notification */
    yang_push_notif_change_send(arg->ncs, arg->yp_data, arg->nc_sub_id);

    /* NOTIF UNLOCK */
    pthread_mutex_unlock(&arg->yp_data->notif_lock);

    /* UNLOCK */
    sub_ntf_unlock(0);
}

/**
 * @brief Check whether an on-change yang-push notification is ready to be sent or will be postponed.
 *
 * @param[in] yp_data yang-push data.
 * @param[out] ready Whether the notification can be sent or was scheduled to be sent later.
 * @return Sysrepo error value.
 */
static int
yang_push_notif_change_ready(struct yang_push_data *yp_data, int *ready)
{
    struct timespec next_notif, cur_time;
    int32_t next_notif_in;
    struct itimerspec trspec;

    if (!yp_data->dampening_period_ms) {
        /* always ready */
        *ready = 1;
        return SR_ERR_OK;
    }

    /* check current timer */
    if (timer_gettime(yp_data->damp_timer, &trspec) == -1) {
        return SR_ERR_SYS;
    }
    if (trspec.it_value.tv_sec || trspec.it_value.tv_nsec) {
        /* timer is already set */
        *ready = 0;
        return SR_ERR_OK;
    }

    /* learn when the next notification is due */
    cur_time = np_gettimespec(1);
    next_notif = yp_data->last_notif;
    np_addtimespec(&next_notif, yp_data->dampening_period_ms);
    next_notif_in = np_difftimespec(&cur_time, &next_notif);

    if (next_notif_in <= 0) {
        /* can be sent */
        *ready = 1;
        return SR_ERR_OK;
    }

    /* schedule the notification */
    trspec.it_value = next_notif;
    if (timer_settime(yp_data->damp_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
        return SR_ERR_SYS;
    }

    *ready = 0;
    return SR_ERR_OK;
}

/**
 * @brief Module change callback for yang-push changes.
 */
static int
np2srv_change_yang_push_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *module_name,
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *private_data)
{
    struct yang_push_cb_arg *arg = private_data;
    char *xp = NULL, buf[26];
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const struct ly_ctx *ly_ctx = NULL;
    struct lyd_node *ly_yp = NULL;
    const char *prev_value, *prev_list;
    enum yang_push_op yp_op;
    int ready, r;
    uint32_t patch_id;

    assert(!arg->yp_data->periodic);

    if (xpath) {
        r = asprintf(&xp, "%s//.", xpath);
    } else {
        r = asprintf(&xp, "/%s:*//.", module_name);
    }
    if (r == -1) {
        EMEM;
        goto cleanup;
    }
    if (sr_get_changes_iter(session, xp, &iter) != SR_ERR_OK) {
        goto cleanup;
    }

    /* NOTIF LOCK */
    pthread_mutex_lock(&arg->yp_data->notif_lock);

    while (sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, NULL) == SR_ERR_OK) {
        /* learn yang-push operation */
        yp_op = yang_push_op_sr2yp(op, node);
        if (arg->yp_data->excluded_change[yp_op]) {
            /* excluded */
            ATOMIC_INC_RELAXED(arg->yp_data->excluded_op_count);
            continue;
        }

        /* there is a change */
        if (!arg->yp_data->change_ntf) {
            /* store as SR data with context lock, is unlocked on error */
            ly_ctx = sr_acquire_context(np2srv.sr_conn);
            if (sr_acquire_data(np2srv.sr_conn, NULL, &arg->yp_data->change_ntf)) {
                goto cleanup_unlock;
            }

            /* create basic structure for push-change-update notification */
            sprintf(buf, "%" PRIu32, arg->nc_sub_id);
            if (lyd_new_path(NULL, ly_ctx, "/ietf-yang-push:push-change-update/id", buf, 0,
                    &arg->yp_data->change_ntf->tree)) {
                goto cleanup_unlock;
            }

            /* generate a new patch-id */
            patch_id = ATOMIC_INC_RELAXED(arg->yp_data->patch_id);
            sprintf(buf, "patch-%" PRIu32, patch_id);
            if (lyd_new_path(arg->yp_data->change_ntf->tree, NULL, "datastore-changes/yang-patch/patch-id", buf, 0, NULL)) {
                goto cleanup_unlock;
            }

            /* initialize edit-id */
            ATOMIC_STORE_RELAXED(arg->yp_data->edit_id, 1);
        }
        if (!ly_yp) {
            ly_yp = lyd_child(lyd_child(arg->yp_data->change_ntf->tree)->next);
        }

        /* append a new edit */
        if (yang_push_notif_change_edit_append(ly_yp, yp_op, node, prev_value, prev_list, arg->yp_data)) {
            goto cleanup_unlock;
        }
    }

    if (!arg->yp_data->change_ntf) {
        /* there are actually no changes */
        goto cleanup_unlock;
    }

    /* check whether the notification can be sent now */
    if (yang_push_notif_change_ready(arg->yp_data, &ready)) {
        goto cleanup_unlock;
    }

    /* send the notification */
    if (ready && yang_push_notif_change_send(arg->ncs, arg->yp_data, arg->nc_sub_id)) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* NOTIF UNLOCK */
    pthread_mutex_unlock(&arg->yp_data->notif_lock);

cleanup:
    free(xp);
    sr_free_change_iter(iter);

    /* return value is ignored anyway */
    return SR_ERR_OK;
}

/**
 * @brief Subscribe to module changes of a module.
 *
 * @param[in] ly_mod Module to subscribe to.
 * @param[in] user_sess User sysrepo session.
 * @param[in] xpath XPath filter to use.
 * @param[in] private_data Private data to set for the callback.
 * @param[in] ev_sess Event sysrepo session for errors.
 * @param[in,out] sub_ids Array of SR sub IDs to add to.
 * @param[in,out] sub_id_count Number of items in @p sub_ids.
 * @return Sysrepo error value.
 */
static int
yang_push_sr_subscribe_mod(const struct lys_module *ly_mod, sr_session_ctx_t *user_sess, const char *xpath,
        void *private_data, sr_session_ctx_t *ev_sess, uint32_t **sub_ids, uint32_t *sub_id_count)
{
    void *mem;
    const sr_error_info_t *err_info;
    int rc;

    /* allocate a new sub ID */
    mem = realloc(*sub_ids, (*sub_id_count + 1) * sizeof **sub_ids);
    if (!mem) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }
    *sub_ids = mem;

    /* subscribe to the module */
    rc = sr_module_change_subscribe(user_sess, ly_mod->name, xpath, np2srv_change_yang_push_cb, private_data,
            0, SR_SUBSCR_PASSIVE | SR_SUBSCR_DONE_ONLY, &np2srv.sr_data_sub);
    if (rc != SR_ERR_OK) {
        sr_session_get_error(user_sess, &err_info);
        sr_session_set_error_message(ev_sess, err_info->err[0].message);
        return rc;
    }

    /* add new sub ID */
    (*sub_ids)[*sub_id_count] = sr_subscription_get_last_sub_id(np2srv.sr_data_sub);
    ++(*sub_id_count);

    return SR_ERR_OK;
}

/**
 * @brief Collect all modules with data selected by an XPath.
 *
 * @param[in] ly_ctx libyang context.
 * @param[in] xpath XPath filter.
 * @param[in] config_mask Config mask for relevant nodes.
 * @param[out] mod_set Set with all the relevant modules.
 * @return Sysrepo error value.
 */
static int
yang_push_sr_subscribe_filter_collect_mods(const struct ly_ctx *ly_ctx, const char *xpath, uint32_t config_mask,
        struct ly_set **mod_set)
{
    const struct lys_module *ly_mod;
    const struct lysc_node *snode;
    struct ly_set *set = NULL;
    uint32_t i;
    int rc = SR_ERR_OK;

    /* learn what nodes are needed for evaluation */
    if (lys_find_xpath_atoms(ly_ctx, NULL, xpath, 0, &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* allocate new set */
    if (ly_set_new(mod_set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* add all the modules of the nodes */
    ly_mod = NULL;
    for (i = 0; i < set->count; ++i) {
        snode = set->snodes[i];

        /* skip uninteresting nodes */
        if ((snode->nodetype & (LYS_RPC | LYS_NOTIF)) || !(snode->flags & config_mask)) {
            continue;
        }

        if (snode->module == ly_mod) {
            /* skip already-added modules */
            continue;
        }
        ly_mod = snode->module;

        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
            /* skip import-only modules, sysrepo, and ietf-netconf (as it has no data, only in libyang) */
            continue;
        }

        ly_set_add(*mod_set, (void *)ly_mod, 0, NULL);
    }

cleanup:
    ly_set_free(set, NULL);
    return rc;
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
yang_push_sr_subscribe(sr_session_ctx_t *user_sess, sr_datastore_t ds, const char *xpath, void *private_data,
        sr_session_ctx_t *ev_sess, uint32_t **sub_ids, uint32_t *sub_id_count)
{
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    struct ly_set *mod_set = NULL;
    int rc;
    uint32_t idx, config_mask = (ds == SR_DS_OPERATIONAL) ? LYS_CONFIG_MASK : LYS_CONFIG_W;

    ly_ctx = sr_session_acquire_context(user_sess);

    *sub_ids = NULL;
    *sub_id_count = 0;

    /* switch to the correct datastore */
    sr_session_switch_ds(user_sess, ds);

    if (!xpath) {
        /* subscribe to all modules with (configuration) data */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
                continue;
            }

            if (np_ly_mod_has_data(ly_mod, config_mask)) {
                /* subscribe to the module */
                rc = yang_push_sr_subscribe_mod(ly_mod, user_sess, xpath, private_data, ev_sess, sub_ids, sub_id_count);
                if (rc != SR_ERR_OK) {
                    goto error;
                }
            }
        }
    } else {
        /* subscribe to all the relevant modules with the filter */
        rc = yang_push_sr_subscribe_filter_collect_mods(ly_ctx, xpath, config_mask, &mod_set);
        if (rc != SR_ERR_OK) {
            goto error;
        }

        for (idx = 0; idx < mod_set->count; ++idx) {
            /* subscribe to the module */
            rc = yang_push_sr_subscribe_mod(mod_set->objs[idx], user_sess, xpath, private_data, ev_sess, sub_ids,
                    sub_id_count);
            if (rc != SR_ERR_OK) {
                goto error;
            }
        }
    }

    sr_session_release_context(user_sess);
    ly_set_free(mod_set, NULL);
    return SR_ERR_OK;

error:
    sr_session_release_context(user_sess);
    ly_set_free(mod_set, NULL);

    for (idx = 0; idx < *sub_id_count; ++idx) {
        sr_unsubscribe_sub(np2srv.sr_data_sub, (*sub_ids)[idx]);
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
 * @param[out] selection_filter_ref Node value, if this filter was present.
 * @param[out] datastore_subtree_filter Duplicated node, if this filter was present.
 * @param[out] datastore_xpath_filter Node value, if this filter was present.
 * @return Sysrepo error value.
 */
static int
yang_push_rpc_filter2xpath(sr_session_ctx_t *user_sess, const struct lyd_node *rpc, sr_session_ctx_t *ev_sess,
        char **xpath, const char **selection_filter_ref, struct lyd_node **datastore_subtree_filter,
        const char **datastore_xpath_filter)
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
    if (selection_filter_ref) {
        *selection_filter_ref = NULL;
    }
    if (datastore_subtree_filter) {
        *datastore_subtree_filter = NULL;
    }
    if (datastore_xpath_filter) {
        *datastore_xpath_filter = NULL;
    }

    /* find the filter node */
    lyd_find_xpath(rpc, "ietf-yang-push:selection-filter-ref | ietf-yang-push:datastore-subtree-filter"
            " | ietf-yang-push:datastore-xpath-filter", &nodeset);
    if (nodeset->count) {
        node = nodeset->dnodes[0];
    }
    ly_set_free(nodeset, NULL);

    if (!node) {
        /* nothing to do */
        return SR_ERR_OK;
    }

    /* first remember the exact filter used */
    if (!strcmp(node->schema->name, "selection-filter-ref")) {
        if (selection_filter_ref) {
            *selection_filter_ref = lyd_get_value(node);
        }
    } else if (!strcmp(node->schema->name, "datastore-subtree-filter")) {
        if (datastore_subtree_filter) {
            *datastore_subtree_filter = node;
        }
    } else {
        assert(!strcmp(node->schema->name, "datastore-xpath-filter"));
        if (datastore_xpath_filter) {
            *datastore_xpath_filter = lyd_get_value(node);
        }
    }

    if (!strcmp(node->schema->name, "selection-filter-ref")) {
        /* first get this filter from sysrepo */
        if (asprintf(&str, "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter[filter-id='%s']",
                lyd_get_value(node)) == -1) {
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
            ERR("Selection filter \"%s\" does not define any actual filter.", lyd_get_value(node));
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }
        node = lyd_child(subtree->tree)->next;
    }

    if (!strcmp(node->schema->name, "datastore-subtree-filter")) {
        /* subtree */
        if (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_DATATREE) {
            if (op_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, &filter)) {
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            if ((rc = op_filter_filter2xpath(&filter, xpath))) {
                goto cleanup;
            }
        }
    } else {
        /* xpath */
        assert(!strcmp(node->schema->name, "datastore-xpath-filter"));
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
 * @brief Send a push-update yang-push notification.
 *
 * @param[in] ncs NETCONF session.
 * @param[in] yp_data yang-push data with the datastore, filter, and counters.
 * @param[in] nc_sub_id NC sub ID of the subscription.
 * @return Sysrepo error value.
 */
static int
yang_push_notif_update_send(struct nc_session *ncs, struct yang_push_data *yp_data, uint32_t nc_sub_id)
{
    struct np2_user_sess *user_sess;
    struct lyd_node *ly_ntf = NULL;
    const struct ly_ctx *ly_ctx;
    sr_data_t *data = NULL;
    char buf[11];
    int rc = SR_ERR_OK;

    /* get user session from NETCONF session */
    user_sess = nc_session_get_data(ncs);
    ATOMIC_INC_RELAXED(user_sess->ref_count);

    /* switch to the datastore */
    sr_session_switch_ds(user_sess->sess, yp_data->datastore);

    /* get the data from sysrepo */
    rc = sr_get_data(user_sess->sess, yp_data->xpath ? yp_data->xpath : "/*", 0, np2srv.sr_timeout, 0, &data);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* NACM filter */
    if (data) {
        ncac_check_data_read_filter(&data->tree, nc_session_get_username(ncs));
    }

    /* context lock is already held by data */
    ly_ctx = sr_acquire_context(np2srv.sr_conn);
    sr_release_context(np2srv.sr_conn);

    /* create the notification */
    sprintf(buf, "%" PRIu32, nc_sub_id);
    if (lyd_new_path(NULL, ly_ctx, "/ietf-yang-push:push-update/id", buf, 0, &ly_ntf)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* datastore-contents */
    if (lyd_new_any(ly_ntf, NULL, "datastore-contents", data ? data->tree : NULL, 1, LYD_ANYDATA_DATATREE, 0, NULL)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    if (data) {
        data->tree = NULL;
    }

    /* send the notification */
    rc = sub_ntf_send_notif(ncs, nc_sub_id, np_gettimespec(1), &ly_ntf, 1);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

cleanup:
    sr_release_data(data);
    lyd_free_tree(ly_ntf);
    np_release_user_sess(user_sess);
    return rc;
}

/**
 * @brief Timer callback for push-update notification of periodic yang-push subscriptions.
 */
static void
yang_push_update_timer_cb(union sigval sval)
{
    struct yang_push_cb_arg *arg = sval.sival_ptr;

    /* READ LOCK */
    if (!sub_ntf_find_lock(arg->nc_sub_id, 0, 0)) {
        return;
    }

    /* send the push-update notification */
    yang_push_notif_update_send(arg->ncs, arg->yp_data, arg->nc_sub_id);

    /* UNLOCK */
    sub_ntf_unlock(0);
}

/**
 * @brief Timer callback for stopping yang-push subscriptions.
 */
static void
yang_push_stop_timer_cb(union sigval sval)
{
    struct yang_push_cb_arg *arg = sval.sival_ptr;
    struct np2srv_sub_ntf *sub;

    /* WRITE LOCK */
    sub = sub_ntf_find_lock(arg->nc_sub_id, 0, 1);
    if (!sub) {
        return;
    }

    /* terminate the subscription */
    sub_ntf_terminate_sub(sub, arg->ncs);

    /* UNLOCK */
    sub_ntf_unlock(0);
}

/**
 * @brief Create a new function timer.
 *
 * @param[in] cb Callback to be called.
 * @param[in] arg Argument for @p cb.
 * @param[in] force_real Whether to force realtime clock ID or can be monotonic if available.
 * @param[out] timer_id Created timer ID.
 * @return Sysrepo error value.
 */
static int
yang_push_create_timer(void (*cb)(union sigval), void *arg, int force_real, timer_t *timer_id)
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
        if (timer_create(NP_CLOCK_ID, &sevp, timer_id) == -1) {
            return SR_ERR_SYS;
        }
    }

    return SR_ERR_OK;
}

int
yang_push_rpc_establish_sub_prepare(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct np2srv_sub_ntf *sub)
{
    struct lyd_node *node, *child, *datastore_subtree_filter = NULL;
    struct nc_session *ncs;
    struct np2_user_sess *user_sess = NULL;
    struct ly_set *set;
    struct yang_push_data *yp_data = NULL;
    const char *selection_filter_ref = NULL, *datastore_xpath_filter = NULL;
    sr_datastore_t datastore;
    char *xp = NULL;
    uint32_t i, period, dampening_period;
    int rc = SR_ERR_OK, periodic, sync_on_start, excluded_change[YP_OP_OPERATION_COUNT] = {0};
    struct timespec anchor_time = {0};

    /* get the NETCONF session and user session */
    if ((rc = np_get_user_sess(ev_sess, &ncs, &user_sess))) {
        goto cleanup;
    }

    /* datastore */
    lyd_find_path(rpc, "ietf-yang-push:datastore", 0, &node);
    rc = yang_push_ident2ds(lyd_get_value(node), &datastore);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(ev_sess, "Unsupported datastore \"%s\".", lyd_get_value(node));
        goto cleanup;
    }

    /* filter, join all into one xpath */
    rc = yang_push_rpc_filter2xpath(user_sess->sess, rpc, ev_sess, &xp, &selection_filter_ref, &datastore_subtree_filter,
            &datastore_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* update-trigger */
    if (!lyd_find_path(rpc, "ietf-yang-push:periodic", 0, &node)) {
        periodic = 1;

        /* period */
        lyd_find_path(node, "period", 0, &child);
        period = ((struct lyd_node_term *)child)->value.uint32;

        /* anchor-time */
        lyd_find_path(node, "anchor-time", 0, &child);
        if (child) {
            ly_time_str2ts(lyd_get_value(child), &anchor_time);
        }
    } else if (!lyd_find_path(rpc, "ietf-yang-push:on-change", 0, &node)) {
        periodic = 0;

        /* dampening-period */
        lyd_find_path(node, "dampening-period", 0, &child);
        dampening_period = ((struct lyd_node_term *)child)->value.uint32;

        /* sync-on-start */
        lyd_find_path(node, "sync-on-start", 0, &child);
        sync_on_start = ((struct lyd_node_term *)child)->value.boolean ? 1 : 0;

        /* excluded-change* */
        if (lyd_find_xpath(node, "excluded-change", &set)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
        for (i = 0; i < set->count; ++i) {
            excluded_change[yang_push_str2op(lyd_get_value(set->dnodes[i]))] = 1;
        }
        ly_set_free(set, NULL);
    } else {
        sr_session_set_error_message(ev_sess, "Unknown update trigger for the yang-push subscription.");
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    /* create specific data */
    sub->data = yp_data = calloc(1, sizeof *yp_data);
    if (!yp_data) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    yp_data->datastore = datastore;
    yp_data->selection_filter_ref = selection_filter_ref ? strdup(selection_filter_ref) : NULL;
    if (datastore_subtree_filter) {
        lyd_dup_single(datastore_subtree_filter, NULL, 0, &yp_data->datastore_subtree_filter);
    } else {
        yp_data->datastore_subtree_filter = NULL;
    }
    yp_data->datastore_xpath_filter = datastore_xpath_filter ? strdup(datastore_xpath_filter) : NULL;
    yp_data->periodic = periodic;

    /* fill xpath filter and callbacks argument */
    if (xp) {
        yp_data->xpath = xp;
        xp = NULL;
    }
    yp_data->cb_arg.ncs = ncs;
    yp_data->cb_arg.yp_data = yp_data;
    yp_data->cb_arg.nc_sub_id = sub->nc_sub_id;

    if (yp_data->periodic) {
        yp_data->period_ms = period * 10;
        yp_data->anchor_time = anchor_time;
    } else {
        yp_data->dampening_period_ms = dampening_period * 10;
        yp_data->sync_on_start = sync_on_start;
        memcpy(yp_data->excluded_change, excluded_change, sizeof excluded_change);

        pthread_mutex_init(&yp_data->notif_lock, NULL);
        ATOMIC_STORE_RELAXED(yp_data->patch_id, 1);
        if (yp_data->dampening_period_ms) {
            /* create dampening timer */
            rc = yang_push_create_timer(yang_push_damp_timer_cb, &yp_data->cb_arg, 1, &yp_data->damp_timer);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }
    if ((selection_filter_ref && !yp_data->selection_filter_ref) ||
            (datastore_subtree_filter && !yp_data->datastore_subtree_filter) ||
            (datastore_xpath_filter && !yp_data->datastore_xpath_filter)) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    if (sub->stop_time.tv_sec) {
        /* create stop timer */
        rc = yang_push_create_timer(yang_push_stop_timer_cb, &yp_data->cb_arg, 1, &yp_data->stop_timer);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

    if (yp_data->periodic) {
        /* create update timer */
        rc = yang_push_create_timer(yang_push_update_timer_cb, &yp_data->cb_arg, 1, &yp_data->update_timer);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

cleanup:
    free(xp);
    np_release_user_sess(user_sess);
    if (rc) {
        yang_push_data_destroy(yp_data);
    }
    return rc;
}

int
yang_push_rpc_establish_sub_start_async(sr_session_ctx_t *ev_sess, struct np2srv_sub_ntf *sub)
{
    struct np2_user_sess *user_sess = NULL;
    struct nc_session *ncs;
    struct yang_push_data *yp_data = sub->data;
    uint32_t sub_id_count;
    int64_t anchor_msec;
    int rc = SR_ERR_OK;
    struct itimerspec trspec = {0};

    /* get the NETCONF session and user session */
    if ((rc = np_get_user_sess(ev_sess, &ncs, &user_sess))) {
        goto cleanup;
    }

    if (sub->stop_time.tv_sec) {
        /* schedule subscription stop */
        trspec.it_value = sub->stop_time;
        if (timer_settime(yp_data->stop_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
            rc = SR_ERR_SYS;
            goto cleanup;
        }
    }

    if (yp_data->periodic) {
        /* schedule the periodic updates */
        trspec.it_value = np_gettimespec(1);
        if (yp_data->anchor_time.tv_sec) {
            /* first update at nearest anchor time on period */
            anchor_msec = np_difftimespec(&yp_data->anchor_time, &trspec.it_value);
            if (anchor_msec < 0) {
                anchor_msec *= -1;
            }
            anchor_msec %= yp_data->period_ms;
            np_addtimespec(&trspec.it_value, anchor_msec);
        }
        trspec.it_interval.tv_sec = yp_data->period_ms / 1000;
        trspec.it_interval.tv_nsec = (yp_data->period_ms % 1000) * 1000000;

        if (timer_settime(yp_data->update_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
            rc = SR_ERR_SYS;
            goto cleanup;
        }
    } else {
        if (yp_data->sync_on_start) {
            /* send the initial update notification */
            rc = yang_push_notif_update_send(ncs, yp_data, sub->nc_sub_id);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }

        /* subscribe to sysrepo module data changes */
        sub_id_count = 0;
        rc = yang_push_sr_subscribe(user_sess->sess, yp_data->datastore, yp_data->xpath, &yp_data->cb_arg, ev_sess,
                &sub->sub_ids, &sub_id_count);
        ATOMIC_STORE_RELAXED(sub->sub_id_count, sub_id_count);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }
    }

cleanup:
    np_release_user_sess(user_sess);
    if (rc) {
        yang_push_data_destroy(yp_data);
    }
    return rc;
}

int
yang_push_rpc_modify_sub(sr_session_ctx_t *ev_sess, const struct lyd_node *rpc, struct timespec stop,
        struct np2srv_sub_ntf *sub)
{
    struct lyd_node *node, *cont, *datastore_subtree_filter = NULL;
    struct np2_user_sess *user_sess = NULL;
    struct yang_push_data *yp_data = sub->data;
    sr_datastore_t datastore;
    const char *selection_filter_ref = NULL, *datastore_xpath_filter = NULL;
    struct itimerspec trspec;
    char *xp = NULL, *datetime = NULL;
    struct timespec anchor_time, next_notif;
    int rc = SR_ERR_OK;
    uint32_t i, period, dampening_period;

    /* get the user session */
    if ((rc = np_get_user_sess(ev_sess, NULL, &user_sess))) {
        goto cleanup;
    }

    /* datastore */
    lyd_find_path(rpc, "ietf-yang-push:datastore", 0, &node);
    if (!node) {
        sr_session_set_error_message(ev_sess, "Subscription with ID %" PRIu32 " is yang-push but \"datastore\""
                " is not set.", sub->nc_sub_id);
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    rc = yang_push_ident2ds(lyd_get_value(node), &datastore);
    if (rc != SR_ERR_OK) {
        sr_session_set_error_message(ev_sess, "Unsupported datastore \"%s\".", lyd_get_value(node));
        goto cleanup;
    } else if (datastore != yp_data->datastore) {
        sr_session_set_error_message(ev_sess, "Subscription with ID %" PRIu32 " is not for \"%s\" datastore.",
                sub->nc_sub_id, lyd_get_value(node));
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /*
     * periodic
     */
    if (!lyd_find_path(rpc, "ietf-yang-push:periodic", 0, &cont)) {
        if (!yp_data->periodic) {
            sr_session_set_error_message(ev_sess, "Subscription with ID %" PRIu32 " is not \"periodic\".",
                    sub->nc_sub_id);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }

        /* period */
        lyd_find_path(cont, "period", 0, &node);
        period = ((struct lyd_node_term *)node)->value.uint32;
        if (period * 10 != yp_data->period_ms) {
            yp_data->period_ms = period * 10;

            /* update the period */
            if (yp_data->anchor_time.tv_sec) {
                trspec.it_value = np_modtimespec(&yp_data->anchor_time, yp_data->period_ms);
            } else {
                trspec.it_value = np_gettimespec(1);
            }
            trspec.it_interval.tv_sec = yp_data->period_ms / 1000;
            trspec.it_interval.tv_nsec = (yp_data->period_ms % 1000) * 1000000;
            if (timer_settime(yp_data->update_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
                rc = SR_ERR_SYS;
                goto cleanup;
            }
        }

        /* anchor-time */
        lyd_find_path(cont, "anchor-time", 0, &node);
        if (node) {
            ly_time_str2ts(lyd_get_value(node), &anchor_time);
            if (memcmp(&anchor_time, &yp_data->anchor_time, sizeof anchor_time)) {
                yp_data->anchor_time = anchor_time;

                /* update the anchor */
                trspec.it_value = np_modtimespec(&yp_data->anchor_time, yp_data->period_ms);
                trspec.it_interval.tv_sec = yp_data->period_ms / 1000;
                trspec.it_interval.tv_nsec = (yp_data->period_ms % 1000) * 1000000;
                if (timer_settime(yp_data->update_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
                    rc = SR_ERR_SYS;
                    goto cleanup;
                }
            }
        }
    }

    /*
     * on-change
     */
    if (!lyd_find_path(rpc, "ietf-yang-push:on-change", 0, &cont)) {
        if (yp_data->periodic) {
            sr_session_set_error_message(ev_sess, "Subscription with ID %" PRIu32 " is not \"on-change\".",
                    sub->nc_sub_id);
            rc = SR_ERR_INVAL_ARG;
            goto cleanup;
        }

        /* dampening-period */
        lyd_find_path(cont, "dampening-period", 0, &node);
        dampening_period = ((struct lyd_node_term *)node)->value.uint32;
        if (dampening_period * 10 != yp_data->dampening_period_ms) {
            if (!yp_data->dampening_period_ms) {
                /* create dampening timer */
                rc = yang_push_create_timer(yang_push_damp_timer_cb, &yp_data->cb_arg, 1, &yp_data->damp_timer);
                if (rc != SR_ERR_OK) {
                    goto cleanup;
                }
            }

            yp_data->dampening_period_ms = dampening_period * 10;

            if (!yp_data->dampening_period_ms) {
                /* delete the dampening timer */
                timer_delete(yp_data->damp_timer);
            } else {
                /* update the dampening timer, if set */
                if (timer_gettime(yp_data->damp_timer, &trspec) == -1) {
                    rc = SR_ERR_SYS;
                    goto cleanup;
                }
                if (trspec.it_value.tv_sec || trspec.it_value.tv_nsec) {
                    /* learn when the next notification is due */
                    next_notif = yp_data->last_notif;
                    np_addtimespec(&next_notif, yp_data->dampening_period_ms);

                    /* schedule the notification */
                    trspec.it_value = next_notif;
                    if (timer_settime(yp_data->damp_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
                        rc = SR_ERR_SYS;
                        goto cleanup;
                    }
                }
            }
        }
    }

    /*
     * filter, join all into one xpath
     */
    rc = yang_push_rpc_filter2xpath(user_sess->sess, rpc, ev_sess, &xp, &selection_filter_ref, &datastore_subtree_filter,
            &datastore_xpath_filter);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    if (xp && (!yp_data->xpath || strcmp(xp, yp_data->xpath))) {
        /* update the filter */
        free(yp_data->xpath);
        yp_data->xpath = xp;
        xp = NULL;

        for (i = 0; i < sub->sub_id_count; ++i) {
            rc = sr_module_change_sub_modify_xpath(np2srv.sr_data_sub, sub->sub_ids[i], yp_data->xpath);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }
    }

    /* update our type-specific filter data */
    free(yp_data->selection_filter_ref);
    lyd_free_tree(yp_data->datastore_subtree_filter);
    free(yp_data->datastore_xpath_filter);

    yp_data->selection_filter_ref = selection_filter_ref ? strdup(selection_filter_ref) : NULL;
    if (datastore_subtree_filter) {
        lyd_dup_single(datastore_subtree_filter, NULL, 0, &yp_data->datastore_subtree_filter);
    } else {
        yp_data->datastore_subtree_filter = NULL;
    }
    yp_data->datastore_xpath_filter = datastore_xpath_filter ? strdup(datastore_xpath_filter) : NULL;
    if ((selection_filter_ref && !yp_data->selection_filter_ref) ||
            (datastore_subtree_filter && !yp_data->datastore_subtree_filter) ||
            (datastore_xpath_filter && !yp_data->datastore_xpath_filter)) {
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /*
     * stop
     */
    if (stop.tv_sec && memcmp(&stop, &sub->stop_time, sizeof stop)) {
        if (!sub->stop_time.tv_sec) {
            /* create stop timer */
            rc = yang_push_create_timer(yang_push_stop_timer_cb, &yp_data->cb_arg, 1, &yp_data->stop_timer);
            if (rc != SR_ERR_OK) {
                goto cleanup;
            }
        }

        /* schedule subscription stop */
        memset(&trspec, 0, sizeof trspec);
        trspec.it_value = stop;
        if (timer_settime(yp_data->stop_timer, TIMER_ABSTIME, &trspec, NULL) == -1) {
            rc = SR_ERR_SYS;
            goto cleanup;
        }
    }

cleanup:
    free(xp);
    free(datetime);
    np_release_user_sess(user_sess);
    return rc;
}

int
yang_push_notif_modified_append_data(struct lyd_node *ntf, void *data)
{
    struct yang_push_data *yp_data = data;
    const struct lys_module *mod;
    char buf[11], *datetime;
    struct lyd_node_any *any;
    struct lyd_node *cont;
    enum yang_push_op op;
    LY_ERR lyrc;

    mod = ly_ctx_get_module_implemented(LYD_CTX(ntf), "ietf-yang-push");
    if (!mod) {
        EINT;
        return SR_ERR_INTERNAL;
    }

    /* datastore */
    if (lyd_new_term(ntf, mod, "datastore", yang_push_ds2ident(yp_data->datastore), 0, NULL)) {
        return SR_ERR_LY;
    }

    if (yp_data->selection_filter_ref) {
        /* selection-filter-ref */
        if (lyd_new_term(ntf, mod, "selection-filter-ref", yp_data->selection_filter_ref, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (yp_data->datastore_subtree_filter) {
        /* datastore-subtree-filter */
        any = (struct lyd_node_any *)yp_data->datastore_subtree_filter;
        if (lyd_new_any(ntf, mod, "datastore-subtree-filter", any->value.tree, 0, any->value_type, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (yp_data->datastore_xpath_filter) {
        /* datastore-xpath-filter */
        if (lyd_new_term(ntf, mod, "datastore-xpath-filter", yp_data->datastore_xpath_filter, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    if (yp_data->periodic) {
        /* periodic */
        if (lyd_new_inner(ntf, mod, "periodic", 0, &cont)) {
            return SR_ERR_LY;
        }

        /* period */
        sprintf(buf, "%" PRIu32, yp_data->period_ms / 10);
        if (lyd_new_term(cont, NULL, "period", buf, 0, NULL)) {
            return SR_ERR_LY;
        }

        /* anchor-time */
        if (yp_data->anchor_time.tv_sec) {
            ly_time_ts2str(&yp_data->anchor_time, &datetime);
            lyrc = lyd_new_term(cont, NULL, "anchor-time", datetime, 0, NULL);
            free(datetime);
            if (lyrc) {
                return SR_ERR_LY;
            }
        }
    } else {
        /* on-change */
        if (lyd_new_inner(ntf, mod, "on-change", 0, &cont)) {
            return SR_ERR_LY;
        }

        /* dampening-period */
        if (yp_data->dampening_period_ms) {
            sprintf(buf, "%" PRIu32, yp_data->dampening_period_ms / 10);
            if (lyd_new_term(cont, NULL, "dampening-period", buf, 0, NULL)) {
                return SR_ERR_LY;
            }
        }

        /* sync-on-start */
        if (lyd_new_term(cont, NULL, "sync-on-start", yp_data->sync_on_start ? "true" : "false", 0, NULL)) {
            return SR_ERR_LY;
        }

        /* excluded-change* */
        for (op = 0; op < YP_OP_OPERATION_COUNT; ++op) {
            if (yp_data->excluded_change[op]) {
                if (lyd_new_term(cont, NULL, "excluded-change", yang_push_op2str(op), 0, NULL)) {
                    return SR_ERR_LY;
                }
            }
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Stream-filter-name match callback.
 */
static int
yang_push_datastore_filter_match_cb(struct np2srv_sub_ntf *sub, const void *match_data)
{
    const char *filter_id = match_data;
    struct yang_push_data *yp_data = sub->data;

    if (sub->type != SUB_TYPE_YANG_PUSH) {
        return 0;
    }

    if (yp_data->selection_filter_ref && !strcmp(yp_data->selection_filter_ref, filter_id)) {
        return 1;
    }
    return 0;
}

int
yang_push_config_filters(const struct lyd_node *filter, sr_change_oper_t op)
{
    int rc = SR_ERR_OK, r;
    struct yang_push_data *yp_data;
    struct np2srv_sub_ntf *sub;
    struct nc_session *ncs;
    char *xp;
    uint32_t i;

    if (op == SR_OP_MODIFIED) {
        /* construct the new filter */
        r = yang_push_rpc_filter2xpath(NULL, filter, NULL, &xp, NULL, NULL, NULL);
        if (r != SR_ERR_OK) {
            return r;
        }

        /* update all the relevant subscriptions */
        sub = NULL;
        while ((sub = sub_ntf_find_next(sub, yang_push_datastore_filter_match_cb, lyd_get_value(lyd_child(filter))))) {
            yp_data = sub->data;

            /* update the xpath */
            free(yp_data->xpath);
            yp_data->xpath = strdup(xp);

            if (!yp_data->periodic) {
                /* modify the filter of the subscription(s) */
                for (i = 0; i < sub->sub_id_count; ++i) {
                    r = sr_module_change_sub_modify_xpath(np2srv.sr_data_sub, sub->sub_ids[i], yp_data->xpath);
                    if (r != SR_ERR_OK) {
                        rc = r;
                    }
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
        while ((sub = sub_ntf_find_next(sub, yang_push_datastore_filter_match_cb, lyd_get_value(lyd_child(filter))))) {
            /* get NETCONF session */
            if ((rc = np_get_nc_sess_by_id(0, sub->nc_id, &ncs))) {
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
yang_push_oper_subscription(struct lyd_node *subscription, void *data)
{
    struct yang_push_data *yp_data = data;
    const struct lys_module *mod;
    char buf[26], *datetime;
    struct lyd_node_any *any;
    struct lyd_node *cont;
    enum yang_push_op op;
    LY_ERR lyrc;

    mod = ly_ctx_get_module_implemented(LYD_CTX(subscription), "ietf-yang-push");
    if (!mod) {
        EINT;
        return SR_ERR_INTERNAL;
    }

    /* datastore */
    if (lyd_new_term(subscription, mod, "datastore", yang_push_ds2ident(yp_data->datastore), 0, NULL)) {
        return SR_ERR_LY;
    }

    if (yp_data->selection_filter_ref) {
        /* selection-filter-ref */
        if (lyd_new_term(subscription, mod, "selection-filter-ref", yp_data->selection_filter_ref, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (yp_data->datastore_subtree_filter) {
        /* datastore-subtree-filter */
        any = (struct lyd_node_any *)yp_data->datastore_subtree_filter;
        if (lyd_new_any(subscription, mod, "datastore-subtree-filter", any->value.tree, 0, any->value_type, 0, NULL)) {
            return SR_ERR_LY;
        }
    } else if (yp_data->datastore_xpath_filter) {
        /* datastore-xpath-filter */
        if (lyd_new_term(subscription, mod, "datastore-xpath-filter", yp_data->datastore_xpath_filter, 0, NULL)) {
            return SR_ERR_LY;
        }
    }

    if (yp_data->periodic) {
        /* periodic */
        if (lyd_new_inner(subscription, mod, "periodic", 0, &cont)) {
            return SR_ERR_LY;
        }

        /* period */
        sprintf(buf, "%" PRIu32, yp_data->period_ms / 10);
        if (lyd_new_term(cont, NULL, "period", buf, 0, NULL)) {
            return SR_ERR_LY;
        }

        /* anchor-time */
        if (yp_data->anchor_time.tv_sec) {
            ly_time_ts2str(&yp_data->anchor_time, &datetime);
            lyrc = lyd_new_term(cont, NULL, "anchor-time", datetime, 0, NULL);
            free(datetime);
            if (lyrc) {
                return SR_ERR_LY;
            }
        }
    } else {
        /* on-change */
        if (lyd_new_inner(subscription, mod, "on-change", 0, &cont)) {
            return SR_ERR_LY;
        }

        /* dampening-period */
        if (yp_data->dampening_period_ms) {
            sprintf(buf, "%" PRIu32, yp_data->dampening_period_ms / 10);
            if (lyd_new_term(cont, NULL, "dampening-period", buf, 0, NULL)) {
                return SR_ERR_LY;
            }
        }

        /* sync-on-start */
        if (lyd_new_term(cont, NULL, "sync-on-start", yp_data->sync_on_start ? "true" : "false", 0, NULL)) {
            return SR_ERR_LY;
        }

        /* excluded-change* */
        for (op = 0; op < YP_OP_OPERATION_COUNT; ++op) {
            if (yp_data->excluded_change[op]) {
                if (lyd_new_term(cont, NULL, "excluded-change", yang_push_op2str(op), 0, NULL)) {
                    return SR_ERR_LY;
                }
            }
        }
    }

    return SR_ERR_OK;
}

uint32_t
yang_push_oper_receiver_excluded(struct np2srv_sub_ntf *sub)
{
    struct yang_push_data *yp_data = sub->data;
    uint32_t i, excluded_count = 0, filtered_out;
    int r;

    if (!yp_data->periodic) {
        /* excluded-event-records */
        for (i = 0; i < ATOMIC_LOAD_RELAXED(sub->sub_id_count); ++i) {
            /* get filter-out count for the subscription */
            r = sr_module_change_sub_get_info(np2srv.sr_data_sub, sub->sub_ids[i], NULL, NULL, NULL, &filtered_out);
            if (r != SR_ERR_OK) {
                return 0;
            }
            excluded_count += filtered_out;
        }

        /* add excluded op */
        excluded_count += ATOMIC_LOAD_RELAXED(yp_data->excluded_op_count);
    } /* else always zero */

    return excluded_count;
}

void
yang_push_terminate_async(void *data)
{
    struct yang_push_data *yp_data = data;
    struct itimerspec tspec = {0};

    /* disarm all timers */
    if (yp_data->periodic) {
        timer_settime(yp_data->update_timer, TIMER_ABSTIME, &tspec, NULL);
    } else {
        if (yp_data->dampening_period_ms) {
            timer_settime(yp_data->damp_timer, TIMER_ABSTIME, &tspec, NULL);
        }
    }
    if (yp_data->stop_timer) {
        timer_settime(yp_data->stop_timer, TIMER_ABSTIME, &tspec, NULL);
    }
}

void
yang_push_data_destroy(void *data)
{
    struct yang_push_data *yp_data = data;

    if (yp_data) {
        free(yp_data->selection_filter_ref);
        lyd_free_tree(yp_data->datastore_subtree_filter);
        free(yp_data->datastore_xpath_filter);
        if (yp_data->periodic) {
            timer_delete(yp_data->update_timer);
        } else {
            pthread_mutex_destroy(&yp_data->notif_lock);
            sr_release_data(yp_data->change_ntf);
            if (yp_data->dampening_period_ms) {
                timer_delete(yp_data->damp_timer);
            }
        }
        free(yp_data->xpath);
        if (yp_data->stop_timer) {
            timer_delete(yp_data->stop_timer);
        }

        free(yp_data);
    }
}

int
np2srv_rpc_resync_sub_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    struct lyd_node *node;
    struct np2srv_sub_ntf *sub;
    struct yang_push_data *yp_data;
    int rc = SR_ERR_OK;
    uint32_t nc_sub_id;

    if (NP_IGNORE_RPC(session, event)) {
        /* ignore in this case (not supported) */
        return SR_ERR_OK;
    }

    /* id */
    lyd_find_path(input, "id", 0, &node);
    nc_sub_id = ((struct lyd_node_term *)node)->value.uint32;

    /* READ LOCK */
    sub = sub_ntf_find_lock(nc_sub_id, 0, 0);
    if (!sub || ((struct yang_push_data *)sub->data)->periodic) {
        sr_session_set_error_message(session, "On-change subscription with ID %" PRIu32 " for the current receiver "
                "does not exist.", nc_sub_id);
        if (sub) {
            rc = SR_ERR_INVAL_ARG;
            goto cleanup_unlock;
        }
        return SR_ERR_INVAL_ARG;
    }
    yp_data = sub->data;

    /* resync the subscription */
    ATOMIC_STORE_RELAXED(yp_data->patch_id, 1);
    rc = yang_push_notif_update_send(yp_data->cb_arg.ncs, yp_data, nc_sub_id);
    if (rc != SR_ERR_OK) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    /* UNLOCK */
    sub_ntf_unlock(0);

    return rc;
}
