/**
 * @file netconf_nmda.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-nmda callbacks
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "netconf_nmda.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>
#include <sysrepo/subscribed_notifications.h>

#include "common.h"
#include "compat.h"
#include "config.h"
#include "log.h"

/**
 * @brief Perform origin filtering.
 *
 * @param[in,out] data Data to filter.
 * @param[in] filter Origin filter identity.
 * @param[in] negated Whether the filter is negated.
 * @return Error reply on error, NULL on success.
 */
struct nc_server_reply *
np_op_data_filter_origin(struct lyd_node **data, const struct lysc_ident *filter, int negated)
{
    struct ly_set *set;
    struct lyd_node *node;
    char *xpath;
    int r;
    LY_ERR lyrc;
    uint32_t i;

    if (!*data) {
        return NULL;
    }

    if (negated) {
        r = asprintf(&xpath, "//*[@origin and derived-from-or-self(@origin, '%s:%s')]", filter->module->name, filter->name);
    } else {
        r = asprintf(&xpath, "//*[@origin and not(derived-from-or-self(@origin, '%s:%s'))]", filter->module->name, filter->name);
    }
    if (r == -1) {
        return np_reply_err_op_failed(NULL, LYD_CTX(*data), "Memory allocation failed.");
    }

    lyrc = lyd_find_xpath(*data, xpath, &set);
    free(xpath);
    if (lyrc) {
        return np_reply_err_op_failed(NULL, LYD_CTX(*data), ly_last_logmsg());
    }

    if (set->count) {
        /* go backwards to allow safe node freeing */
        i = set->count;
        do {
            --i;
            node = set->dnodes[i];
            if (node->schema->flags & LYS_CONFIG_R) {
                /* state nodes are not affected */
                continue;
            }

            /* free non-matching subtree */
            if (node == *data) {
                *data = (*data)->next;
            }
            lyd_free_tree(node);
        } while (i);
    }
    ly_set_free(set, NULL);

    return NULL;
}

struct nc_server_reply *
np2srv_rpc_getdata_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    struct lyd_node_term *leaf;
    struct lyd_node *node, *data = NULL, *output = NULL;
    char *xp_filter = NULL, *msg;
    uint32_t i, max_depth = 0;
    struct ly_set *nodeset;
    sr_datastore_t ds;
    NC_WD_MODE nc_wd;
    sr_get_options_t get_opts = 0;

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    lyd_find_path(rpc, "datastore", 0, (struct lyd_node **)&leaf);
    if (!strcmp(leaf->value.ident->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(leaf->value.ident->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(leaf->value.ident->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(leaf->value.ident->name, "operational")) {
        ds = SR_DS_OPERATIONAL;
    } else if (!strcmp(leaf->value.ident->name, "factory-default")) {
        ds = SR_DS_FACTORY_DEFAULT;
    } else {
        if (asprintf(&msg, "Datastore \"%s\" is not supported.", lyd_get_value(&leaf->node)) == -1) {
            msg = NULL;
        }
        reply = np_reply_err_invalid_val(LYD_CTX(rpc), msg, "datastore");
        free(msg);
        goto cleanup;
    }

    /* create filters */
    lyd_find_xpath(rpc, "subtree-filter | xpath-filter", &nodeset);
    node = nodeset->count ? nodeset->dnodes[0] : NULL;
    ly_set_free(nodeset, NULL);
    if (node && !strcmp(node->schema->name, "subtree-filter")) {
        if (((struct lyd_node_any *)node)->value.tree) {
            if (srsn_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, user_sess->sess, &xp_filter)) {
                reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
                goto cleanup;
            }
        }
    } else {
        xp_filter = strdup(node ? lyd_get_value(node) : "/*");
    }

    /* config filter */
    if (!lyd_find_path(rpc, "config-filter", 0, &node)) {
        if (!strcmp(lyd_get_value(node), "false")) {
            get_opts |= SR_OPER_NO_CONFIG;
        } else {
            get_opts |= SR_OPER_NO_STATE;
        }
    }

    /* depth */
    if (!lyd_find_path(rpc, "max-depth", 0, &node) && strcmp(lyd_get_value(node), "unbounded")) {
        max_depth = ((struct lyd_node_term *)node)->value.uint16;
    }

    /* origin */
    if (!lyd_find_path(rpc, "with-origin", 0, &node)) {
        get_opts |= SR_OPER_WITH_ORIGIN;
    }

    /* get with-defaults mode */
    if (!lyd_find_path(rpc, "with-defaults", 0, &node)) {
        if (!strcmp(lyd_get_value(node), "report-all")) {
            nc_wd = NC_WD_ALL;
        } else if (!strcmp(lyd_get_value(node), "report-all-tagged")) {
            nc_wd = NC_WD_ALL_TAG;
        } else if (!strcmp(lyd_get_value(node), "trim")) {
            nc_wd = NC_WD_TRIM;
        } else {
            assert(!strcmp(lyd_get_value(node), "explicit"));
            nc_wd = NC_WD_EXPLICIT;
        }
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* create the data tree for the data reply */
    if ((reply = np_op_filter_data_get(user_sess->sess, max_depth, get_opts, xp_filter, &data))) {
        goto cleanup;
    }

    /* origin filter */
    lyd_find_xpath(rpc, "origin-filter | negated-origin-filter", &nodeset);
    for (i = 0; i < nodeset->count; ++i) {
        leaf = (struct lyd_node_term *)nodeset->dnodes[i];
        if ((reply = np_op_data_filter_origin(&data, leaf->value.ident, strcmp(leaf->schema->name, "origin-filter")))) {
            goto cleanup;
        }
    }
    ly_set_free(nodeset, NULL);

    /* generate output */
    if (lyd_dup_single(rpc, NULL, LYD_DUP_WITH_PARENTS, &output)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    if (lyd_new_any(output, NULL, "data", data, LYD_ANYDATA_DATATREE, LYD_NEW_ANY_USE_VALUE | LYD_NEW_VAL_OUTPUT, NULL)) {
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), ly_last_logmsg());
        goto cleanup;
    }
    data = NULL;
    reply = np_reply_success(rpc, output);
    output = NULL;

cleanup:
    free(xp_filter);
    lyd_free_siblings(data);
    lyd_free_siblings(output);
    return reply;
}

struct nc_server_reply *
np2srv_rpc_editdata_cb(const struct lyd_node *rpc, struct np_user_sess *user_sess)
{
    struct nc_server_reply *reply = NULL;
    sr_datastore_t ds;
    struct ly_set *nodeset;
    struct lyd_node_term *leaf;
    struct lyd_node *node, *config = NULL;
    const char *defop;
    char *msg;

    /* get know which datastore is being affected */
    lyd_find_path(rpc, "datastore", 0, (struct lyd_node **)&leaf);
    if (!strcmp(leaf->value.ident->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(leaf->value.ident->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(leaf->value.ident->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        if (asprintf(&msg, "Datastore \"%s\" is not supported or writable.", lyd_get_value(&leaf->node)) == -1) {
            msg = NULL;
        }
        reply = np_reply_err_invalid_val(LYD_CTX(rpc), msg, "dtastore");
        free(msg);
        goto cleanup;
    }

    /* default-operation */
    lyd_find_path(rpc, "default-operation", 0, &node);
    defop = lyd_get_value(node);

    /* config */
    lyd_find_xpath(rpc, "config | url", &nodeset);
    node = nodeset->dnodes[0];
    ly_set_free(nodeset, NULL);
    if (!strcmp(node->schema->name, "config")) {
        reply = np_op_parse_config((struct lyd_node_any *)node, LYD_PARSE_OPAQ | LYD_PARSE_ONLY, &config);
        if (reply) {
            goto cleanup;
        }
    } else {
        assert(!strcmp(node->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        reply = np_op_parse_url(LYD_CTX(rpc), lyd_get_value(node), 0, &config);
        if (reply) {
            goto cleanup;
        }
#else
        reply = np_reply_err_op_failed(NULL, LYD_CTX(rpc), "URL not supported.");
        goto cleanup;
#endif
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if (sr_edit_batch(user_sess->sess, config, defop)) {
        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
    }
    if (sr_apply_changes(user_sess->sess, np2srv.sr_timeout)) {
        reply = np_reply_err_sr(user_sess->sess, LYD_NAME(rpc));
        goto cleanup;
    }

    /* OK reply */
    reply = np_reply_success(rpc, NULL);

cleanup:
    /* discard any changes that possibly failed to be applied */
    sr_discard_changes(user_sess->sess);

    lyd_free_siblings(config);
    return reply;
}
