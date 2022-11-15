/**
 * @file netconf_nmda.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-nmda callbacks
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

#include "netconf_nmda.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "common.h"
#include "compat.h"
#include "config.h"
#include "err_netconf.h"
#include "log.h"

/**
 * @brief Perform origin filtering.
 *
 * @param[in,out] data Data to filter.
 * @param[in] filter Origin filter identity.
 * @param[in] negated Whether the filter is negated.
 * @return Sysrepo error value.
 */
static int
op_data_filter_origin(struct lyd_node **data, const struct lysc_ident *filter, int negated)
{
    struct ly_set *set;
    struct lyd_node *node;
    char *xpath;
    int ret;
    LY_ERR lyrc;
    uint32_t i;

    if (!*data) {
        return SR_ERR_OK;
    }

    if (negated) {
        ret = asprintf(&xpath, "//*[@origin and derived-from-or-self(@origin, '%s:%s')]", filter->module->name, filter->name);
    } else {
        ret = asprintf(&xpath, "//*[@origin and not(derived-from-or-self(@origin, '%s:%s'))]", filter->module->name, filter->name);
    }
    if (ret == -1) {
        EMEM;
        return SR_ERR_NO_MEMORY;
    }

    lyrc = lyd_find_xpath(*data, xpath, &set);
    free(xpath);
    if (lyrc) {
        return SR_ERR_INTERNAL;
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

    return SR_ERR_OK;
}

int
np2srv_rpc_getdata_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *output,
        void *UNUSED(private_data))
{
    struct lyd_node_term *leaf;
    struct lyd_node *node, *data = NULL;
    struct np2_filter filter = {0};
    int rc = SR_ERR_OK;
    struct np2_user_sess *user_sess = NULL;
    uint32_t i, max_depth = 0;
    struct ly_set *nodeset;
    sr_datastore_t ds;
    NC_WD_MODE nc_wd;
    sr_get_options_t get_opts = 0;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    lyd_find_path(input, "datastore", 0, (struct lyd_node **)&leaf);
    if (!strcmp(leaf->value.ident->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(leaf->value.ident->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(leaf->value.ident->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(leaf->value.ident->name, "operational")) {
        ds = SR_DS_OPERATIONAL;
    } else {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "Datastore \"%s\" is not supported.", lyd_get_value(&leaf->node));
        goto cleanup;
    }

    /* create filters */
    lyd_find_xpath(input, "subtree-filter | xpath-filter", &nodeset);
    node = nodeset->count ? nodeset->dnodes[0] : NULL;
    ly_set_free(nodeset, NULL);
    if (node && !strcmp(node->schema->name, "subtree-filter")) {
        if ((rc = op_filter_create_subtree(((struct lyd_node_any *)node)->value.tree, session, &filter))) {
            goto cleanup;
        }
    } else {
        if ((rc = op_filter_create_xpath(node ? lyd_get_value(node) : "/*", &filter))) {
            goto cleanup;
        }
    }

    /* config filter */
    if (!lyd_find_path(input, "config-filter", 0, &node)) {
        if (!strcmp(lyd_get_value(node), "false")) {
            get_opts |= SR_OPER_NO_CONFIG;
        } else {
            get_opts |= SR_OPER_NO_STATE;
        }
    }

    /* depth */
    if (!lyd_find_path(input, "max-depth", 0, &node) && strcmp(lyd_get_value(node), "unbounded")) {
        max_depth = ((struct lyd_node_term *)node)->value.uint16;
    }

    /* origin */
    if (!lyd_find_path(input, "with-origin", 0, &node)) {
        get_opts |= SR_OPER_WITH_ORIGIN;
    }

    /* get with-defaults mode */
    if (!lyd_find_path(input, "with-defaults", 0, &node)) {
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

    /* get the user session */
    if ((rc = np_get_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* create the data tree for the data reply */
    if ((rc = op_filter_data_get(user_sess->sess, max_depth, get_opts, &filter, session, &data))) {
        goto cleanup;
    }

    /* origin filter */
    lyd_find_xpath(input, "origin-filter | negated-origin-filter", &nodeset);
    for (i = 0; i < nodeset->count; ++i) {
        leaf = (struct lyd_node_term *)nodeset->dnodes[i];
        op_data_filter_origin(&data, leaf->value.ident, strcmp(leaf->schema->name, "origin-filter"));
    }
    ly_set_free(nodeset, NULL);

    /* add output */
    if (lyd_new_any(output, NULL, "data", data, 1, LYD_ANYDATA_DATATREE, 1, NULL)) {
        goto cleanup;
    }
    data = NULL;

cleanup:
    op_filter_erase(&filter);
    lyd_free_siblings(data);
    np_release_user_sess(user_sess);
    return rc;
}

int
np2srv_rpc_editdata_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(op_path),
        const struct lyd_node *input, sr_event_t event, uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output),
        void *UNUSED(private_data))
{
    sr_datastore_t ds;
    struct ly_set *nodeset;
    struct lyd_node_term *leaf;
    struct lyd_node *node, *config = NULL;
    struct np2_user_sess *user_sess = NULL;
    const char *defop;
    int rc = SR_ERR_OK;

    if (np_ignore_rpc(session, event, &rc)) {
        /* ignore in this case */
        return rc;
    }

    /* get know which datastore is being affected */
    lyd_find_path(input, "datastore", 0, (struct lyd_node **)&leaf);
    if (!strcmp(leaf->value.ident->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(leaf->value.ident->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(leaf->value.ident->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        rc = SR_ERR_INVAL_ARG;
        sr_session_set_error_message(session, "Datastore \"%s\" is not supported or writable.", lyd_get_value(&leaf->node));
        goto cleanup;
    }

    /* default-operation */
    lyd_find_path(input, "default-operation", 0, &node);
    defop = lyd_get_value(node);

    /* config */
    lyd_find_xpath(input, "config | url", &nodeset);
    node = nodeset->dnodes[0];
    ly_set_free(nodeset, NULL);
    if (!strcmp(node->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_any *)node, LYD_PARSE_OPAQ | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            goto cleanup;
        }
    } else {
        assert(!strcmp(node->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(lyd_get_value(node), 0, &rc, session);
        if (rc) {
            goto cleanup;
        }
#else
        rc = SR_ERR_UNSUPPORTED;
        sr_session_set_error_message(session, "URL not supported.");
        goto cleanup;
#endif
    }

    /* get the user session */
    if ((rc = np_get_user_sess(session, __func__, NULL, &user_sess))) {
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess->sess, ds);

    /* sysrepo API */
    if ((rc = sr_edit_batch(user_sess->sess, config, defop))) {
        goto cleanup;
    }

    if ((rc = sr_apply_changes(user_sess->sess, np2srv.sr_timeout))) {
        /* specific edit-config error */
        np_err_sr2nc_edit(session, user_sess->sess);
        goto cleanup;
    }

cleanup:
    if (user_sess) {
        /* discard any changes that possibly failed to be applied */
        sr_discard_changes(user_sess->sess);
    }
    lyd_free_siblings(config);
    np_release_user_sess(user_sess);
    return rc;
}
