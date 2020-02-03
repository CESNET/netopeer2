/**
 * @file netconf_nmda.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-netconf-nmda callbacks
 *
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <assert.h>
#include <inttypes.h>
#include <unistd.h>
#include <string.h>

#include <sysrepo.h>
#include <libyang/libyang.h>

#include "config.h"
#include "common.h"
#include "log.h"
#include "netconf_acm.h"

/**
 * @brief Perform origin filtering.
 *
 * @param[in,out] data Data to filter.
 * @param[in] filter Origin filter identity.
 * @param[in] negated Whether the filter is negated.
 * @return Sysrepo error value.
 */
static int
op_data_filter_origin(struct lyd_node **data, const struct lys_ident *filter, int negated)
{
    struct ly_set *set;
    struct lyd_node *node;
    char *xpath;
    int ret;
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
        return SR_ERR_NOMEM;
    }

    set = lyd_find_path(*data, xpath);
    free(xpath);
    if (!set) {
        return SR_ERR_INTERNAL;
    }

    if (set->number) {
        /* go backwards to allow safe node freeing */
        i = set->number;
        do {
            --i;
            node = set->set.d[i];
            if (node->schema->flags & LYS_CONFIG_R) {
                /* state nodes are not affected */
                continue;
            }

            /* free non-matching subtree */
            if (node == *data) {
                *data = (*data)->next;
            }
            lyd_free(node);
        } while (i);
    }
    ly_set_free(set);

    return SR_ERR_OK;
}

int
np2srv_rpc_getdata_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *output, void *UNUSED(private_data))
{
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *node, *data_get = NULL;
    char **filters = NULL;
    int filter_count = 0, i, rc = SR_ERR_OK;
    uint32_t max_depth = 0;
    struct ly_set *nodeset;
    sr_datastore_t ds;
    NC_WD_MODE nc_wd;
    sr_get_oper_options_t get_opts = 0;

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "datastore");
    leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
    ly_set_free(nodeset);
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
        sr_set_error(session, NULL, "Datastore \"%s\" is not supported.", leaf->value_str);
        goto cleanup;
    }

    /* create filters */
    nodeset = lyd_find_path(input, "subtree-filter | xpath-filter");
    node = nodeset->number ? nodeset->set.d[0] : NULL;
    ly_set_free(nodeset);
    if (node && !strcmp(node->schema->name, "subtree-filter")) {
        if (op_filter_create(node, &filters, &filter_count)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        filters = malloc(sizeof *filters);
        if (!filters) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        filter_count = 1;
        filters[0] = node ? strdup(((struct lyd_node_leaf_list *)node)->value_str) : strdup("/*");
        if (!filters[0]) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    }

    /* config filter */
    nodeset = lyd_find_path(input, "config-filter");
    leaf = nodeset->number ? (struct lyd_node_leaf_list *)nodeset->set.d[0] : NULL;
    ly_set_free(nodeset);
    if (leaf) {
        if (!strcmp(leaf->value_str, "false")) {
            get_opts |= SR_OPER_NO_CONFIG;
        } else {
            get_opts |= SR_OPER_NO_STATE;
        }
    }

    /* depth */
    nodeset = lyd_find_path(input, "max-depth");
    leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
    ly_set_free(nodeset);
    if (leaf && strcmp(leaf->value_str, "unbounded")) {
        max_depth = leaf->value.uint16;
    }

    /* origin */
    nodeset = lyd_find_path(input, "with-origin");
    leaf = nodeset->number ? (struct lyd_node_leaf_list *)nodeset->set.d[0] : NULL;
    ly_set_free(nodeset);
    if (leaf) {
        get_opts |= SR_OPER_WITH_ORIGIN;
    }

    /* get with-defaults mode */
    nodeset = lyd_find_path(input, "ietf-netconf-with-defaults:with-defaults");
    leaf = nodeset->number ? (struct lyd_node_leaf_list *)nodeset->set.d[0] : NULL;
    ly_set_free(nodeset);
    if (leaf) {
        if (!strcmp(leaf->value_str, "report-all")) {
            nc_wd = NC_WD_ALL;
        } else if (!strcmp(leaf->value_str, "report-all-tagged")) {
            nc_wd = NC_WD_ALL_TAG;
        } else if (!strcmp(leaf->value_str, "trim")) {
            nc_wd = NC_WD_TRIM;
        } else {
            assert(!strcmp(leaf->value_str, "explicit"));
            nc_wd = NC_WD_EXPLICIT;
        }
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /*
     * create the data tree for the data reply
     */
    for (i = 0; i < filter_count; i++) {
        rc = sr_get_data(session, filters[i], max_depth, 0, get_opts, &node);
        if (rc != SR_ERR_OK) {
            ERR("Getting data \"%s\" from sysrepo failed (%s).", filters[i], sr_strerror(rc));
            goto cleanup;
        }

        if (!data_get) {
            data_get = node;
        } else if (node && lyd_merge(data_get, node, LYD_OPT_DESTRUCT | LYD_OPT_EXPLICIT)) {
            lyd_free_withsiblings(node);
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* origin filter */
    nodeset = lyd_find_path(input, "origin-filter | negated-origin-filter");
    for (i = 0; i < (signed)nodeset->number; ++i) {
        leaf = (struct lyd_node_leaf_list *)nodeset->set.d[i];
        op_data_filter_origin(&data_get, leaf->value.ident, strcmp(leaf->schema->name, "origin-filter"));
    }
    ly_set_free(nodeset);

    /* perform correct NACM filtering */
    ncac_check_data_read_filter(&data_get, sr_session_get_user(session));

    /* add output */
    node = lyd_new_output_anydata(output, NULL, "data", data_get, LYD_ANYDATA_DATATREE);
    if (!node) {
        goto cleanup;
    }
    data_get = NULL;

    /* success */

cleanup:
    for (i = 0; i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);
    lyd_free_withsiblings(data_get);
    return rc;
}

int
np2srv_rpc_editdata_cb(sr_session_ctx_t *session, const char *UNUSED(op_path), const struct lyd_node *input,
        sr_event_t UNUSED(event), uint32_t UNUSED(request_id), struct lyd_node *UNUSED(output), void *UNUSED(private_data))
{
    sr_datastore_t ds;
    struct ly_set *nodeset;
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *node, *config = NULL;
    const sr_error_info_t *err_info;
    const char *defop;
    int rc = SR_ERR_OK;

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(input, "datastore");
    leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
    ly_set_free(nodeset);
    if (!strcmp(leaf->value.ident->name, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(leaf->value.ident->name, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(leaf->value.ident->name, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else {
        rc = SR_ERR_INVAL_ARG;
        sr_set_error(session, NULL, "Datastore \"%s\" is not supported or writable.", leaf->value_str);
        goto cleanup;
    }

    /* default-operation */
    nodeset = lyd_find_path(input, "default-operation");
    leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
    ly_set_free(nodeset);
    defop = leaf->value_str;

    /* config */
    nodeset = lyd_find_path(input, "config | url");
    node = nodeset->set.d[0];
    ly_set_free(nodeset);
    if (!strcmp(node->schema->name, "config")) {
        config = op_parse_config((struct lyd_node_anydata *)node, LYD_OPT_EDIT | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            goto cleanup;
        }
    } else {
        assert(!strcmp(node->schema->name, "url"));
#ifdef NP2SRV_URL_CAPAB
        config = op_parse_url(((struct lyd_node_leaf_list *)node)->value_str, LYD_OPT_EDIT | LYD_OPT_STRICT, &rc, session);
        if (rc) {
            goto cleanup;
        }
#else
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(session, ds);

    /* sysrepo API */
    rc = sr_edit_batch(session, config, defop);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    rc = sr_apply_changes(session, 0, 0);
    if (rc != SR_ERR_OK) {
        sr_get_error(session, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_withsiblings(config);
    return rc;
}
