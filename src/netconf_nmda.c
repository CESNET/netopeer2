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

#include "netconf_nmda.h"

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
        return SR_ERR_NOMEM;
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
    struct lyd_node *node, *select_data = NULL, *data = NULL;
    struct np2_filter filter = {0};
    int rc = SR_ERR_OK;
    sr_session_ctx_t *user_sess;
    uint32_t i, max_depth = 0;
    struct ly_set *nodeset;
    sr_datastore_t ds;
    NC_WD_MODE nc_wd;
    sr_get_oper_options_t get_opts = 0;
    char *username = NULL;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
    }

    /* Get username. It is assumed that right now the NETCONF session cannot end
     * due to the RPC lock held while np2srv_rpc_cb() is executing (which called this callback).
     */
    if ((username = (char *)np_get_nc_sess_user(session))) {
        if (!(username = strdup(username))) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
    } else {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
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
        sr_set_error(session, NULL, "Datastore \"%s\" is not supported.", leaf->value.canonical);
        goto cleanup;
    }

    /* create filters */
    lyd_find_xpath(input, "subtree-filter | xpath-filter", &nodeset);
    node = nodeset->count ? nodeset->dnodes[0] : NULL;
    ly_set_free(nodeset, NULL);
    if (node && !strcmp(node->schema->name, "subtree-filter")) {
        if (op_filter_subtree2xpath(((struct lyd_node_any *)node)->value.tree, &filter)) {
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        filter.filters = malloc(sizeof *filter.filters);
        if (!filter.filters) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        filter.count = 1;
        filter.filters[0].str = node ? strdup(LYD_CANON_VALUE(node)) : strdup("/*");
        if (!filter.filters[0].str) {
            EMEM;
            rc = SR_ERR_NOMEM;
            goto cleanup;
        }
        filter.filters[0].selection = 1;
    }

    /* config filter */
    lyd_find_path(input, "config-filter", 0, (struct lyd_node **)&leaf);
    if (leaf) {
        if (!strcmp(leaf->value.canonical, "false")) {
            get_opts |= SR_OPER_NO_CONFIG;
        } else {
            get_opts |= SR_OPER_NO_STATE;
        }
    }

    /* depth */
    lyd_find_path(input, "max-depth", 0, (struct lyd_node **)&leaf);
    if (leaf && strcmp(leaf->value.canonical, "unbounded")) {
        max_depth = leaf->value.uint16;
    }

    /* origin */
    lyd_find_path(input, "with-origin", 0, (struct lyd_node **)&leaf);
    if (leaf) {
        get_opts |= SR_OPER_WITH_ORIGIN;
    }

    /* get with-defaults mode */
    lyd_find_path(input, "with-defaults", 0, (struct lyd_node **)&leaf);
    if (leaf) {
        if (!strcmp(leaf->value.canonical, "report-all")) {
            nc_wd = NC_WD_ALL;
        } else if (!strcmp(leaf->value.canonical, "report-all-tagged")) {
            nc_wd = NC_WD_ALL_TAG;
        } else if (!strcmp(leaf->value.canonical, "trim")) {
            nc_wd = NC_WD_TRIM;
        } else {
            assert(!strcmp(leaf->value.canonical, "explicit"));
            nc_wd = NC_WD_EXPLICIT;
        }
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /*
     * create the data tree for the data reply
     */
    if ((rc = op_filter_data_get(user_sess, max_depth, get_opts, &filter, session, &select_data))) {
        goto cleanup;
    }
    if ((rc = op_filter_data_filter(&select_data, &filter, 0, &data))) {
        goto cleanup;
    }

    /* origin filter */
    lyd_find_xpath(input, "origin-filter | negated-origin-filter", &nodeset);
    for (i = 0; i < nodeset->count; ++i) {
        leaf = (struct lyd_node_term *)nodeset->dnodes[i];
        op_data_filter_origin(&data, leaf->value.ident, strcmp(leaf->schema->name, "origin-filter"));
    }
    ly_set_free(nodeset, NULL);

    /* perform correct NACM filtering */
    ncac_check_data_read_filter(&data, username);

    /* add output */
    if (lyd_new_any(output, NULL, "data", data, 1, LYD_ANYDATA_DATATREE, 1, NULL)) {
        goto cleanup;
    }
    data = NULL;

    /* success */

cleanup:
    op_filter_erase(&filter);
    lyd_free_siblings(select_data);
    lyd_free_siblings(data);
    free(username);
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
    const sr_error_info_t *err_info;
    sr_session_ctx_t *user_sess;
    const char *defop;
    int rc = SR_ERR_OK;

    if (event == SR_EV_ABORT) {
        /* ignore in this case */
        return SR_ERR_OK;
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
        sr_set_error(session, NULL, "Datastore \"%s\" is not supported or writable.", leaf->value.canonical);
        goto cleanup;
    }

    /* default-operation */
    lyd_find_path(input, "default-operation", 0, (struct lyd_node **)&leaf);
    defop = leaf->value.canonical;

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
        config = op_parse_url(LYD_CANON_VALUE(node), LYD_PARSE_OPAQ | LYD_PARSE_ONLY, &rc, session);
        if (rc) {
            goto cleanup;
        }
#else
        rc = SR_ERR_UNSUPPORTED;
        sr_set_error(session, NULL, "URL not supported.");
        goto cleanup;
#endif
    }

    /* get the user session */
    user_sess = np_get_user_sess(session);
    if (!user_sess) {
        EINT;
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* update sysrepo session datastore */
    sr_session_switch_ds(user_sess, ds);

    /* sysrepo API */
    rc = sr_edit_batch(user_sess, config, defop);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    rc = sr_apply_changes(user_sess, np2srv.sr_timeout, 1);
    if (rc != SR_ERR_OK) {
        sr_get_error(user_sess, &err_info);
        sr_set_error(session, err_info->err[0].xpath, err_info->err[0].message);
        goto cleanup;
    }

    /* success */

cleanup:
    lyd_free_siblings(config);
    return rc;
}
