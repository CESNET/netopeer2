/**
 * @file op_get_config.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF <get> and <get-config> operations implementation
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

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"
#include "netconf_monitoring.h"

/* add whole subtree */
static int
opget_build_subtree_from_sysrepo(sr_session_ctx_t *srs, struct lyd_node **root, const char *subtree_xpath)
{
    sr_val_t *value;
    sr_val_iter_t *sriter;
    struct lyd_node *node;
    struct sr2ly_cache cache;
    char *full_subtree_xpath = NULL;
    int rc;

    if (asprintf(&full_subtree_xpath, "%s//.", subtree_xpath) == -1) {
        EMEM;
        return -1;
    }

    memset(&cache, 0, sizeof cache);
    np2srv_sr_session_refresh(srs, NULL);

    rc = np2srv_sr_get_items_iter(srs, full_subtree_xpath, &sriter, NULL);
    free(full_subtree_xpath);
    if (rc == 1) {
        /* it's ok, model without data */
        return 0;
    } else if (rc) {
        return -1;
    }

    while ((!np2srv_sr_get_item_next(srs, sriter, &value, NULL))) {
        if (op_sr2ly(*root, value, &node, &cache)) {
            sr_free_val(value);
            sr_free_val_iter(sriter);
            return -1;
        }

        if (!(*root)) {
            *root = node;
        }
        sr_free_val(value);
    }
    sr_free_val_iter(sriter);

    op_sr2ly_free_cache(&cache);
    return 0;
}

struct nc_server_reply *
op_get(struct lyd_node *rpc, struct nc_session *ncs)
{
    const struct lys_module *module;
    const struct lys_node *snode;
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *root = NULL, *node;
    char **filters = NULL, *path;
    int filter_count = 0, rc;
    unsigned int config_only;
    uint32_t i;
    struct np2_sessions *sessions;
    struct ly_set *nodeset;
    sr_datastore_t ds = 0;
    struct nc_server_error *e;
    struct nc_server_reply *ereply = NULL;
    NC_WD_MODE nc_wd;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (!strcmp(rpc->schema->name, "get")) {
        rc = np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:get", &ereply);
    } else {
        rc = np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:get-config", &ereply);
    }
    if (rc) {
        goto error;
    }

    /* get default value for with-defaults */
    nc_server_get_capab_withdefaults(&nc_wd, NULL);

    /* get know which datastore is being affected */
    if (!strcmp(rpc->schema->name, "get")) {
        config_only = 0;
        ds = SR_DS_RUNNING;
    } else { /* get-config */
        config_only = SR_SESS_CONFIG_ONLY;
        nodeset = lyd_find_path(rpc, "/ietf-netconf:get-config/source/*");
        if (!strcmp(nodeset->set.d[0]->schema->name, "running")) {
            ds = SR_DS_RUNNING;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "startup")) {
            ds = SR_DS_STARTUP;
        } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
            ds = SR_DS_CANDIDATE;
        }
        /* TODO URL capability */

        ly_set_free(nodeset);
    }
    if (ds != sessions->ds) {
        /* update sysrepo session datastore */
        if (np2srv_sr_session_switch_ds(sessions->srs, ds, &ereply)) {
           goto error;
        }
        sessions->ds = ds;
    }
    if ((sessions->opts & SR_SESS_CONFIG_ONLY) != config_only) {
        /* update sysrepo session config */
        if (np2srv_sr_session_set_options(sessions->srs, sessions->opts ^ SR_SESS_CONFIG_ONLY, &ereply)) {
            goto error;
        }
        sessions->opts ^= SR_SESS_CONFIG_ONLY;
    }

    /* create filters */
    nodeset = lyd_find_path(rpc, "/ietf-netconf:*/filter");
    if (nodeset->number) {
        node = nodeset->set.d[0];
        ly_set_free(nodeset);
        if (op_filter_create(node, &filters, &filter_count)) {
            goto error;
        }
    } else {
        ly_set_free(nodeset);

        i = 0;
        while ((module = ly_ctx_get_module_iter(np2srv.ly_ctx, &i))) {
            if (!module->implemented) {
                continue;
            }

            LY_TREE_FOR(module->data, snode) {
                if (!(snode->nodetype & (LYS_GROUPING | LYS_NOTIF | LYS_RPC))) {
                    /* module with some actual data definitions */
                    break;
                }
            }

            if (snode) {
                asprintf(&path, "/%s:*", module->name);
                if (op_filter_xpath_add_filter(path, &filters, &filter_count)) {
                    free(path);
                    goto error;
                }
            }
        }
    }

    /* get with-defaults mode */
    nodeset = lyd_find_path(rpc, "/ietf-netconf:*/ietf-netconf-with-defaults:with-defaults");
    if (nodeset->number) {
        leaf = (struct lyd_node_leaf_list *)nodeset->set.d[0];
        if (!strcmp(leaf->value_str, "report-all")) {
            nc_wd = NC_WD_ALL;
        } else if (!strcmp(leaf->value_str, "report-all-tagged")) {
            nc_wd = NC_WD_ALL_TAG;
        } else if (!strcmp(leaf->value_str, "trim")) {
            nc_wd = NC_WD_TRIM;
        } else if (!strcmp(leaf->value_str, "explicit")) {
            nc_wd = NC_WD_EXPLICIT;
        } else {
            /* we received it, so it was validated, this cannot be */
            EINT;
            goto error;
        }
    }
    ly_set_free(nodeset);


    if (sessions->ds != SR_DS_CANDIDATE) {
        /* refresh sysrepo data */
        if (np2srv_sr_session_refresh(sessions->srs, &ereply)) {
            goto error;
        }
    } else if (!(sessions->flags & NP2S_CAND_CHANGED)) {
        /* update candidate to be the same as running */
        if (np2srv_sr_session_refresh(sessions->srs, &ereply)) {
            goto error;
        }
    }

    /*
     * create the data tree for the data reply
     */
    for (i = 0; (signed)i < filter_count; i++) {
        /* create the subtree */
        if (opget_build_subtree_from_sysrepo(sessions->srs, &root, filters[i])) {
            goto error;
        }
    }

    for (i = 0; (signed)i < filter_count; ++i) {
        free(filters[i]);
    }
    filter_count = 0;
    free(filters);
    filters = NULL;

    /* debug
    lyd_print_file(stdout, root, LYD_XML_FORMAT, LYP_WITHSIBLINGS);
    debug */

    /* build RPC Reply */
    if (lyd_validate(&root, (config_only ? LYD_OPT_GETCONFIG : LYD_OPT_GET), np2srv.ly_ctx)) {
        EINT;
        goto error;
    }
    node = root;
    root = lyd_dup(rpc, 0);

    lyd_new_output_anydata(root, NULL, "data", node, LYD_ANYDATA_DATATREE);
    if (lyd_validate(&root, LYD_OPT_RPCREPLY, NULL)) {
        EINT;
        goto error;
    }

    return nc_server_reply_data(root, nc_wd, NC_PARAMTYPE_FREE);

error:
    if (!ereply) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(np2srv.ly_ctx), "en");
        ereply = nc_server_reply_err(e);
    }

    for (i = 0; (signed)i < filter_count; ++i) {
        free(filters[i]);
    }
    free(filters);

    lyd_free_withsiblings(root);
    return ereply;
}
