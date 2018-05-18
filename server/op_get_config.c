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

static int
opget_build_subtree_from_sysrepo_is_key(const char *xpath)
{
    const char *last_node, *ptr;
    char quote;
    int key_len;

    ptr = xpath + strlen(xpath);

    do {
        if ((--ptr == xpath) || (ptr[0] == ']')) {
            return 0;
        }
    } while (ptr[0] != '/');
    /* last node name found */
    last_node = ptr + 1;

    /* go through all predicates and compare keys with the last node */
    while ((--ptr != xpath) && (ptr[0] == ']')) {
        /* value end */
        if ((--ptr == xpath) || ((ptr[0] != '\'') && (ptr[0] != '"'))) {
            return 0;
        }
        quote = ptr[0];

        /* skip the value */
        do {
            if (--ptr == xpath) {
                return 0;
            }
        } while (ptr[0] != quote);

        /* equals */
        if ((--ptr == xpath) || (ptr[0] != '=')) {
            return 0;
        }

        /* key length must be at least one */
        if ((--ptr == xpath) || (ptr[0] == '[')) {
            return 0;
        }

        /* predicate start */
        key_len = 0;
        do {
            if (--ptr == xpath) {
                return 0;
            }
            ++key_len;
        } while (ptr[0] != '[');

        /* compare key name with the last node */
        if (!strncmp(last_node, ptr + 1, key_len) && !last_node[key_len]) {
            return 1;
        }
    }

    return 0;
}

/* add whole subtree */
static int
opget_build_subtree_from_sysrepo(sr_session_ctx_t *srs, struct lyd_node **root, const char *subtree_xpath)
{
    sr_val_t *value;
    sr_val_iter_t *sriter;
    struct lyd_node *node;
    char *full_subtree_xpath = NULL;
    int rc;

    if (asprintf(&full_subtree_xpath, "%s//.", subtree_xpath) == -1) {
        EMEM;
        return -1;
    }

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
        /* skip list keys, they were created during list instance creation */
        if (!opget_build_subtree_from_sysrepo_is_key(value->xpath)) {
            if (op_sr_val_to_lyd_node(*root, value, &node)) {
                sr_free_val(value);
                sr_free_val_iter(sriter);
                return -1;
            }

            if (!(*root)) {
                *root = node;
            }
        }
        sr_free_val(value);
    }
    sr_free_val_iter(sriter);

    return 0;
}

struct nc_server_reply *
op_get(struct lyd_node *rpc, struct nc_session *ncs)
{
    const struct lys_module *module;
    const struct lys_node *snode;
    struct lyd_node_leaf_list *leaf;
    struct lyd_node *root = NULL, *node, *yang_lib_data = NULL, *ncm_data = NULL, *ntf_data = NULL;
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
    if (ds != sessions->ds || (sessions->opts & SR_SESS_CONFIG_ONLY) != config_only) {
        /* update sysrepo session datastore */
        if (np2srv_sr_session_switch_ds(sessions->srs, ds, &ereply)) {
           goto error;
        }
        sessions->ds = ds;

        /* update sysrepo session config */
        if (np2srv_sr_session_set_options(sessions->srs, config_only, &ereply)) {
            goto error;
        }
        sessions->opts = config_only;
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
        /* special case, we have this data locally */
        if (!strncmp(filters[i], "/ietf-yang-library:", 19)) {
            if (config_only) {
                /* these are all state data */
                continue;
            }

            if (!yang_lib_data) {
                yang_lib_data = ly_ctx_info(np2srv.ly_ctx);
                if (!yang_lib_data) {
                    goto error;
                }
            }

            if (op_filter_get_tree_from_data(&root, yang_lib_data, filters[i])) {
                goto error;
            }
            continue;
        } else if (!strncmp(filters[i], "/ietf-netconf-monitoring:", 25)) {
            if (config_only) {
                /* these are all state data */
                continue;
            }

            if (!ncm_data) {
                ncm_data = ncm_get_data();
                if (!ncm_data) {
                    goto error;
                }
            }

            if (op_filter_get_tree_from_data(&root, ncm_data, filters[i])) {
                goto error;
            }
            continue;
        } else if (!strncmp(filters[i], "/nc-notifications:", 18)) {
            if (config_only) {
                /* these are all state data */
                continue;
            }

            if (!ntf_data) {
                ntf_data = ntf_get_data();
                if (!ntf_data) {
                    goto error;
                }
            }

            if (op_filter_get_tree_from_data(&root, ntf_data, filters[i])) {
                goto error;
            }
            continue;
        }

        /* create this subtree */
        if (opget_build_subtree_from_sysrepo(sessions->srs, &root, filters[i])) {
            goto error;
        }
    }
    lyd_free_withsiblings(yang_lib_data);
    yang_lib_data = NULL;
    lyd_free_withsiblings(ncm_data);
    ncm_data = NULL;
    lyd_free_withsiblings(ntf_data);
    ntf_data = NULL;

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

    lyd_free_withsiblings(yang_lib_data);
    lyd_free_withsiblings(ncm_data);
    lyd_free_withsiblings(ntf_data);
    lyd_free_withsiblings(root);
    return ereply;
}
