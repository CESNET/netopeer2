/**
 * @file op_editconfig.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF <edit-config> operation implementation
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

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

static enum NP2_EDIT_OP
edit_get_op(struct lyd_node *node, enum NP2_EDIT_OP parentop, enum NP2_EDIT_DEFOP defop)
{
    enum NP2_EDIT_OP retval = NP2_EDIT_ERROR;
    struct lyd_attr *attr;

    assert(node);

    /* TODO check conflicts between parent and current operations */
    for (attr = node->attr; attr; attr = attr->next) {
        if (!strcmp(attr->name, "operation") &&
                !strcmp(attr->module->name, "ietf-netconf")) {
            /* NETCONF operation attribute */
            if (!strcmp(attr->value, "create")) {
                retval = NP2_EDIT_CREATE;
            } else if (!strcmp(attr->value, "delete")) {
                retval = NP2_EDIT_DELETE;
            } else if (!strcmp(attr->value, "remove")) {
                retval = NP2_EDIT_REMOVE;
            } else if (!strcmp(attr->value, "replace")) {
                retval = NP2_EDIT_REPLACE;
            } else if (!strcmp(attr->value, "merge")) {
                retval = NP2_EDIT_MERGE;
            } /* else invalid attribute checked by libyang */

            goto cleanup;
        }
    }

    if (parentop > 0) {
        return parentop;
    } else {
        return (enum NP2_EDIT_OP) defop;
    }

cleanup:

    lyd_free_attr(node->schema->module->ctx, node, attr, 0);
    return retval;
}

static int
edit_get_move(struct lyd_node *node, const char *path, sr_move_position_t *pos, char **rel)
{
    const char *name, *format;
    struct lyd_attr *attr_iter;

    if (node->schema->nodetype & LYS_LIST) {
        name = "key";
        format = "%s%s";
    } else {
        name = "value";
        format = "%s[.=\'%s\']";
    }

    for(attr_iter = node->attr; attr_iter; attr_iter = attr_iter->next) {
        if (!strcmp(attr_iter->module->name, "yang")) {
            if (!strcmp(attr_iter->name, "insert")) {
                if (!strcmp(attr_iter->value, "first")) {
                    *pos = SR_MOVE_FIRST;
                } else if (!strcmp(attr_iter->value, "last")) {
                    *pos = SR_MOVE_LAST;
                } else if (!strcmp(attr_iter->value, "before")) {
                    *pos = SR_MOVE_BEFORE;
                } else if (!strcmp(attr_iter->value, "after")) {
                    *pos = SR_MOVE_AFTER;
                }
            } else if (!strcmp(attr_iter->name, name)) {
                if (asprintf(rel, format, path, attr_iter->value)) {
                    ERR("%s: memory allocation failed (%s) - %s:%d",
                        __func__, strerror(errno), __FILE__, __LINE__);
                    return EXIT_FAILURE;
                }
            }
        }
    }

    return EXIT_SUCCESS;
}

struct nc_server_reply *
op_editconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    struct np2_sessions *sessions;
    sr_datastore_t ds = 0;
    sr_move_position_t pos = SR_MOVE_LAST;
    sr_val_t value;
    struct ly_set *nodeset;
    /* default value for default-operation is "merge" */
    enum NP2_EDIT_DEFOP defop = NP2_EDIT_DEFOP_MERGE;
    /* default value for test-option is "test-then-set" */
    enum NP2_EDIT_TESTOPT testopt = NP2_EDIT_TESTOPT_TESTANDSET;
    /* default value for error-option is "stop-on-error" */
    enum NP2_EDIT_ERROPT erropt = NP2_EDIT_ERROPT_STOP;
    struct lyxml_elem *config_xml;
    struct lyd_node *config = NULL, *next, *iter;
    char *str, path[1024], *rel;
    const char *cstr;
    enum NP2_EDIT_OP *op = NULL, *op_new;
    int op_index, op_size, path_index = 0, missing_keys = 0, lastkey = 0;
    int ret;
    struct lys_node_container *cont;
    struct lyd_node_anyxml *axml;
    const sr_error_info_t *err_info;
    size_t err_count, i;

    /* init */
    path[path_index] = '\0';

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /*
     * parse parameters
     */

    /* target */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/target/*");
    cstr = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(cstr, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(cstr, "candidate")) {
        ds = SR_DS_CANDIDATE;
    }
    /* edit-config on startup is not allowed by RFC 6241 */
    if (ds != sessions->ds) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, ds);
        sessions->ds = ds;
    }

    /* default-operation */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/default-operation");
    if (nodeset->number) {
        cstr = ((struct lyd_node_leaf_list*)nodeset->set.d[0])->value_str;
        if (!strcmp(cstr, "replace")) {
            defop = NP2_EDIT_DEFOP_REPLACE;
        } else if (!strcmp(cstr, "none")) {
            defop = NP2_EDIT_DEFOP_NONE;
        } else if (!strcmp(cstr, "merge")) {
            defop = NP2_EDIT_DEFOP_MERGE;
        }
    }
    ly_set_free(nodeset);

    /* test-option */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/test-option");
    if (nodeset->number) {
        cstr = ((struct lyd_node_leaf_list*)nodeset->set.d[0])->value_str;
        if (!strcmp(cstr, "set")) {
            testopt = NP2_EDIT_TESTOPT_SET;
        } else if (!strcmp(cstr, "test-only")) {
            testopt = NP2_EDIT_TESTOPT_TEST;
        } else if (!strcmp(cstr, "test-then-set")) {
            testopt = NP2_EDIT_TESTOPT_TESTANDSET;
        }
    }
    ly_set_free(nodeset);

    /* error-option */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/error-option");
    if (nodeset->number) {
        cstr = ((struct lyd_node_leaf_list*)nodeset->set.d[0])->value_str;
        if (!strcmp(cstr, "rollback-on-error")) {
            erropt = NP2_EDIT_ERROPT_ROLLBACK;
        } else if (!strcmp(cstr, "continue-on-error")) {
            erropt = NP2_EDIT_ERROPT_CONT;
        } else if (!strcmp(cstr, "stop-on-error")) {
            erropt = NP2_EDIT_ERROPT_STOP;
        }
    }
    ly_set_free(nodeset);


    /* config */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/config");
    if (nodeset->number) {
        axml = (struct lyd_node_anyxml *)nodeset->set.d[0];
        if (axml->xml_struct) {
            config_xml = axml->value.xml;
            config = lyd_parse_xml(np2srv.ly_ctx, &config_xml, LYD_OPT_EDIT);
        } else {
            cstr = axml->value.str;
            config = lyd_parse_mem(np2srv.ly_ctx, cstr, LYD_XML, LYD_OPT_EDIT);
        }
        ly_set_free(nodeset);
        if (ly_errno) {
            return nc_server_reply_err(nc_err_libyang());
        } else if (!config) {
            /* nothing to do */
            return nc_server_reply_ok();
        }
    } else {
        /* TODO support for :url capability */
        ly_set_free(nodeset);
        goto internalerror;
    }

    lyd_print_mem(&str, config, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    DBG("EDIT_CONFIG: ds %d, defop %d, testopt %d, config:\n%s", sessions->srs, defop, testopt, str);
    free(str);

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update data from sysrepo */
        if (sr_session_refresh(sessions->srs) != SR_ERR_OK) {
            goto internalerror;
        }
    }

    /*
     * data manipulation
     */

    op_size = 16;
    op = malloc(op_size * sizeof *op);
    op[0] = NP2_EDIT_NONE;
    op_index = 0;
    LY_TREE_DFS_BEGIN(config, next, iter) {

        /* maintain list of operations */
        if (!missing_keys) {
            op_index++;
            if (op_index == op_size) {
                op_size += 16;
                op_new = realloc(op, op_size * sizeof *op);
                if (!op_new) {
                    ERR("%s: memory allocation failed (%s) - %s:%d", __func__, strerror(errno), __FILE__, __LINE__);
                    goto internalerror;
                }
                op = op_new;
            }
            op[op_index] = edit_get_op(iter, op[op_index - 1], defop);

            /* maintain path */
            if (!iter->parent || lyd_node_module(iter) != lyd_node_module(iter->parent)) {
                /* with prefix */
                path_index += sprintf(&path[path_index], "/%s:%s", lyd_node_module(iter)->name, iter->schema->name);
            } else {
                /* without prefix */
                path_index += sprintf(&path[path_index], "/%s", iter->schema->name);
            }

            /* erase value */
            memset(&value, 0, sizeof value);
        }

        /* specific work for different node types */
        ret = -1;
        rel = NULL;
        lastkey = 0;
        switch(iter->schema->nodetype) {
        case LYS_CONTAINER:
            cont = (struct lys_node_container *)iter->schema;
            if (op[op_index] < NP2_EDIT_DELETE && !cont->presence) {
                /* do nothing, creating non-presence containers is not necessary */
                goto dfs_continue;
            }

            DBG("EDIT_CONFIG: presence container %s, operation %d", path, op[op_index]);

            /* set value for sysrepo */
            op_set_srval(iter, NULL, 0, &value, &str);

            break;
        case LYS_LEAF:
            if (missing_keys) {
                /* still processing list keys */
                missing_keys--;
                /* add key predicate into the list's path */
                path_index += sprintf(&path[path_index], "[%s=\'%s\']", iter->schema->name,
                                      ((struct lyd_node_leaf_list *)iter)->value_str);
                if (!missing_keys) {
                    /* the last key, create the list instance */
                    lastkey = 1;

                    DBG("EDIT_CONFIG: list %s, operation %d", path, op[op_index]);
                    break;
                }
                goto dfs_continue;
            }
            /* regular leaf */
            DBG("EDIT_CONFIG: leaf %s, operation %d", path, op[op_index]);

            /* set value for sysrepo */
            op_set_srval(iter, NULL, 0, &value, &str);

            break;
        case LYS_LEAFLIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            DBG("EDIT_CONFIG: leaflist %s, operation %d", path, op[op_index]);
            if (pos != SR_MOVE_LAST) {
                DBG("EDIT_CONFIG: moving leaflist %s, position %d (%s)", path, pos, rel ? rel : "absolute");
            }

            /* set value for sysrepo */
            op_set_srval(iter, NULL, 0, &value, &str);

            /* in leaf-list, the value is also the key, so add it into the path */
            path_index += sprintf(&path[path_index], "[.=\'%s\']", ((struct lyd_node_leaf_list *)iter)->value_str);

            break;
        case LYS_LIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            /* set value for sysrepo, it will be used as soon as all the keys are processed */
            op_set_srval(iter, NULL, 0, &value, &str);

            /* the creation must be finished later when we get know keys */
            missing_keys = ((struct lys_node_list *)iter->schema)->keys_size;
            goto dfs_continue;
        case LYS_ANYXML:
            /* set value for sysrepo */
            op_set_srval(iter, NULL, 0, &value, &str);

            break;
        default:
            ERR("%s: Invalid node to process", __func__);
            goto internalerror;
        }

        /* apply change to sysrepo */
        switch (op[op_index]) {
        case NP2_EDIT_MERGE:
        case NP2_EDIT_REPLACE:
            /* create the node */
            ret = sr_set_item(sessions->srs, path, &value, 0);
            break;
        case NP2_EDIT_CREATE:
            /* create the node, but it must not exists */
            ret = sr_set_item(sessions->srs, path, &value, SR_EDIT_STRICT);
            break;
        case NP2_EDIT_DELETE:
            /* remove the node, but it must exists */
            ret = sr_delete_item(sessions->srs, path, SR_EDIT_STRICT);
            break;
        case NP2_EDIT_REMOVE:
            /* remove the node */
            ret = sr_delete_item(sessions->srs, path, 0);
            break;
        default:
            /* do nothing */
            break;
        }
        if (str) {
            free(str);
            str = NULL;
        }

resultcheck:
        /* check the result */
        switch (ret) {
        case SR_ERR_OK:
            DBG("EDIT_CONFIG: success (%s).", path);
            /* no break */
        case -1:
            /* do nothing */
            break;
        case SR_ERR_UNAUTHORIZED:
            e = nc_err(NC_ERR_ACCESS_DENIED, NC_ERR_TYPE_PROT);
            nc_err_set_path(e, path);
            break;
        case SR_ERR_DATA_EXISTS:
            e = nc_err(NC_ERR_DATA_EXISTS, NC_ERR_TYPE_PROT);
            nc_err_set_path(e, path);
            break;
        case SR_ERR_DATA_MISSING:
            e = nc_err(NC_ERR_DATA_MISSING, NC_ERR_TYPE_PROT);
            nc_err_set_path(e, path);
            break;
        default:
            /* not covered error */
            goto internalerror;
        }
        if (e) {
            switch (erropt) {
            case NP2_EDIT_ERROPT_CONT:
                DBG("EDIT_CONFIG: continue-on-error (%s).", nc_err_get_msg(e));
                if (ereply) {
                    nc_server_reply_add_err(ereply, e);
                } else {
                    ereply = nc_server_reply_err(e);
                }
                e = NULL;
                goto dfs_nextsibling;
            case NP2_EDIT_ERROPT_ROLLBACK:
                DBG("EDIT_CONFIG: rollback-on-error (%s).", nc_err_get_msg(e));
                sr_discard_changes(sessions->srs);
                goto cleanup;
            case NP2_EDIT_ERROPT_STOP:
                DBG("EDIT_CONFIG: stop-on-error (%s).", nc_err_get_msg(e));
                if (sessions->ds != SR_DS_CANDIDATE) {
                    sr_commit(sessions->srs);
                } else {
                    /* mark candidate as modified */
                    sessions->flags |= NP2S_CAND_CHANGED;
                }
                goto cleanup;
            }
        }

        /* move user-ordered list/leaflist */
        if (pos != SR_MOVE_LAST) {
            ret = sr_move_item(sessions->srs, path, pos, rel);
            free(rel);
            pos = SR_MOVE_LAST;
            goto resultcheck;
        }

        if (op[op_index] > NP2_EDIT_CREATE) {
            /* when delete, remove or replace subtree
             * no need to go into children */
            if (lastkey) {
                /* we were processing list's keys */
                goto dfs_parent;
            } else {
                goto dfs_nextsibling;
            }
        }

dfs_continue:
        /* where go next? - modified LY_TREE_DFS_END */
        if (iter->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) {
            next = NULL;
        } else {
            next = iter->child;
        }
        if (!next) {
dfs_nextsibling:
            /* no children, try siblings */
            next = iter->next;

            /* maintain "stack" variables */
            if (!missing_keys && !lastkey) {
                op_index--;
                str = strrchr(path, '/');
                if (str) {
                    *str = '\0';
                    path_index = str - path;
                } else {
                    path[0] = '\0';
                    path_index = 0;
                }
            }
        }
        while (!next) {
dfs_parent:
            iter = iter->parent;

            /* parent is already processed, go to its sibling */
            if (!iter) {
                /* we are done */
                break;
            }
            next = iter->next;

            /* maintain "stack" variables */
            if (!missing_keys) {
                op_index--;
                str = strrchr(path, '/');
                if (str) {
                    *str = '\0';
                    path_index = str - path;
                } else {
                    path[0] = '\0';
                    path_index = 0;
                }
            }

        }
        /* end of modified LY_TREE_DFS_END */
    }

cleanup:
    /* cleanup */
    free(op);
    op = NULL;
    lyd_free_withsiblings(config);
    config = NULL;

    if (e || ereply) {
        /* send error reply */
        goto errorreply;
    } else {
        switch (testopt) {
        case NP2_EDIT_TESTOPT_SET:
            VRB("edit-config test-option \"set\" not supported, validation will be performed.");
            /* fallthrough */
        case NP2_EDIT_TESTOPT_TESTANDSET:
            if (sessions->ds != SR_DS_CANDIDATE) {
                /* commit in candidate causes copy to running */
                ret =  sr_commit(sessions->srs);
                switch (ret) {
                case SR_ERR_OK:
                    break;
                case SR_ERR_VALIDATION_FAILED:
                    sr_get_last_errors(sessions->srs, &err_info, &err_count);
                    for (i = 0; i < err_count; ++i) {
                        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_PROT);
                        nc_err_set_msg(e, err_info[i].message, "en");
                        nc_err_set_path(e, err_info[i].xpath);

                        if (ereply) {
                            nc_server_reply_add_err(ereply, e);
                        } else {
                            ereply = nc_server_reply_err(e);
                        }
                        e = NULL;
                    }
                    break;
                default:
                    goto internalerror;
                }
            } else {
                /* mark candidate as modified */
                sessions->flags |= NP2S_CAND_CHANGED;
            }
            break;
        case NP2_EDIT_TESTOPT_TEST:
            sr_discard_changes(sessions->srs);
            break;
        default:
            EINT;
            goto internalerror;
        }

        /* build positive RPC Reply */
        DBG("EDIT_CONFIG: done.");
        return nc_server_reply_ok();
    }

internalerror:
    e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, np2log_lasterr(), "en");

    /* fatal error, so continue-on-error does not apply here,
     * instead we rollback */
    DBG("EDIT_CONFIG: fatal error, rolling back.");
    sr_discard_changes(sessions->srs);

    free(op);
    lyd_free_withsiblings(config);

errorreply:
    if (ereply) {
        return ereply;
    } else {
        return nc_server_reply_err(e);
    }
}
