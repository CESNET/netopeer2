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
                !strcmp(attr->annotation->module->name, "ietf-netconf")) {
            /* NETCONF operation attribute */
            if (!strcmp(attr->value_str, "create")) {
                retval = NP2_EDIT_CREATE;
            } else if (!strcmp(attr->value_str, "delete")) {
                retval = NP2_EDIT_DELETE;
            } else if (!strcmp(attr->value_str, "remove")) {
                retval = NP2_EDIT_REMOVE;
            } else if (!strcmp(attr->value_str, "replace")) {
                retval = NP2_EDIT_REPLACE;
            } else if (!strcmp(attr->value_str, "merge")) {
                retval = NP2_EDIT_MERGE;
            } /* else invalid attribute checked by libyang */

            goto cleanup;
        }
    }

    switch (parentop) {
    case NP2_EDIT_REPLACE:
        return NP2_EDIT_REPLACE_INNER;
    case NP2_EDIT_NONE:
        switch (defop) {
        case NP2_EDIT_DEFOP_NONE:
            return NP2_EDIT_NONE;
        case NP2_EDIT_DEFOP_MERGE:
            return NP2_EDIT_MERGE;
        case NP2_EDIT_DEFOP_REPLACE:
            return NP2_EDIT_REPLACE;
        default:
            EINT;
            return 0;
        }
    default:
        return parentop;
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
        if (!strcmp(attr_iter->annotation->module->name, "yang")) {
            if (!strcmp(attr_iter->name, "insert")) {
                if (!strcmp(attr_iter->value_str, "first")) {
                    *pos = SR_MOVE_FIRST;
                } else if (!strcmp(attr_iter->value_str, "last")) {
                    *pos = SR_MOVE_LAST;
                } else if (!strcmp(attr_iter->value_str, "before")) {
                    *pos = SR_MOVE_BEFORE;
                } else if (!strcmp(attr_iter->value_str, "after")) {
                    *pos = SR_MOVE_AFTER;
                }
            } else if (!strcmp(attr_iter->name, name)) {
                if (asprintf(rel, format, path, attr_iter->value_str) < 0) {
                    ERR("%s: memory allocation failed (%s) - %s:%d",
                        __func__, strerror(errno), __FILE__, __LINE__);
                    return -1;
                }
            }
        }
    }

    return 0;
}

static const char *
defop2str(enum NP2_EDIT_DEFOP defop)
{
    switch (defop) {
    case NP2_EDIT_DEFOP_MERGE:
        return "merge";
    case NP2_EDIT_DEFOP_REPLACE:
        return "replace";
    default:
        break;
    }

    return "none";
}

static const char *
op2str(enum NP2_EDIT_OP op)
{
    switch (op) {
    case NP2_EDIT_ERROR:
        return "error";
    case NP2_EDIT_MERGE:
        return "merge";
    case NP2_EDIT_CREATE:
        return "create";
    case NP2_EDIT_REPLACE:
        return "replace";
    case NP2_EDIT_REPLACE_INNER:
        return "inner replace";
    case NP2_EDIT_DELETE:
        return "delete";
    case NP2_EDIT_REMOVE:
        return "remove";
    default:
        break;
    }

    return "none";
}

struct nc_server_reply *
op_editconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    struct np2_sessions *sessions = NULL;
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
    struct lyd_node *config = NULL, *next, *iter;
    char *str, *path, *rel, *valbuf, quot;
    const char *cstr;
    enum NP2_EDIT_OP *op = NULL, *op_new;
    uint16_t *path_levels = NULL, *path_levels_new;
    uint16_t path_levels_index, path_levels_size = 0;
    int op_index, op_size, path_index = 0, missing_keys = 0, lastkey = 0, np_cont;
    int ret, path_len, new_len;
    struct lyd_node_anydata *any;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:edit-config", &ereply)) {
        goto cleanup;
    }

    /* init */
    path_len = 128;
    path = malloc(path_len);
    if (!path) {
        EMEM;
        goto internalerror;
    }
    path[path_index] = '\0';

    /*
     * parse parameters
     */

    /* target */
    nodeset = lyd_find_path(rpc, "/ietf-netconf:edit-config/target/*");
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
        if (np2srv_sr_session_switch_ds(sessions->srs, ds, &ereply)) {
            goto cleanup;
        }
        sessions->ds = ds;
    }

    /* default-operation */
    nodeset = lyd_find_path(rpc, "/ietf-netconf:edit-config/default-operation");
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
    nodeset = lyd_find_path(rpc, "/ietf-netconf:edit-config/test-option");
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
    nodeset = lyd_find_path(rpc, "/ietf-netconf:edit-config/error-option");
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
    nodeset = lyd_find_path(rpc, "/ietf-netconf:edit-config/config");
    if (nodeset->number) {
        any = (struct lyd_node_anydata *)nodeset->set.d[0];
        switch (any->value_type) {
        case LYD_ANYDATA_CONSTSTRING:
        case LYD_ANYDATA_STRING:
        case LYD_ANYDATA_SXML:
            config = lyd_parse_mem(np2srv.ly_ctx, any->value.str, LYD_XML, LYD_OPT_EDIT | LYD_OPT_STRICT);
            break;
        case LYD_ANYDATA_DATATREE:
            config = any->value.tree;
            any->value.tree = NULL; /* "unlink" data tree from anydata to have full control */
            break;
        case LYD_ANYDATA_XML:
            config = lyd_parse_xml(np2srv.ly_ctx, &any->value.xml, LYD_OPT_EDIT | LYD_OPT_STRICT);
            break;
        case LYD_ANYDATA_JSON:
        case LYD_ANYDATA_JSOND:
        case LYD_ANYDATA_SXMLD:
            EINT;
            break;
        }
        ly_set_free(nodeset);
        if (ly_errno) {
            ereply = nc_server_reply_err(nc_err_libyang());
            goto cleanup;
        } else if (!config) {
            /* nothing to do */
            ereply = nc_server_reply_ok();
            goto cleanup;
        }
    } else {
        /* TODO support for :url capability */
        ly_set_free(nodeset);
        EINT;
        goto internalerror;
    }

    lyd_print_mem(&str, config, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    DBG("EDIT_CONFIG: ds %d, defop %s, testopt %d, config:\n%s", sessions->srs, defop2str(defop), testopt, str);
    free(str);
    str = NULL;

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update data from sysrepo */
        if (np2srv_sr_session_refresh(sessions->srs, &ereply)) {
            goto cleanup;
        }
    }

    /*
     * data manipulation
     */
    valbuf = NULL;
    path_levels_size = op_size = 16;
    op = malloc(op_size * sizeof *op);
    op[0] = NP2_EDIT_NONE;
    op_index = 0;
    path_levels = malloc(path_levels_size * sizeof *path_levels);
    path_levels_index = 0;
    LY_TREE_DFS_BEGIN(config, next, iter) {

        /* maintain list of operations */
        if (!missing_keys) {
            op_index++;
            if (op_index == op_size) {
                op_size += 16;
                op_new = realloc(op, op_size * sizeof *op);
                if (!op_new) {
                    EMEM;
                    goto internalerror;
                }
                op = op_new;
            }
            op[op_index] = edit_get_op(iter, op[op_index - 1], defop);

            /* maintain path */
            if (path_levels_index == path_levels_size) {
                path_levels_size += 16;
                path_levels_new = realloc(path_levels, path_levels_size * sizeof *path_levels);
                if (!path_levels_new) {
                    EMEM;
                    goto internalerror;
                }
                path_levels = path_levels_new;
            }
            path_levels[path_levels_index++] = path_index;
            if (!iter->parent || lyd_node_module(iter) != lyd_node_module(iter->parent)) {
                /* with prefix */
                new_len = path_index + 1 + strlen(lyd_node_module(iter)->name) + 1 + strlen(iter->schema->name) + 1;
                if (new_len > path_len) {
                    path_len = new_len;
                    path = realloc(path, new_len);
                }
                path_index += sprintf(&path[path_index], "/%s:%s", lyd_node_module(iter)->name, iter->schema->name);
            } else {
                /* without prefix */
                new_len = path_index + 1 + strlen(iter->schema->name) + 1;
                if (new_len > path_len) {
                    path_len = new_len;
                    path = realloc(path, new_len);
                }
                path_index += sprintf(&path[path_index], "/%s", iter->schema->name);
            }

            /* erase value */
            memset(&value, 0, sizeof value);
        }

        /* specific work for different node types */
        ret = -1;
        rel = NULL;
        lastkey = 0;
        np_cont = 0;
        switch (iter->schema->nodetype) {
        case LYS_CONTAINER:
            if (!((struct lys_node_container *)iter->schema)->presence) {
                np_cont = 1;
            }
            if ((op[op_index] < NP2_EDIT_REPLACE) && np_cont) {
                /* do nothing, creating non-presence containers is not necessary */
                goto dfs_continue;
            }


            DBG("EDIT_CONFIG: %s container %s, operation %s", (!np_cont ? "presence" : ""), path, op2str(op[op_index]));
            break;
        case LYS_LEAF:
            if (missing_keys) {
                /* still processing list keys */
                missing_keys--;
                /* add key predicate into the list's path */
                new_len = path_index + 1 + strlen(iter->schema->name) + 2
                          + strlen(((struct lyd_node_leaf_list *)iter)->value_str) + 3;
                if (new_len > path_len) {
                    path_len = new_len;
                    path = realloc(path, new_len);
                }

                if (strchr(((struct lyd_node_leaf_list *)iter)->value_str, '\'')) {
                    quot = '\"';
                } else {
                    quot = '\'';
                }
                path_index += sprintf(&path[path_index], "[%s=%c%s%c]", iter->schema->name, quot,
                                      ((struct lyd_node_leaf_list *)iter)->value_str, quot);
                if (!missing_keys) {
                    /* the last key, create the list instance */
                    lastkey = 1;

                    DBG("EDIT_CONFIG: list %s, operation %s", path, op2str(op[op_index]));
                    break;
                }
                goto dfs_continue;
            }

            /* regular leaf */
            DBG("EDIT_CONFIG: leaf %s, operation %s", path, op2str(op[op_index]));
            break;
        case LYS_LEAFLIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            DBG("EDIT_CONFIG: leaflist %s, operation %s", path, op2str(op[op_index]));
            if (pos != SR_MOVE_LAST) {
                DBG("EDIT_CONFIG: moving leaflist %s, position %d (%s)", path, pos, rel ? rel : "absolute");
            }

            /* in leaf-list, the value is also the key, so add it into the path */
            new_len = path_index + 4 + strlen(((struct lyd_node_leaf_list *)iter)->value_str) + 3;
            if (new_len > path_len) {
                path_len = new_len;
                path = realloc(path, new_len);
            }
            if (strchr(((struct lyd_node_leaf_list *)iter)->value_str, '\'')) {
                quot = '\"';
            } else {
                quot = '\'';
            }
            path_index += sprintf(&path[path_index], "[.=%c%s%c]", quot, ((struct lyd_node_leaf_list *)iter)->value_str, quot);

            break;
        case LYS_LIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            if (op[op_index] < NP2_EDIT_DELETE) {
                /* set value for sysrepo, it will be used as soon as all the keys are processed */
                op_set_srval(iter, NULL, 0, &value, &valbuf);
            }

            /* the creation must be finished later when we get know keys */
            missing_keys = ((struct lys_node_list *)iter->schema)->keys_size;
            goto dfs_continue;
        case LYS_ANYXML:
        case LYS_ANYDATA:
            /* nothing special needed, not even supported by sysrepo */
            break;
        default:
            ERR("%s: Invalid node to process", __func__);
            goto internalerror;
        }

        if ((op[op_index] < NP2_EDIT_DELETE) && !lastkey) {
            /* set value for sysrepo */
            op_set_srval(iter, NULL, 0, &value, &valbuf);
        }

        /* apply change to sysrepo */
        switch (op[op_index]) {
        case NP2_EDIT_MERGE:
            /* create the node */
            if (!np_cont) {
                ret = np2srv_sr_set_item(sessions->srs, path, &value, 0, &ereply);
            }
            break;
        case NP2_EDIT_REPLACE_INNER:
        case NP2_EDIT_CREATE:
            /* create the node, but it must not exists */
            ret = np2srv_sr_set_item(sessions->srs, path, &value, SR_EDIT_STRICT, &ereply);
            break;
        case NP2_EDIT_DELETE:
            /* remove the node, but it must exists */
            ret = np2srv_sr_delete_item(sessions->srs, path, SR_EDIT_STRICT, &ereply);
            break;
        case NP2_EDIT_REMOVE:
            /* remove the node */
            ret = np2srv_sr_delete_item(sessions->srs, path, 0, &ereply);
            break;
        case NP2_EDIT_REPLACE:
            /* remove the node first */
            ret = np2srv_sr_delete_item(sessions->srs, path, 0, &ereply);
            /* create it again (but we removed all the children, sysrepo forbids creating NP containers as it's redundant) */
            if (!ret && !np_cont) {
                ret = np2srv_sr_set_item(sessions->srs, path, &value, 0, &ereply);
            }
            break;
        default:
            /* do nothing */
            break;
        }
        if (valbuf) {
            free(valbuf);
            valbuf = NULL;
        }

resultcheck:
        /* check the result */
        if (!ret) {
            DBG("EDIT_CONFIG: success (%s).", path);
        } else {
            switch (erropt) {
            case NP2_EDIT_ERROPT_CONT:
                DBG("EDIT_CONFIG: continue-on-error (%s).", nc_err_get_msg(nc_server_reply_get_last_err(ereply)));
                goto dfs_nextsibling;
            case NP2_EDIT_ERROPT_ROLLBACK:
                DBG("EDIT_CONFIG: rollback-on-error (%s).", nc_err_get_msg(nc_server_reply_get_last_err(ereply)));
                goto cleanup;
            case NP2_EDIT_ERROPT_STOP:
                DBG("EDIT_CONFIG: stop-on-error (%s).", nc_err_get_msg(nc_server_reply_get_last_err(ereply)));
                goto cleanup;
            }
        }

        /* move user-ordered list/leaflist */
        if (pos != SR_MOVE_LAST) {
            ret = np2srv_sr_move_item(sessions->srs, path, pos, rel, &ereply);
            free(rel);
            pos = SR_MOVE_LAST;
            goto resultcheck;
        }

        if ((op[op_index] == NP2_EDIT_DELETE) || (op[op_index] == NP2_EDIT_REMOVE)
                || ((op[op_index] == NP2_EDIT_CREATE) && (ret == SR_ERR_DATA_EXISTS))) {
            /* when delete, remove subtree, or failed create
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
            	assert(op_index > 0);
                assert(path_levels_index > 0);
                op_index--;
                path_levels_index--;
                path_index = path_levels[path_levels_index];
                path[path_index] = '\0';
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
            	assert(op_index > 0);
                assert(path_levels_index > 0);
                op_index--;
                path_levels_index--;
                path_index = path_levels[path_levels_index];
                path[path_index] = '\0';
            }

        }
        /* end of modified LY_TREE_DFS_END */
    }

cleanup:
    /* cleanup */
    free(path);
    path = NULL;
    free(op);
    op = NULL;
    free(path_levels);
    path_levels = NULL;
    lyd_free_withsiblings(config);
    config = NULL;

    /* just rollback and return error */
    if ((erropt == NP2_EDIT_ERROPT_ROLLBACK) && ereply) {
        np2srv_sr_discard_changes(sessions->srs, NULL);
        return ereply;
    }

    switch (testopt) {
    case NP2_EDIT_TESTOPT_SET:
        VRB("edit-config test-option \"set\" not supported, validation will be performed.");
        /* fallthrough */
    case NP2_EDIT_TESTOPT_TESTANDSET:
        /* commit changes */
        if (np2srv_sr_commit(sessions->srs, &ereply)) {
            np2srv_sr_discard_changes(sessions->srs, NULL); /* rollback the changes */
        }
        if (sessions->ds == SR_DS_CANDIDATE) {
            /* mark candidate as modified */
            sessions->flags |= NP2S_CAND_CHANGED;
        }
        break;
    case NP2_EDIT_TESTOPT_TEST:
        np2srv_sr_discard_changes(sessions->srs, NULL);
        break;
    }

    if (ereply) {
        return ereply;
    }

    /* build positive RPC Reply */
    DBG("EDIT_CONFIG: success.");
    return nc_server_reply_ok();

internalerror:
    e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, np2log_lasterr(), "en");
    if (ereply) {
        nc_server_reply_add_err(ereply, e);
    } else {
        ereply = nc_server_reply_err(e);
    }

    /* fatal error, so continue-on-error does not apply here,
     * instead we rollback */
    DBG("EDIT_CONFIG: fatal error, rolling back.");
    np2srv_sr_discard_changes(sessions->srs, NULL);

    free(path);
    free(op);
    free(path_levels);
    lyd_free_withsiblings(config);
    return ereply;
}
