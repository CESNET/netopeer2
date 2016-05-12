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
                retval = NP2_EDIT_REPLACE;
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

static void
edit_set_value(struct lyd_node_leaf_list *leaf, sr_val_t *value)
{
    int i;
    uint8_t dig;
    int64_t shift = 10;
    sr_type_t map_ly2sr[] = {
        SR_BINARY_T,      /* LY_TYPE_BINARY */
        SR_BITS_T,        /* LY_TYPE_BITS */
        SR_BOOL_T,        /* LY_TYPE_BOOL */
        SR_DECIMAL64_T,   /*LY_TYPE_DEC64 */
        SR_LEAF_EMPTY_T,  /* LY_TYPE_EMPTY */
        SR_ENUM_T,        /* LY_TYPE_ENUM */
        SR_IDENTITYREF_T, /* LY_TYPE_IDENT */
        SR_INSTANCEID_T,  /* LY_TYPE_INST */
        SR_LEAFREF_T,     /* LY_TYPE_LEAFREF */
        SR_STRING_T,      /* LY_TYPE_STRING */
        SR_UNION_T,       /* LY_TYPE_UNION */
        SR_INT8_T,        /* LY_TYPE_INT8 */
        SR_UINT8_T,       /* LY_TYPE_UINT8 */
        SR_INT16_T,       /* LY_TYPE_INT16 */
        SR_UINT16_T,      /* LY_TYPE_UINT16 */
        SR_INT32_T,       /* LY_TYPE_INT32 */
        SR_UINT32_T,      /* LY_TYPE_UINT32 */
        SR_INT64_T,       /* LY_TYPE_INT64 */
        SR_UINT64_T       /* LY_TYPE_UINT64 */
    };

    assert(leaf && value);

    memset(value, 0, sizeof *value);
    value->type = map_ly2sr[leaf->value_type - 1];
    switch(leaf->value_type) {
    case LY_TYPE_BINARY:
    case LY_TYPE_BITS:
    case LY_TYPE_ENUM:
    case LY_TYPE_IDENT:
    case LY_TYPE_INST:
    case LY_TYPE_LEAFREF:
    case LY_TYPE_STRING:
        value->data.string_val = (char*)leaf->value.string;
        VRB("EDIT_CONFIG: type string (%d), value %s", leaf->value_type, value->data.string_val);
        break;
    case LY_TYPE_BOOL:
        value->data.bool_val = leaf->value.bln ? true : false;
        VRB("EDIT_CONFIG: type bool, value %d", value->data.bool_val);
        break;
    case LY_TYPE_DEC64:
        /* value = dec64 / 10^fraction-digits */
        dig = ((struct lys_node_leaf *)leaf->schema)->type.info.dec64.dig;
        for (i = 1; i < dig ; i++) {
            shift *= 10;
        }
        value->data.decimal64_val = leaf->value.dec64 / shift;
        VRB("EDIT_CONFIG: type dec64, value %f", value->data.decimal64_val);
        break;
    case LY_TYPE_INT8:
        value->data.int8_val = leaf->value.int8;
        VRB("EDIT_CONFIG: type int8, value %d", value->data.int8_val);
        break;
    case LY_TYPE_UINT8:
        value->data.uint8_val = leaf->value.uint8;
        VRB("EDIT_CONFIG: type uint8, value %u", value->data.uint8_val);
        break;
    case LY_TYPE_INT16:
        value->data.int16_val = leaf->value.int16;
        VRB("EDIT_CONFIG: type int16, value %d", value->data.int16_val);
        break;
    case LY_TYPE_UINT16:
        value->data.uint16_val = leaf->value.uint16;
        VRB("EDIT_CONFIG: type uint16, value %u", value->data.uint16_val);
        break;
    case LY_TYPE_INT32:
        value->data.int32_val = leaf->value.int32;
        VRB("EDIT_CONFIG: type int32, value %d", value->data.int32_val);
        break;
    case LY_TYPE_UINT32:
        value->data.uint32_val = leaf->value.uint32;
        VRB("EDIT_CONFIG: type uint32, value %u", value->data.uint32_val);
        break;
    case LY_TYPE_INT64:
        value->data.int64_val = leaf->value.int64;
        VRB("EDIT_CONFIG: type int32, value %ld", value->data.int32_val);
        break;
    case LY_TYPE_UINT64:
        value->data.uint64_val = leaf->value.uint64;
        VRB("EDIT_CONFIG: type uint64, value %lu", value->data.uint64_val);
        break;
    default:
        /* empty */
        break;
    }
}

struct nc_server_reply *
op_editconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    struct np2sr_sessions *sessions;
    sr_session_ctx_t *ds = NULL;
    sr_move_position_t pos = SR_MOVE_LAST;
    sr_val_t value_, *value = NULL;
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

    /* init */
    path[path_index] = '\0';

    /* get sysrepo connections for this session */
    sessions = (struct np2sr_sessions *)nc_session_get_data(ncs);

    /*
     * parse parameters
     */

    /* target */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:edit-config/target/*");
    cstr = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(cstr, "running")) {
        ds = sessions->running;
    /* TODO sysrepo does not support candidate
    } else if (!strcmp(nodeset->set.d[0]->schema->name, "candidate")) {
        ds = sessions->candidate;
    */
    }
    /* edit-config on startup is not allowed by RFC 6241 */

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
        config_xml = ((struct lyd_node_anyxml *)nodeset->set.d[0])->value.xml;
        ly_set_free(nodeset);

        config = lyd_parse_xml(np2srv.ly_ctx, &config_xml, LYD_OPT_EDIT);
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
    VRB("EDIT-CONFIG: ds %d, defop %d, testopt %d, config:\n%s", ds, defop, testopt, str);
    free(str);

    if (ds != sessions->candidate || !(sessions->flags & NP2SRV_CAND_MODIFIED)) {
        /* update data from sysrepo */
        if (sr_session_refresh(ds) != SR_ERR_OK) {
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
        }

        /* specific work for different node types */
        ret = -1;
        rel = NULL;
        switch(iter->schema->nodetype) {
        case LYS_CONTAINER:
            cont = (struct lys_node_container *)iter->schema;
            if (!cont->presence) {
                /* do nothing */
                goto dfs_continue;
            }

            VRB("EDIT_CONFIG: presence container %s, operation %d", path, op[op_index]);
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
                    VRB("EDIT_CONFIG: list %s, operation %d", path, op[op_index]);
                    break;
                }
                goto dfs_continue;
            }
            /* regular leaf */
            VRB("EDIT_CONFIG: leaf %s, operation %d", path, op[op_index]);

            /* set value for sysrepo */
            value = &value_;
            edit_set_value((struct lyd_node_leaf_list *)iter, value);


            break;
        case LYS_LEAFLIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            VRB("EDIT_CONFIG: leaflist %s, operation %d", path, op[op_index]);
            if (pos != SR_MOVE_LAST) {
                VRB("EDIT_CONFIG: moving leaflist %s, position %d (%s)", path, pos, rel ? rel : "absolute");
            }

            /* set value for sysrepo */
            value = &value_;
            edit_set_value((struct lyd_node_leaf_list *)iter, value);

            break;
        case LYS_LIST:
            /* get info about inserting to a specific place */
            if (edit_get_move(iter, path, &pos, &rel)) {
                goto internalerror;
            }

            /* the creation must be finished later when we get know keys */
            missing_keys = ((struct lys_node_list *)iter->schema)->keys_size;
            goto dfs_continue;
        case LYS_ANYXML:
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
            ret = sr_set_item(ds, path, value, 0);
            break;
        case NP2_EDIT_CREATE:
            /* create the node, but it must not exists */
            ret = sr_set_item(ds, path, value, SR_EDIT_STRICT);
            break;
        case NP2_EDIT_DELETE:
            /* remove the node, but it must exists */
            ret = sr_delete_item(ds, path, SR_EDIT_STRICT);
            break;
        case NP2_EDIT_REMOVE:
            /* remove the node */
            ret = sr_delete_item(ds, path, 0);
            break;
        default:
            /* do nothing */
            break;
        }
        value = NULL;

resultcheck:
        /* check the result */
        switch (ret) {
        case SR_ERR_OK:
            VRB("EDIT_CONFIG: success (%s)", path);
            if (ds == sessions->candidate) {
                sessions->flags |= NP2SRV_CAND_MODIFIED;
            }
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
                VRB("EDIT-CONFIG: continue-on-error (%s).", nc_err_get_msg(e));
                if (ereply) {
                    nc_server_reply_add_err(ereply, e);
                } else {
                    ereply = nc_server_reply_err(e);
                }
                e = NULL;
                goto dfs_nextsibling;
            case NP2_EDIT_ERROPT_ROLLBACK:
                VRB("EDIT-CONFIG: rollback-on-error (%s).", nc_err_get_msg(e));
                sr_discard_changes(ds);
                goto cleanup;
            case NP2_EDIT_ERROPT_STOP:
                VRB("EDIT-CONFIG: stop-on-error (%s).", nc_err_get_msg(e));
                if (ds != sessions->candidate) {
                    sr_commit(ds);
                }
                goto cleanup;
            }
        }

        /* move user-ordered list/leaflist */
        if (pos != SR_MOVE_LAST) {
            ret = sr_move_item(ds, path, pos, rel);
            free(rel);
            pos = SR_MOVE_LAST;
            goto resultcheck;
        }

dfs_continue:
        /* where go next? - modified LY_TREE_DFS_END */
        if (iter->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) {
dfs_nextsibling:
            next = NULL;
        } else {
            next = iter->child;
        }
        if (!next) {
            /* no children, try siblings */
            next = iter->next;

            /* maintain "stack" variables */
            if (!missing_keys && !(lastkey--)) {
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
        if (ds != sessions->candidate) {
            /* commit the result */
            if (sr_commit(ds) != SR_ERR_OK) {
                goto internalerror;
            }
        } /* in case of candidate, it is applied by an explicit commit operation */

        /* build positive RPC Reply */
        VRB("EDIT-CONFIG: done.");
        return nc_server_reply_ok();
    }

internalerror:
    e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, np2log_lasterr(), "en");

    /* fatal error, so continue-on-error does not apply here,
     * instead we rollback */
    VRB("EDIT-CONFIG: fatal error, rolling back.");
    sr_discard_changes(ds);

    free(op);
    lyd_free_withsiblings(config);

errorreply:
    if (ereply) {
        nc_server_reply_add_err(ereply, e);
        return ereply;
    } else {
        return nc_server_reply_err(e);
    }
}
