/**
 * @file op_generic.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF generic RPC operation implementation
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

static int
copy_bits(const struct lyd_node_leaf_list *leaf, char **dest)
{
    int i;
    struct lys_node_leaf *sch = (struct lys_node_leaf *) leaf->schema;
    char *bits_str = NULL;
    int bits_count = sch->type.info.bits.count;
    struct lys_type_bit **bits = leaf->value.bit;

    size_t length = 1; /* terminating NULL byte*/
    for (i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            length += strlen(bits[i]->name);
            length++; /*space after bit*/
        }
    }
    bits_str = calloc(length, sizeof(*bits_str));
    if (NULL == bits_str) {
        EMEM;
        return -1;
    }
    size_t offset = 0;
    for (i = 0; i < bits_count; i++) {
        if (NULL != bits[i] && NULL != bits[i]->name) {
            strcpy(bits_str + offset, bits[i]->name);
            offset += strlen(bits[i]->name);
            bits_str[offset] = ' ';
            offset++;
        }
    }
    if (0 != offset) {
        bits_str[offset - 1] = '\0';
    }

    *dest = bits_str;
    return 0;
}

static int
create_sr_value(struct lyd_node *node, sr_val_t *val)
{
    uint32_t i;
    struct lyd_node_leaf_list *leaf;

    val->xpath = lyd_path(node);
    val->dflt = 0;
    val->data.int64_val = 0;

    switch (node->schema->nodetype) {
    case LYS_CONTAINER:
        val->type = ((struct lys_node_container *)node->schema)->presence ? SR_CONTAINER_PRESENCE_T : SR_CONTAINER_T;
        break;
    case LYS_LIST:
        val->type = SR_LIST_T;
        break;
    case LYS_LEAF:
    case LYS_LEAFLIST:
        leaf = (struct lyd_node_leaf_list *)node;

        switch (((struct lys_node_leaf *)node->schema)->type.base) {
        case LY_TYPE_BINARY:
            val->type = SR_BINARY_T;
            val->data.binary_val = strdup(leaf->value.binary);
            if (NULL == val->data.binary_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_BITS:
            val->type = SR_BITS_T;
            if (copy_bits(leaf, &(val->data.bits_val))) {
                ERR("Copy value failed for leaf '%s' of type 'bits'", leaf->schema->name);
                return -1;
            }
            break;
        case LY_TYPE_BOOL:
            val->type = SR_BOOL_T;
            val->data.bool_val = leaf->value.bln;
            break;
        case LY_TYPE_DEC64:
            val->type = SR_DECIMAL64_T;
            val->data.decimal64_val = (double)leaf->value.dec64;
            for (i = 0; i < ((struct lys_node_leaf *)node->schema)->type.info.dec64.dig; i++) {
                /* shift decimal point */
                val->data.decimal64_val *= 0.1;
            }
            break;
        case LY_TYPE_EMPTY:
            val->type = SR_LEAF_EMPTY_T;
            break;
        case LY_TYPE_ENUM:
            val->type = SR_ENUM_T;
            val->data.enum_val = strdup(leaf->value.enm->name);
            if (NULL == val->data.enum_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_IDENT:
            val->type = SR_IDENTITYREF_T;
            val->data.identityref_val = strdup(leaf->value.ident->name);
            if (NULL == val->data.identityref_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_INST:
            val->type = SR_INSTANCEID_T;
            break;
        case LY_TYPE_STRING:
            val->type = SR_STRING_T;
            val->data.string_val = strdup(leaf->value.string);
            if (NULL == val->data.string_val) {
                EMEM;
                return -1;
            }
            break;
        case LY_TYPE_INT8:
            val->type = SR_INT8_T;
            val->data.int8_val = leaf->value.int8;
            break;
        case LY_TYPE_UINT8:
            val->type = SR_UINT8_T;
            val->data.uint8_val = leaf->value.uint8;
            break;
        case LY_TYPE_INT16:
            val->type = SR_INT16_T;
            val->data.int16_val = leaf->value.int16;
            break;
        case LY_TYPE_UINT16:
            val->type = SR_UINT16_T;
            val->data.uint16_val = leaf->value.uint16;
            break;
        case LY_TYPE_INT32:
            val->type = SR_INT32_T;
            val->data.int32_val = leaf->value.int32;
            break;
        case LY_TYPE_UINT32:
            val->type = SR_UINT32_T;
            val->data.uint32_val = leaf->value.uint32;
            break;
        case LY_TYPE_INT64:
            val->type = SR_INT64_T;
            val->data.int64_val = leaf->value.int64;
            break;
        case LY_TYPE_UINT64:
            val->type = SR_UINT64_T;
            val->data.uint64_val = leaf->value.uint64;
            break;
        default:
            //LY_LEAFREF, LY_DERIVED, LY_UNION
            val->type = SR_UNKNOWN_T;
            break;
        }
        break;
    default:
        val->type = SR_UNKNOWN_T;
        break;
    }

    return 0;
}

static int
build_rpc_from_output(struct lyd_node *rpc, sr_val_t *output, size_t out_count, NC_WD_MODE wd)
{
    struct lyd_node *node;
    uint32_t i;
    int rc;
    char buf[21];

    for (i = 0; i < out_count; ++i) {
        /* default values */
        rc = op_dflt_data_inspect(np2srv.ly_ctx, &output[i], wd);
        if (rc < 0) {
            continue;
        }

        node = lyd_new_path(rpc, np2srv.ly_ctx, output[i].xpath, op_get_srval_value(np2srv.ly_ctx, &output[i], buf),
                            LYD_PATH_OPT_UPDATE | LYD_PATH_OPT_OUTPUT);
        if (ly_errno) {
            return -1;
        }

        if (rc) {
            /* add the default attribute */
            assert(node);
            while (node->schema->nodetype & (LYS_CONTAINER | LYS_LIST)) {
                node = node->child;
                assert(node);
            }
            assert(node->schema->nodetype == LYS_LEAF);
            node->dflt = 1;
        }
    }

    return 0;
}

struct nc_server_reply *
op_generic(struct lyd_node *rpc, struct nc_session *ncs)
{
    int rc;
    uint32_t i;
    char *rpc_xpath;
    sr_val_t *input, *output = NULL;
    size_t in_count, out_count = 0;
    struct np2_sessions *sessions;
    struct nc_server_error *e;
    struct ly_set *set = NULL;
    struct lyd_node *reply_data;
    NC_WD_MODE nc_wd;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* perform operation on running to make notification
     * for the sysrepo's subscriber implementing the RPC */
    if (sessions->ds != SR_DS_RUNNING) {
        sr_session_switch_ds(sessions->srs, SR_DS_RUNNING);
    }

    /* process input into sysrepo format */
    set = lyd_get_node(rpc, "//*");
    if (!set->number || (set->set.d[0]->schema->nodetype != LYS_RPC)) {
        EINT;
        goto error;
    }
    in_count = set->number - 1;
    if (in_count) {
        input = malloc(in_count * sizeof *input);
        if (!input) {
            EMEM;
            goto error;
        }
        for (i = 0; i < in_count; ++i) {
            if (create_sr_value(set->set.d[i + 1], &input[i])) {
                goto error;
            }
        }
    }
    ly_set_free(set);
    set = NULL;

    rpc_xpath = lyd_path(rpc);

    rc = sr_rpc_send(sessions->srs, rpc_xpath, input, in_count, &output, &out_count);
    free(rpc_xpath);
    sr_free_values(input, in_count);

    if ((rc == SR_ERR_UNKNOWN_MODEL) || (rc == SR_ERR_NOT_FOUND)) {
        return nc_server_reply_err(nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_PROT));
    } else if (rc != SR_ERR_OK) {
        ERR("Sending an RPC (%s) to sysrepo failed (%s).", rpc->schema->name, sr_strerror(rc));
        goto error;
    }

    reply_data = lyd_dup(rpc, 0);

    nc_server_get_capab_withdefaults(&nc_wd, NULL);
    rc = build_rpc_from_output(reply_data, output, out_count, nc_wd);
    sr_free_values(output, out_count);

    if (rc) {
        lyd_free(reply_data);
        goto error;
    }

    return nc_server_reply_data(reply_data, NC_PARAMTYPE_FREE);

error:
    ly_set_free(set);
    sr_free_values(output, out_count);

    e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, np2log_lasterr(), "en");
    return nc_server_reply_err(e);
}
