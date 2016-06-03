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
build_rpc_from_output(struct lyd_node *rpc, sr_val_t *output, size_t out_count, NC_WD_MODE wd)
{
    struct lyd_node *node;
    uint32_t i;
    int rc;
    char buf[21];

    for (i = 0; i < out_count; ++i) {
        /* default values */
        rc = op_dflt_data_inspect(np2srv.ly_ctx, &output[i], wd, 1);
        if (rc < 0) {
            continue;
        }

        node = lyd_new_path(rpc, np2srv.ly_ctx, output[i].xpath, op_get_srval(np2srv.ly_ctx, &output[i], buf),
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
    sr_val_t *input = NULL, *output = NULL;
    size_t in_count = 0, out_count = 0;
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
        sessions->ds = SR_DS_RUNNING;
    }

    /* process input into sysrepo format */
    set = lyd_get_node(rpc, "//*");
    if (!set->number || (set->set.d[0]->schema->nodetype != LYS_RPC)) {
        EINT;
        goto error;
    }
    in_count = set->number - 1;
    if (in_count) {
        input = calloc(in_count, sizeof *input);
        if (!input) {
            EMEM;
            goto error;
        }
        for (i = 0; i < in_count; ++i) {
            if (op_set_srval(set->set.d[i + 1], lyd_path(set->set.d[i + 1]), 1, &input[i])) {
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
    input = NULL;
    in_count = 0;

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
    sr_free_values(input, in_count);
    sr_free_values(output, out_count);

    e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
    nc_err_set_msg(e, np2log_lasterr(), "en");
    return nc_server_reply_err(e);
}
