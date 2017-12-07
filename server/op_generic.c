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
build_rpc_act_from_output(struct lyd_node *rpc_act, sr_val_t *output, size_t out_count)
{
    struct lyd_node *node, *iter;
    uint32_t i;
    char buf[21];

    for (i = 0; i < out_count; ++i) {
        ly_errno = LY_SUCCESS;
        node = lyd_new_path(rpc_act, np2srv.ly_ctx, output[i].xpath, op_get_srval(np2srv.ly_ctx, &output[i], buf),
                (output->type == SR_ANYXML_T || output->type == SR_ANYDATA_T) ? LYD_ANYDATA_SXML : 0,
                LYD_PATH_OPT_UPDATE | LYD_PATH_OPT_OUTPUT);
        if (ly_errno) {
            return -1;
        }

        if (node) {
            /* propagate default flag */
            if (output[i].dflt) {
                /* go down */
                for (iter = node;
                     !(iter->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) && iter->child;
                     iter = iter->child);
                /* go up, back to the node */
                for (; ; iter = iter->parent) {
                    if (iter->schema->nodetype == LYS_CONTAINER && ((struct lys_node_container *)iter->schema)->presence) {
                        /* presence container */
                        break;
                    } else if (iter->schema->nodetype == LYS_LIST && ((struct lys_node_list *)iter->schema)->keys_size) {
                        /* list with keys */
                        break;
                    }
                    iter->dflt = 1;
                    if (iter == node) {
                        /* done */
                        break;
                    }
                }
            } else { /* non default node, propagate it to the parents */
                for (iter = node->parent; iter && iter->dflt; iter = iter->parent) {
                    iter->dflt = 0;
                }
            }
        }
    }
    if (lyd_validate(&rpc_act, LYD_OPT_RPCREPLY, NULL)) {
        return -1;
    }

    return 0;
}

struct nc_server_reply *
op_generic(struct lyd_node *rpc, struct nc_session *ncs)
{
    int rc;
    uint32_t i;
    char *rpc_xpath = NULL, *str;
    sr_val_t *input = NULL, *output = NULL;
    size_t in_count = 0, out_count = 0;
    struct np2_sessions *sessions;
    struct nc_server_error *e;
    struct nc_server_reply *ereply = NULL;
    struct ly_set *set = NULL, *strs = NULL;
    struct lyd_node *reply_data, *next, *act = NULL;
    NC_WD_MODE nc_wd;

    if (rpc->schema->nodetype != LYS_RPC) {
        /* action */
        act = lyd_dup(rpc, 1);
        if (!act) {
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, np2log_lasterr(), "en");
            ereply = nc_server_reply_err(e);
            goto finish;
        }

        LY_TREE_DFS_BEGIN(act, next, rpc) {
            if (rpc->schema->nodetype == LYS_ACTION) {
                break;
            }
            LY_TREE_DFS_END(act, next, rpc);
        }
        if (!rpc) {
            EINT;
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, np2log_lasterr(), "en");
            ereply = nc_server_reply_err(e);
            goto finish;
        }
    }
    rpc_xpath = lyd_path(rpc);

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, rpc_xpath, &ereply)) {
        goto finish;
    }

    /* perform operation on running to make notification
     * for the sysrepo's subscriber implementing the RPC */
    if (sessions->ds != SR_DS_RUNNING) {
        if (np2srv_sr_session_switch_ds(sessions->srs, SR_DS_RUNNING, &ereply)) {
            goto finish;
        }
        sessions->ds = SR_DS_RUNNING;
    }

    /* process input into sysrepo format */
    set = lyd_find_path(rpc, ".//*");
    in_count = set->number;
    if (in_count) {
        input = calloc(in_count, sizeof *input);
        strs = ly_set_new();
        if (!input || !strs) {
            EMEM;
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, np2log_lasterr(), "en");
            ereply = nc_server_reply_err(e);
            goto finish;
        }
        for (i = 0; i < set->number; ++i) {
            if (set->set.d[i]->dflt) {
                --in_count;
                continue;
            }

            if (op_set_srval(set->set.d[i], lyd_path(set->set.d[i]), 0, &input[i], &str)) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(), "en");
                ereply = nc_server_reply_err(e);
                goto finish;
            }
            if (str) {
                /* keep pointer to additional memory needed for input[i] */
                ly_set_add(strs, str, LY_SET_OPT_USEASLIST);
            }
        }
    }
    ly_set_free(set);
    set = NULL;

    if (!act) {
        rc = np2srv_sr_rpc_send(sessions->srs, rpc_xpath, input, in_count, &output, &out_count, &ereply);
    } else {
        rc = np2srv_sr_action_send(sessions->srs, rpc_xpath, input, in_count, &output, &out_count, &ereply);
    }
    if (rc) {
        goto finish;
    }

    if (out_count) {
        if (!act) {
            reply_data = lyd_dup(rpc, 0);
            rc = build_rpc_act_from_output(reply_data, output, out_count);
        } else {
            lyd_free_withsiblings(rpc->child);
            rc = build_rpc_act_from_output(rpc, output, out_count);
            reply_data = act;
        }

        if (rc) {
            lyd_free(reply_data);
            e = nc_err_libyang();
            ereply = nc_server_reply_err(e);
            goto finish;
        }

        nc_server_get_capab_withdefaults(&nc_wd, NULL);
        ereply = nc_server_reply_data(reply_data, nc_wd, NC_PARAMTYPE_FREE);
    } else {
        lyd_free(act);
        ereply = nc_server_reply_ok();
    }

finish:
    ly_set_free(set);
    if (strs) {
        for (i = 0; i < strs->number; i++) {
            free(strs->set.g[i]);
        }
        ly_set_free(strs);
    }
    for (i = 0; i < in_count; ++i) {
        free(input[i].xpath);
    }
    free(input);
    sr_free_values(output, out_count);
    free(rpc_xpath);
    return ereply;
}
