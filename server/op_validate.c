/**
 * @file op_validate.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF <validate> operation implementation
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#include <string.h>

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

struct nc_server_reply *
op_validate(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    struct ly_set *nodeset = NULL;
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    struct lyd_node *config = NULL;
    struct lyd_node_anydata *any;
    const char *dsname;
    sr_datastore_t ds = SR_DS_CANDIDATE;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:validate", &ereply)) {
        goto finish;
    }

    /* get know which datastore is being affected */
    nodeset = lyd_find_path(rpc, "/ietf-netconf:validate/source/*");
    dsname = nodeset->set.d[0]->schema->name;
    if (!strcmp(dsname, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(dsname, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(dsname, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(dsname, "config")) {
        /* get data tree to validate */
        any = (struct lyd_node_anydata *)nodeset->set.d[0];
        ly_errno = LY_SUCCESS;
        switch (any->value_type) {
        case LYD_ANYDATA_CONSTSTRING:
        case LYD_ANYDATA_STRING:
        case LYD_ANYDATA_SXML:
            config = lyd_parse_mem(np2srv.ly_ctx, any->value.str, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_DESTRUCT | LYD_OPT_STRICT);
            break;
        case LYD_ANYDATA_DATATREE:
            config = any->value.tree;
            any->value.tree = NULL; /* "unlink" data tree from anydata to have full control */
            if (lyd_validate(&config, LYD_OPT_CONFIG, np2srv.ly_ctx)) {
                e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
                nc_err_set_msg(e, np2log_lasterr(np2srv.ly_ctx), "en");
                ereply = nc_server_reply_err(e);
                goto finish;
            }
            break;
        case LYD_ANYDATA_XML:
            config = lyd_parse_xml(np2srv.ly_ctx, &any->value.xml, LYD_OPT_CONFIG | LYD_OPT_DESTRUCT | LYD_OPT_STRICT);
            break;
        case LYD_ANYDATA_JSON:
        case LYD_ANYDATA_JSOND:
        case LYD_ANYDATA_SXMLD:
            EINT;
            e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
            nc_err_set_msg(e, np2log_lasterr(np2srv.ly_ctx), "en");
            ereply = nc_server_reply_err(e);
            goto finish;
        }

        /* cleanup */
        lyd_free_withsiblings(config);

        if (ly_errno != LY_SUCCESS) {
            e = nc_err_libyang(np2srv.ly_ctx);
            ereply = nc_server_reply_err(e);
            goto finish;
        }

        ereply = nc_server_reply_ok();
        goto finish;
    }
    /* TODO support URL */

    if (ds != sessions->ds) {
        /* update sysrepo session */
        if (np2srv_sr_session_switch_ds(sessions->srs, ds, &ereply)) {
            goto finish;
        }
        sessions->ds = ds;
    }
    if (ds != SR_DS_CANDIDATE) {
        /* refresh datastore content */
        if (np2srv_sr_session_refresh(sessions->srs, &ereply)) {
            goto finish;
        }
    }

    /* validate sysrepo's datastore */
    if (np2srv_sr_validate(sessions->srs, &ereply)) {
        goto finish;
    }

    ereply = nc_server_reply_ok();

finish:
    ly_set_free(nodeset);
    return ereply;
}
