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
    struct ly_set *nodeset;
    struct nc_server_error *e = NULL;
    int rc;
    struct lyd_node *config = NULL;
    struct lyd_node_anydata *any;
    const char *dsname;
    sr_datastore_t ds = SR_DS_CANDIDATE;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* get know which datastore is being affected */
    nodeset = lyd_find_xpath(rpc, "/ietf-netconf:validate/source/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);
    if (!strcmp(dsname, "running")) {
        ds = SR_DS_RUNNING;
    } else if (!strcmp(dsname, "startup")) {
        ds = SR_DS_STARTUP;
    } else if (!strcmp(dsname, "candidate")) {
        ds = SR_DS_CANDIDATE;
    } else if (!strcmp(dsname, "config")) {
        /* get data tree to validate */
        any = (struct lyd_node_anydata *)nodeset->set.d[0];
        switch (any->value_type) {
        case LYD_ANYDATA_CONSTSTRING:
        case LYD_ANYDATA_STRING:
            config = lyd_parse_mem(np2srv.ly_ctx, any->value.str, LYD_XML, LYD_OPT_CONFIG | LYD_OPT_DESTRUCT);
            break;
        case LYD_ANYDATA_DATATREE:
            config = any->value.tree;
            any->value.tree = NULL; /* "unlink" data tree from anydata to have full control */
            break;
        case LYD_ANYDATA_XML:
            config = lyd_parse_xml(np2srv.ly_ctx, &any->value.xml, LYD_OPT_CONFIG | LYD_OPT_DESTRUCT);
            break;
        case LYD_ANYDATA_JSON:
        case LYD_ANYDATA_JSOND:
            EINT;
            ly_set_free(nodeset);
            goto error;
        }
        if (ly_errno != LY_SUCCESS) {
            ly_set_free(nodeset);
            goto error;
        }
        rc = lyd_validate(&config, LYD_OPT_CONFIG, np2srv.ly_ctx);

        /* cleanup */
        lyd_free_withsiblings(config);

        goto done;
    }
    /* TODO support URL */

    if (ds != sessions->ds) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, ds);
        sessions->ds = ds;
    }
    if (ds != SR_DS_CANDIDATE) {
        /* refresh datastore content */
        if (sr_session_refresh(sessions->srs) != SR_ERR_OK) {
            goto error;
        }
    }

    /* validate sysrepo's datastore */
    rc = sr_validate(sessions->srs);
    if (rc != SR_ERR_OK) {
        goto error;
    }

done:

    return nc_server_reply_ok();

error:
    /* handle error */
    if (!e) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(), "en");
    }

    return nc_server_reply_err(e);
}
