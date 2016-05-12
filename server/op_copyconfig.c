/**
 * @file op_copyconfig.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF <copy-config> operation implementation
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

struct nc_server_reply *
op_copyconfig(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2sr_sessions *sessions;
    sr_datastore_t target, source;
    struct ly_set *nodeset;
    const char *dsname;
    struct nc_server_error *e;
    int rc;

    /* get sysrepo connections for this session */
    sessions = (struct np2sr_sessions *)nc_session_get_data(ncs);

    /* get know which datastore is being affected */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:copy-config/target/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(dsname, "startup")) {
        target = SR_DS_STARTUP;
    /* TODO support other datastores */
    } else {
        e = nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, "<copy-config> is currently supported only from <running/> to <startup/>.", "en");
        return nc_server_reply_err(e);
    }

    /* get source */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:copy-config/source/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(dsname, "running")) {
        source = SR_DS_RUNNING;
    /* TODO support other datastores */
    } else {
        e = nc_err(NC_ERR_OP_NOT_SUPPORTED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, "<copy-config> is currently supported only from <running/> to <startup/>.", "en");
        return nc_server_reply_err(e);
    }

    /* perform operation */
    rc = sr_copy_config(sessions->running, NULL, source, target);
    if (rc != SR_ERR_OK) {
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }

    return nc_server_reply_ok();
}
