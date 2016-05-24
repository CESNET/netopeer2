/**
 * @file op_candidate.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief various NETCONF operations specific for the candidate datastore
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <libyang/libyang.h>
#include <nc_server.h>
#include <sysrepo.h>

#include "common.h"
#include "operations.h"

struct nc_server_reply *
op_commit(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    struct nc_server_error *e;
    int rc;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, SR_DS_CANDIDATE);
        sessions->ds = SR_DS_CANDIDATE;
    }

    rc = sr_commit(sessions->srs);
    if (rc != SR_ERR_OK) {
        /* fill the error */
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }

    /* remove modify flag */
    sessions->flags &= ~NP2S_CAND_CHANGED;
    return nc_server_reply_ok();
}

struct nc_server_reply *
op_discardchanges(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    struct nc_server_error *e;
    int rc;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, SR_DS_CANDIDATE);
        sessions->ds = SR_DS_CANDIDATE;
    }

    rc = sr_discard_changes(sessions->srs);
    if (rc != SR_ERR_OK) {
        /* fill the error */
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }

    return nc_server_reply_ok();
}
