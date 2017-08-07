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
    int rc;
    bool permitted;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* check NACM */
    rc = sr_check_exec_permission(sessions->srs, "/ietf-netconf:commit", &permitted);
    if (rc != SR_ERR_OK) {
        return op_build_err_sr(NULL, sessions->srs);
    } else if (!permitted) {
        return op_build_err_nacm(NULL);
    }

    rc = sr_copy_config(sessions->srs, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING);
    if (rc != SR_ERR_OK) {
        /* get the error */
        return op_build_err_sr(NULL, sessions->srs);
    }

    /* remove modify flag */
    sessions->flags &= ~NP2S_CAND_CHANGED;

    return nc_server_reply_ok();
}

struct nc_server_reply *
op_discardchanges(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    int rc;
    bool permitted;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* check NACM */
    rc = sr_check_exec_permission(sessions->srs, "/ietf-netconf:discard-changes", &permitted);
    if (rc != SR_ERR_OK) {
        return op_build_err_sr(NULL, sessions->srs);
    } else if (!permitted) {
        return op_build_err_nacm(NULL);
    }

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, SR_DS_CANDIDATE);
        sessions->ds = SR_DS_CANDIDATE;
    }

    rc = sr_discard_changes(sessions->srs);
    if (rc != SR_ERR_OK) {
        /* get the error */
        return op_build_err_sr(NULL, sessions->srs);
    }

    /* remove modify flag */
    sessions->flags &= ~NP2S_CAND_CHANGED;

    return nc_server_reply_ok();
}
