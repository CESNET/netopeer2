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
    struct nc_server_reply *ereply = NULL;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:commit", &ereply)) {
        goto finish;
    }

    if (np2srv_sr_copy_config(sessions->srs, NULL, SR_DS_CANDIDATE, SR_DS_RUNNING, &ereply)) {
        goto finish;
    }

    /* remove modify flag */
    sessions->flags &= ~NP2S_CAND_CHANGED;

    ereply = nc_server_reply_ok();

finish:
    return ereply;
}

struct nc_server_reply *
op_discardchanges(struct lyd_node *UNUSED(rpc), struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    struct nc_server_reply *ereply = NULL;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:discard-changes", &ereply)) {
        goto finish;
    }

    if (sessions->ds != SR_DS_CANDIDATE) {
        /* update sysrepo session */
        np2srv_sr_session_switch_ds(sessions->srs, SR_DS_CANDIDATE, NULL);
        sessions->ds = SR_DS_CANDIDATE;
    }

    if (np2srv_sr_discard_changes(sessions->srs, &ereply)) {
        goto finish;
    }

    /* remove modify flag */
    sessions->flags &= ~NP2S_CAND_CHANGED;

    ereply = nc_server_reply_ok();

finish:
    return ereply;
}
