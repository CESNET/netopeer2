/**
 * @file op_kill.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief NETCONF <kill-session> operation implementation
 *
 * Copyright (c) 2017 CESNET, z.s.p.o.
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
op_kill(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    struct ly_set *set = NULL;
    struct nc_server_error *e = NULL;
    struct nc_server_reply *ereply = NULL;
    uint32_t kill_sid;
    uint16_t i;
    struct nc_session *kill_sess;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    if (np2srv_sr_check_exec_permission(sessions->srs, "/ietf-netconf:kill-session", &ereply)) {
        goto finish;
    }

    set = lyd_find_path(rpc, "session-id");
    if (!set || (set->number != 1) || (set->set.d[0]->schema->nodetype != LYS_LEAF)) {
        EINT;
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_APP);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        ereply = nc_server_reply_err(e);
        goto finish;
    }

    kill_sid = ((struct lyd_node_leaf_list *)set->set.d[0])->value.uint32;

    if (kill_sid == nc_session_get_id(ncs)) {
        e = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, "It is forbidden to kill own session.", "en");
        ereply = nc_server_reply_err(e);
        goto finish;
    }

    for (i = 0; (kill_sess = nc_ps_get_session(np2srv.nc_ps, i)); ++i) {
        if (nc_session_get_id(kill_sess) == kill_sid) {
            break;
        }
    }
    if (!kill_sess) {
        e = nc_err(NC_ERR_INVALID_VALUE, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, "Session with the specified \"session-id\" not found.", "en");
        ereply = nc_server_reply_err(e);
        goto finish;
    }

    /* kill the session */
    nc_session_set_status(kill_sess, NC_STATUS_INVALID);
    nc_session_set_term_reason(kill_sess, NC_SESSION_TERM_KILLED);
    nc_session_set_killed_by(kill_sess, nc_session_get_id(ncs));

    ereply = nc_server_reply_ok();

finish:
    ly_set_free(set);
    return ereply;
}
