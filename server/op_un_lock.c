/**
 * @file op_un_lock.c
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief NETCONF <lock> and <unlock> operations implementation
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
op_lock(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    sr_datastore_t ds = 0;
    struct nc_session **dsl = NULL;
    struct ly_set *nodeset;
    struct nc_server_error *e;
    const char *dsname;
    int rc;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* get know which datastore is being affected */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:lock/target/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(dsname, "running")) {
        /* TODO additional requirements in case of supporting confirmed-commit */
        ds = SR_DS_RUNNING;
        dsl = &dslock.running;
    } else if (!strcmp(dsname, "startup")) {
        ds = SR_DS_STARTUP;
        dsl = &dslock.startup;
    } else if (!strcmp(dsname, "candidate")) {
        /* TODO RFC 6020 has some addition requirements here */
        ds = SR_DS_CANDIDATE;
        dsl = &dslock.candidate;
    }
    if (ds != sessions->ds) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, ds);
        sessions->ds = ds;
    }

    pthread_rwlock_rdlock(&dslock_rwl);
    if (*dsl) {
lock_held:
        /* lock already held */
        pthread_rwlock_unlock(&dslock_rwl);
        ERR("Locking datastore %s by session %d failed (datastore is already locked by session %d).",
            dsname, nc_session_get_id(ncs), nc_session_get_id(*dsl));
        e = nc_err(NC_ERR_LOCK_DENIED, nc_session_get_id(*dsl));
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }
    pthread_rwlock_unlock(&dslock_rwl);

    pthread_rwlock_wrlock(&dslock_rwl);
    /* check again dsl, it could change between unlock and wrlock */
    if (*dsl) {
        goto lock_held;
    }

    rc = sr_lock_datastore(sessions->srs);
    if (rc != SR_ERR_OK) {
        /* lock is held outside Netopeer */
        pthread_rwlock_unlock(&dslock_rwl);
        ERR("Locking datastore %s by session %d failed (%s).", dsname,
            nc_session_get_id(ncs), sr_strerror(rc));
        e = nc_err(NC_ERR_LOCK_DENIED, 0);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }

    /* update local information about locks */
    *dsl = ncs;
    pthread_rwlock_unlock(&dslock_rwl);

    /* build positive RPC Reply */
    return nc_server_reply_ok();
}

struct nc_server_reply *
op_unlock(struct lyd_node *rpc, struct nc_session *ncs)
{
    struct np2_sessions *sessions;
    sr_datastore_t ds = 0;
    struct nc_session **dsl = NULL;
    struct ly_set *nodeset;
    const char *dsname;
    struct nc_server_error *e;
    int rc;

    /* get sysrepo connections for this session */
    sessions = (struct np2_sessions *)nc_session_get_data(ncs);

    /* get know which datastore is being affected */
    nodeset = lyd_get_node(rpc, "/ietf-netconf:unlock/target/*");
    dsname = nodeset->set.d[0]->schema->name;
    ly_set_free(nodeset);

    if (!strcmp(dsname, "running")) {
        ds = SR_DS_RUNNING;
        dsl = &dslock.running;
    } else if (!strcmp(dsname, "startup")) {
        ds = SR_DS_STARTUP;
        dsl = &dslock.startup;
    } else if (!strcmp(dsname, "candidate")) {
        ds = SR_DS_CANDIDATE;
        dsl = &dslock.candidate;
    }
    if (ds != sessions->ds) {
        /* update sysrepo session */
        sr_session_switch_ds(sessions->srs, ds);
        sessions->ds = ds;
    }

    pthread_rwlock_rdlock(&dslock_rwl);
    if (!(*dsl)) {
        /* lock is not held */
        pthread_rwlock_unlock(&dslock_rwl);
        ERR("Unlocking datastore %s by session %d failed (lock is not active).",
            dsname, nc_session_get_id(ncs));
        e = nc_err(NC_ERR_OP_FAILED, NC_ERR_TYPE_PROT);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    } else {
        /* lock is held, but by who? */
        if ((*dsl) != ncs) {
            /* by someone else */
            pthread_rwlock_unlock(&dslock_rwl);
            ERR("Unlocking datastore %s by session %d failed (lock is held by session %d).",
                dsname, nc_session_get_id(ncs), nc_session_get_id(*dsl));
            e = nc_err(NC_ERR_LOCK_DENIED, nc_session_get_id(*dsl));
            nc_err_set_msg(e, np2log_lasterr(), "en");
            return nc_server_reply_err(e);
        }
    }
    pthread_rwlock_unlock(&dslock_rwl);
    pthread_rwlock_wrlock(&dslock_rwl);

    rc = sr_unlock_datastore(sessions->srs);
    if (rc != SR_ERR_OK) {
        /* lock is held outside Netopeer */
        pthread_rwlock_unlock(&dslock_rwl);
        ERR("Unlocking datastore %s by session %d failed (%s).", dsname,
            nc_session_get_id(ncs), sr_strerror(rc));
        e = nc_err(NC_ERR_LOCK_DENIED, 0);
        nc_err_set_msg(e, np2log_lasterr(), "en");
        return nc_server_reply_err(e);
    }

    /* update local information about locks */
    *dsl = NULL;
    pthread_rwlock_unlock(&dslock_rwl);

    /* build positive RPC Reply */
    return nc_server_reply_ok();
}
