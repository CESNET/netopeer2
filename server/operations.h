/**
 * @file operations.h
 * @author Radek Krejci <rkrejci@cesnet.cz>
 * @brief Basic NETCONF operations
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef NP2SRV_OPERATIONS_H_
#define NP2SRV_OPERATIONS_H_

#include <nc_server.h>

struct np2srv_dslock {
    struct nc_session *running;
    struct nc_session *startup;
    struct nc_session *candidate;
};

extern struct np2srv_dslock dslock;
extern pthread_rwlock_t dslock_rwl;

enum NP2_EDIT_ERROPT {
    NP2_EDIT_ERROPT_STOP,
    NP2_EDIT_ERROPT_CONT,
    NP2_EDIT_ERROPT_ROLLBACK
};

enum NP2_EDIT_TESTOPT {
    NP2_EDIT_TESTOPT_TESTANDSET,
    NP2_EDIT_TESTOPT_SET,
    NP2_EDIT_TESTOPT_TEST
};

enum NP2_EDIT_DEFOP {
    NP2_EDIT_DEFOP_NONE,
    NP2_EDIT_DEFOP_MERGE,
    NP2_EDIT_DEFOP_REPLACE,
};

enum NP2_EDIT_OP {
    NP2_EDIT_ERROR = -1,
    NP2_EDIT_NONE,
    NP2_EDIT_MERGE,
    NP2_EDIT_REPLACE,
    NP2_EDIT_CREATE,
    NP2_EDIT_DELETE,
    NP2_EDIT_REMOVE
};

char *op_get_srval_value(struct ly_ctx *ctx, sr_val_t *value, char *buf);

/* return: -1 = discard, 0 = keep, 1 = keep and add the attribute */
int op_dflt_data_inspect(struct ly_ctx *ctx, sr_val_t *value, NC_WD_MODE wd);

struct nc_server_reply *op_get(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_lock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_unlock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_editconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_copyconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_generic(struct lyd_node *rpc, struct nc_session *ncs);

#endif /* NP2SRV_OPERATIONS_H_ */
