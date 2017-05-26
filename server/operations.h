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
    time_t running_time;
    struct nc_session *startup;
    time_t startup_time;
    struct nc_session *candidate;
    time_t candidate_time;
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
    NP2_EDIT_CREATE,
    NP2_EDIT_REPLACE_INNER,
    NP2_EDIT_REPLACE,
    NP2_EDIT_DELETE,
    NP2_EDIT_REMOVE
};

char *op_get_srval(struct ly_ctx *ctx, const sr_val_t *value, char *buf);

/**
 * @brief Fill sr_val_t for communication with sysrepo
 *
 * @param[in] node Node from which the value is filled
 * @param[in] path Node's path, NULL value is not invalid since sysrepo allows NULL
 *                 path in sr_val_t for specific use.
 * @param[in] dup Flag if the \p path and values from \p node are supposed to be duplicated into \p value.
 * @param[in,out] val Pointer to the structure to fill.
 * @param[out] val_buf Duplication avoidance is not always possible. If the function needs to allocate
 *                 some data to fill the \p val structure, the allocated memory is returned as pointer
 *                 to char and can be freed with free(). The parameter to store the pointer is required
 *                 only if the \p dup is zero.
 */
int op_set_srval(struct lyd_node *node, char *path, int dup, sr_val_t *val, char **val_buf);

/**
 * @brief Build error reply based on errors from sysrepo
 */
struct nc_server_reply *op_build_err_sr(struct nc_server_reply *ereply, sr_session_ctx_t *session);

int op_filter_get_tree_from_data(struct lyd_node **root, struct lyd_node *data, const char *subtree_path);
int op_filter_xpath_add_filter(char *new_filter, char ***filters, int *filter_count);
int op_filter_create(struct lyd_node *filter_node, char ***filters, int *filter_count);

struct nc_server_reply *op_get(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_lock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_unlock(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_editconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_copyconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_deleteconfig(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_commit(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_discardchanges(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_validate(struct lyd_node *rpc, struct nc_session *ncs);
struct nc_server_reply *op_generic(struct lyd_node *rpc, struct nc_session *ncs);

struct nc_server_reply *op_ntf_subscribe(struct lyd_node *rpc, struct nc_session *ncs);
void op_ntf_unsubscribe(struct nc_session *session);
void op_ntf_yang_lib_change(const struct lyd_node *ylib_info);
struct lyd_node *ntf_get_data(void);


#endif /* NP2SRV_OPERATIONS_H_ */
