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
    NP2_EDIT_DEFOP_NONE = 0,
    NP2_EDIT_DEFOP_MERGE,
    NP2_EDIT_DEFOP_REPLACE,
};

enum NP2_EDIT_OP {
    NP2_EDIT_ERROR = -1,
    NP2_EDIT_NONE = 0,
    NP2_EDIT_MERGE,
    NP2_EDIT_CREATE,
    NP2_EDIT_REPLACE_INNER,
    NP2_EDIT_REPLACE,
    NP2_EDIT_DELETE,
    NP2_EDIT_REMOVE
};

/**
 * @brief Sysrepo wrapper functions.
 *
 * MUST BE CALLED HOLDING sr_lock FOR READING!
 */
int np2srv_sr_session_switch_ds(sr_session_ctx_t *srs, sr_datastore_t ds, struct nc_server_reply **ereply);
int np2srv_sr_set_item(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts,
        struct nc_server_reply **ereply);
int np2srv_sr_delete_item(sr_session_ctx_t *srs, const char *xpath, const sr_edit_options_t opts, struct nc_server_reply **ereply);
int np2srv_sr_get_item(sr_session_ctx_t *srs, const char *xpath, sr_val_t **value, struct nc_server_reply **ereply);
int np2srv_sr_get_items(sr_session_ctx_t *srs, const char *xpath, sr_val_t **values, size_t *value_cnt, struct nc_server_reply **ereply);
int np2srv_sr_get_changes_iter(sr_session_ctx_t *srs, const char *xpath, sr_change_iter_t **iter, struct nc_server_reply **ereply);
int np2srv_sr_get_change_next(sr_session_ctx_t *srs, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value, struct nc_server_reply **ereply);
int np2srv_sr_get_items_iter(sr_session_ctx_t *srs, const char *xpath, sr_val_iter_t **iter, struct nc_server_reply **ereply);
int np2srv_sr_get_item_next(sr_session_ctx_t *srs, sr_val_iter_t *iter, sr_val_t **value, struct nc_server_reply **ereply);
int np2srv_sr_move_item(sr_session_ctx_t *srs, const char *xpath, const sr_move_position_t position,
        const char *relative_item, struct nc_server_reply **ereply);
int np2srv_sr_rpc_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *input,  const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, struct nc_server_reply **ereply);
int np2srv_sr_action_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *input,  const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, struct nc_server_reply **ereply);
int np2srv_sr_check_exec_permission(sr_session_ctx_t *srs, const char *xpath, struct nc_server_reply **ereply);
int np2srv_sr_module_change_subscribe(sr_session_ctx_t *srs, const char *module_name, sr_module_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply);
int np2srv_sr_module_install_subscribe(sr_session_ctx_t *srs, sr_module_install_cb callback, void *private_ctx,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply);
int np2srv_sr_feature_enable_subscribe(sr_session_ctx_t *srs, sr_feature_enable_cb callback, void *private_ctx,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply);
int np2srv_sr_subtree_change_subscribe(sr_session_ctx_t *srs, const char *xpath, sr_subtree_change_cb callback,
        void *private_ctx, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply);
int np2srv_sr_event_notif_subscribe(sr_session_ctx_t *srs, const char *xpath, sr_event_notif_cb callback,
        void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription, struct nc_server_reply **ereply);
int np2srv_sr_event_notif_replay(sr_session_ctx_t *srs, sr_subscription_ctx_t *subscription, time_t start_time,
        time_t stop_time, struct nc_server_reply **ereply);
int np2srv_sr_event_notif_send(sr_session_ctx_t *srs, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, sr_ev_notif_flag_t opts, struct nc_server_reply **ereply);
int np2srv_sr_session_start_user(const char *user_name, const sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session, struct nc_server_reply **ereply);
int np2srv_sr_session_stop(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_session_set_options(sr_session_ctx_t *srs, const sr_sess_options_t opts, struct nc_server_reply **ereply);
int np2srv_sr_session_refresh(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_discard_changes(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_commit(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_validate(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_copy_config(sr_session_ctx_t *srs, const char *module_name, sr_datastore_t src_datastore,
        sr_datastore_t dst_datastore, struct nc_server_reply **ereply);
int np2srv_sr_lock_datastore(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_unlock_datastore(sr_session_ctx_t *srs, struct nc_server_reply **ereply);
int np2srv_sr_unsubscribe(sr_session_ctx_t *srs, sr_subscription_ctx_t *subscription, struct nc_server_reply **ereply);
int np2srv_sr_list_schemas(sr_session_ctx_t *srs, sr_schema_t **schemas, size_t *schema_cnt, struct nc_server_reply **ereply);
int np2srv_sr_get_submodule_schema(sr_session_ctx_t *srs, const char *submodule_name, const char *submodule_revision,
        sr_schema_format_t format, char **schema_content, struct nc_server_reply **ereply);
int np2srv_sr_get_schema(sr_session_ctx_t *srs, const char *module_name, const char *revision,
         const char *submodule_name, sr_schema_format_t format, char **schema_content, struct nc_server_reply **ereply);

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
 * @brief Build error reply because of NACM access denied
 */
struct nc_server_reply *op_build_err_nacm(struct nc_server_reply *ereply);

int op_filter_get_tree_from_data(struct lyd_node **root, struct lyd_node *data, const char *subtree_path);
int op_filter_xpath_add_filter(char *new_filter, char ***filters, int *filter_count);
int op_filter_create(struct lyd_node *filter_node, char ***filters, int *filter_count);
int op_sr_val_to_lyd_node(struct lyd_node *root, const sr_val_t *sr_val, struct lyd_node **new_node);

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
struct nc_server_reply *op_kill(struct lyd_node *rpc, struct nc_session *ncs);

struct nc_server_reply *op_ntf_subscribe(struct lyd_node *rpc, struct nc_session *ncs);
void op_ntf_unsubscribe(struct nc_session *session);
void op_ntf_yang_lib_change(const struct lyd_node *ylib_info);
struct lyd_node *ntf_get_data(void);


#endif /* NP2SRV_OPERATIONS_H_ */
