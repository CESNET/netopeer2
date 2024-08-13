/**
 * @file np2_test.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @author Tadeas Vintlik <xvintr04@stud.fit.vutbr.cz>
 * @brief base header for netopeer2 testing
 *
 * @copyright
 * Copyright (c) 2019 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _NP2_TEST_H_
#define _NP2_TEST_H_

#include <string.h>
#include <unistd.h>

#include <nc_client.h>
#include <sysrepo.h>

/* test state structure */
struct np2_test {
    pid_t server_pid;
    char socket_path[256];
    char test_name[256];
    sr_conn_ctx_t *conn;
    sr_session_ctx_t *sr_sess;
    sr_session_ctx_t *sr_sess2;
    sr_subscription_ctx_t *sub;
    struct ly_in *in;
    const struct ly_ctx *ctx;
    struct lyd_node *node;
    struct nc_session *nc_sess;
    struct nc_session *nc_sess2;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;
    char *str;
    char *path;
    uint32_t ntf_id;
    struct np_other_client *oc_sess;
};

#define SETUP_FAIL_LOG \
    fprintf(stderr, "Setup fail in %s:%d.\n", __FILE__, __LINE__)

#define FREE_TEST_VARS(state) \
    nc_rpc_free(state->rpc); \
    state->rpc = NULL; \
    lyd_free_tree(state->envp); \
    state->envp = NULL; \
    lyd_free_tree(state->op); \
    state->op = NULL; \
    lyd_free_siblings(state->node); \
    state->node = NULL; \
    if (state->str) { \
        free(state->str); \
    } \
    state->str = NULL;

#define ASSERT_OK_REPLY_PARAM(nc_sess, timeout_ms, state) \
    do { \
        state->msgtype = nc_recv_reply(nc_sess, state->rpc, state->msgid, timeout_ms, &state->envp, &state->op); \
    } while (state->msgtype == NC_MSG_NOTIF); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    if (strcmp(LYD_NAME(lyd_child(state->envp)), "ok")) { \
        printf("Expected \"ok\" reply, received \"%s\" instead.\n", LYD_NAME(lyd_child(state->envp))); \
        printf("op:\n"); \
        if (state->op) { \
            lyd_print_file(stdout, state->op, LYD_XML, 0); \
        } \
        printf("\nenvp:\n"); \
        if (state->envp) { \
            lyd_print_file(stdout, state->envp, LYD_XML, 0); \
        } \
        fail(); \
    } \
    assert_null(state->op);

#define ASSERT_OK_REPLY(state) \
    ASSERT_OK_REPLY_PARAM(state->nc_sess, 3000, state)

#define ASSERT_OK_REPLY_SESS(state, nc_sess) \
    ASSERT_OK_REPLY_PARAM(nc_sess, 3000, state)

#define ASSERT_DATA_REPLY_PARAM(nc_sess, timeout_ms, state) \
    do { \
        state->msgtype = nc_recv_reply(nc_sess, state->rpc, state->msgid, timeout_ms, &state->envp, &state->op); \
    } while (state->msgtype == NC_MSG_NOTIF); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    if (lyd_child(state->envp) || !state->op) { \
        printf("Expected \"data\" reply, received \"%s\" instead.\n", lyd_child(state->envp) ? LYD_NAME(lyd_child(state->envp)) : "unknown"); \
        printf("op:\n"); \
        if (state->op) { \
            lyd_print_file(stdout, state->op, LYD_XML, 0); \
        } \
        printf("\nenvp:\n"); \
        if (state->envp) { \
            lyd_print_file(stdout, state->envp, LYD_XML, 0); \
        } \
        fail(); \
    } \
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&state->str, state->op, LYD_XML, 0));

#define ASSERT_DATA_REPLY(state) \
    ASSERT_DATA_REPLY_PARAM(state->nc_sess, 3000, state)

#define ASSERT_OK_REPLY_SESS2(state) \
    state->msgtype = nc_recv_reply(state->nc_sess2, state->rpc, state->msgid, 3000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    assert_null(state->op); \
    assert_string_equal(LYD_NAME(lyd_child(state->envp)), "ok");

#define ASSERT_ERROR_REPLY_PARAM(state, nc_sess, err_tag) \
    state->msgtype = nc_recv_reply(nc_sess, state->rpc, state->msgid, 3000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    if (!lyd_child(state->envp) || strcmp(LYD_NAME(lyd_child(state->envp)), "rpc-error")) { \
        if (lyd_child(state->envp)) { \
            printf("Expected \"rpc-error\" reply, received \"%s\" instead.\n", LYD_NAME(lyd_child(state->envp))); \
        } else { \
            printf("Expected \"rpc-error\" reply, received data instead.\n"); \
        } \
        printf("op:\n"); \
        if (state->op) { \
            lyd_print_file(stdout, state->op, LYD_XML, 0); \
        } \
        printf("\nenvp:\n"); \
        if (state->envp) { \
            lyd_print_file(stdout, state->envp, LYD_XML, 0); \
        } \
        fail(); \
    } \
    assert_null(state->op); \
    if (err_tag) { \
        assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), err_tag); \
    } else { \
        assert_int_equal(LY_SUCCESS, lyd_print_mem(&state->str, lyd_child(state->envp), LYD_XML, LYD_PRINT_WITHSIBLINGS)); \
    }

#define ASSERT_ERROR_REPLY(state) \
    ASSERT_ERROR_REPLY_PARAM(state, state->nc_sess, NULL)

#define ASSERT_ERROR_REPLY_TAG(state, err_tag) \
    ASSERT_ERROR_REPLY_PARAM(state, state->nc_sess, err_tag)

#define ASSERT_ERROR_REPLY_SESS2(state) \
    state->msgtype = nc_recv_reply(state->nc_sess2, state->rpc, state->msgid, 3000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    assert_null(state->op); \
    assert_string_equal(LYD_NAME(lyd_child(state->envp)), "rpc-error");

#define SEND_GET_CONFIG_PARAM(state, ds, wd, filter) \
    state->rpc = nc_rpc_getconfig(ds, filter, wd, NC_PARAMTYPE_CONST); \
    state->msgtype = nc_send_rpc(state->nc_sess, state->rpc, 1000, &state->msgid); \
    assert_int_equal(NC_MSG_RPC, state->msgtype);

#define GET_CONFIG_DS_WD_FILTER(state, ds, wd, filter) \
    SEND_GET_CONFIG_PARAM(state, ds, wd, filter) \
    state->msgtype = nc_recv_reply(state->nc_sess, state->rpc, state->msgid, 3000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    assert_non_null(state->op); \
    assert_non_null(state->envp); \
    assert_string_equal(LYD_NAME(lyd_child(state->op)), "data"); \
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&state->str, state->op, LYD_XML, LYD_PRINT_WD_IMPL_TAG));

#define GET_CONFIG_DS_FILTER(state, ds, filter) GET_CONFIG_DS_WD_FILTER(state, ds, NC_WD_ALL, filter);

#define GET_CONFIG_WD(state, wd) GET_CONFIG_DS_WD_FILTER(state, NC_DATASTORE_RUNNING, wd, NULL);

#define GET_CONFIG_FILTER(state, filter) \
    GET_CONFIG_DS_FILTER(state, NC_DATASTORE_RUNNING, filter);

#define GET_CONFIG(state) GET_CONFIG_FILTER(state, NULL);

#define GET_DS_CONFIG(state, ds) GET_CONFIG_DS_FILTER(state, ds, NULL);

#define GET_FILTER(state, filter) \
    state->rpc = nc_rpc_get(filter, NC_WD_ALL, NC_PARAMTYPE_CONST); \
    state->msgtype = nc_send_rpc(state->nc_sess, state->rpc, 1000, &state->msgid); \
    assert_int_equal(NC_MSG_RPC, state->msgtype); \
    state->msgtype = nc_recv_reply(state->nc_sess, state->rpc, state->msgid, 3000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    assert_non_null(state->op); \
    assert_non_null(state->envp); \
    assert_string_equal(LYD_NAME(lyd_child(state->op)), "data"); \
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&state->str, state->op, LYD_XML, 0));

#define GET_DATA_FILTER(state, ds, filter, config_filter, origin_filter, origin_filter_count, neg_origin_filter, max_depth, with_origin, wd_mode) \
    state->rpc = nc_rpc_getdata(ds, filter, config_filter, origin_filter, origin_filter_count, neg_origin_filter, max_depth, with_origin, wd_mode, NC_PARAMTYPE_CONST); \
    state->msgtype = nc_send_rpc(state->nc_sess, state->rpc, 1000, &state->msgid); \
    assert_int_equal(NC_MSG_RPC, state->msgtype); \
    state->msgtype = nc_recv_reply(state->nc_sess, state->rpc, state->msgid, 2000, &state->envp, &state->op); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    assert_non_null(state->op); \
    assert_non_null(state->envp); \
    assert_string_equal(LYD_NAME(lyd_child(state->op)), "data"); \
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&state->str, state->op, LYD_XML, 0));

#define SEND_EDIT_RPC_PARAM(state, ds, dfltop, config) \
    state->rpc = nc_rpc_edit(ds, dfltop, NC_RPC_EDIT_TESTOPT_SET, NC_RPC_EDIT_ERROPT_ROLLBACK, \
            config, NC_PARAMTYPE_CONST); \
    state->msgtype = nc_send_rpc(state->nc_sess, state->rpc, 1000, &state->msgid); \
    assert_int_equal(NC_MSG_RPC, state->msgtype);

#define SEND_EDIT_RPC_DS(state, ds, config) \
    SEND_EDIT_RPC_PARAM(state, ds, NC_RPC_EDIT_DFLTOP_MERGE, config);

#define SEND_EDIT_RPC(state, config) \
    SEND_EDIT_RPC_DS(state, NC_DATASTORE_RUNNING, config);

#define EMPTY_GETCONFIG \
    "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n" \
    "  <data/>\n" \
    "</get-config>\n"

#define ASSERT_EMPTY_CONFIG_FILTER(state, filter) \
    GET_CONFIG_FILTER(state, filter); \
    assert_string_equal(state->str, EMPTY_GETCONFIG); \
    FREE_TEST_VARS(state);

#define SR_EDIT_SESSION(state, session, data) \
    assert_int_equal(LY_SUCCESS, lyd_parse_data_mem(state->ctx, data, LYD_XML, LYD_PARSE_STRICT | LYD_PARSE_ONLY, 0, \
                &state->node)); \
    assert_non_null(state->node); \
    assert_int_equal(SR_ERR_OK, sr_edit_batch(session, state->node, "merge")); \
    assert_int_equal(SR_ERR_OK, sr_apply_changes(session, 0));

#define SR_EDIT(state, data) SR_EDIT_SESSION(state, state->sr_sess, data);

#define NOTIF_PARSE(state, data) \
    assert_int_equal(ly_in_new_memory(data, &state->in), LY_SUCCESS); \
    assert_int_equal(lyd_parse_op(state->ctx, NULL, state->in, LYD_XML, \
                                  LYD_TYPE_NOTIF_YANG, &state->node, NULL), \
                                  LY_SUCCESS); \
    ly_in_free(state->in, 0);

#define RECV_NOTIF_PARAM(nc_sess, timeout_ms, state) \
    do { \
        state->msgtype = nc_recv_notif(nc_sess, timeout_ms, &state->envp, &state->op); \
    } while (state->msgtype == NC_MSG_REPLY); \
    assert_int_equal(NC_MSG_NOTIF, state->msgtype); \
    while (state->op->parent) state->op = lyd_parent(state->op); \
    assert_int_equal(lyd_print_mem(&state->str, state->op, LYD_XML, 0), LY_SUCCESS);

#define RECV_NOTIF(state) \
    RECV_NOTIF_PARAM(state->nc_sess, 3000, state)

#define ASSERT_NO_NOTIF(state) \
    state->msgtype = nc_recv_notif(state->nc_sess, 10, &state->envp, &state->op); \
    assert_int_equal(NC_MSG_WOULDBLOCK, state->msgtype); \

#define ASSERT_OK_SUB_NTF(state) \
    do { \
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op); \
    } while (st->msgtype == NC_MSG_NOTIF); \
    assert_int_equal(state->msgtype, NC_MSG_REPLY); \
    if (!state->op) { \
        lyd_print_file(stdout, st->envp, LYD_XML, 0); \
        fail(); \
    } \
    assert_string_equal(LYD_NAME(lyd_child(state->op)), "id");  \
    state->ntf_id = (uint32_t) strtoul(lyd_get_value(lyd_child(state->op)), NULL, 10);

#define SEND_RPC_ESTABSUB(st, filter, stream, start_time, stop_time) \
    st->rpc = nc_rpc_establishsub(filter, stream, start_time, stop_time, NULL, NC_PARAMTYPE_CONST); \
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid); \
    assert_int_equal(NC_MSG_RPC, st->msgtype);

#define SEND_RPC_DELSUB(st, id) \
    st->rpc = nc_rpc_deletesub(id); \
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid); \
    assert_int_equal(NC_MSG_RPC, st->msgtype);

#define SEND_RPC_MODSUB(st, id, filter, stop_time) \
    st->rpc = nc_rpc_modifysub(id, filter, stop_time, NC_PARAMTYPE_CONST); \
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid); \
    assert_int_equal(NC_MSG_RPC, st->msgtype);

#define SEND_RPC_KILLSUB(st, id) \
    st->rpc = nc_rpc_killsub(id); \
    st->msgtype =  nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid); \
    assert_int_equal(NC_MSG_RPC, st->msgtype);

#define RECV_SUBMOD_NOTIF(st) \
    RECV_NOTIF(st); \
    assert_string_equal(LYD_NAME(st->op), "subscription-modified"); \
    lyd_free_tree(st->envp); \
    lyd_free_tree(st->op); \
    ASSERT_OK_REPLY(st); \
    FREE_TEST_VARS(st); \

void np2_glob_test_setup_test_name(char *buf);

int np2_glob_test_setup_env(const char *test_name);

#define NP_GLOB_SETUP_OTHER_CLIENT 0x1
int np2_glob_test_setup_server(void **state, const char *test_name, const char **modules, uint32_t flags);

int np2_glob_test_teardown_notif(const char *test_name);

int np2_glob_test_teardown(void **state, const char **modules);

void parse_arg(int argc, char **argv);

const char *np2_get_user(void);

int np2_is_nacm_recovery(void);

int np2_glob_test_setup_nacm(void **state);

#endif /* _NP2_TEST_H_ */
