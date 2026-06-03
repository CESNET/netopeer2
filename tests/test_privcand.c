/**
 * @file test_privcand.c
 * @author Juraj Budai <budai@cesnet.cz>
 * @brief tests for private candidate configuration
 *
 * @copyright
 * Copyright (c) 2026 Deutsche Telekom AG.
 * Copyright (c) 2026 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo/private_candidate.h>

#include "np2_test.h"
#include "np2_test_config.h"

#if defined (__has_feature)
#  if __has_feature(thread_sanitizer)
#    define NP2_TSAN
#  endif
#elif defined (__SANITIZE_THREAD__)
#  define NP2_TSAN
#endif

#define UPDATE_RPC(RES_MODE) \
    "  <update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-private-candidate\">\n" \
    "    <resolution-mode>"RES_MODE"</resolution-mode>\n" \
    "  </update>\n" \

#define TCC_NOTIF_XMLNS "\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\""

#define TCC_RECV_NOTIF_PARAM(nc_sess, timeout_ms, state) \
    do { \
        state->msgtype = nc_recv_notif(nc_sess, timeout_ms, &state->envp, &state->op); \
    } while (state->msgtype == NC_MSG_REPLY); \
    assert_int_equal(NC_MSG_NOTIF, state->msgtype); \
    while (state->op->parent) state->op = lyd_parent(state->op); \

#define TCC_RECV_NOTIF(state) \
    TCC_RECV_NOTIF_PARAM(state->nc_sess, 3000, state)

#define TCC_ASSERT_NOTIF_EVENT(state, event, ssid) \
    { \
        assert_int_equal(lyd_print_mem(&state->str, state->op, LYD_XML, 0), LY_SUCCESS); \
        char *exp_cce = notif_cc_event(event, ssid); \
        assert_non_null(exp_cce); \
        assert_string_equal(exp_cce, state->str); \
        free(exp_cce); \
        free(state->str); \
        state->str = NULL; \
    }

static char *
notif_cc_event(const char *event, uint32_t ssid)
{
    char *msg = NULL;
    int r;

    /* Check data without 'timeout' leaf */
    if (!strcmp("timeout", event)) {
        r = asprintf(&msg,
                "<netconf-confirmed-commit xmlns="TCC_NOTIF_XMLNS ">\n"
                "  <confirm-event>timeout</confirm-event>\n"
                "</netconf-confirmed-commit>\n");
        assert_int_not_equal(r, -1);
    } else {
        r = asprintf(&msg,
                "<netconf-confirmed-commit xmlns="TCC_NOTIF_XMLNS ">\n"
                "  <username>%s</username>\n"
                "  <session-id>%" PRIu32 "</session-id>\n"
                "  <confirm-event>%s</confirm-event>\n"
                "</netconf-confirmed-commit>\n",
                np2_get_user(), ssid, event);
        assert_int_not_equal(r, -1);
    }

    return msg;
}

static int
notif_check_cc_timeout(struct np2_test *st, uint32_t expected_timeout)
{
    struct lyd_node *timeout_node;
    const uint32_t timeout_tolerance = 2;
    uint32_t timeout;

    timeout_node = lyd_child(st->op)->prev;
    if (!timeout_node || strcmp(timeout_node->schema->name, "timeout")) {
        /* timeout node is missing */
        return 2;
    }
    timeout = ((struct lyd_node_term *)timeout_node)->value.uint32;

    if ((expected_timeout <= timeout_tolerance) ||
            ((timeout >= (expected_timeout - timeout_tolerance)) &&
            (timeout <= expected_timeout))) {
        /* success, timeout node is checked so it can be removed */
        lyd_free_tree(timeout_node);
        return 0;
    } else {
        /* timeout is out of range */
        return 1;
    }
}

static int
local_setup(void **state)
{
    struct np2_test *st = *state;
    const char *modules[] = {NP_TEST_MODULE_DIR "/edit1.yang", NULL};
    char test_name[256];
    int rc;

    /* use private candidate */
    rc = nc_client_set_capability("urn:ietf:params:netconf:capability:private-candidate:1.0");
    assert_int_equal(rc, 0);

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, NULL, 0);
    assert_int_equal(rc, 0);
    st = *state;

    assert_int_equal(sr_session_start(st->conn, SR_DS_CANDIDATE, &st->sr_sess2), SR_ERR_OK);

    /* setup NACM */
    rc = np2_glob_test_setup_nacm(state);
    assert_int_equal(rc, 0);

    /* Enable replay support for ietf-netconf-notifications */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 1));

    /* Subscribe confirm-commit notification */
    SEND_RPC_ESTABSUB(st, "/ietf-netconf-notifications:netconf-confirmed-commit",
            "ietf-netconf-notifications", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np2_test *st = *state;
    const char *modules[] = {"edit1", NULL};

    if (!st) {
        return 0;
    }

    free(st->path);

    /* close the candidate session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    return np2_glob_test_teardown(state, modules);
}

static int
setup_common(void **state)
{
    struct np2_test *st = *state;
    const char *data = "<first xmlns=\"urn:ed1\">Test</first>";

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_common(void **state)
{
    struct np2_test *st = *state;
    const char *rpc = UPDATE_RPC("prefer-candidate");
    const char *data =
            "<first xmlns=\"urn:ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>"
            "<cont xmlns=\"urn:ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SR_EDIT_SESSION(st, st->sr_sess, data);
    FREE_TEST_VARS(st);
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    st->rpc = nc_rpc_act_generic_xml(rpc, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    FREE_TEST_VARS(st);

    return 0;
}

static void
test_pc_copy_config(void **state)
{
    struct np2_test *st = *state;
    const char *expected_client1;

    /* target: Candidate, source: Running */
    st->rpc = nc_rpc_copy(NC_DATASTORE_CANDIDATE, NULL, NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    GET_CONFIG_DS_FILTER(st, NC_DATASTORE_CANDIDATE, "/edit1:*");
    expected_client1 =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected_client1);
    FREE_TEST_VARS(st);
}

static void
test_pc_update_rpc(void **state)
{
    struct np2_test *st = *state;
    const char *data1, *data2, *data_cand;

    data1 = "<first xmlns=\"urn:ed1\">running1</first>";
    data2 = "<first xmlns=\"urn:ed1\">running2</first>";
    data_cand = "<first xmlns=\"urn:ed1\">candidate1</first>";

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_RUNNING, data1);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data_cand);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_RUNNING, data2);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    const char *rpc = UPDATE_RPC("revert-on-conflict");

    st->rpc = nc_rpc_act_generic_xml(rpc, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->envp);

    lyd_print_mem(&st->str, st->envp, LYD_XML, LYD_PRINT_SIBLINGS);
    assert_non_null(strstr(st->str, "<conflict xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-private-candidate\">"));

    FREE_TEST_VARS(st);
}

static void
test_pc_nmda_rpcs(void **state)
{
    struct np2_test *st = *state;
    const char *expected_client1;
    const char *data_merge = "<first xmlns=\"urn:ed1\">Test</first>";

    st->rpc = nc_rpc_editdata("ietf-datastores:candidate", NC_RPC_EDIT_DFLTOP_MERGE, data_merge, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    st->rpc = nc_rpc_getdata("ietf-datastores:candidate", "/edit1:*", NULL, NULL,
            0, 0, 0, 0, NC_WD_ALL, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->op);

    lyd_print_mem(&st->str, st->op, LYD_XML, LYD_PRINT_SIBLINGS);
    expected_client1 =
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-data>\n";
    assert_string_equal(st->str, expected_client1);

    FREE_TEST_VARS(st);
}

static void
test_pc_validate(void **state)
{
    struct np2_test *st = *state;

    st->rpc = nc_rpc_validate(NC_DATASTORE_CANDIDATE, NULL, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

// <delete-config> not supported for the candidate datastore yet – test not applicable.

static void
test_pc_lock_unlock(void **state)
{
    struct np2_test *st = *state;

    st->rpc = nc_rpc_lock(NC_DATASTORE_CANDIDATE);
    assert_non_null(st->rpc);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    st->rpc = nc_rpc_unlock(NC_DATASTORE_CANDIDATE);
    assert_non_null(st->rpc);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

/* COMMIT & CONFIRMED COMMIT */

static void
test_pc_basic_commit(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Prior to the test running of edit1 should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* Send a confirmed-commit rpc */
    st->rpc = nc_rpc_commit(1, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 600), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate, same as basic commit */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Send a commit rpc to confirm it */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'complete' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "complete", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);
}

#ifndef NP2_TSAN
// This test a path in netopeer2 which starts a timer via the C library, and that makes TSAN segfault:
// https://github.com/google/sanitizers/issues/1612
static void
test_pc_commit_timeout_runout(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Prior to the test running of edit1 should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* running lock RPC */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 1s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 1), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate, same as basic commit */
    GET_FILTER(st, "/edit1:first");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* There could be a potential data-race if a second passes between receiving the reply and the get-config */

    /* wait for the duration of the timeout */
    sleep(2);

    /* Expect 'timeout' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "timeout", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should have reverted back to it's original value */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* running unlock RPC */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);
}

#endif

static void
test_pc_timeout_confirm(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 1s timeout*/
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 1), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Send a commit rpc to confirm it */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'complete' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "complete", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    sleep(2);

    /* Data should remain unchanged */
    GET_CONFIG_FILTER(st, "/edit1:*");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);
}

static void
test_pc_timeout_confirm_modify(void **state)
{
    struct np2_test *st = *state;
    const char *expected;
    const char *data;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 1), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Modify candidate to see if confirm-commit only cancels the timer */
    data = "<first xmlns=\"urn:ed1\">Alt</first>";
    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send a commit rpc to confirm it */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    sleep(2);

    /* Expect 'complete' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "complete", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Data should change */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Alt</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_pc_cancel_commit(void **state)
{
    struct np2_test *st = *state;
    const char *run_expected, *cand_expected, *data, *data1;
    const char *rpc = UPDATE_RPC("prefer-running");

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* edit running */
    data = "<first xmlns=\"urn:ed1\">val</first><cont xmlns=\"urn:ed1\"><second/><third>5</third></cont>";
    SR_EDIT_SESSION(st, st->sr_sess, data);
    FREE_TEST_VARS(st);

    // update candidate so it has same data as running
    st->rpc = nc_rpc_act_generic_xml(rpc, NC_PARAMTYPE_CONST);
    assert_non_null(st->rpc);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    FREE_TEST_VARS(st);

    /* send cancel-commit rpc, should fail as there is no commit */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an error reply */
    ASSERT_ERROR_REPLY(st);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);

    data1 = "<first xmlns=\"urn:ed1\">Test</first>";

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data1);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* send a confirmed-commit rpc with 10m timeout */
    st->rpc = nc_rpc_commit(1, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 10m timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 600), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    run_expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "    <cont xmlns=\"urn:ed1\">\n"
            "      <second/>\n"
            "      <third>5</third>\n"
            "    </cont>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, run_expected);
    FREE_TEST_VARS(st);

    /* send cancel-commit rpc */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'cancel' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "cancel", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be back how it was */
    GET_CONFIG_FILTER(st, "/edit1:*");
    run_expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">val</first>\n"
            "    <cont xmlns=\"urn:ed1\">\n"
            "      <second/>\n"
            "      <third>5</third>\n"
            "    </cont>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, run_expected);
    FREE_TEST_VARS(st);

    GET_CONFIG_DS_FILTER(st, NC_DATASTORE_CANDIDATE, "/edit1:*");
    cand_expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "    <cont xmlns=\"urn:ed1\">\n"
            "      <second/>\n"
            "      <third>5</third>\n"
            "    </cont>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, cand_expected);
    FREE_TEST_VARS(st);
}

static void
test_pc_rollback_disconnect(void **state)
{
    struct np2_test *st = *state;
    struct nc_session *ncs;
    const char *expected;
    uint32_t sid;
    const char *data1 = "<first xmlns=\"urn:ed1\">Test</first>";

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* create a new session */
    ncs = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(ncs);

    st->rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET, NC_RPC_EDIT_ERROPT_ROLLBACK,
            data1, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(ncs, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY_SESS(st, ncs);
    FREE_TEST_VARS(st);

    /* send a confirmed-commit rpc with 60s timeout */
    st->rpc = nc_rpc_commit(1, 60, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(ncs, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* expect OK */
    ASSERT_OK_REPLY_SESS(st, ncs);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 60s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 60), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(ncs));
    FREE_TEST_VARS(st);

    /* running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* disconnect session, commit is rolled back */
    sid = nc_session_get_id(ncs);
    nc_session_free(ncs, NULL);

    /* reply is sent before the server callback is called so give it a chance to perform the rollback */
    usleep(100000);

    /* Expect 'cancel' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "cancel", sid);
    FREE_TEST_VARS(st);

    /* data should remain unchanged, empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");
}

static void
test_cp_confirm_persist(void **state)
{
    struct np2_test *st = *state;
    const char *expected, *persist = "test-persist-1";

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* Send a confirmed-commit rpc with persist */
    st->rpc = nc_rpc_commit(1, 0, persist, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 600), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Send commit rpc on a different session with persist-id */
    st->rpc = nc_rpc_commit(0, 0, NULL, persist, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY_SESS2(st);
    FREE_TEST_VARS(st);

    /* Expect 'complete' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "complete", nc_session_get_id(st->nc_sess2));
    FREE_TEST_VARS(st);

    /* Data should remain unchanged */
    GET_CONFIG_FILTER(st, "/edit1:*");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_pc_cancel_persist(void **state)
{
    struct np2_test *st = *state;
    const char *expected, *persist = "test-persist-2";
    struct nc_session *nc_sess;
    const char *data1 = "<first xmlns=\"urn:ed1\">Test</first>";

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* start a new NC session */
    nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(nc_sess);

    st->rpc = nc_rpc_edit(NC_DATASTORE_CANDIDATE, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET, NC_RPC_EDIT_ERROPT_ROLLBACK,
            data1, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY_SESS(st, nc_sess);
    FREE_TEST_VARS(st);

    /* send a confirmed-commit rpc with persist */
    st->rpc = nc_rpc_commit(1, 0, persist, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an OK reply */
    ASSERT_OK_REPLY_PARAM(nc_sess, 3000, st)
    FREE_TEST_VARS(st);

    /* Expect 'start' notification */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 600), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"urn:ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* disconnect NC session */
    nc_session_free(nc_sess, NULL);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);

    /* send cancel-commit rpc on a different session */
    st->rpc = nc_rpc_cancel(persist, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'cancel' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "cancel", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pc_copy_config, setup_common, teardown_common),
        cmocka_unit_test_teardown(test_pc_update_rpc, teardown_common),

        cmocka_unit_test_setup_teardown(test_pc_validate, setup_common, teardown_common),
        cmocka_unit_test_teardown(test_pc_nmda_rpcs, teardown_common),
        cmocka_unit_test(test_pc_lock_unlock),

        cmocka_unit_test_setup_teardown(test_pc_basic_commit, setup_common, teardown_common),
#ifndef NP2_TSAN
        cmocka_unit_test_setup_teardown(test_pc_commit_timeout_runout, setup_common, teardown_common),
#endif
        cmocka_unit_test_setup_teardown(test_pc_timeout_confirm, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_pc_timeout_confirm_modify, setup_common, teardown_common),

        cmocka_unit_test_teardown(test_pc_cancel_commit, teardown_common),
        cmocka_unit_test_teardown(test_pc_rollback_disconnect, teardown_common),

        cmocka_unit_test_setup_teardown(test_cp_confirm_persist, setup_common, teardown_common),
        cmocka_unit_test_teardown(test_pc_cancel_persist, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
