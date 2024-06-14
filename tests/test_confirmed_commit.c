/**
 * @file test_confirmed_commit.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief tests around the confirmed commit capability
 *
 * @copyright
 * Copyright (c) 2019 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <dirent.h>
#include <errno.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo/netconf_acm.h>

#include "np2_test.h"
#include "np2_test_config.h"

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

    /* Check data without 'timeout' leaf */
    if (!strcmp("timeout", event)) {
        asprintf(&msg,
                "<netconf-confirmed-commit xmlns="TCC_NOTIF_XMLNS ">\n"
                "  <confirm-event>timeout</confirm-event>\n"
                "</netconf-confirmed-commit>\n");
    } else {
        asprintf(&msg,
                "<netconf-confirmed-commit xmlns="TCC_NOTIF_XMLNS ">\n"
                "  <username>%s</username>\n"
                "  <session-id>%" PRIu32 "</session-id>\n"
                "  <confirm-event>%s</confirm-event>\n"
                "</netconf-confirmed-commit>\n",
                np2_get_user(), ssid, event);
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
    struct np2_test *st;
    const char *modules[] = {NP_TEST_MODULE_DIR "/edit1.yang", NULL};
    char test_name[256];
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules);
    assert_int_equal(rc, 0);
    st = *state;

    /* start candidate session */
    assert_int_equal(sr_session_start(st->conn, SR_DS_CANDIDATE, &st->sr_sess2), SR_ERR_OK);

    /*
     * The use of st->path is a little overriden until test_failed_file is called it stores test_name after that
     * the path to the test server file directory
     */
    st->path = strdup(test_name);
    if (!st->path) {
        return 1;
    }

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

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

static int
setup_common(void **state)
{
    struct np2_test *st = *state;
    const char *data = "<first xmlns=\"ed1\">Test</first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_common(void **state)
{
    struct np2_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>"
            "<cont xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SR_EDIT_SESSION(st, st->sr_sess, data);
    FREE_TEST_VARS(st);
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    return 0;
}

static void
test_sameas_commit(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Prior to the test running of edit1 should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*")

    /* Send a confirmed-commit rpc */
    st->rpc = nc_rpc_commit(1, 0, NULL, NULL, NC_PARAMTYPE_CONST);
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

    /* Running should now be same as candidate, same as basic commit */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
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
}

static void
test_timeout_runout(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Prior to the test running of edit1 should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*")

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

    /* Running should now be same as candidate */
    GET_FILTER(st, "/edit1:first");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
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

static void
test_timeout_confirm(void **state)
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
            "    <first xmlns=\"ed1\">Test</first>\n"
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
test_timeout_confirm_modify(void **state)
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
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Modify candidate to see if confirm-commit only cancels the timer */
    data = "<first xmlns=\"ed1\">Alt</first>";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
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
            "    <first xmlns=\"ed1\">Alt</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_timeout_followup(void **state)
{
    struct np2_test *st = *state;
    const char *data, *expected;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* send a confirmed-commit rpc with 60s timeout */
    st->rpc = nc_rpc_commit(1, 60, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 60s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 60), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* modify candidate */
    data = "<first xmlns=\"ed1\">Test2</first>";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    /* send another confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'extend' notification with 1s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 1), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "extend", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test2</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* wait for the rollback */
    sleep(2);

    /* Expect 'timeout' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "timeout", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* data should remain unchanged, empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");
}

static void
test_cancel(void **state)
{
    struct np2_test *st = *state;
    const char *expected, *data;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* send cancel-commit rpc, should fail as there is no commit */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an error reply */
    ASSERT_ERROR_REPLY(st);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);

    /* edit running */
    data = "<first xmlns=\"ed1\">val</first><cont xmlns=\"ed1\"><second/><third>5</third></cont>";
    SR_EDIT_SESSION(st, st->sr_sess, data);
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
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
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
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">val</first>\n"
            "    <cont xmlns=\"ed1\">\n"
            "      <second/>\n"
            "      <third>5</third>\n"
            "    </cont>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_rollback_disconnect(void **state)
{
    struct np2_test *st = *state;
    struct nc_session *ncs;
    const char *expected;
    uint32_t sid;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* create a new session */
    ncs = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(ncs);

    /* send a confirmed-commit rpc with 60s timeout */
    st->rpc = nc_rpc_commit(1, 60, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(ncs, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* expect OK */
    st->msgtype = nc_recv_reply(ncs, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "ok");
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
            "    <first xmlns=\"ed1\">Test</first>\n"
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
test_rollback_locked(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* running lock RPC */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* send a persistent confirmed-commit rpc with 60s timeout */
    st->rpc = nc_rpc_commit(1, 60, "test-persist", NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'start' notification with 60s timeout */
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 60), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* running should now be the same as candidate */
    GET_CONFIG_FILTER(st, "/edit1:*");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* cancel-commit on a different session, running locked */
    st->rpc = nc_rpc_cancel("test-persist", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_ERROR_REPLY_SESS2(st);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);

    /* cancel-commit on the same session */
    st->rpc = nc_rpc_cancel("test-persist", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Expect 'cancel' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "cancel", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* data should remain unchanged, empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* running unlock RPC */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* No notification should occur */
    ASSERT_NO_NOTIF(st);
}

static void
test_confirm_persist(void **state)
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
            "    <first xmlns=\"ed1\">Test</first>\n"
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
test_cancel_persist(void **state)
{
    struct np2_test *st = *state;
    const char *expected, *persist = "test-persist-2";
    struct nc_session *nc_sess;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

    /* start a new NC session */
    nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(nc_sess);

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
            "    <first xmlns=\"ed1\">Test</first>\n"
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

static void
test_wrong_session(void **state)
{
    struct np2_test *st = *state;

    /* send a confirmed-commit rpc with 60s timeout */
    st->rpc = nc_rpc_commit(1, 60, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    TCC_RECV_NOTIF(st);
    assert_int_equal(notif_check_cc_timeout(st, 60), 0);
    TCC_ASSERT_NOTIF_EVENT(st, "start", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* send another confirmed-commit rpc on a different NC session, invalid */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_ERROR_REPLY_SESS2(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "operation-failed");
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);

    /* send confirming commit rpc on a different NC session, invalid */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_ERROR_REPLY_SESS2(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "operation-failed");
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);

    /* send cancel commit rpc on a different NC session, invalid */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_ERROR_REPLY_SESS2(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "operation-failed");
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);

    /* send running lock rpc on a different NC session, invalid */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_ERROR_REPLY_SESS2(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "lock-denied");
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);

    /* send cancel-commit rpc */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "cancel", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);
}

static void
test_wrong_persist_id(void **state)
{
    struct np2_test *st = *state;
    const char *persist = "test-persist-3";

    /* Send a confirmed-commit rpc with unknown persist-id */
    st->rpc = nc_rpc_commit(0, 0, NULL, persist, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an error */
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);
}

static int
setup_test_failed_file(void **state)
{
    struct np2_test *st = *state;
    char *test_name, *file_name;
    FILE *file;

    /* get test backup directory */
    test_name = strdup(st->path);
    free(st->path);
    if (!test_name) {
        return 1;
    }
    if (asprintf(&st->path, "%s/%s/confirmed_commit", NP_TEST_DIR, test_name) == -1) {
        return 1;
    }
    if (asprintf(&file_name, "%s/bogus.json", st->path) == -1) {
        return 1;
    }
    file = fopen(file_name, "w+");
    if (!file) {
        printf("Could not create file \"%s\" (%s).\n", file_name, strerror(errno));
        return 1;
    }
    free(file_name);
    free(test_name);
    fclose(file);
    return 0;
}

static void
test_failed_file(void **state)
{
    struct np2_test *st = *state;
    struct dirent *file = NULL;
    int found = 0;
    DIR *dir = NULL;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG_FILTER(st, "/edit1:*");

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

    /* Wait for the duration of the timeout */
    sleep(2);

    /* Expect 'timeout' notification */
    TCC_RECV_NOTIF(st);
    TCC_ASSERT_NOTIF_EVENT(st, "timeout", nc_session_get_id(st->nc_sess));
    FREE_TEST_VARS(st);

    /* Try and find the .failed file, should be exactly one */
    dir = opendir(st->path);
    assert_non_null(dir);
    while ((file = readdir(dir))) {
        if (!strcmp("..", file->d_name) || !strcmp(".", file->d_name)) {
            continue;
        }
        if (strstr(file->d_name, ".failed")) {
            found += 1;
        }
    }
    closedir(dir);
    assert_int_equal(found, 1);
}

static int
teardown_test_failed_file(void **state)
{
    struct np2_test *st = *state;
    DIR *dir;
    struct dirent *file;
    char *path = NULL;

    dir = opendir(st->path);
    assert_non_null(dir);
    while ((file = readdir(dir))) {
        if (!strcmp("..", file->d_name) || !strcmp(".", file->d_name)) {
            continue;
        }
        if (strstr(file->d_name, ".failed")) {
            assert_return_code(asprintf(&path, "%s/%s", st->path, file->d_name), 0);
            if (unlink(path) == -1) {
                printf("%s", strerror(errno));
                return 1;
            }
            free(path);
            path = NULL;
        }
    }
    closedir(dir);
    return 0;
}

int
main(int argc, char **argv)
{
    if (np2_is_nacm_recovery()) {
        puts("Running as NACM_RECOVERY_USER. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sameas_commit, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_runout, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_confirm, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_confirm_modify, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_followup, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_cancel, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_rollback_disconnect, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_rollback_locked, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_confirm_persist, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_cancel_persist, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_wrong_session, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_wrong_persist_id, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_failed_file, setup_test_failed_file, teardown_test_failed_file),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
