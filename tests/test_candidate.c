/**
 * @file test_candidate.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests around candidate configuration and corresponding rpcs
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo/netconf_acm.h>

#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    struct np_test *st = *state;
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/edit1.yang", NP_TEST_MODULE_DIR "/edit2.yang"};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules, sizeof modules / sizeof *modules);
    assert_int_equal(rc, 0);
    st = *state;

    /* candidate session */
    assert_int_equal(sr_session_start(st->conn, SR_DS_CANDIDATE, &st->sr_sess2), SR_ERR_OK);

    /* setup NACM */
    rc = setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    const char *modules[] = {"edit1", "edit2"};

    if (!st) {
        return 0;
    }

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state, modules, sizeof modules / sizeof *modules);
}

static int
setup_candidate(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\">TestFirst</first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);
    return 0;
}

static int
empty_candidate(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);
    return 0;
}

static int
empty_running(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<first xmlns=\"ed1\""
            "xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\""
            "xc:operation=\"remove\"/>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);
    return 0;
}

static void
test_edit_basic(void **state)
{
    struct np_test *st = *state;
    char *data, *expected;

    /* Get a simple config into candidate */
    data = "<first xmlns=\"ed1\">TestFirst</first>";

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if it was merged */
    GET_DS_CONFIG(st, NC_DATASTORE_CANDIDATE);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Remove it from the configuration */
    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SEND_EDIT_RPC_DS(st, NC_DATASTORE_CANDIDATE, data);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
}

static void
test_commit(void **state)
{
    struct np_test *st = *state;
    char *data, *expected;

    /* Get some data into candidate */
    data = "<first xmlns=\"ed1\">TestFirst</first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    /* Check if running is empty */
    GET_DS_CONFIG(st, NC_DATASTORE_RUNNING);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Send commit rpc */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if running is now same as candidate */
    GET_DS_CONFIG(st, NC_DATASTORE_CANDIDATE);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_discard_changes(void **state)
{
    struct np_test *st = *state;
    char *expected;

    /* Check if Running is empty */
    GET_DS_CONFIG(st, NC_DATASTORE_RUNNING);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Check if Candidate has config */
    GET_DS_CONFIG(st, NC_DATASTORE_CANDIDATE);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Send discard-changes rpc */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if Candidate is now empty too */
    GET_DS_CONFIG(st, NC_DATASTORE_CANDIDATE);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_validate_valid(void **state)
{
    struct np_test *st = *state;

    /* Send validate rpc */
    st->rpc = nc_rpc_validate(NC_DATASTORE_CANDIDATE, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
}

static void
test_validate_invalid(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "  <num>ClearlyNotANumericValue</num>"
            "</top>";

    /* Send validate rpc */
    st->rpc = nc_rpc_validate(NC_DATASTORE_CONFIG, data, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
}

static int
setup_discard_changes_advanced(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Merge config into running */
    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "</top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    /* Merge config into candidate */
    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "  <num>12</num>"
            "</top>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_commit_locked_running(void **state)
{
    struct np_test *st = *state;

    /* lock from another session */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* receive reply, should succeed */
    ASSERT_OK_REPLY_SESS2(st);

    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_commit_locked_running(void **state)
{
    struct np_test *st = *state;

    /* lock from another session */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* receive reply, should succeed */
    ASSERT_OK_REPLY_SESS2(st);
    return 0;
}

static void
test_commit_locked_running(void **state)
{
    struct np_test *st = *state;

    /* Send commit rpc */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Receive  a reply should have error-tag in-use */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "in-use");

    FREE_TEST_VARS(st);
}

static int
setup_lock_modified_candidate(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Modify candidate in any way */
    data = "<first xmlns=\"ed1\">TestFirst</first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_lock_modified_candidate(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Remove anything */
    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);

    return 0;
}

static void
test_lock_modified_candidate(void **state)
{
    struct np_test *st = *state;

    /* lock */
    st->rpc = nc_rpc_lock(NC_DATASTORE_CANDIDATE);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_RPC_ERROR(st);

    FREE_TEST_VARS(st);
}

static int
teardown_discard_changes_advanced(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Remove config from running */
    data = "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    /* Remove config from candidate */
    SR_EDIT_SESSION(st, st->sr_sess2, data);

    FREE_TEST_VARS(st);

    return 0;
}

static void
test_discard_changes_advanced(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Check if running has correct data */
    GET_DS_CONFIG(st, NC_DATASTORE_RUNNING);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed2\">\n"
            "      <name>TestSecond</name>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Check if candidate has correct dada */
    GET_DS_CONFIG(st, NC_DATASTORE_CANDIDATE);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed2\">\n"
            "      <name>TestSecond</name>\n"
            "      <num>12</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    /* Send discard-changes rpc */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if candidate is now same as running */
    GET_DS_CONFIG(st, NC_DATASTORE_RUNNING);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed2\">\n"
            "      <name>TestSecond</name>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_edit_basic),
        cmocka_unit_test_setup_teardown(test_commit, setup_candidate, empty_running),
        cmocka_unit_test_setup(test_discard_changes, setup_candidate),
        cmocka_unit_test_setup_teardown(test_validate_valid, setup_candidate, empty_candidate),
        cmocka_unit_test(test_validate_invalid),
        cmocka_unit_test_setup_teardown(test_commit_locked_running, setup_commit_locked_running,
                teardown_commit_locked_running),
        cmocka_unit_test_setup_teardown(test_lock_modified_candidate, setup_lock_modified_candidate,
                teardown_lock_modified_candidate),
        cmocka_unit_test_setup_teardown(test_discard_changes_advanced, setup_discard_changes_advanced,
                teardown_discard_changes_advanced),
    };

    if (np_is_nacm_recovery()) {
        puts("Running as NACM_RECOVERY_USER. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
