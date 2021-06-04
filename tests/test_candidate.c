/**
 * @file test_candidate.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests around candidate configuration and corresponding rpcs
 *
 * @copyright
 * Copyright 2021 Deutsche Telekom AG.
 * Copyright 2021 CESNET, z.s.p.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;
    const char *features[] = {NULL};
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/edit2.yang";
    int rv;

    /* setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
        st = *state;
        /* Open two connections to start a session for the tests
         * One for Candidate and other for running
         */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));
        assert_int_equal(sr_session_start(st->conn, SR_DS_CANDIDATE, &st->sr_sess2), SR_ERR_OK);
    }
    return rv;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;

    /* Close the sessions and connection needed for tests */
    assert_int_equal(sr_session_stop(st->sr_sess), SR_ERR_OK);
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);
    assert_int_equal(sr_disconnect(st->conn), SR_ERR_OK);

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
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

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
