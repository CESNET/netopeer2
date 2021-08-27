/**
 * @file test_rpc.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief test executing simple RPCs
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
    int rv;

    /* Setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* Connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
        st = *state;
        /* Open the connection to start a session for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));
        rv |= setup_nacm(state);
    }
    return rv;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;

    /* Close the session and connection needed for tests */
    assert_int_equal(sr_session_stop(st->sr_sess), SR_ERR_OK);
    assert_int_equal(sr_disconnect(st->conn), SR_ERR_OK);

    /* Connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Close netopeer2 server */
    return np_glob_teardown(state);
}

static int
teardown_test_lock(void **state)
{
    struct np_test *st = *state;

    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_lock_basic(void **state)
{
    struct np_test *st = *state;

    /* Check if lock RPC succeeds */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(st->rpc);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static void
test_lock_fail(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *error;

    /* Lock from first session */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(st->rpc);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Request to lock from another session should fail when locked already */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_RPC_ERROR_SESS2(st);

    /* Check error message */
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));
    template =
            "<rpc-reply "
            "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%ld\">\n"
            "  <rpc-error>\n"
            "    <error-type>protocol</error-type>\n"
            "    <error-tag>lock-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-message xml:lang=\"en\">Access to the requested lock is denied"
            " because the lock is currently held by another entity.</error-message>\n"
            "    <error-info>\n"
            "      <session-id>%d</session-id>\n"
            "    </error-info>\n"
            "  </rpc-error>\n"
            "</rpc-reply>\n";
    assert_int_not_equal(-1, asprintf(&error, template, st->msgid, nc_session_get_id(st->nc_sess)));
    assert_string_equal(st->str, error);

    free(error);
    FREE_TEST_VARS(st);
}

static int
setup_test_lock_changes(void **state)
{
    struct np_test *st = *state;

    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(st->rpc);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static int
teardown_test_lock_changes(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_lock_changes(void **state)
{
    struct np_test *st = *state;

    /* Send RPC editing module edit1 on the same session, should succeed */
    SEND_EDIT_RPC(st, "<first xmlns=\"ed1\">TestFirst</first>");
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send RPC editing module edit1 on another session, should fail */
    st->rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, "<first xmlns=\"ed1\">TestFirst</first>", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    st->msgtype = nc_recv_reply(st->nc_sess2, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");
    FREE_TEST_VARS(st);
}

static int
setup_test_unlock(void **state)
{
    struct np_test *st = *state;

    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_unlock(void **state)
{
    struct np_test *st = *state;

    /* Check if unlock RPC succeeds */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
teardown_test_unlock_fail(void **state)
{
    struct np_test *st = *state;

    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_unlock_fail(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *error;

    /* Try unlocking a lock by a different session, should fail */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check error message */
    ASSERT_RPC_ERROR_SESS2(st);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));
    template =
            "<rpc-reply "
            "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%ld\">\n"
            "  <rpc-error>\n"
            "    <error-type>protocol</error-type>\n"
            "    <error-tag>lock-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-message xml:lang=\"en\">Access to the requested lock is denied"
            " because the lock is currently held by another entity.</error-message>\n"
            "    <error-info>\n"
            "      <session-id>%d</session-id>\n"
            "    </error-info>\n"
            "  </rpc-error>\n"
            "</rpc-reply>\n";
    assert_int_not_equal(-1, asprintf(&error, template, st->msgid, nc_session_get_id(st->nc_sess)));
    assert_string_equal(st->str, error);
    free(error);
    FREE_TEST_VARS(st);
}

static void
test_get(void **state)
{
    struct np_test *st = *state;

    /* Check if get RPC succeeds */
    /* TODO: get crashes the server on a locked session */
    st->rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->op);
    assert_non_null(st->envp);

    FREE_TEST_VARS(st);
}

static void
test_kill(void **state)
{
    struct np_test *st = *state;
    char *username, *error, *expected;
    const char *template;

    if (is_nacm_rec_uid()) {
        puts("Skipping the test.");
        return;
    }

    /* Try to close a session, should fail due to wrong permissions */
    st->rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess));
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_RPC_ERROR(st);

    /* Check the error message */
    lyd_print_mem(&error, st->envp, LYD_XML, 0);
    get_username(&username);
    template =
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%ld\">\n"
            "  <rpc-error>\n"
            "    <error-type>application</error-type>\n"
            "    <error-tag>access-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-path>/ietf-netconf:kill-session</error-path>\n"
            "    <error-message xml:lang=\"en\">Executing the operation is denied "
            "because \"%s\" NACM authorization failed.</error-message>\n"
            "  </rpc-error>\n"
            "</rpc-reply>\n";
    assert_int_not_equal(-1, asprintf(&expected, template, st->msgid, username));
    assert_string_equal(error, expected);

    free(username);
    free(error);
    free(expected);
    FREE_TEST_VARS(st);
    /* Functionality tested in  test_nacm.c */
}

static void
test_commit(void **state)
{
    struct np_test *st = *state;

    /* Check if commit RPC succeeds */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    /* Functionality tested in test_candidate.c */
}

static void
test_discard(void **state)
{
    struct np_test *st = *state;

    /* Check if discard RPC succeeds */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    /* Functionality tested in  test_candidate.c */
}

static void
test_getconfig(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    char *configuration;

    /* Try getting configuration */
    st->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);

    /* Check the reply */
    assert_non_null(st->op);
    assert_non_null(st->envp);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&configuration, st->op, LYD_XML, 0));
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";
    assert_string_equal(configuration, expected);
    free(configuration);
    FREE_TEST_VARS(st);
    /* Functionality tested in test_edit.c */
}

static void
test_validate(void **state)
{
    struct np_test *st = *state;

    /* Try validating configuration of the running datastore */
    st->rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    /* Functionality tested in test_candidate.c */
}

static void
test_unsuported(void **state)
{
    struct np_test *st = *state;

    /* Testing RPCs unsupported by netopeer2, all should fail */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_ERROR, st->msgtype);

    nc_rpc_free(st->rpc);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_lock_basic, teardown_test_lock),
        cmocka_unit_test_teardown(test_lock_fail, teardown_test_lock),
        cmocka_unit_test_setup_teardown(test_lock_changes, setup_test_lock_changes, teardown_test_lock_changes),
        cmocka_unit_test_setup(test_unlock, setup_test_unlock),
        cmocka_unit_test_setup_teardown(test_unlock_fail, setup_test_unlock, teardown_test_unlock_fail),
        cmocka_unit_test(test_get),
        cmocka_unit_test(test_kill),
        cmocka_unit_test(test_commit),
        cmocka_unit_test(test_discard),
        cmocka_unit_test(test_getconfig),
        cmocka_unit_test(test_validate),
        cmocka_unit_test(test_unsuported),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
