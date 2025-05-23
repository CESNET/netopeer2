/**
 * @file test_rpc.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test executing simple RPCs
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

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo/netconf_acm.h>

#include "np2_test.h"
#include "np2_test_config.h"

static int
local_setup(void **state)
{
    char test_name[256];
    const char *modules[] = {
        NP_TEST_MODULE_DIR "/edit1.yang",
        NP_TEST_MODULE_DIR "/sm.yang",
        NULL
    };
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, 0);
    assert_int_equal(rc, 0);

    /* setup NACM */
    rc = np2_glob_test_setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"edit1", "sm", NULL};

    /* close netopeer2 server */
    if (*state) {
        return np2_glob_test_teardown(state, modules);
    }

    return 0;
}

static int
teardown_test_lock(void **state)
{
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;
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
    ASSERT_ERROR_REPLY_SESS2(st);

    /* Check error message */
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));
    template =
            "<rpc-reply "
            "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%" PRIu64 "\">\n"
            "  <rpc-error>\n"
            "    <error-type>protocol</error-type>\n"
            "    <error-tag>lock-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-message xml:lang=\"en\">Access to the requested lock is denied"
            " because the lock is currently held by another entity.</error-message>\n"
            "    <error-info>\n"
            "      <session-id>%" PRIu32 "</session-id>\n"
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
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;
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
    struct np2_test *st = *state;

    /* Send RPC editing module edit1 on the same session, should succeed */
    SEND_EDIT_RPC(st, "<first xmlns=\"ed1\">TestFirst</first>");
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send RPC editing module edit1 on another session, should fail */
    st->rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, "<first xmlns=\"ed1\">TestFirst</first>", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY_SESS2(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_unlock(void **state)
{
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;

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
    struct np2_test *st = *state;
    const char *template;
    char *error;

    /* Try unlocking a lock by a different session, should fail */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check error message */
    ASSERT_ERROR_REPLY_SESS2(st);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));
    template =
            "<rpc-reply "
            "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%" PRIu64 "\">\n"
            "  <rpc-error>\n"
            "    <error-type>protocol</error-type>\n"
            "    <error-tag>lock-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-message xml:lang=\"en\">Access to the requested lock is denied"
            " because the lock is currently held by another entity.</error-message>\n"
            "    <error-info>\n"
            "      <session-id>%" PRIu32 "</session-id>\n"
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
    struct np2_test *st = *state;

    /* Check if get RPC succeeds */
    st->rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_DATA_REPLY(st);
    FREE_TEST_VARS(st);
}

static void
test_kill(void **state)
{
    struct np2_test *st = *state;
    char *error, *expected;
    const char *template;

    if (np2_is_nacm_recovery()) {
        puts("Skipping the test.");
        return;
    }

    /* try to close a session, should fail due to wrong permissions */
    st->rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess));
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);

    /* check the error message */
    lyd_print_mem(&error, st->envp, LYD_XML, 0);
    template =
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "message-id=\"%" PRIu64 "\">\n"
            "  <rpc-error>\n"
            "    <error-type>protocol</error-type>\n"
            "    <error-tag>access-denied</error-tag>\n"
            "    <error-severity>error</error-severity>\n"
            "    <error-path xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">/nc:kill-session</error-path>\n"
            "    <error-message xml:lang=\"en\">Executing the operation is denied "
            "because \"%s\" NACM authorization failed.</error-message>\n"
            "  </rpc-error>\n"
            "</rpc-reply>\n";
    assert_int_not_equal(-1, asprintf(&expected, template, st->msgid, np2_get_user()));
    assert_string_equal(error, expected);

    free(error);
    free(expected);
    FREE_TEST_VARS(st);

    /* functionality tested in test_nacm.c */
}

static void
test_commit(void **state)
{
    struct np2_test *st = *state;

    /* check if commit RPC succeeds */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* functionality tested in test_candidate.c */
}

static void
test_discard(void **state)
{
    struct np2_test *st = *state;

    /* check if discard RPC succeeds */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* functionality tested in  test_candidate.c */
}

static void
test_getconfig(void **state)
{
    struct np2_test *st = *state;

    if (np2_is_nacm_recovery()) {
        puts("Skipping the test.");
        return;
    }

    /* get-config */
    GET_CONFIG_FILTER(st, "/edit1:*");
    assert_string_equal(st->str,
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n");
    FREE_TEST_VARS(st);
}

static void
test_validate(void **state)
{
    struct np2_test *st = *state;

    /* Try validating configuration of the running datastore */
    st->rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    /* Functionality tested in test_candidate.c */
}

static void
test_schema_mount(void **state)
{
    struct np2_test *st = *state;

    /* send RPC editing module edit1 on the same session, should succeed */
    SEND_EDIT_RPC(st,
            "<root xmlns=\"urn:sm\">"
            "  <first xmlns=\"ed1\">TestFirst</first>"
            "  <cont xmlns=\"ed1\">"
            "    <second/>"
            "    <third>25</third>"
            "  </cont>"
            "</root>");
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* read back the configuration */
    GET_CONFIG_FILTER(st, "/sm:root/*");
    assert_string_equal(st->str,
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <root xmlns=\"urn:sm\">\n"
            "      <first xmlns=\"ed1\">TestFirst</first>\n"
            "      <cont xmlns=\"ed1\">\n"
            "        <second/>\n"
            "        <third>25</third>\n"
            "      </cont>\n"
            "    </root>\n"
            "  </data>\n"
            "</get-config>\n");
    FREE_TEST_VARS(st);
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
        cmocka_unit_test(test_schema_mount),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
