/**
 * @file test_confirmed_commit.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests around the confirmed commit capability
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

#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    struct np_test *st;
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/edit1.yang"};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules, sizeof modules / sizeof *modules);
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
    rc = setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    const char *modules[] = {"edit1"};

    if (!st) {
        return 0;
    }

    free(st->path);

    /* close the candidate session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state, modules, sizeof modules / sizeof *modules);
}

static int
setup_common(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\">Test</first>";

    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
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
test_basic(void **state)
{
    struct np_test *st = *state;

    /* Send a confirmed-commit rpc */
    st->rpc = nc_rpc_commit(1, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "ok");
    FREE_TEST_VARS(st);
}

static void
test_sameas_commit(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc */
    st->rpc = nc_rpc_commit(1, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate, same as basic commit */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_timeout_runout(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* There could be a potential data-race if a second passes between receiving the reply and the get-config */

    /* wait for the duration of the timeout */
    sleep(2);

    /* Running should have reverted back to it's original value */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_timeout_confirm(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG(st);
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

    sleep(2);

    /* Data should remain unchanged */
    GET_CONFIG(st);
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_timeout_confirm_modify(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *data;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG(st);
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

    /* Data should change */
    GET_CONFIG(st);
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
test_cancel(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data;

    /* prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* send cancel-commit rpc, should fail as there is no commit */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* check if received an error reply */
    ASSERT_RPC_ERROR(st);
    FREE_TEST_VARS(st);

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

    /* running should now be same as candidate */
    GET_CONFIG(st);
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

    /* running should now be back how it was */
    GET_CONFIG(st);
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
test_confirm_persist(void **state)
{
    struct np_test *st = *state;
    const char *expected, *persist = "test-persist-1";

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with persist */
    st->rpc = nc_rpc_commit(1, 0, persist, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG(st);
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

    /* Data should remain unchanged */
    GET_CONFIG(st);
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_cancel_persist(void **state)
{
    struct np_test *st = *state;
    const char *expected, *persist = "test-persist-2";

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with persist */
    st->rpc = nc_rpc_commit(1, 0, persist, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Running should now be same as candidate */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Send cancel-commit rpc on a different session */
    st->rpc = nc_rpc_cancel(persist, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY_SESS2(st);
    FREE_TEST_VARS(st);

    /* Running should now be empty */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_wrong_persist_id(void **state)
{
    struct np_test *st = *state;
    const char *persist = "test-persist-3";

    /* Send a confirmed-commit rpc with unknown persist-id */
    st->rpc = nc_rpc_commit(0, 0, NULL, persist, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an error */
    ASSERT_RPC_ERROR(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    FREE_TEST_VARS(st);
}

static int
setup_test_failed_file(void **state)
{
    struct np_test *st = *state;
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
    struct np_test *st = *state;
    struct dirent *file = NULL;
    int found = 0;
    DIR *dir = NULL;

    /* Prior to the test running should be empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Send a confirmed-commit rpc with 1s timeout */
    st->rpc = nc_rpc_commit(1, 1, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* Check if received an OK reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Wait for the duration of the timeout */
    sleep(2);

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
    struct np_test *st = *state;
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
    if (np_is_nacm_recovery()) {
        puts("Running as NACM_RECOVERY_USER. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic),
        cmocka_unit_test_setup_teardown(test_sameas_commit, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_runout, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_confirm, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_timeout_confirm_modify, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_cancel, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_confirm_persist, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_cancel_persist, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_wrong_persist_id, setup_common, teardown_common),
        cmocka_unit_test_setup_teardown(test_failed_file, setup_test_failed_file, teardown_test_failed_file),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
