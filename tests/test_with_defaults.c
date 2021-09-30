/**
 * @file test_with_defaults.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for with-defaults arguement
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
    char test_name[256];
    const char *module1 = NP_TEST_MODULE_DIR "/defaults1.yang";
    int rv;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state, test_name))) {
        /* state is allocated in np_glob_setup_np2 have to set here */
        st = *state;
        /* Open connection to start a session for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));
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

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "defaults1"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_all_nothing_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Send RPC  trying to get all including default values */
    st->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);

    /* Get reply, should succeed */
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->op);
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(lyd_child(st->op)), "data");
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->op, LYD_XML, 0));

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Test</name>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static int
setup_data_num(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_data_all(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><name>Alt</name><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_data_all_default(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><name>Test</name><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_data(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static void
test_all_non_default_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_ALL);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Test</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_all_tag_non_default_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_ALL_TAG);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name xmlns:ncwd=\"urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults\""
            " ncwd:default=\"true\">Test</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_trim_non_default_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_TRIM);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_explicit_non_default_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_TRIM);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_all_set_all(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_ALL);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Alt</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_all_tag_set_all(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_ALL_TAG);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Alt</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_trim_set_all(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_TRIM);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Alt</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_explicit_all_set(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_EXPLICIT);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Alt</name>\n"
            "      <num>1</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_explicit_all_set_default(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG_WD(st, NC_WD_EXPLICIT);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name>Test</name>\n"
            "      <num>1</num>\n"
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
        cmocka_unit_test(test_all_nothing_set),
        cmocka_unit_test_setup_teardown(test_all_non_default_set, setup_data_num, teardown_data),
        cmocka_unit_test_setup_teardown(test_all_tag_non_default_set, setup_data_num, teardown_data),
        cmocka_unit_test_setup_teardown(test_trim_non_default_set, setup_data_num, teardown_data),
        cmocka_unit_test_setup_teardown(test_explicit_non_default_set, setup_data_num, teardown_data),
        cmocka_unit_test_setup_teardown(test_all_set_all, setup_data_all, teardown_data),
        cmocka_unit_test_setup_teardown(test_all_tag_set_all, setup_data_all, teardown_data),
        cmocka_unit_test_setup_teardown(test_trim_set_all, setup_data_all, teardown_data),
        cmocka_unit_test_setup_teardown(test_explicit_all_set, setup_data_all, teardown_data),
        cmocka_unit_test_setup_teardown(test_all_non_default_set, setup_data_all_default, teardown_data),
        cmocka_unit_test_setup_teardown(test_all_tag_non_default_set, setup_data_all_default, teardown_data),
        cmocka_unit_test_setup_teardown(test_trim_non_default_set, setup_data_all_default, teardown_data),
        cmocka_unit_test_setup_teardown(test_explicit_all_set_default, setup_data_all_default, teardown_data),
    };

    if (is_nacm_rec_uid()) {
        puts("Running as NACM_RECOVERY_UID. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
