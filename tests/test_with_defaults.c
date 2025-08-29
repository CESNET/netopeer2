/**
 * @file test_with_defaults.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for with-defaults arguement
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
    const char *modules[] = {NP_TEST_MODULE_DIR "/defaults1.yang", NULL};
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, NULL, 0);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"defaults1", NULL};

    if (!*state) {
        return 0;
    }

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

static void
test_all_nothing_set(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    /* Send RPC  trying to get all including default values */
    st->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, "/defaults1:*", NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Get reply, should succeed */
    ASSERT_DATA_REPLY(st);
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
    struct np2_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_data_all(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><name>Alt</name><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_data_all_default(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\"><name>Test</name><num>1</num></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static int
teardown_data(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    data = "<top xmlns=\"def1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></top>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);

    return 0;
}

static void
test_all_non_default_set(void **state)
{
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_ALL, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_ALL_TAG, "/defaults1:*");

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"def1\">\n"
            "      <name xmlns:dflt=\"urn:ietf:params:xml:ns:netconf:default:1.0\" dflt:default=\"true\">Test</name>\n"
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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_TRIM, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_TRIM, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_ALL, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_ALL_TAG, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_TRIM, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_EXPLICIT, "/defaults1:*");

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
    struct np2_test *st = *state;
    const char *expected;

    GET_CONFIG_DS_WD_FILTER(st, NC_DATASTORE_RUNNING, NC_WD_EXPLICIT, "/defaults1:*");

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

    if (np2_is_nacm_recovery()) {
        puts("Running as NACM_RECOVERY_USER. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
