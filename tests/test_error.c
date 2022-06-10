/**
 * @file test_error.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test errors from the specification
 *
 * @copyright
 * Copyright (c) 2022 Deutsche Telekom AG.
 * Copyright (c) 2022 CESNET, z.s.p.o.
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

#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/errors.yang"};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules, sizeof modules / sizeof *modules);
    assert_int_equal(rc, 0);

    /* setup NACM */
    rc = setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"errors"};

    /* close netopeer2 server */
    if (*state) {
        return np_glob_teardown(state, modules, sizeof modules / sizeof *modules);
    }

    return 0;
}

static void
test_unique(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a list instance */
    data = "<cont xmlns=\"urn:errors\"><l><k>key1</k><u>uniq</u></l></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* create another list instance violating the unique constraint */
    data = "<cont xmlns=\"urn:errors\"><l><k>key2</k><u>uniq</u></l></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>data-not-unique</error-app-tag>\n"
            "  <error-message xml:lang=\"en\">Unique constraint violated.</error-message>\n"
            "  <error-info>\n"
            "    <non-unique xmlns=\"urn:ietf:params:xml:ns:yang:1\">/errors:cont/l[k='key2']</non-unique>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

static void
test_max_elem(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a list instance */
    data = "<cont xmlns=\"urn:errors\"><l2><k>key1</k></l2></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* create 2 more list instances violating the max-elements constraint */
    data = "<cont xmlns=\"urn:errors\"><l2><k>key2</k></l2><l2><k>key3</k></l2></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>too-many-elements</error-app-tag>\n"
            "  <error-path>/errors:cont/l2[k='key3']</error-path>\n"
            "  <error-message xml:lang=\"en\">Too many elements.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

static void
test_min_elem(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a single leaf-list instance violating the min-elements constraint */
    data = "<cont2 xmlns=\"urn:errors\"><l3>value</l3></cont2>";
    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>too-few-elements</error-app-tag>\n"
            "  <error-path>/errors:cont2/l3</error-path>\n"
            "  <error-message xml:lang=\"en\">Too few elements.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_unique),
        cmocka_unit_test(test_max_elem),
        cmocka_unit_test(test_min_elem),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
