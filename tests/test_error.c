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
    const char *modules[] = {NP_TEST_MODULE_DIR "/errors.yang", NULL};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules);
    assert_int_equal(rc, 0);

    /* setup NACM */
    rc = setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"errors", NULL};

    /* close netopeer2 server */
    if (*state) {
        return np_glob_teardown(state, modules);
    }

    return 0;
}

/* RFC 7950 sec.15.1 */
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
    ASSERT_ERROR_REPLY(st);
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

/* RFC 7950 sec.15.2 */
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
    ASSERT_ERROR_REPLY(st);
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

/* RFC 7950 sec.15.3 */
static void
test_min_elem(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a single leaf-list instance violating the min-elements constraint */
    data = "<cont2 xmlns=\"urn:errors\"><l3>value</l3></cont2>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
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

/* RFC 7950 sec.15.4 */
static void
test_must(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a leaf violating the must constraint */
    data = "<l4 xmlns=\"urn:errors\">val</l4>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>must-violation</error-app-tag>\n"
            "  <error-path>/errors:l4</error-path>\n"
            "  <error-message xml:lang=\"en\">Must condition \"/cont/l/k = 'key'\" not satisfied.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 7950 sec.15.5 */
static void
test_require_instance(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a leafref without its target */
    data = "<l5 xmlns=\"urn:errors\">val</l5>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-missing</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>instance-required</error-app-tag>\n"
            "  <error-path>/errors:l5</error-path>\n"
            "  <error-message xml:lang=\"en\">Required leafref target with value \"val\" missing.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);

    /* create a non-existing instance-identifier */
    data = "<l6 xmlns=\"urn:errors\" xmlns:e=\"urn:errors\">/e:target</l6>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-missing</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>instance-required</error-app-tag>\n"
            "  <error-path>/errors:l6</error-path>\n"
            "  <error-message xml:lang=\"en\">Required instance-identifier \"/errors:target\" missing.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 7950 sec.15.6 */
static void
test_mandatory_choice(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a container without its mandatory choice */
    data = "<cont3 xmlns=\"urn:errors\"/>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-missing</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>mandatory-choice</error-app-tag>\n"
            "  <error-path>/errors:cont3</error-path>\n"
            "  <error-message xml:lang=\"en\">Missing mandatory choice.</error-message>\n"
            "  <error-info>\n"
            "    <missing-choice xmlns=\"urn:ietf:params:xml:ns:yang:1\">/errors:cont3/ch</missing-choice>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 7950 sec.15.7 */
static void
test_invalid_insert(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* use non-existing list instance as insert anchor */
    data = "<l9 xmlns=\"urn:errors\" xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "yang:insert=\"after\" yang:key=\"[k='first']\"><k>key</k></l9>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-attribute</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>missing-instance</error-app-tag>\n"
            "  <error-message xml:lang=\"en\">Missing insert anchor \"l9\" instance.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);

    /* use non-existing leaf-list instance as insert anchor */
    data = "<l10 xmlns=\"urn:errors\" xmlns:yang=\"urn:ietf:params:xml:ns:yang:1\" "
            "yang:insert=\"before\" yang:value=\"first\"/>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-attribute</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-app-tag>missing-instance</error-app-tag>\n"
            "  <error-message xml:lang=\"en\">Missing insert anchor \"l10\" instance.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 sec.7.2 Attributes:operation:create */
static void
test_create_exists(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create a list instance */
    data = "<cont xmlns=\"urn:errors\"><l><k>key_created</k></l></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* try to create another list instance */
    data = "<cont xmlns=\"urn:errors\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<l nc:operation=\"create\"><k>key_created</k></l></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-exists</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Node \"l\" to be created already exists.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 sec.7.2 Attributes:operation:delete */
static void
test_delete_missing(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* try to delete a non-existing list instance */
    data = "<cont xmlns=\"urn:errors\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<l nc:operation=\"delete\"><k>key_deleted</k></l></cont>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-missing</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Node \"l\" to be deleted does not exist.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 sec.7.2 Parameters:default-operation:none */
static void
test_none_missing(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* use none operation for a non-existing node */
    data = "<cont xmlns=\"urn:errors\"><l><k>key_none</k></l></cont>";
    SEND_EDIT_RPC_PARAM(st, NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_NONE, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>data-missing</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Node \"l\" does not exist.</error-message>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 Appendix A bad-element */
static void
test_bad_element(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* wrong type */
    data = "<num xmlns=\"urn:errors\">string</num>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Invalid type uint32 value \"string\".</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>/errors:num</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);

    /* out of range */
    data = "<num xmlns=\"urn:errors\">5</num>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Unsatisfied range - value \"5\" is out of the allowed range.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>/errors:num</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);

    /* unsatisfied pattern */
    data = "<str xmlns=\"urn:errors\">bb</str>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Unsatisfied pattern - \"bb\" does not conform to \"a*\".</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>/errors:str</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 Appendix A unknown-element */
static void
test_unknown_element(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* unknown element */
    data = "<numero xmlns=\"urn:errors\">string</numero>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>unknown-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Node \"numero\" not found in the \"errors\" module.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>numero</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

/* RFC 6241 Appendix A unknown-namespace */
static void
test_unknown_namespace(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* unknown namespace */
    data = "<numero xmlns=\"urn:errs\">string</numero>";
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>unknown-namespace</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">An unexpected namespace is present.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>numero</bad-element>\n"
            "    <bad-namespace>urn:errs</bad-namespace>\n"
            "  </error-info>\n"
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
        cmocka_unit_test(test_must),
        cmocka_unit_test(test_require_instance),
        cmocka_unit_test(test_mandatory_choice),
        cmocka_unit_test(test_invalid_insert),
        cmocka_unit_test(test_create_exists),
        cmocka_unit_test(test_delete_missing),
        cmocka_unit_test(test_none_missing),
        cmocka_unit_test(test_bad_element),
        cmocka_unit_test(test_unknown_element),
        cmocka_unit_test(test_unknown_namespace),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
