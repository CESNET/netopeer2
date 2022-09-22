/**
 * @file test_nacm.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for NETCONF Access Control Management
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
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>
#include <sysrepo/netconf_acm.h>

#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    struct np_test *st;
    char test_name[256];
    const char *modules[] = {
        NP_TEST_MODULE_DIR "/edit1.yang", NP_TEST_MODULE_DIR "/example2.yang",
        NP_TEST_MODULE_DIR "/nacm-test1.yang", NP_TEST_MODULE_DIR "/nacm-test2.yang", NULL
    };
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules);
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
    const char *modules[] = {"edit1", "example2", "nacm-test1", "nacm-test2", NULL};

    if (!st) {
        return 0;
    }

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state, modules);
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"></first>\n"
            "<top xmlns=\"ex2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"></top>\n"
            "<top xmlns=\"urn:nt1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"></top>\n"
            "<people xmlns=\"urn:nt2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"><name>John</name></people>\n"
            "<people xmlns=\"urn:nt2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"><name>Thomas</name></people>\n"
            "<people xmlns=\"urn:nt2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"><name>Arnold</name></people>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\" "
            "xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <read-default xc:operation=\"remove\">deny</read-default>\n"
            "  <rule-list  xc:operation=\"remove\">\n"
            "    <name>rule1</name>\n"
            "  </rule-list>\n"
            "</nacm>";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"></first>\n"
            "<top xmlns=\"urn:nt1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" "
            "xc:operation=\"remove\"></top>\n";
    /* Remove from candidate as well */
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);
    return 0;
}

static int
setup_test_exec_get(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>permit</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-get</name>\n"
            "       <module-name>ietf-netconf</module-name>\n"
            "       <rpc-name>get</rpc-name>\n"
            "       <access-operations>exec</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>disallow-get-config</name>\n"
            "       <module-name>ietf-netconf</module-name>\n"
            "       <rpc-name>get-config</rpc-name>\n"
            "       <access-operations>exec</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_exec_get(void **state)
{
    struct np_test *st = *state;

    /* get and get-config bypass execution permissions */
    GET_FILTER(st, NULL);
    assert_non_null(st->str);
    FREE_TEST_VARS(st);

    GET_CONFIG(st);
    assert_non_null(st->str);
    FREE_TEST_VARS(st);
}

static int
setup_test_read_default(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_read_default(void **state)
{
    struct np_test *st = *state;
    const char *expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get>\n";

    GET_FILTER(st, NULL);
    /* Since <read-default> is set to deny it should return empty data */
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_read_default_allow_path(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\">TestFirst</first>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>allow-first</name>\n"
            "      <module-name>edit1</module-name>\n"
            "      <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_read_default_allow_path(void **state)
{
    struct np_test *st = *state;
    const char *expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get>\n";

    /* Since there is an expeption for the <first> element it should be returned */
    GET_FILTER(st, NULL);
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_get_config(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\">TestFirst</first>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>read</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_get_config(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Since reading of this node is denied it should return empty config */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_get_config_filter(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Using a filter on a denied node should not cause access denied error */
    GET_CONFIG_FILTER(st, "/edit1:first[.='TestFirst']");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_xpath_filter_denied(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>John</name>\n"
            "  <weight>75</weight>\n"
            "</people>\n"
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>Thomas</name>\n"
            "  <weight>100</weight>\n"
            "</people>\n"
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>Arnold</name>\n"
            "  <weight>110</weight>\n"
            "</people>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>disallow-num</name>\n"
            "      <module-name>nacm-test2</module-name>\n"
            "      <path xmlns:nt2=\"urn:nt2\">/nt2:people/nt2:weight</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>deny</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_xpath_filter_denied(void **state)
{
    /* Issue #846 */
    struct np_test *st = *state;
    const char *expected, *filter = "/people[weight>100]";

    GET_CONFIG_FILTER(st, filter);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <people xmlns=\"urn:nt2\">\n"
            "      <name>Arnold</name>\n"
            "    </people>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_filter_key_list(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>John</name>\n"
            "  <weight>75</weight>\n"
            "</people>\n"
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>Thomas</name>\n"
            "  <weight>100</weight>\n"
            "</people>\n"
            "<people xmlns=\"urn:nt2\">\n"
            "  <name>Arnold</name>\n"
            "  <weight>110</weight>\n"
            "</people>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>test-group</group>\n"
            "    <rule>\n"
            "      <name>disallow-num-arnold</name>\n"
            "      <module-name>nacm-test2</module-name>\n"
            "      <path xmlns:nt2=\"urn:nt2\">/nt2:people[nt2:name='Arnold']/nt2:weight</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>deny</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_filter_key_list(void **state)
{
    /* Issue #755 */
    struct np_test *st = *state;
    const char *expected;

    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <people xmlns=\"urn:nt2\">\n"
            "      <name>John</name>\n"
            "      <weight>75</weight>\n"
            "    </people>\n"
            "    <people xmlns=\"urn:nt2\">\n"
            "      <name>Thomas</name>\n"
            "      <weight>100</weight>\n"
            "    </people>\n"
            "    <people xmlns=\"urn:nt2\">\n"
            "      <name>Arnold</name>\n"
            "    </people>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_rule_wildcard_groups(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\">TestFirst</first>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <read-default>deny</read-default>\n"
            "  <rule-list>\n"
            "    <name>rule1</name>\n"
            "    <group>*</group>\n"
            "    <rule>\n"
            "      <name>allow-first</name>\n"
            "      <module-name>edit1</module-name>\n"
            "      <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "      <access-operations>read</access-operations>\n"
            "      <action>permit</action>\n"
            "    </rule>\n"
            "  </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_rule_wildcard_groups(void **state)
{
    /* Issue #619 */
    struct np_test *st = *state;
    const char *expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get>\n";

    /* Since there is an expeption for the <first> element using wildcard for groups it should be returned */
    GET_FILTER(st, NULL);
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_edit_config(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>deny</write-default>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;

}

static int
teardown_edit_config(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>permit</write-default>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;

}

static void
test_edit_config(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\">TestFirst</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);
}

static int
setup_test_edit_config_permit(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\">TestFirst</first>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>deny</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>create</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_edit_config_permit(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\">TestFirst</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_edit_config_update(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>deny</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>update</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_edit_config_update(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data = "<first xmlns=\"ed1\">Test</first>\n";

    /* Creating is not permited */
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    /* Merge the data bypassing NACM */
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Updating an existing node is permited */
    data = "<first xmlns=\"ed1\">Alt</first>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

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

static int
setup_test_edit_config_subtree(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>0.0.0.0</name>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-examle2-name</name>\n"
            "       <module-name>example2</module-name>\n"
            "       <path xmlns:ex2=\"ex2\">"
            "/ex2:top/ex2:protocols/ex2:ospf/ex2:area/ex2:interfaces/ex2:interface</path>\n"
            "       <access-operations>create</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>allow-examle2-remove</name>\n"
            "       <module-name>example2</module-name>\n"
            "       <path xmlns:ex2=\"ex2\">"
            "/ex2:top/ex2:protocols/ex2:ospf/ex2:area</path>\n"
            "       <access-operations>delete</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_edit_config_subtree(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>0.0.0.0</name>\n"
            "        <interfaces>\n"
            "          <interface>\n"
            "            <name>192.0.2.4</name>\n"
            "          </interface>\n"
            "        </interfaces>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    /* Adding another interface should succeed */
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>192.168.0.0</name>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    /* Adding another area should fail */
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area xmlns:pref=\"urn:ietf:params:xml:ns:netconf:base:1.0\" pref:operation=\"remove\">\n"
            "        <name>0.0.0.0</name>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    /* removing area should succeed */
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_edit_config_when(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"urn:nt1\">\n"
            "  <name>Test</name>\n"
            "  <num>12</num>\n"
            "</top>\n"
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-nt1-name</name>\n"
            "       <module-name>nacm-test1</module-name>\n"
            "       <path xmlns:nt1=\"urn:nt1\">/nt1:top/nt1:name</path>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>disallow-nt1-num</name>\n"
            "       <module-name>nacm-test1</module-name>\n"
            "       <path xmlns:nt1=\"urn:nt1\">/nt1:top/nt1:num</path>\n"
            "       <access-operations>delete</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_edit_config_when(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"urn:nt1\">\n"
            "  <num xmlns:p=\"urn:ietf:params:xml:ns:netconf:base:1.0\" p:operation=\"remove\"/>\n"
            "</top>\n";

    /* Removing the num should fail */
    SEND_EDIT_RPC(st, data);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"urn:nt1\">\n"
            "  <name xmlns:p=\"urn:ietf:params:xml:ns:netconf:base:1.0\" p:operation=\"remove\"/>\n"
            "</top>\n";

    /* Removing the name should also remove the num since it is under when-stmt */
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    GET_CONFIG(st);
    expected = "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n  <data/>\n</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_copy_config_running2startup(void **state)
{
    struct np_test *st = *state;

    /* From running to startup only needs execute on copy-config */
    st->rpc = nc_rpc_copy(NC_DATASTORE_STARTUP, NULL, NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_copy_config_ds2ds_fail_read(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>deny</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-read-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>read</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data = "<first xmlns=\"ed1\">TestFirst</first>\n";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    return 0;
}

static int
setup_test_copy_config_ds2ds_fail_write(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>deny</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-read-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>read</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data = "<first xmlns=\"ed1\">TestFirst</first>\n";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);

    return 0;
}

static void
test_copy_config_ds2ds_fail_read(void **state)
{
    struct np_test *st = *state;

    st->rpc = nc_rpc_copy(NC_DATASTORE_RUNNING, NULL, NC_DATASTORE_CANDIDATE, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);
}

static void
test_copy_config_ds2ds_fail_write(void **state)
{
    test_copy_config_ds2ds_fail_read(state);
}

static void
test_delete_config(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Should be disabled by default */
    st->rpc = nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <write-default>permit</write-default>\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-delete</name>\n"
            "       <module-name>ietf-netconf</module-name>\n"
            "       <rpc-name>delete-config</rpc-name>\n"
            "       <access-operations>exec</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>allow-delete-all</name>\n"
            "       <module-name>*</module-name>\n"
            "       <access-operations>delete</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Should succeed now */
    st->rpc = nc_rpc_delete(NC_DATASTORE_STARTUP, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_commit(void **state)
{
    struct np_test *st = *state;
    char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-name</name>\n"
            "       <module-name>nacm-test1</module-name>\n"
            "       <path xmlns:nt1=\"urn:nt1\">/nt1:top/nt1:name</path>\n"
            "       <access-operations>create</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>allow-num</name>\n"
            "       <path xmlns:nt1=\"urn:nt1\">/nt1:top/nt1:num</path>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st)

    /* Merge into candidate */
    data =
            "<top xmlns=\"urn:nt1\">\n"
            "  <name>Test</name>\n"
            "  <num>12</num>\n"
            "</top>";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_commit(void **state)
{
    struct np_test *st = *state;
    const char *data, *expected;

    /* Should fail since candidate has element that is denied to merge */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    /* Merge the missing element into running */
    data =
            "<top xmlns=\"urn:nt1\">\n"
            "  <name>Test</name>\n"
            "</top>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Should succeed now */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"urn:nt1\">\n"
            "      <name>Test</name>\n"
            "      <num>12</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_discard_changes(void **state)
{
    struct np_test *st = *state;
    char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>disallow-first</name>\n"
            "       <module-name>edit1</module-name>\n"
            "       <path xmlns:ed1=\"ed1\">/ed1:first</path>\n"
            "       <access-operations>delete</access-operations>\n"
            "       <action>deny</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st)

    /* Merge into candidate */
    data = "<first xmlns=\"ed1\">Test</first>";
    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_discard_changes(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    /* Should succeed despite not having rights over the datastore nodes */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    GET_CONFIG_DS_FILTER(st, NC_DATASTORE_CANDIDATE, NULL);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_kill_session(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Should fail since the rpc is disallowed */
    st->rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess2));
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);

    data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-delete</name>\n"
            "       <module-name>ietf-netconf</module-name>\n"
            "       <rpc-name>kill-session</rpc-name>\n"
            "       <access-operations>exec</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Should succeed now */
    st->rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess2));
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_OK_REPLY(st);
}

int
main(int argc, char **argv)
{
    if (np_is_nacm_recovery()) {
        puts("Running as NACM_RECOVERY_USER. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);

    if (sr_get_su_uid() != getuid()) {
        /* not sysrepo super user skip write tests */
        puts("Not running as sysrepo super-user. Skipping tests that depend on it.");
        const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_exec_get,
                    setup_test_exec_get,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_read_default,
                    setup_test_read_default,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_read_default_allow_path,
                    setup_test_read_default_allow_path,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_get_config,
                    setup_test_get_config,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_get_config_filter,
                    setup_test_get_config,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_xpath_filter_denied,
                    setup_test_xpath_filter_denied,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_filter_key_list,
                    setup_test_filter_key_list,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_rule_wildcard_groups,
                    setup_test_rule_wildcard_groups,
                    teardown_common),
        };

        return cmocka_run_group_tests(tests, local_setup, local_teardown);
    } else {
        /* sysrepo super run with write tests */
        const struct CMUnitTest tests[] = {
            cmocka_unit_test_setup_teardown(test_exec_get,
                    setup_test_exec_get,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_read_default,
                    setup_test_read_default,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_read_default_allow_path,
                    setup_test_read_default_allow_path,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_get_config,
                    setup_test_get_config,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_get_config_filter,
                    setup_test_get_config,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_xpath_filter_denied,
                    setup_test_xpath_filter_denied,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_filter_key_list,
                    setup_test_filter_key_list,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_rule_wildcard_groups,
                    setup_test_rule_wildcard_groups,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_edit_config,
                    setup_edit_config,
                    teardown_edit_config),
            cmocka_unit_test_setup_teardown(test_edit_config_permit,
                    setup_test_edit_config_permit,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_edit_config_update,
                    setup_test_edit_config_update,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_edit_config_subtree,
                    setup_test_edit_config_subtree,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_edit_config_when,
                    setup_test_edit_config_when,
                    teardown_common),
            cmocka_unit_test(test_copy_config_running2startup),
            cmocka_unit_test_setup_teardown(test_copy_config_ds2ds_fail_read,
                    setup_test_copy_config_ds2ds_fail_read,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_copy_config_ds2ds_fail_write,
                    setup_test_copy_config_ds2ds_fail_write,
                    teardown_common),
            cmocka_unit_test_teardown(test_delete_config,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_commit,
                    setup_test_commit,
                    teardown_common),
            cmocka_unit_test_setup_teardown(test_discard_changes,
                    setup_test_discard_changes,
                    teardown_common),
            cmocka_unit_test_teardown(test_kill_session,
                    teardown_common),
        };

        return cmocka_run_group_tests(tests, local_setup, local_teardown);
    }
}
