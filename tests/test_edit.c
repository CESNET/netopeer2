/**
 * @file test_edit.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for the edit-config rpc
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
#include <sysrepo.h>
#include "np_test.h"
#include "np_test_config.h"

static int
local_setup(void **state)
{
    struct np_test *st;
    sr_conn_ctx_t *conn;
    char test_name[256];
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/edit2.yang";
    const char *module3 = NP_TEST_MODULE_DIR "/edit3.yang";
    const char *module4 = NP_TEST_MODULE_DIR "/edit4.yang";
    const char *module5 = NP_TEST_MODULE_DIR "/example1.yang";
    const char *module6 = NP_TEST_MODULE_DIR "/example2.yang";
    int rv;

    /* get test name */
    NP_GLOB_SETUP_TEST_NAME(test_name);

    /* Setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    /* Connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module3, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module4, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module5, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module6, NULL, NULL), SR_ERR_OK);
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
    assert_int_equal(sr_remove_module(conn, "edit2"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit3"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit4"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "example1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "example2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Close netopeer2 server */
    return np_glob_teardown(state);
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>\n"
            "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>\n"
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>\n"
            "<top xmlns=\"ex1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>\n"
            "<top xmlns=\"ex2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"/>\n"
            "<top xmlns=\"ed4\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"/>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_merge_edit1(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send RPC editing module edit1 */
    data = "<first xmlns=\"ed1\">TestFirst</first>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if added to config */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestFirst"));
    FREE_TEST_VARS(st);
}

static void
test_merge_edit2(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send RPC editing module edit2 */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "  <num>123</num>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if added to config */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestSecond"));
    FREE_TEST_VARS(st);
}

static void
test_merge_edit2_fail(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send invalid RPC editing module edit2 */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "  <num>ClearlyNotANumericValue</num>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_delete_edit1(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\">TestFirst</first>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_delete_edit1(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send rpc deleting config in module edit1 */
    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"/>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if the config was deleted */
    ASSERT_EMPTY_CONFIG(st);
}

static int
setup_test_delete_edit2(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send RPC editing module edit2 */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "  <num>123</num>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_delete_edit2(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send rpc deleting config in module edit2 */
    data = "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"/>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if the config was deleted */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_delete_empty(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Try deleting a non-existent config, should fail */
    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"/>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    FREE_TEST_VARS(st);
}

static void
test_merge_patrial(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "</top>\n";

    /* Merge a partial config */
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if merged successfully */
    GET_CONFIG(st);
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

static int
setup_test_merge_into_existing(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_merge_into_existing(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ed2\">\n"
            "  <num>123</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if correctly merged */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed2\">\n"
            "      <name>TestSecond</name>\n"
            "      <num>123</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_merge_overwrite(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ed2\">\n"
            "  <name>TestSecond</name>\n"
            "  <num>123</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_merge_overwrite(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ed2\">\n"
            "  <num>456</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if config was correctly overwritten */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed2\">\n"
            "      <name>TestSecond</name>\n"
            "      <num>456</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_replace(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">\n"
            "  <name>TestThird</name>\n"
            "  <num>123</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_replace(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">\n"
            "  <name>TestThird</name>\n"
            "  <num>456</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if replaced correctly */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed3\">\n"
            "      <name>TestThird</name>\n"
            "      <num>456</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_replace_create(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">\n"
            "  <name>TestThird</name>\n"
            "  <num>456</num>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if created correctly */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ed3\">\n"
            "      <name>TestThird</name>\n"
            "      <num>456</num>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_create(void **state)
{
    struct np_test *st = *state;
    const char *expected, *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"create\">"
            "TestFourth"
            "</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if config config now contains edit1 */
    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFourth</first>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_create_fail(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"create\">"
            "TestFourth"
            "</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_create_fail(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"create\">"
            "TestFourth"
            "</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_RPC_ERROR(st);
    FREE_TEST_VARS(st);
}

static int
setup_test_remove(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\">TestFirst</first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_remove(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_remove_empty(void **state)
{
    struct np_test *st = *state;
    const char *data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></first>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    ASSERT_EMPTY_CONFIG(st);
}

static int
setup_test_ex1(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<top xmlns=\"ex1\">\n"
            "  <interface>\n"
            "    <name>Ethernet0/0</name>\n"
            "    <mtu>1500</mtu>\n"
            "  </interface>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_ex1(void **state)
{
    /* First example for edit-config from rfc 6241 section 7.2 */
    struct np_test *st = *state;
    const char *expected, *data;

    data =
            "<top xmlns=\"ex1\">\n"
            "  <interface operation=\"replace\"\n>\n"
            "    <name>Ethernet0/0</name>\n"
            "    <mtu>1500</mtu>\n"
            "    <address>\n"
            "      <name>192.0.2.4</name>\n"
            "      <prefix-length>24</prefix-length>\n"
            "    </address>\n"
            "  </interface>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex1\">\n"
            "      <interface>\n"
            "        <name>Ethernet0/0</name>\n"
            "        <mtu>1500</mtu>\n"
            "        <address>\n"
            "          <name>192.0.2.4</name>\n"
            "          <prefix-length>24</prefix-length>\n"
            "        </address>\n"
            "      </interface>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static int
setup_test_ex2(void **state)
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
            "            <name>192.0.2.1</name>\n"
            "          </interface>\n"
            "          <interface>\n"
            "            <name>192.0.2.4</name>\n"
            "          </interface>\n"
            "        </interfaces>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_ex2(void **state)
{
    /* Second example for edit-config from rfc 6241 section 7.2 */
    struct np_test *st = *state;
    const char *expected, *data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>0.0.0.0</name>\n"
            "        <interfaces xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "          <interface xc:operation=\"delete\">\n"
            "            <name>192.0.2.4</name>\n"
            "          </interface>\n"
            "        </interfaces>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    GET_CONFIG(st);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_autodel_case(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* create case #1 */
    data =
            "<top xmlns=\"ed4\">\n"
            "  <l1>value</l1>\n"
            "  <l2/>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* check data */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "l1"));
    assert_non_null(strstr(st->str, "l2"));
    FREE_TEST_VARS(st);

    /* create case #2 */
    data =
            "<top xmlns=\"ed4\">\n"
            "  <c2>58</c2>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* check data */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "l1"));
    assert_null(strstr(st->str, "l2"));
    assert_non_null(strstr(st->str, "c2"));
    FREE_TEST_VARS(st);

    /* create case #3 */
    data =
            "<top xmlns=\"ed4\">\n"
            "  <cont>\n"
            "    <l3>-256</l3>\n"
            "  </cont>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* check data */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "c2"));
    assert_non_null(strstr(st->str, "l3"));
    FREE_TEST_VARS(st);

    /* create case #4 */
    data =
            "<top xmlns=\"ed4\">\n"
            "  <l4>a</l4>\n"
            "  <l5>b</l5>\n"
            "</top>\n";
    SEND_EDIT_RPC(st, data);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* check data */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "l3"));
    assert_non_null(strstr(st->str, "l4"));
    assert_non_null(strstr(st->str, "l5"));
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_merge_edit1, teardown_common),
        cmocka_unit_test_teardown(test_merge_edit2, teardown_common),
        cmocka_unit_test_teardown(test_merge_edit2_fail, teardown_common),
        cmocka_unit_test_setup(test_delete_edit1, setup_test_delete_edit1),
        cmocka_unit_test_setup(test_delete_edit2, setup_test_delete_edit2),
        cmocka_unit_test(test_delete_empty),
        cmocka_unit_test_teardown(test_merge_patrial, teardown_common),
        cmocka_unit_test_setup_teardown(test_merge_into_existing, setup_test_merge_into_existing, teardown_common),
        cmocka_unit_test_setup_teardown(test_merge_overwrite, setup_test_merge_overwrite, teardown_common),
        cmocka_unit_test_setup_teardown(test_replace, setup_test_replace, teardown_common),
        cmocka_unit_test_teardown(test_replace_create, teardown_common),
        cmocka_unit_test_teardown(test_create, teardown_common),
        cmocka_unit_test_setup_teardown(test_create_fail, setup_test_create_fail, teardown_common),
        cmocka_unit_test_setup(test_remove, setup_test_remove),
        cmocka_unit_test(test_remove_empty),
        cmocka_unit_test_setup_teardown(test_ex1, setup_test_ex1, teardown_common),
        cmocka_unit_test_setup_teardown(test_ex2, setup_test_ex2, teardown_common),
        cmocka_unit_test_teardown(test_autodel_case, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
