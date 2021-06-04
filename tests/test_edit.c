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
    sr_conn_ctx_t *conn;
    const char *features[] = {NULL};
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/edit2.yang";
    const char *module3 = NP_TEST_MODULE_DIR "/edit3.yang";
    const char *module4 = NP_TEST_MODULE_DIR "/example1.yang";
    const char *module5 = NP_TEST_MODULE_DIR "/example2.yang";

    /* setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module3, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module4, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module5, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    return np_glob_setup_np2(state);
}

static int
local_teardown(void **state)
{
    sr_conn_ctx_t *conn;

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit2"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit3"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "example1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "example2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_merge(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\">TestFirst</first>";
    /* Send rpc editing module edit1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if added to config */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestFirst"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "  <num>123</num>"
            "</top>";

    /* Send rpc editing module edit2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if added to config */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestSecond"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "  <num>ClearlyNotANumericValue</num>"
            "</top>";

    /* Send invalid rpc editing module edit2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should fail */
    ASSERT_RPC_ERROR(st);

    FREE_TEST_VARS(st);
}

static void
test_delete(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></first>";

    /* Check if the config for both is present */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestFirst"));
    assert_non_null(strstr(st->str, "TestSecond"));
    FREE_TEST_VARS(st);

    /* Send rpc deleting config in module edit1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should suceed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if the config was deleted */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "TestFirst"));
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></top>";

    /* Send rpc deleting config in module edit2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if the config was deleted */
    ASSERT_EMPTY_CONFIG(st);

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></first>";

    /* Try deleting a non-existent config */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should fail */
    ASSERT_RPC_ERROR(st);

    FREE_TEST_VARS(st);
}

static void
test_merge_advanced(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Check if config empty */
    ASSERT_EMPTY_CONFIG(st);

    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "</top>";

    /* Merge a partial config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if merged*/
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestSecond"));
    assert_null(strstr(st->str, "123"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ed2\">"
            "  <name>TestSecond</name>"
            "  <num>123</num>"
            "</top>";

    /* Merge a full config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if merged */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestSecond"));
    assert_non_null(strstr(st->str, "123"));
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></top>";

    /* Empty the config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config empty */
    ASSERT_EMPTY_CONFIG(st);

    data =
            "<top xmlns=\"ed3\">"
            "  <name>TestThird</name>"
            "  <num>123</num>"
            "</top>";

    /* Send rpc to merge into edit3 config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if merged */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestThird"));
    assert_non_null(strstr(st->str, "123"));
    assert_null(strstr(st->str, "456"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ed3\">"
            "  <name>TestThird</name>"
            "  <num>456</num>"
            "</top>";

    /* Send rpc to merge alternate edit3 config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if merged, should now contain both since merging a leaf-list */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestThird"));
    assert_non_null(strstr(st->str, "123"));
    assert_non_null(strstr(st->str, "456"));
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></top>";

    /* Empty the config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config empty */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_replace(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">"
            "  <name>TestThird</name>"
            "  <num>123</num>"
            "</top>";

    /* Send rpc to replace in an empty config, should create */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if correct config */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestThird"));
    assert_non_null(strstr(st->str, "123"));
    assert_null(strstr(st->str, "456"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"replace\">"
            "  <name>TestThird</name>"
            "  <num>456</num>"
            "</top>";

    /* Send rpc to replace the original config */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if replaced correctly */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestThird"));
    assert_non_null(strstr(st->str, "456"));
    assert_null(strstr(st->str, "123"));
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ed3\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></top>";

    /* Empty the config */
    SEND_EDIT_RPC(st, data);

    /* Recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config empty */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_create(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"create\">"
            "TestFirst"
            "</first>";

    /* Send rpc creating config in module edit1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config config now contains edit1 */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "TestFirst"));
    FREE_TEST_VARS(st);

    /* Send rpc creating the same module */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should fail */
    ASSERT_RPC_ERROR(st);

    FREE_TEST_VARS(st);

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></first>";

    /* remove to get an empty config */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* check if empty config */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_remove(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\">TestFirst</first>";

    /* Send rpc editing module edit1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config was merged */
    GET_CONFIG(st);
    assert_string_not_equal(st->str, EMPTY_GETCONFIG);
    FREE_TEST_VARS(st);

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"></first>";

    /* Try removing the merged config */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config is now empty */
    ASSERT_EMPTY_CONFIG(st);

    /* Try removing the from empty config */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if config is still empty */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_ex1(void **state)
{
    /* First example for edit-config from rfc 6241 section 7.2 */
    struct np_test *st = *state;
    const char *data;

    data =
            "<top xmlns=\"ex1\">"
            "  <interface>"
            "    <name>Ethernet0/0</name>"
            "    <mtu>1500</mtu>"
            "  </interface>"
            "</top>";

    /* Send rpc editing module ex1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if there is no address element */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "address"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex1\">"
            "  <interface operation=\"replace\">"
            "    <name>Ethernet0/0</name>"
            "    <mtu>1500</mtu>"
            "    <address>"
            "      <name>192.0.2.4</name>"
            "      <prefix-length>24</prefix-length>"
            "    </address>"
            "  </interface>"
            "</top>";

    /* Send rpc replacing module ex1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if the address element is now present */
    GET_CONFIG(st);
    assert_non_null(strstr(st->str, "address"));
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "  <interface xc:operation=\"delete\">"
            "    <name>Ethernet0/0</name>"
            "  </interface>"
            "</top>";

    /* Send rpc deleting config in module ex1 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if empty config */
    ASSERT_EMPTY_CONFIG(st);
}

static void
test_ex2(void **state)
{
    /* Second example for edit-config from rfc 6241 section 7.2 */
    struct np_test *st = *state;
    const char *data;

    /* Need to have some running config first */

    data =
            "<top xmlns=\"ex2\">"
            "  <protocols>"
            "    <ospf>"
            "      <area>"
            "        <name>0.0.0.0</name>"
            "        <interfaces>"
            "          <interface>"
            "            <name>192.0.2.4</name>"
            "          </interface>"
            "        </interfaces>"
            "      </area>"
            "    </ospf>"
            "  </protocols>"
            "</top>";

    /* Send rpc editing module ex2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex2\">"
            "  <protocols>"
            "    <ospf>"
            "      <area>"
            "        <name>0.0.0.0</name>"
            "        <interfaces>"
            "          <interface>"
            "            <name>192.0.2.1</name>"
            "          </interface>"
            "        </interfaces>"
            "      </area>"
            "    </ospf>"
            "  </protocols>"
            "</top>";

    /* Send another rpc editing module ex2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"ex2\">"
            "  <protocols>"
            "    <ospf>"
            "      <area>"
            "        <name>0.0.0.0</name>"
            "        <interfaces"
            "         xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "          <interface xc:operation=\"delete\">"
            "            <name>192.0.2.4</name>"
            "          </interface>"
            "        </interfaces>"
            "      </area>"
            "    </ospf>"
            "  </protocols>"
            "</top>";

    /* Send rpc deleting part of the data from module ex2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if the config was patrialy deleted */
    GET_CONFIG(st);
    assert_null(strstr(st->str, "192.0.2.4"));
    assert_non_null(strstr(st->str, "192.0.2.1"));
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ex2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"delete\"></top>";

    /* Send rpc deleting part of the data from module ex2 */
    SEND_EDIT_RPC(st, data);

    /* Receive a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if empty config */
    ASSERT_EMPTY_CONFIG(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_merge),
        cmocka_unit_test(test_delete),
        cmocka_unit_test(test_merge_advanced),
        cmocka_unit_test(test_replace),
        cmocka_unit_test(test_create),
        cmocka_unit_test(test_remove),
        cmocka_unit_test(test_ex1),
        cmocka_unit_test(test_ex2),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
