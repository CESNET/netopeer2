/**
 * @file test_url.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for RPCs that take url as an argument
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
setup_nacm_rules(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-keystore</name>\n"
            "       <module-name>ietf-keystore</module-name>\n"
            "       <path xmlns:ks=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">/ks:keystore</path>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>allow-nacm</name>\n"
            "       <module-name>ietf-netconf-acm</module-name>\n"
            "       <path xmlns:nacm=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">/nacm:nacm</path>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "     <rule>\n"
            "       <name>allow-truststore</name>\n"
            "       <module-name>ietf-truststore</module-name>\n"
            "       <path xmlns:ts=\"urn:ietf:params:xml:ns:yang:ietf-truststore\">/ts:truststore</path>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static int
local_setup(void **state)
{
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;
    char test_name[256];
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";
    int rv;

    /* get test name */
    NP_GLOB_SETUP_TEST_NAME(test_name);

    /* setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
        /* state is allocated in np_glob_setup_np2 have to set here */
        st = *state;
        /* Open connection to start a session for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));
        rv |= setup_nacm(state);
        rv |= setup_nacm_rules(state);
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
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_validate(void **state)
{
    struct np_test *st = *state;
    const char *url;

    url = "file://" NP_TEST_MODULE_DIR "/edit1.xml";

    /* Send validate rpc */
    st->rpc = nc_rpc_validate(NC_DATASTORE_URL, url, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 2000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
}

static int
teardown_data(void **state)
{
    struct np_test *st = *state;
    const char *data;

    if (setup_nacm(state) || setup_nacm_rules(state)) {
        return 1;
    }

    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);
    return 0;
}

static void
test_copy_config(void **state)
{
    struct np_test *st = *state;
    const char *url, *expected;

    url = "file://" NP_TEST_MODULE_DIR "/edit1.xml";

    /* Send copy config */
    st->rpc = nc_rpc_copy(NC_DATASTORE_RUNNING, NULL, NC_DATASTORE_URL, url, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Recieve reply */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    GET_CONFIG(st);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_copy_config_same(void **state)
{
    struct np_test *st = *state;
    const char *url;

    url = "file://" NP_TEST_MODULE_DIR "/edit1.xml";

    /* Send copy config */
    st->rpc = nc_rpc_copy(NC_DATASTORE_URL, url, NC_DATASTORE_URL, url, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Recieve reply */
    ASSERT_RPC_ERROR(st);

    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");

    FREE_TEST_VARS(st);
}

static int
setup_data(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data = "<first xmlns=\"ed1\">TestFirst</first>";

    SR_EDIT(st, data);

    FREE_TEST_VARS(st);
    return 0;
}

static void
test_copy_config_into_file(void **state)
{
    struct np_test *st = *state;
    const char *path, *url, *template;
    char *expected, *config, *user;
    long size;
    FILE *file;

    /* Remove the file if it exists */
    path = "/tmp/np2-test.xml";
    url = "file:///tmp/np2-test.xml";

    /* Send copy config */
    st->rpc = nc_rpc_copy(NC_DATASTORE_URL, url, NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Recieve reply */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    file = fopen(path, "r");
    assert_non_null(file);

    /* Get file size */
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    /* Allcate buffer */
    config = calloc((size + 1), sizeof *config);
    assert_non_null(config);

    /* Read the file */
    assert_int_equal(fread(config, sizeof *config, size, file), size);

    template =
            "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <first xmlns=\"ed1\">TestFirst</first>\n"
            "  <nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "    <enable-nacm>true</enable-nacm>\n"
            "    <read-default>permit</read-default>\n"
            "    <write-default>permit</write-default>\n"
            "    <exec-default>permit</exec-default>\n"
            "    <enable-external-groups>false</enable-external-groups>\n"
            "    <groups>\n"
            "      <group>\n"
            "        <name>test-group</name>\n"
            "        <user-name>%s</user-name>\n"
            "      </group>\n"
            "    </groups>\n"
            "    <rule-list>\n"
            "      <name>rule1</name>\n"
            "      <group>test-group</group>\n"
            "      <rule>\n"
            "        <name>allow-keystore</name>\n"
            "        <module-name>ietf-keystore</module-name>\n"
            "        <path xmlns:ks=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">/ks:keystore</path>\n"
            "        <access-operations>*</access-operations>\n"
            "        <action>permit</action>\n"
            "      </rule>\n"
            "      <rule>\n"
            "        <name>allow-nacm</name>\n"
            "        <module-name>ietf-netconf-acm</module-name>\n"
            "        <path xmlns:nacm=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">/nacm:nacm</path>\n"
            "        <access-operations>*</access-operations>\n"
            "        <action>permit</action>\n"
            "      </rule>\n"
            "      <rule>\n"
            "        <name>allow-truststore</name>\n"
            "        <module-name>ietf-truststore</module-name>\n"
            "        <path xmlns:ts=\"urn:ietf:params:xml:ns:yang:ietf-truststore\">/ts:truststore</path>\n"
            "        <access-operations>*</access-operations>\n"
            "        <action>permit</action>\n"
            "      </rule>\n"
            "    </rule-list>\n"
            "  </nacm>\n"
            "</config>\n";

    assert_int_equal(0, get_username(&user));
    assert_int_not_equal(-1, asprintf(&expected, template, user) == -1);
    assert_string_equal(config, expected);
    free(expected);
    free(user);

    free(config);
    fclose(file);
    assert_int_equal(0, remove(path));
    FREE_TEST_VARS(st);
}

static void
test_copy_config_url2url(void **state)
{
    struct np_test *st = *state;
    const char *url_source, *url_target, *path, *expected;
    char *config;
    FILE *file;
    long size;

    url_source = "file://" NP_TEST_MODULE_DIR "/edit1.xml";
    url_target = "file:///tmp/np2-test.xml";
    path = "/tmp/np2-test.xml";

    /* Send copy config */
    st->rpc = nc_rpc_copy(NC_DATASTORE_URL, url_target, NC_DATASTORE_URL, url_source, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Recieve reply */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    file = fopen(path, "r");
    assert_non_null(file);

    /* Get file size */
    fseek(file, 0, SEEK_END);
    size = ftell(file);
    rewind(file);

    /* Allcate buffer */
    config = calloc((size + 1), sizeof *config);
    assert_non_null(config);

    /* Read the file */
    assert_int_equal(fread(config, sizeof *config, size, file), size);

    expected =
            "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <first xmlns=\"ed1\">TestFirst</first>\n"
            "</config>\n";

    assert_string_equal(config, expected);

    free(config);
    fclose(file);
    assert_int_equal(0, remove(path));
    FREE_TEST_VARS(st);
}

static void
test_edit_config(void **state)
{
    struct np_test *st = *state;
    const char *url, *template;
    char *expected, *user;

    url = "file://" NP_TEST_MODULE_DIR "/edit1.xml";

    /* Send rpc edit */
    st->rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, url, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid); \
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Check if merged */
    GET_CONFIG(st);

    template =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "    <nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "      <enable-nacm>true</enable-nacm>\n"
            "      <read-default>permit</read-default>\n"
            "      <write-default>permit</write-default>\n"
            "      <exec-default>permit</exec-default>\n"
            "      <enable-external-groups>false</enable-external-groups>\n"
            "      <groups>\n"
            "        <group>\n"
            "          <name>test-group</name>\n"
            "          <user-name>%s</user-name>\n"
            "        </group>\n"
            "      </groups>\n"
            "      <rule-list>\n"
            "        <name>rule1</name>\n"
            "        <group>test-group</group>\n"
            "        <rule>\n"
            "          <name>allow-keystore</name>\n"
            "          <module-name>ietf-keystore</module-name>\n"
            "          <path xmlns:ks=\"urn:ietf:params:xml:ns:yang:ietf-keystore\">/ks:keystore</path>\n"
            "          <access-operations>*</access-operations>\n"
            "          <action>permit</action>\n"
            "        </rule>\n"
            "        <rule>\n"
            "          <name>allow-nacm</name>\n"
            "          <module-name>ietf-netconf-acm</module-name>\n"
            "          <path xmlns:nacm=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">/nacm:nacm</path>\n"
            "          <access-operations>*</access-operations>\n"
            "          <action>permit</action>\n"
            "        </rule>\n"
            "        <rule>\n"
            "          <name>allow-truststore</name>\n"
            "          <module-name>ietf-truststore</module-name>\n"
            "          <path xmlns:ts=\"urn:ietf:params:xml:ns:yang:ietf-truststore\">/ts:truststore</path>\n"
            "          <access-operations>*</access-operations>\n"
            "          <action>permit</action>\n"
            "        </rule>\n"
            "      </rule-list>\n"
            "    </nacm>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_int_equal(0, get_username(&user));
    assert_int_not_equal(-1, asprintf(&expected, template, user) == -1);
    assert_string_equal(st->str, expected);
    free(expected);
    free(user);

    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_validate),
        cmocka_unit_test_teardown(test_copy_config, teardown_data),
        cmocka_unit_test_teardown(test_copy_config_same, teardown_data),
        cmocka_unit_test_setup_teardown(test_copy_config_into_file, setup_data, teardown_data),
        cmocka_unit_test(test_copy_config_url2url),
        cmocka_unit_test_teardown(test_edit_config, teardown_data),
    };

    if (is_nacm_rec_uid()) {
        puts("Running as NACM_RECOVERY_UID. Tests will not run correctly as this user bypases NACM. Skipping.");
        return 0;
    }

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
