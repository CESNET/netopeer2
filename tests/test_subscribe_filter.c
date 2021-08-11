/**
 * @file test_subscribe_filter.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for filtering notifications
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

static void
setup_data(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "  </device>\n"
            "  <device>\n"
            "    <name>Secondary</name>\n"
            "  </device>\n"
            "</devices>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
}

static void
reestablish_sub(void **state, const char *filter)
{
    struct np_test *st = *state;

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, filter, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "ok");

    FREE_TEST_VARS(st);
}

static int
local_setup(void **state)
{
    struct np_test *st;
    sr_conn_ctx_t *conn;
    const char *features[] = {NULL};
    const char *module1 = NP_TEST_MODULE_DIR "/notif1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/notif2.yang";
    int rv;

    /* Setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* Connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
        /* State is allocated in np_glob_setup_np2 have to set here */
        st = *state;
        /* Open connection to start a session for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sr_sess), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));
        setup_data(state);
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
    assert_int_equal(sr_remove_module(conn, "notif1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "notif2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_basic_notif(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL);
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_list_notif(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_no_matching_node(void **state)
{
    struct np_test *st = *state;
    const char *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "  </device>\n"
            "</devices>\n";

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, filter, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);

    /* Should be an rpc-error since no notification can match the filter */
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_selection_node_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "<n1 xmlns=\"n1\"/>");
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_selection_node_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "<n1 xmlns=\"n1\"/>");
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_content_match_node_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data, *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on/>\n"
            "  </device>\n"
            "</devices>\n";

    /* Send the notification */
    reestablish_sub(state, filter);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Secondary</name>\n"
            "    <power-on>\n"
            "      <boot-time>45</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_content_match_node_pass(void **state)
{
    struct np_test *st = *state;
    const char *data, *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on/>\n"
            "  </device>\n"
            "</devices>\n";

    /* Send the notification */
    reestablish_sub(state, filter);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_no_matching_node(void **state)
{
    struct np_test *st = *state;

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, "/notif2:devices/device[name='Main']", NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);

    /* Should be an rpc-error since no notification can match the filter */
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_selection_node_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    reestablish_sub(state, "/notif1:n1/first");

    /* Send the notification */
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_selection_node_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "/notif1:n1/first");
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_content_match_node_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "/notif2:devices/device[name='Main']/power-on");
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Secondary</name>\n"
            "    <power-on>\n"
            "      <boot-time>45</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_content_match_node_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "/notif2:devices/device[name='Main']/power-on");
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_boolean_no_pass(void **state)
{
    struct np_test *st = *state;
    char *data, *filter =
            "/notif2:devices/device[name='Secondary']/power-on and /notif2:devices/device/power-on[boot-time=12]";

    /* Send the notification */
    reestablish_sub(state, filter);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_boolean_pass(void **state)
{
    struct np_test *st = *state;
    char *data, *filter =
            "/notif2:devices/device[name='Main']/power-on and /notif2:devices/device/power-on[boot-time=12]";

    /* Send the notification */
    reestablish_sub(state, filter);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_basic_notif),
        cmocka_unit_test(test_list_notif),
        cmocka_unit_test(test_subtree_filter_no_matching_node),
        cmocka_unit_test(test_subtree_filter_notif_selection_node_no_pass),
        cmocka_unit_test(test_subtree_filter_notif_selection_node_pass),
        cmocka_unit_test(test_subtree_filter_notif_content_match_node_no_pass),
        cmocka_unit_test(test_subtree_filter_notif_content_match_node_pass),
        cmocka_unit_test(test_xpath_filter_notif_selection_node_no_pass),
        cmocka_unit_test(test_xpath_filter_notif_selection_node_pass),
        cmocka_unit_test(test_xpath_filter_notif_content_match_node_no_pass),
        cmocka_unit_test(test_xpath_filter_notif_content_match_node_pass),
        cmocka_unit_test(test_xpath_filter_no_matching_node),
        cmocka_unit_test(test_xpath_boolean_no_pass),
        cmocka_unit_test(test_xpath_boolean_pass),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
