/**
 * @file test_subscribe_filter.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for filtering notifications
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
#include <sysrepo.h>

#include "np2_test.h"
#include "np2_test_config.h"

static void
setup_data(void **state)
{
    struct np2_test *st = *state;
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
reestablish_sub(void **state, const char *stream, const char *filter)
{
    struct np2_test *st = *state;

    /* free the current session (with its subscription) */
    nc_session_free(st->nc_sess, NULL);

    /* create a new session */
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(stream, filter, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static int
local_setup(void **state)
{
    struct np2_test *st;
    const char *modules[] = {NP_TEST_MODULE_DIR "/notif1.yang", NP_TEST_MODULE_DIR "/notif2.yang", NULL};
    char test_name[256];
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, 0);
    assert_int_equal(rc, 0);
    st = *state;

    /* use operational DS */
    assert_int_equal(sr_session_switch_ds(st->sr_sess, SR_DS_OPERATIONAL), SR_ERR_OK);
    setup_data(state);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"notif1", "notif2", NULL};

    if (!*state) {
        return 0;
    }

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

static void
test_basic_notif(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "notif1", NULL);
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_list_notif(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, "notif2", NULL);
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_no_matching_node(void **state)
{
    struct np2_test *st = *state;
    const char *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "  </device>\n"
            "</devices>\n";

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications, rpc-error since no notification can match the filter */
    st->rpc = nc_rpc_subscribe(NULL, filter, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_selection_node_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL, "<n1 xmlns=\"n1\"/>");
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_selection_node_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL, "<n1 xmlns=\"n1\"/>");
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_content_match_node_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data, *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on/>\n"
            "  </device>\n"
            "</devices>\n";

    /* Send the notification */
    reestablish_sub(state, "notif2", filter);
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_subtree_filter_notif_content_match_node_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data, *filter =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on/>\n"
            "  </device>\n"
            "</devices>\n";

    /* Send the notification */
    reestablish_sub(state, NULL, filter);
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_no_matching_node(void **state)
{
    struct np2_test *st = *state;

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications, rpc-error since no notification can match the filter */
    st->rpc = nc_rpc_subscribe(NULL, "/notif2:devices/device[name='Main']", NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    ASSERT_ERROR_REPLY(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_selection_node_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    reestablish_sub(state, NULL, "/notif1:n1/first");

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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_selection_node_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL, "/notif1:n1/first");
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_content_match_node_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL, "/notif2:devices/device[name='Main']/power-on");
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_filter_notif_content_match_node_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Send the notification */
    reestablish_sub(state, NULL, "/notif2:devices/device[name='Main']/power-on");
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Notification should pass the filter */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_xpath_boolean_no_pass(void **state)
{
    struct np2_test *st = *state;
    char *data, *filter =
            "/notif2:devices/device[name='Secondary']/power-on and /notif2:devices/device/power-on[boot-time=12]";

    /* Send the notification */
    reestablish_sub(state, NULL, filter);
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass due to the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_xpath_boolean_pass(void **state)
{
    struct np2_test *st = *state;
    char *data, *filter =
            "/notif2:devices/device[name='Main']/power-on and /notif2:devices/device/power-on[boot-time=12]";

    /* Send the notification */
    reestablish_sub(state, NULL, filter);
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
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
