/**
 * @file test_sub_filter.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for subscription filters including filters by ref
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>

#include "np2_test.h"
#include "np2_test_config.h"

static const char *test_modules[] = {NP_TEST_MODULE_DIR "/notif1.yang", NP_TEST_MODULE_DIR "/notif2.yang", NULL};

static int
local_setup(void **state)
{
    struct np2_test *st;
    char test_name[256];
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment*/
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, test_modules);
    assert_int_equal(rc, 0);
    st = *state;

    /* second session */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess2), SR_ERR_OK);

    /* enable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));

    return 0;
}

static int
teardown_common(void **state)
{
    struct np2_test *st = *state;

    /* remove notifications */
    if (np2_glob_test_teardown_notif(st->test_name)) {
        return 1;
    }

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, NULL);
    assert_non_null(st->nc_sess);
    np2_glob_test_setup_sess_ctx(st->nc_sess, test_modules);

    return 0;
}

static void
remove_filter(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    data =
            "<filters xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\" "
            "xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
}

static int
teardown_filter(void **state)
{
    teardown_common(state);
    remove_filter(state);
    return 0;
}

static int
local_teardown(void **state)
{
    struct np2_test *st = *state;
    const char *modules[] = {"notif1", "notif2", NULL};

    if (!st) {
        return 0;
    }

    /* disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* remove the notifications */
    teardown_common(state);

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

static void
test_basic_xpath_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "/notif1:n1/first", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_basic_xpath_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "/notif1:n1/first[.='Alt']", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_basic_subtree_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    data = "<n1 xmlns=\"n1\"/>";
    SEND_RPC_ESTABSUB(st, data, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_basic_subtree_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Alt</first>\n"
            "</n1>\n";
    SEND_RPC_ESTABSUB(st, data, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static int
setup_filter(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    data =
            "<filters xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <stream-filter>\n"
            "    <name>xpath-pass</name>\n"
            "    <stream-xpath-filter>/n1/first</stream-xpath-filter>\n"
            "  </stream-filter>\n"
            "  <stream-filter>\n"
            "    <name>xpath-no-pass</name>\n"
            "    <stream-xpath-filter>/n1/first[.='Alt']</stream-xpath-filter>\n"
            "  </stream-filter>\n"
            "  <stream-filter>\n"
            "    <name>subtree-pass</name>\n"
            "    <stream-subtree-filter><n1 xmlns=\"n1\"/></stream-subtree-filter>\n"
            "  </stream-filter>\n"
            "  <stream-filter>\n"
            "    <name>subtree-no-pass</name>\n"
            "    <stream-subtree-filter><n1 xmlns=\"n1\"><first>Alt</first></n1></stream-subtree-filter>\n"
            "  </stream-filter>\n"
            "</filters>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_ref_xpath_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "xpath-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_ref_xpath_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "xpath-no-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_ref_subtree_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "subtree-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_ref_subtree_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "subtree-no-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_filter_change(void **state)
{
    struct np2_test *st = *state;
    const char *data, *template;
    char *ntf;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "xpath-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Modify the filter */
    data =
            "<filters xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <stream-filter>\n"
            "    <name>xpath-pass</name>\n"
            "    <stream-xpath-filter>/n1/first[.='Alt']</stream-xpath-filter>\n"
            "  </stream-filter>\n"
            "</filters>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Check for subscription-modified notification */
    RECV_NOTIF(st);
    template =
            "<subscription-modified xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <stream-filter-name>xpath-pass</stream-filter-name>\n"
            "</subscription-modified>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_filter_remove(void **state)
{
    struct np2_test *st = *state;
    const char *data, *template;
    char *ntf;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "xpath-pass", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Remove the filter */
    remove_filter(state);

    /* Check for subscription-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason>filter-unavailable</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_filter_non_existent(void **state)
{
    struct np2_test *st = *state;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "non-existant", "notif1", NULL, NULL);
    ASSERT_ERROR_REPLY(st);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_basic_xpath_pass, teardown_common),
        cmocka_unit_test_teardown(test_basic_xpath_no_pass, teardown_common),
        cmocka_unit_test_teardown(test_basic_subtree_pass, teardown_common),
        cmocka_unit_test_teardown(test_basic_subtree_no_pass, teardown_common),
        cmocka_unit_test_setup_teardown(test_ref_xpath_pass, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_ref_xpath_no_pass, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_ref_subtree_pass, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_ref_subtree_no_pass, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_filter_change, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_filter_remove, setup_filter, teardown_filter),
        cmocka_unit_test_setup_teardown(test_filter_non_existent, setup_filter, teardown_filter),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
