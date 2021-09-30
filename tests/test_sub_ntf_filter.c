/**
 * @file test_sub_filter.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for subscription filters including filters by ref
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
#include <time.h>
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
    const char *module1 = NP_TEST_MODULE_DIR "/notif1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/notif2.yang";
    int rv;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state, test_name))) {
        /* state is allocated in np_glob_setup_np2 have to set here */
        st = *state;
        /* Open connection to start a session for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess2), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));

        /* Enable replay support */
        assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));
    }
    return rv;
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    char *cmd;
    int ret;

    /* Remove the notifications */
    if (asprintf(&cmd, "rm -rf %s/%s/data/notif/notif1.notif*", NP_SR_REPOS_DIR, st->test_name) == -1) {
        return 1;
    }

    ret = system(cmd);
    free(cmd);

    if (ret == -1) {
        return 1;
    } else if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        return 1;
    }

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, NULL);
    assert_non_null(st->nc_sess);

    return 0;
}

static void
remove_filter(void **state)
{
    struct np_test *st = *state;
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
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;

    if (!st) {
        return 0;
    }

    /* Disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif2", 0));

    /* Close the sessions and connection needed for tests */
    assert_int_equal(sr_session_stop(st->sr_sess), SR_ERR_OK);
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);
    assert_int_equal(sr_disconnect(st->conn), SR_ERR_OK);

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "notif1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "notif2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* Remove the notifications */
    teardown_common(state);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_basic_xpath_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_basic_xpath_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "/notif1:n1/first[.=Alt]", "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_basic_subtree_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_basic_subtree_no_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static int
setup_filter(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<filters xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <stream-filter>\n"
            "    <name>xpath-pass</name>\n"
            "    <stream-xpath-filter>/n1/first</stream-xpath-filter>\n"
            "  </stream-filter>\n"
            "  <stream-filter>\n"
            "    <name>xpath-no-pass</name>\n"
            "    <stream-xpath-filter>/n1/first[.=Alt]</stream-xpath-filter>\n"
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
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_ref_xpath_no_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_ref_subtree_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_ref_subtree_no_pass(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* No notification should pass the filter */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_filter_change(void **state)
{
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Check for notification content */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Modify the filter */
    data =
            "<filters xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <stream-filter>\n"
            "    <name>xpath-pass</name>\n"
            "    <stream-xpath-filter>/n1/first[.=Alt]</stream-xpath-filter>\n"
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
    struct np_test *st = *state;
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:filter-unavailable</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_filter_non_existent(void **state)
{
    struct np_test *st = *state;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, "non-existant", "notif1", NULL, NULL);
    ASSERT_RPC_ERROR(st);
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
