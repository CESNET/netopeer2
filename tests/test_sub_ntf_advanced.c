/**
 * @file test_sub_ntf_advanced.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief advanced tests for subscriptions and its' parameters
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
    NP_GLOB_SETUP_TEST_NAME(test_name);

    /* setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, NULL), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
        /* state is allocated in np_glob_setup_np2 have to set here */
        st = *state;
        /* Open connection to start a sessions for the tests */
        assert_int_equal(sr_connect(SR_CONN_DEFAULT, &st->conn), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess), SR_ERR_OK);
        assert_int_equal(sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sr_sess2), SR_ERR_OK);
        assert_non_null(st->ctx = sr_get_context(st->conn));

        /* Enable replay support */
        assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));
        rv |= setup_nacm(state);
    }
    return rv;
}

void
test_path_notif_dir(char **path)
{
    if (SR_NOTIFICATION_PATH[0]) {
        *path = strdup(SR_NOTIFICATION_PATH);
    } else {
        if (asprintf(path, "%s/data/notif", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    char *path, *cmd;
    int ret;

    /* Remove the notifications */
    test_path_notif_dir(&path);
    if (!path) {
        return 1;
    }

    if (asprintf(&cmd, "rm -rf %s/notif1.notif*", path) == -1) {
        return 1;
    }

    free(path);
    ret = system(cmd);
    free(cmd);

    if (ret == -1) {
        return 1;
    } else if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        return 1;
    }

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    sr_conn_ctx_t *conn;

    /* Disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));

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
test_filter_pass(void **state)
{
    struct np_test *st = *state;
    const char *filter, *data;

    filter = "<n1 xmlns=\"n1\"/>";
    SEND_RPC_ESTABSUB(st, filter, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_filter_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *filter, *data;

    filter = "<n1 xmlns=\"n1\"><first>Different</first></n1>";
    SEND_RPC_ESTABSUB(st, filter, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);

    /* Notification should not pass */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_modifysub_filter(void **state)
{
    struct np_test *st = *state;
    const char *filter, *data, *template;
    char *ntf;

    filter = "<n1 xmlns=\"n1\"/>";
    SEND_RPC_ESTABSUB(st, filter, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Modify the filter so that notifications do no pass */
    filter = "<n1 xmlns=\"n1\"><first>Different</first></n1>";
    SEND_RPC_MODSUB(st, st->ntf_id, filter, NULL);
    RECV_NOTIF(st);
    template =
            "<subscription-modified xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <stream-subtree-filter>\n"
            "    <n1 xmlns=\"n1\">\n"
            "      <first>Different</first>\n"
            "    </n1>\n"
            "  </stream-subtree-filter>\n"
            "</subscription-modified>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
    st->rpc = nc_rpc_modifysub(st->ntf_id, NULL, NULL, NC_PARAMTYPE_CONST);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_modifysub_stop_time(void **state)
{
    struct np_test *st = *state;
    const char *data, *template;
    char *ntf;
    char *stop_time;

    /* Establish a subscription with no stop-time */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Nothing should happen */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Modify the stop_time to now, session should end */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(time(NULL) + 1, NULL, &stop_time));
    SEND_RPC_MODSUB(st, st->ntf_id, "<n1 xmlns=\"n1\"/>", stop_time);
    free(stop_time);
    RECV_NOTIF(st);
    /* Checking the content of the notification would depend on having precise timestamp */
    FREE_TEST_VARS(st);
    st->rpc = nc_rpc_modifysub(st->ntf_id, NULL, NULL, NC_PARAMTYPE_CONST);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check for subscription-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No notification should arrive now */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_modifysub_fail_no_such_sub(void **state)
{
    struct np_test *st = *state;

    /* Try modifying a non-existent subscription */
    SEND_RPC_MODSUB(st, 1, "<n1 xmlns=\"n1\"/>", NULL);
    ASSERT_RPC_ERROR(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    /* Check if correct error-app-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next->next->next->next),
            "ietf-subscribed-notifications:no-such-subscription");
    FREE_TEST_VARS(st);
}

static void
test_deletesub(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish a subscription to delete */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    SEND_RPC_DELSUB(st, st->ntf_id);
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
    st->rpc = nc_rpc_deletesub(st->ntf_id);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_deletesub_fail(void **state)
{
    struct np_test *st = *state;

    /* Try deleting a non-existent subscription */
    SEND_RPC_DELSUB(st, 1);
    ASSERT_RPC_ERROR(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    /* Check if correct error-app-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next->next->next->next),
            "ietf-subscribed-notifications:no-such-subscription");
    FREE_TEST_VARS(st);
}

static void
test_deletesub_fail_diff_sess(void **state)
{
    struct np_test *st = *state;
    const char *data;
    struct nc_session *tmp;

    /* Establish a sub */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send notification, should arrive */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Create a new session */
    tmp = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(tmp);

    /* Try to delete it */
    st->rpc = nc_rpc_deletesub(st->ntf_id);
    st->msgtype = nc_send_rpc(tmp, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    /* Receive rpc-error reply */
    st->msgtype = nc_recv_reply(tmp, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    /* Check if correct error-app-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next->next->next->next),
            "ietf-subscribed-notifications:no-such-subscription");
    FREE_TEST_VARS(st);

    /* Close the new session */
    nc_session_free(tmp, NULL);
}

static void
test_ds_subscriptions(void **state)
{
    struct np_test *st = *state;
    char *expected;
    const char *template =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>0</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    /* Establish a subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    assert_int_not_equal(-1, asprintf(&expected, template, st->ntf_id, nc_session_get_id(st->nc_sess)));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);
}

static void
test_ds_subscriptions_sent_event(void **state)
{
    struct np_test *st = *state;
    char *expected;
    const char *data, *template =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    /* Establish a subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send 3 notifications */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    for (uint8_t i = 0; i < 3; i++) {
        NOTIF_PARSE(st, data);
        assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
        RECV_NOTIF(st);
        FREE_TEST_VARS(st);
    }

    GET_FILTER(st, "/subscriptions");
    assert_int_not_equal(-1, asprintf(&expected, template, st->ntf_id, nc_session_get_id(st->nc_sess)));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);
}

static void
test_ds_subscriptions_excluded_event(void **state)
{
    struct np_test *st = *state;
    char *expected;
    const char *data, *filter, *template =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>1</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    /* Establish a subscription */
    filter = "<n1 xmlns=\"n1\"><first>Different</first></n1>";
    SEND_RPC_ESTABSUB(st, filter, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send 2 notifications, one should pass the filter, the other should not */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Different</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    assert_int_not_equal(-1, asprintf(&expected, template, st->ntf_id, nc_session_get_id(st->nc_sess)));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);
}

static void
test_multiple_subscriptions(void **state)
{
    struct np_test *st = *state;
    char *expected;
    uint32_t nc_sess_id, tmp_id;
    const char *template =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>0</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>0</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    /* Establish a subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);
    tmp_id = st->ntf_id;

    /* Establish another subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    nc_sess_id = nc_session_get_id(st->nc_sess);
    assert_int_not_equal(-1, asprintf(&expected, template, tmp_id, nc_sess_id, st->ntf_id, nc_sess_id));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);
}

static void
test_multiple_subscriptions_notif(void **state)
{
    struct np_test *st = *state;
    char *expected;
    uint32_t nc_sess_id, tmp_ids[3];
    const char *data, *template =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>%d</id>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>NETCONF session %d</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    /* Establish three subscriptions */
    for (uint8_t i = 0; i < 3; i++) {
        SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
        ASSERT_OK_SUB_NTF(st);
        tmp_ids[i] = st->ntf_id;
        FREE_TEST_VARS(st);
    }

    /* Send one notification, should arrive for all subscriptions */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive three notifications */
    for (uint8_t i = 0; i < 3; i++) {
        RECV_NOTIF(st);
        FREE_TEST_VARS(st);
    }

    GET_FILTER(st, "/subscriptions");
    nc_sess_id = nc_session_get_id(st->nc_sess);
    assert_int_not_equal(-1, asprintf(&expected, template, tmp_ids[0], nc_sess_id,
            tmp_ids[1], nc_sess_id, tmp_ids[2], nc_sess_id));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);
}

static int
setup_notif2_data(void **state)
{
    struct np_test *st = *state;
    const char *data;

    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "  </device>\n"
            "</devices>\n";

    SR_EDIT_SESSION(st, st->sr_sess2, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_multiple_subscriptions_notif_interlaced(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Establish first sub */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send one notification to the first session and check it */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Send another notification to the first session */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Establish second sub for a different stream */
    SEND_RPC_ESTABSUB(st, NULL, "notif2", NULL, NULL);

    /* Receive the notification sent before establishing another subscription and check it */
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Check for establishing the sub */
    st->rpc = nc_rpc_establishsub(NULL, "notif2", NULL, NULL, NULL, NC_PARAMTYPE_CONST);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send last notification to the first session */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Send notification to the second session */
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
    FREE_TEST_VARS(st);

    /* Receive the notification from first sub */
    RECV_NOTIF(st);
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Receive the notification from second sub */
    RECV_NOTIF(st);
    data =
            "<devices xmlns=\"n2\">\n"
            "  <device>\n"
            "    <name>Main</name>\n"
            "    <power-on>\n"
            "      <boot-time>12</boot-time>\n"
            "    </power-on>\n"
            "  </device>\n"
            "</devices>\n";
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);
}

static int
teardown_nacm(void **state)
{
    struct np_test *st = *state;
    const char *data;

    teardown_common(state);

    /* Remove NACM rules */
    data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\" "
            "xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <read-default xc:operation=\"remove\">deny</read-default>\n"
            "  <rule-list  xc:operation=\"remove\">\n"
            "    <name>rule1</name>\n"
            "  </rule-list>\n"
            "</nacm>";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    return 0;
}

static void
test_killsub_fail_nacm(void **state)
{
    struct np_test *st = *state;

    /* Check for NACM_RECOVERY_UID */
    if (is_nacm_rec_uid()) {
        puts("Running as NACM_RECOVERY_UID. Tests will not run correctly as this user bypases NACM. Skipping.");
        return;
    }

    /* Should fail on NACM */
    SEND_RPC_KILLSUB(st, 1);
    ASSERT_RPC_ERROR(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "access-denied");
    FREE_TEST_VARS(st);
}

static int
setup_test_killsub(void **state)
{
    struct np_test *st = *state;
    const char *data =
            "<nacm xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-acm\">\n"
            "  <rule-list>\n"
            "     <name>rule1</name>\n"
            "     <group>test-group</group>\n"
            "     <rule>\n"
            "       <name>allow-killsub</name>\n"
            "       <module-name>ietf-subscribed-notifications</module-name>\n"
            "       <rpc-name>kill-subscription</rpc-name>\n"
            "       <access-operations>exec</access-operations>\n"
            "       <action>permit</action>\n"
            "     </rule>\n"
            "   </rule-list>\n"
            "</nacm>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
    return 0;
}

static void
test_killsub_fail_no_such_sub(void **state)
{
    struct np_test *st = *state;

    SEND_RPC_KILLSUB(st, 1);
    /* Should fail on no such sub */
    ASSERT_RPC_ERROR(st);
    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "invalid-value");
    /* Check if correct error-app-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next->next->next->next),
            "ietf-subscribed-notifications:no-such-subscription");
    FREE_TEST_VARS(st);
}

static void
test_killsub_same_sess(void **state)
{
    struct np_test *st = *state;
    const char *data, *template;
    char *ntf;

    /* Establish a sub */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send notification, should arrive */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Kill it */
    SEND_RPC_KILLSUB(st, st->ntf_id);
    /* Check for subscription-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
    st->rpc = nc_rpc_killsub(st->ntf_id);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Send notification, should NOT arrive */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_killsub_diff_sess(void **state)
{
    struct np_test *st = *state;
    const char *data, *template;
    struct nc_session *tmp;
    char *ntf;

    /* Establish a sub */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send notification, should arrive */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);

    /* Create a new session */
    tmp = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(tmp);

    /* Kill it */
    st->rpc = nc_rpc_killsub(st->ntf_id);
    st->msgtype = nc_send_rpc(tmp, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    /* Check for subscription-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
    st->rpc = nc_rpc_killsub(st->ntf_id);
    /* Receive OK reply */
    st->msgtype = nc_recv_reply(tmp, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "ok");
    FREE_TEST_VARS(st);

    /* Send notification, should NOT arrive */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Close the new session */
    nc_session_free(tmp, NULL);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_filter_pass, teardown_common),
        cmocka_unit_test_teardown(test_filter_no_pass, teardown_common),
        cmocka_unit_test_teardown(test_modifysub_filter, teardown_common),
        cmocka_unit_test_teardown(test_modifysub_stop_time, teardown_common),
        cmocka_unit_test(test_modifysub_fail_no_such_sub),
        cmocka_unit_test_teardown(test_deletesub, teardown_common),
        cmocka_unit_test(test_deletesub_fail),
        cmocka_unit_test_teardown(test_deletesub_fail_diff_sess, teardown_common),
        cmocka_unit_test_teardown(test_ds_subscriptions, teardown_common),
        cmocka_unit_test_teardown(test_ds_subscriptions_sent_event, teardown_common),
        cmocka_unit_test_teardown(test_ds_subscriptions_excluded_event, teardown_common),
        cmocka_unit_test_teardown(test_multiple_subscriptions, teardown_common),
        cmocka_unit_test_teardown(test_multiple_subscriptions_notif, teardown_common),
        cmocka_unit_test_setup_teardown(test_multiple_subscriptions_notif_interlaced, setup_notif2_data, teardown_common),
        cmocka_unit_test_teardown(test_killsub_fail_nacm, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_killsub_fail_no_such_sub, setup_test_killsub, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_killsub_same_sess, setup_test_killsub, teardown_nacm),
        cmocka_unit_test_setup_teardown(test_killsub_diff_sess, setup_test_killsub, teardown_nacm),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
