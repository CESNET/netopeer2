/**
 * @file test_subscribe_param.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for subscriptions and its' parameters
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

static void
reestablish_sub(void **state, const char *stream, const char *start_time, const char *stop_time)
{
    struct np_test *st = *state;

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(stream, NULL, start_time, stop_time, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    st->msgtype = NC_MSG_NOTIF;
    while (st->msgtype == NC_MSG_NOTIF) {
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    }
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

    /* setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module2, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    if (!(rv = np_glob_setup_np2(state))) {
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
clear_notif(void **state)
{
    char *path, *cmd;
    int ret;

    (void)state;

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

    /* Remove the notfications */
    clear_notif(state);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_stop_time_invalid(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    time_t cur;
    char *start_time, *stop_time;

    cur = time(NULL);
    assert_int_not_equal(-1, time);

    /* startTime is current time */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &start_time));

    /* stopTime is in the past */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur - 1, NULL, &stop_time));

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, start_time, stop_time, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    st->msgtype = NC_MSG_NOTIF;
    while (st->msgtype == NC_MSG_NOTIF) {
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    }
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");

    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "bad-element");

    expected =
            "    <error-info>\n"
            "      <bad-element>stopTime</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));

    FREE_TEST_VARS(st);
    free(start_time);
    free(stop_time);
}

static void
test_start_time_invalid(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    time_t cur;
    char *start_time;

    cur = time(NULL);
    assert_int_not_equal(-1, time);

    /* startTime is in the future */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur + 10, NULL, &start_time));

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, start_time, NULL, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    st->msgtype = NC_MSG_NOTIF;
    while (st->msgtype == NC_MSG_NOTIF) {
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    }
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");

    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "bad-element");

    expected =
            "    <error-info>\n"
            "      <bad-element>startTime</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));

    FREE_TEST_VARS(st);
    free(start_time);
}

static void
test_stop_time_no_start_time(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    time_t cur;
    char *stop_time;

    cur = time(NULL);
    assert_int_not_equal(-1, time);

    /* stopTime is the current time */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &stop_time));

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, NULL, stop_time, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    st->msgtype = NC_MSG_NOTIF;
    while (st->msgtype == NC_MSG_NOTIF) {
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    }
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");

    /* Check if correct error-tag */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "missing-element");

    expected =
            "    <error-info>\n"
            "      <bad-element>startTime</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));

    FREE_TEST_VARS(st);
    free(stop_time);
}

static void
test_basic_replay(void **state)
{
    struct np_test *st = *state;
    const char *data;
    time_t cur;
    char *timestr;

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    cur = time(NULL);
    assert_int_not_equal(-1, time);
    cur -= 10; /* To subscribe to replay of notifications  from last 10 seconds*/

    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &timestr));

    /* Subscribe to notfications */
    reestablish_sub(state, NULL, timestr, NULL);
    free(timestr);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* Check for replayComplete notification since the replay is done */
    RECV_NOTIF(st);

    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);

    FREE_TEST_VARS(st);
}

static void
test_replay_real_time(void **state)
{
    struct np_test *st = *state;
    const char *data, *expected;
    time_t cur;
    char *timestr;

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>First</first>\n"
            "</n1>\n";
    expected = data;

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    cur = time(NULL);
    assert_int_not_equal(-1, time);
    cur -= 10; /* To subscribe to replay of notifications  from last 10 seconds*/

    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &timestr));

    /* Subscribe to notfications */
    reestablish_sub(state, NULL, timestr, NULL);
    free(timestr);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);

    assert_string_equal(expected, st->str);

    FREE_TEST_VARS(st);

    /* Check for replayComplete notification since the replay is done */
    RECV_NOTIF(st);

    expected = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(expected, st->str);

    FREE_TEST_VARS(st);

    /* Check for real time notification */
    RECV_NOTIF(st);

    expected =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";

    assert_string_equal(expected, st->str);

    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);

    FREE_TEST_VARS(st);
}

static void
test_stop_time(void **state)
{
    struct np_test *st = *state;
    const char *data, *expected;
    time_t start;
    char *start_time, *stop_time;

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    expected = data;

    NOTIF_PARSE(st, data);

    /* Send the notification */
    start = time(NULL);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    FREE_TEST_VARS(st);

    /* To subscribe to replay of the notification */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(start, NULL, &start_time));

    /* To subscribe to replay of notifications until time was called, should not include any called after */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(time(NULL), NULL, &stop_time));

    /* Subscribe to notfications */
    reestablish_sub(state, NULL, start_time, stop_time);
    free(start_time);
    free(stop_time);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);

    assert_string_equal(expected, st->str);

    FREE_TEST_VARS(st);

    /* Check for replayComplete notification since there was nothing to replay */
    RECV_NOTIF(st);

    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* Check for notficationComplete notification since the subscription should be done */
    RECV_NOTIF(st);

    data = "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Another</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);

    FREE_TEST_VARS(st);
}

static void
test_stop_time_sub_end(void **state)
{
    struct np_test *st = *state;
    const char *data;
    time_t cur;
    char *start_time, *stop_time;

    cur = time(NULL);
    assert_int_not_equal(-1, time);

    /* Needed for stopTime */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &start_time));

    /* Stop time is now + 1s, should end right away */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur + 1, NULL, &stop_time));

    reestablish_sub(state, NULL, start_time, stop_time);
    free(start_time);
    free(stop_time);

    RECV_NOTIF(st);

    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    RECV_NOTIF(st);

    data = "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* Subsription should have ended now due to stop time, try to create a new one */
    st->rpc = nc_rpc_subscribe(NULL, NULL, NULL, NULL, NC_PARAMTYPE_CONST);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    st->msgtype = NC_MSG_NOTIF;
    while (st->msgtype == NC_MSG_NOTIF) {
        st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    }
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "ok");

    FREE_TEST_VARS(st);

    /* Try sending a notfication real time on new session */
    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);
}

static void
test_history_only(void **state)
{
    struct np_test *st = *state;
    const char *data;
    time_t cur;
    char *start_time, *stop_time;

    cur = time(NULL);
    assert_int_not_equal(-1, time);

    /* startTime is 10 seconds in the past */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur - 10, NULL, &start_time));

    /* Stop time is 5 seconds in the past */
    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur - 5, NULL, &stop_time));

    reestablish_sub(state, NULL, start_time, stop_time);
    free(start_time);
    free(stop_time);

    RECV_NOTIF(st);

    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    RECV_NOTIF(st);

    data = "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

}

static void
test_stream_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Subscribe to notfications from a different stream */
    reestablish_sub(state, "notif2", NULL, NULL);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* It should no be recieved since it is in a a different stream than subscribed to */
    ASSERT_NO_NOTIF(st);

    FREE_TEST_VARS(st);
}

static void
test_stream_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Subscribe to notfications from the same stream */
    reestablish_sub(state, "notif1", NULL, NULL);

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);

    assert_string_equal(st->str, data);

    FREE_TEST_VARS(st);
}

static void
test_stream_no_pass_start_time(void **state)
{
    struct np_test *st = *state;
    const char *data;
    time_t cur;
    char *timestr;

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    cur = time(NULL);
    assert_int_not_equal(-1, time);
    cur -= 10; /* To subscribe to replay of notifications  from last 10 seconds*/

    assert_int_equal(LY_SUCCESS, ly_time_time2str(cur, NULL, &timestr));

    /* Subscribe to notfications from a different stream */
    reestablish_sub(state, "notif2", timestr, NULL);
    free(timestr);

    /* Check for replayComplete notification since the replay is done */
    RECV_NOTIF(st);

    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";

    assert_string_equal(data, st->str);

    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);

    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_stop_time_invalid),
        cmocka_unit_test(test_start_time_invalid),
        cmocka_unit_test(test_stop_time_no_start_time),
        cmocka_unit_test_teardown(test_basic_replay, clear_notif),
        cmocka_unit_test_teardown(test_replay_real_time, clear_notif),
        cmocka_unit_test_teardown(test_stop_time, clear_notif),
        cmocka_unit_test_teardown(test_stop_time_sub_end, clear_notif),
        cmocka_unit_test_teardown(test_history_only, clear_notif),
        cmocka_unit_test(test_stream_no_pass),
        cmocka_unit_test(test_stream_pass),
        cmocka_unit_test(test_stream_no_pass_start_time),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
