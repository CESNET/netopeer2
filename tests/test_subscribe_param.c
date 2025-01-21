/**
 * @file test_subscribe_param.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for subscriptions and its' parameters
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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>

#include "np2_test.h"
#include "np2_test_config.h"

static void
reestablish_sub(void **state, const char *stream, const char *start_time, const char *stop_time)
{
    struct np2_test *st = *state;

    /* free the current session (with its subscription) */
    nc_session_free(st->nc_sess, NULL);

    /* create a new session */
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(stream, NULL, start_time, stop_time, NC_PARAMTYPE_CONST);
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

    /* second running session */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess2), SR_ERR_OK);

    /* rnable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));

    return 0;
}

static int
clear_notif(void **state)
{
    struct np2_test *st = *state;

    /* remove notifications */
    if (np2_glob_test_teardown_notif(st->test_name)) {
        return 1;
    }

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

    /* remove the notfications */
    clear_notif(state);

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

static void
test_stop_time_invalid(void **state)
{
    struct np2_test *st = *state;
    struct timespec ts;
    char *start_time, *stop_time;

    /* startTime is current time */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* stopTime is in the past */
    ts.tv_sec--;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, start_time, stop_time, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Specified \"stopTime\" is earlier than \"startTime\".</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>stopTime</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
    free(start_time);
    free(stop_time);
}

static void
test_start_time_invalid(void **state)
{
    struct np2_test *st = *state;
    struct timespec ts;
    char *start_time;

    /* startTime is in the future */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec += 30;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, start_time, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Specified \"startTime\" is in future.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>startTime</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
    free(start_time);
}

static void
test_stop_time_no_start_time(void **state)
{
    struct np2_test *st = *state;
    struct timespec ts;
    char *stop_time;

    /* stopTime is the current time */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));

    /* Reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    /* Get a subscription to receive notifications */
    st->rpc = nc_rpc_subscribe(NULL, NULL, NULL, stop_time, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Check reply */
    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>missing-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">An expected element is missing.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>startTime</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
    free(stop_time);
}

static void
test_basic_replay(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct timespec ts;
    char *start_time;

    /* Subsrcibe to replay */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Subscribe to notfications */
    reestablish_sub(state, "notif1", start_time, NULL);
    free(start_time);

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
    struct np2_test *st = *state;
    const char *data, *expected;
    struct timespec ts;
    char *timestr;

    /* Subsrcibe to replay */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &timestr));

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>First</first>\n"
            "</n1>\n";
    expected = data;
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Subscribe to notfications */
    reestablish_sub(state, "notif1", timestr, NULL);
    free(timestr);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
    struct np2_test *st = *state;
    const char *data, *expected;
    struct timespec start, stop;
    char *start_time, *stop_time;

    /* To subscribe to replay of the notification */
    clock_gettime(CLOCK_REALTIME, &start);
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&start, &start_time));

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    expected = data;
    NOTIF_PARSE(st, data);

    /* Send the notification */
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* To subscribe to replay of notifications until time was called, should not include any called after */
    clock_gettime(CLOCK_REALTIME, &stop);
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&stop, &stop_time));

    /* Subscribe to notfications */
    reestablish_sub(state, "notif1", start_time, stop_time);
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

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Another</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_stop_time_sub_end(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct timespec ts;
    char *start_time, *stop_time;

    /* needed for stopTime */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* stopTime is now, should end right away */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));

    /* subscribe to notfications */
    reestablish_sub(state, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);

    /* receive the notification and test the contents */
    RECV_NOTIF(st);
    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* receive the notification and test the contents */
    RECV_NOTIF(st);
    data = "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* wait a bit to increase chances that the subscription thread was scheduled and the subscription finished due to stop time */
    usleep(10000);

    /* create new subscription */
    st->rpc = nc_rpc_subscribe("notif1", NULL, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* check reply */
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* try sending a notfication real time on new session */
    /* send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_history_only(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct timespec ts;
    char *start_time, *stop_time;

    /* startTime is 10 seconds in the past */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec -= 10;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* stopTime is 5 seconds in the past */
    ts.tv_sec += 5;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));

    /* Subscribe to notfications */
    reestablish_sub(state, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    data = "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    data = "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>\n";
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

static void
test_stream_no_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Subscribe to notfications from a different stream */
    reestablish_sub(state, "notif2", NULL, NULL);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* It should no be recieved since it is in a a different stream than subscribed to */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_stream_pass(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Subscribe to notfications from the same stream */
    reestablish_sub(state, "notif1", NULL, NULL);

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(st->str, data);
    FREE_TEST_VARS(st);
}

static void
test_stream_no_pass_start_time(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct timespec ts;
    char *start_time;

    /* Subscribe to replay */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Subscribe to notfications from a different stream */
    reestablish_sub(state, "notif2", start_time, NULL);
    free(start_time);

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
