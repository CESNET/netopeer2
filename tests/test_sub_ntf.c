/**
 * @file test_sub_ntf.c
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
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
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
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/notif1.yang", NP_TEST_MODULE_DIR "/notif2.yang", NULL};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules);
    assert_int_equal(rc, 0);
    st = *state;

    /* start second session for the tests */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess2), SR_ERR_OK);

    /* enable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));

    return 0;
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

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    const char *modules[] = {"notif1", "notif2", NULL};

    if (!st) {
        return 0;
    }

    /* disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif2", 0));

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* remove the notifications */
    teardown_common(state);

    /* close netopeer2 server */
    return np_glob_teardown(state, modules);
}

static void
test_invalid_start_time(void **state)
{
    struct np_test *st = *state;
    char *start_time;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec += 10; /* Put start time in the future */
    assert_int_equal(ly_time_ts2str(&ts, &start_time), LY_SUCCESS);

    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, NULL);
    free(start_time);

    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Specified \"replay-start-time\" is in future.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>replay-start-time</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

static void
test_invalid_stop_time(void **state)
{
    struct np_test *st = *state;
    char *stop_time;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec -= 1; /* Put stop time in the past */
    assert_int_equal(ly_time_ts2str(&ts, &stop_time), LY_SUCCESS);

    /* Should fail since there is no start-time and it is in the past */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, stop_time);
    free(stop_time);

    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Specified \"stop-time\" is in the past.</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>stop-time</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

static void
test_invalid_start_stop_time(void **state)
{
    struct np_test *st = *state;
    char *start_time, *stop_time;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(ly_time_ts2str(&ts, &start_time), LY_SUCCESS);
    ts.tv_sec -= 2;
    assert_int_equal(ly_time_ts2str(&ts, &stop_time), LY_SUCCESS);

    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);

    ASSERT_ERROR_REPLY(st);
    assert_string_equal(st->str,
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>protocol</error-type>\n"
            "  <error-tag>bad-element</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Specified \"stop-time\" is earlier than \"replay-start-time\".</error-message>\n"
            "  <error-info>\n"
            "    <bad-element>stop-time</bad-element>\n"
            "  </error-info>\n"
            "</rpc-error>\n");
    FREE_TEST_VARS(st);
}

static void
test_basic_sub(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
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
test_replay_sub(void **state)
{
    struct np_test *st = *state;
    struct timespec ts;
    const char *data, *template;
    char *expected;
    char *timestr;

    /* Subscribe to replay */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &timestr));

    /* Parse notification into lyd_node */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    SEND_RPC_ESTABSUB(st, NULL, "notif1", timestr, NULL);
    free(timestr);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
    /* Check for replay-completed notification since the replay is done */
    RECV_NOTIF(st);
    template =
            "<replay-completed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "</replay-completed>\n";
    assert_int_not_equal(-1, asprintf(&expected, template, st->ntf_id));
    assert_string_equal(st->str, expected);
    free(expected);
    FREE_TEST_VARS(st);

    /* No other notification should arrive */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

static void
test_replay_real_time(void **state)
{
    struct np_test *st = *state;
    const char *data, *expected, *template;
    char *ntf;
    struct timespec ts;
    char *start_time;

    /* Subscribe to replay */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>First</first>\n"
            "</n1>\n";
    expected = data;
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

    /* Subscribe to notifications */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, NULL);
    free(start_time);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

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

    /* Check for replay-completed notification since the replay is done */
    RECV_NOTIF(st);
    template =
            "<replay-completed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "</replay-completed>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
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
    const char *data, *expected, *template;
    char *ntf;
    struct timespec ts;
    char *start_time, *stop_time;

    /* To subscribe to replay of the notification */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));

    /* Send the notification */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    expected = data;
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* To subscribe to replay of notifications until time was called, should not include any called after */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));
    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Receive the notification and test the contents */
    RECV_NOTIF(st);
    assert_string_equal(expected, st->str);
    FREE_TEST_VARS(st);

    /* Check for replay-completed notification since the replay is done */
    RECV_NOTIF(st);
    template =
            "<replay-completed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "</replay-completed>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Check for subscriptin-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Parse and send the notification */
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
test_history_only(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *ntf;
    struct timespec ts;
    char *start_time, *stop_time;

    /* Subscription in the past */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec -= 10;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &start_time));
    ts.tv_sec += 5;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));
    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Check for replay-completed notification since the replay is done */
    RECV_NOTIF(st);
    template =
            "<replay-completed xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "</replay-completed>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Check for subscriptin-terminated notification */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_stream_no_pass(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Subscribe to notfications from a different stream */
    SEND_RPC_ESTABSUB(st, NULL, "notif2", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send the notification should not be recieved */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_invalid_start_time, teardown_common),
        cmocka_unit_test_teardown(test_invalid_stop_time, teardown_common),
        cmocka_unit_test_teardown(test_invalid_start_stop_time, teardown_common),
        cmocka_unit_test_teardown(test_basic_sub, teardown_common),
        cmocka_unit_test_teardown(test_replay_sub, teardown_common),
        cmocka_unit_test_teardown(test_replay_real_time, teardown_common),
        cmocka_unit_test_teardown(test_stop_time, teardown_common),
        cmocka_unit_test_teardown(test_history_only, teardown_common),
        cmocka_unit_test_teardown(test_stream_no_pass, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
