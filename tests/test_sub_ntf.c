/**
 * @file test_sub_ntf.c
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
test_invalid_start_time(void **state)
{
    struct np_test *st = *state;
    char *start_time, *expected;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec += 10; /* Put start time in the future */
    assert_int_equal(ly_time_ts2str(&ts, &start_time), LY_SUCCESS);

    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, NULL);
    free(start_time);
    ASSERT_RPC_ERROR(st);

    /* Should fail since start-time has to be in the past */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "bad-element");
    expected =
            "    <error-info>\n"
            "      <bad-element>replay-start-time</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));
    FREE_TEST_VARS(st);
}

static void
test_invalid_stop_time(void **state)
{
    struct np_test *st = *state;
    char *stop_time, *expected;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_sec -= 1; /* Put stop time in the past */
    assert_int_equal(ly_time_ts2str(&ts, &stop_time), LY_SUCCESS);

    /* Should fail since there is no start-time and it is in the past */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, stop_time);
    free(stop_time);
    ASSERT_RPC_ERROR(st);
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "bad-element");
    expected =
            "    <error-info>\n"
            "      <bad-element>stop-time</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));
    FREE_TEST_VARS(st);
}

static void
test_invalid_start_stop_time(void **state)
{
    struct np_test *st = *state;
    char *start_time, *stop_time, *expected;
    struct timespec ts;

    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    assert_int_equal(ly_time_ts2str(&ts, &start_time), LY_SUCCESS);
    ts.tv_sec -= 2;
    assert_int_equal(ly_time_ts2str(&ts, &stop_time), LY_SUCCESS);

    SEND_RPC_ESTABSUB(st, NULL, "notif1", start_time, stop_time);
    free(start_time);
    free(stop_time);
    ASSERT_RPC_ERROR(st);

    /* Should fail since start-time exists and stop-time is not later than start-time */
    assert_string_equal(lyd_get_value(lyd_child(lyd_child(st->envp))->next), "bad-element");
    expected =
            "    <error-info>\n"
            "      <bad-element>stop-time</bad-element>\n"
            "    </error-info>\n";

    /* Check if correct error-info is given */
    lyd_print_mem(&st->str, st->envp, LYD_XML, 0);
    assert_non_null(strstr(st->str, expected));
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);

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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* To subscribe to replay of notifications until time was called, should not include any called after */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_nsec += 100000000; /* + 0.1s */
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
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
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
    const char *data, *template;
    char *ntf;
    struct timespec ts;
    char *stop_time;

    /* Stop time is now + 0.1, should end almost right away */
    assert_int_not_equal(-1, clock_gettime(CLOCK_REALTIME, &ts));
    ts.tv_nsec += 100000000;
    assert_int_equal(LY_SUCCESS, ly_time_ts2str(&ts, &stop_time));
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, stop_time);
    free(stop_time);
    ASSERT_OK_SUB_NTF(st);
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

    /* Try sending a notfication, should not arrive since it is after end of subscription */
    data =
            "<n1 xmlns=\"n1\">\n"
            "  <first>Second</first>\n"
            "</n1>\n";

    NOTIF_PARSE(st, data);
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
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
            "  <reason xmlns:sn=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">sn:no-such-subscription</reason>\n"
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
    assert_int_equal(sr_event_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
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
        cmocka_unit_test_teardown(test_stop_time_sub_end, teardown_common),
        cmocka_unit_test_teardown(test_history_only, teardown_common),
        cmocka_unit_test_teardown(test_stream_no_pass, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
