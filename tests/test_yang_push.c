/**
 * @file test_yang_push.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests yang push notifications
 *
 * @copyright
 * Copyright 2021 Deutsche Telekom AG.
 * Copyright 2021 CESNET, z.s.p.o.
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
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";
    const char *module2 = NP_TEST_MODULE_DIR "/edit2.yang";
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
        assert_non_null(st->ctx = sr_get_context(st->conn));

        /* Enable replay support */
        assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "edit1", 1));
    }
    return rv;
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    const char *data;
    char *cmd;
    int ret;

    /* stop NETCONF session */
    nc_session_free(st->nc_sess, NULL);

    /* Remove the data */
    data = "<first xmlns=\"ed1\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data = "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xc:operation=\"remove\"/>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

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

    /* create new default NETCONF session */
    st->nc_sess = nc_connect_unix(st->socket_path, NULL);
    assert_non_null(st->nc_sess);

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
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "edit1", 0));

    /* Close the sessions and connection needed for tests */
    assert_int_equal(sr_session_stop(st->sr_sess), SR_ERR_OK);
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);
    assert_int_equal(sr_disconnect(st->conn), SR_ERR_OK);

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit2"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_periodic_basic(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish periodic push */
    st->rpc = nc_rpc_establishpush_periodic("ietf-datastores:running", NULL, NULL, NULL, 10, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Receive a notification */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents/>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </datastore-contents>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    FREE_TEST_VARS(st);

    /* Test yet again if arives with the same data */
    RECV_NOTIF(st);
    assert_string_equal(st->str, ntf);
    FREE_TEST_VARS(st);
    free(ntf);
}

static void
test_on_change_basic(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish on-change push */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 0, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* No notification should arrive until a change occurs */
    ASSERT_NO_NOTIF(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No other notification should be sent */
    ASSERT_NO_NOTIF(st);
}

static void
test_on_change_multiple(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish on-change push */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 0, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* No notification should arrive until a change occurs */
    ASSERT_NO_NOTIF(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Change the data */
    data = "<first xmlns=\"ed1\">TestSecond</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the change */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-2</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>replace</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestSecond</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Remove the data */
    data = "<first xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xmlns=\"ed1\" xc:operation=\"remove\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the deletion */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-3</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/edit1:first</target>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No other notification should be sent */
    ASSERT_NO_NOTIF(st);
}

static void
test_periodic_anchor_time(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *ntf;

    /* Establish periodic push with anchor-time */
    st->rpc = nc_rpc_establishpush_periodic("ietf-datastores:running", NULL, NULL, NULL, 10,
            "1970-01-01T01:00:00+01:00", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Receive a notification */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents/>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Testing the exact time proved to be too unreliable */
}

static void
test_on_change_dampening_time(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish on-change push with 0.1s dampening time */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 10, 0,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <name>Test</name>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Put some more data into the datastore */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <num>123</num>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data dampened */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-2</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit2:top/name</target>\n"
            "        <value>\n"
            "          <name xmlns=\"ed2\">Test</name>\n"
            "        </value>\n"
            "      </edit>\n"
            "      <edit>\n"
            "        <edit-id>edit-2</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit2:top/num</target>\n"
            "        <value>\n"
            "          <num xmlns=\"ed2\">123</num>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No other notification should be sent */
    ASSERT_NO_NOTIF(st);
}

static void
test_on_change_dampening_time_same_node(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish on-change push with 0.1s dampening time */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 10, 0,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestSecond</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Put some more data into the datastore */
    data = "<first xmlns=\"ed1\">TestThird</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data dampened */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-2</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-2</edit-id>\n"
            "        <operation>replace</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestThird</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No other notification should be sent */
    ASSERT_NO_NOTIF(st);
}

static void
test_on_change_dampening_time_create_delete(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    char *ntf;

    /* Establish on-change push with 0.1s dampening time */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 10, 0,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data =
            "<top xmlns=\"ed2\">\n"
            "  <name>Test</name>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Remove the data from the datastore */
    data =
            "<top xmlns=\"ed2\" xmlns:xc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <name xc:operation=\"remove\">Test</name>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with deletion */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-2</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-2</edit-id>\n"
            "        <operation>delete</operation>\n"
            "        <target>/edit2:top/name</target>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No other notification should be sent */
    ASSERT_NO_NOTIF(st);
}

static void
test_on_change_excluded(void **state)
{
    struct np_test *st = *state;
    const char *template, *data;
    const char *excluded[] = {"create", NULL};
    char *ntf;

    /* Establish on-change push */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 0,
            excluded, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* No notification should arrive until a change occurs */
    ASSERT_NO_NOTIF(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* No notification should arrive on creation */
    ASSERT_NO_NOTIF(st);

    /* Modify the data */
    data = "<first xmlns=\"ed1\">TestSecond</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with the new data */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>replace</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestSecond</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_sync_on_start(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *ntf;

    /* Establish on-change push with sync on start */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 1,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Sync notification should arrive */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents/>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static int
setup_test_sync_on_start_non_empty(void **state)
{
    struct np_test *st = *state;
    const char *data;

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    return 0;
}

static void
test_sync_on_start_non_empty(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *ntf;

    /* Establish on-change push with sync on start */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 1,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Sync notification should arrive */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </datastore-contents>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

static void
test_resync(void **state)
{
    struct np_test *st = *state;
    const char *template;
    char *ntf;

    /* Establish on-change push */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 0,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* No notification should arrive */
    ASSERT_NO_NOTIF(st);

    /* Resync the subscription */
    st->rpc = nc_rpc_resyncsub(st->ntf_id);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);

    /* Sync notification should arrive */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents/>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    lyd_free_tree(st->envp);
    lyd_free_tree(st->op);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);
}

static void
test_resync_id_reset(void **state)
{
    struct np_test *st = *state;
    const char *data, *template;
    char *ntf;

    /* Establish on-change push */
    st->rpc = nc_rpc_establishpush_onchange("ietf-datastores:running", NULL, NULL, NULL, 0, 0,
            NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Put some data into the datastore */
    data = "<first xmlns=\"ed1\">TestFirst</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with patch id 1 */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>create</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestFirst</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);

    /* Resync the subscription */
    st->rpc = nc_rpc_resyncsub(st->ntf_id);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);

    /* Sync notification should arrive */
    RECV_NOTIF(st);
    template =
            "<push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-contents>\n"
            "    <first xmlns=\"ed1\">TestFirst</first>\n"
            "  </datastore-contents>\n"
            "</push-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    lyd_free_tree(st->op);
    lyd_free_tree(st->envp);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Replace the data */
    data = "<first xmlns=\"ed1\">TestSecond</first>";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    /* Receive a notification with patch id 1 */
    RECV_NOTIF(st);
    template =
            "<push-change-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "  <id>%d</id>\n"
            "  <datastore-changes>\n"
            "    <yang-patch>\n"
            "      <patch-id>patch-1</patch-id>\n"
            "      <edit>\n"
            "        <edit-id>edit-1</edit-id>\n"
            "        <operation>replace</operation>\n"
            "        <target>/edit1:first</target>\n"
            "        <value>\n"
            "          <first xmlns=\"ed1\">TestSecond</first>\n"
            "        </value>\n"
            "      </edit>\n"
            "    </yang-patch>\n"
            "  </datastore-changes>\n"
            "</push-change-update>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(st->str, ntf);
    free(ntf);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_periodic_basic, teardown_common),
        cmocka_unit_test_teardown(test_on_change_basic, teardown_common),
        cmocka_unit_test_teardown(test_on_change_multiple, teardown_common),
        cmocka_unit_test_teardown(test_periodic_anchor_time, teardown_common),
        cmocka_unit_test_teardown(test_on_change_dampening_time, teardown_common),
        cmocka_unit_test_teardown(test_on_change_dampening_time_same_node, teardown_common),
        cmocka_unit_test_teardown(test_on_change_dampening_time_create_delete, teardown_common),
        cmocka_unit_test_teardown(test_on_change_excluded, teardown_common),
        cmocka_unit_test_teardown(test_sync_on_start, teardown_common),
        cmocka_unit_test_setup_teardown(test_sync_on_start_non_empty,
                setup_test_sync_on_start_non_empty, teardown_common),
        cmocka_unit_test_teardown(test_resync, teardown_common),
        cmocka_unit_test_teardown(test_resync_id_reset, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
