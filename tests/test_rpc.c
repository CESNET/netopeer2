/**
 * @file test_rpc.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief test executing simple RPCs
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

#include "np_test.h"
#include "np_test_config.h.in"

#define LOCK_FAIL_TEMPLATE "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%ld\">\n"\
        "  <rpc-error>\n"\
        "    <error-type>protocol</error-type>\n"\
        "    <error-tag>lock-denied</error-tag>\n"\
        "    <error-severity>error</error-severity>\n"\
        "    <error-message lang=\"en\">Access to the requested lock is denied because the lock is currently held by another entity.</error-message>\n"\
        "    <error-info>\n"\
        "      <session-id>%d</session-id>\n"\
        "    </error-info>\n"\
        "  </rpc-error>\n"\
        "</rpc-reply>\n"

NP_GLOB_SETUP_FUNC

static void
test_types(void **state)
{
    struct nc_rpc *rpc;

    (void)state;

    /* Test that all constructors create the right type of rpc */
    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_int_equal(NC_RPC_LOCK, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    assert_int_equal(NC_RPC_UNLOCK, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_get("", NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_GET, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_kill(NC_DATASTORE_RUNNING);
    assert_int_equal(NC_RPC_KILL, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_commit(NC_DATASTORE_RUNNING, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_COMMIT, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_discard();
    assert_int_equal(NC_RPC_DISCARD, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_cancel("", NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_CANCEL, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, "", NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_VALIDATE, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_subscribe("", "", "", "", NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_SUBSCRIBE, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_getdata("", "", "", NULL, 0, 0, 0, 0, NC_WD_ALL, NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_GETDATA, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    rpc = nc_rpc_editdata("", NC_RPC_EDIT_DFLTOP_MERGE, "", NC_PARAMTYPE_CONST);
    assert_int_equal(NC_RPC_EDITDATA, nc_rpc_get_type(rpc));
    nc_rpc_free(rpc);

    /* TODO: NC_RPC_ESTABLISHSUB and the rest */
}

static void
test_lock(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;
    char *str, *str2;

    /* lock from first session */
    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);

    /* send request */
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* receive reply */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    lyd_free_tree(envp);

    /* request to lock from another session should fail when lock already */
    msgtype = nc_send_rpc(st->nc_sess2, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* recieve reply, should yield error */
    msgtype = nc_recv_reply(st->nc_sess2, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&str, envp, LYD_XML, 0));

    assert_int_not_equal(-1, asprintf(&str2, LOCK_FAIL_TEMPLATE, msgid, nc_session_get_id(st->nc_sess)));

    /* error expected */
    assert_string_equal(str, str2);
    free(str);
    free(str2);

    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* unlock RPC */
    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    /* TODO: check if lock prevents changes */
}

static void
test_unlock(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;
    char *str, *str2;

    /* Simple locking checked in previous tests */

    /* Lock by a different session */
    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    msgtype = nc_send_rpc(st->nc_sess2, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* receive reply */
    msgtype = nc_recv_reply(st->nc_sess2, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* Try unlocking a lock by a different session */
    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* recieve reply, should yield error */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&str, envp, LYD_XML, 0));

    /* error expected */
    assert_int_not_equal(-1, asprintf(&str2, LOCK_FAIL_TEMPLATE, msgid, nc_session_get_id(st->nc_sess2)));
    assert_string_equal(str, str2);
    free(str);
    free(str2);

    nc_rpc_free(rpc);
    lyd_free_tree(envp);

    /* Try unlocking the original session, should succeed */
    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
    msgtype = nc_send_rpc(st->nc_sess2, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_RPC, msgtype);

    /* recieve reply, should succeed */
    msgtype = nc_recv_reply(st->nc_sess2, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
}

static void
test_get(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;

    /* Try to get all */
    rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_RPC, msgtype);

    /* recieve reply, should succeed */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_non_null(op);
    assert_non_null(envp);

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    lyd_free_tree(op);

    /* TODO: test if filter works */
}

static void
test_kill(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;

    /* Try to close a session */
    rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess2));
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_RPC, msgtype);

    /* recieve reply, should fail since wrong permissions */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "rpc-error");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    /* TODO: Check error message, would depend on current user */
    /* TODO: NACM tests */
}

static void
test_commit(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;

    /* Try to close a session */
    rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_RPC, msgtype);

    /* recieve reply, should fail since wrong permissions */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    /* TODO: test funcionality */
}

static void
test_discard(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;

    /* Try to close a session */
    rpc = nc_rpc_discard();
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_RPC, msgtype);

    /* recieve reply, should fail since wrong permissions */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");

    nc_rpc_free(rpc);
    lyd_free_tree(envp);
    /* TODO: test funcionality */
}

static void
test_unsuported(void **state)
{
    struct np_test *st = *state;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;

    /* Testing RPCs unsupported by netopeer, all should fail */
    rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(NC_MSG_ERROR, msgtype);

    nc_rpc_free(rpc);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_types),
        cmocka_unit_test(test_lock),
        cmocka_unit_test(test_unlock),
        cmocka_unit_test(test_get),
        cmocka_unit_test(test_kill),
        cmocka_unit_test(test_commit),
        cmocka_unit_test(test_discard),
        cmocka_unit_test(test_unsuported),
    };

    nc_verbosity(NC_VERB_WARNING);
    return cmocka_run_group_tests(tests, np_glob_setup, np_glob_teardown);
}
