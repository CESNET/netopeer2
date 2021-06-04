/**
 * @file test_rpc.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
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
#include "np_test_config.h"

#define LOCK_FAIL_TEMPLATE "<rpc-reply " \
    "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" " \
    "message-id=\"%ld\">\n" \
    "  <rpc-error>\n" \
    "    <error-type>protocol</error-type>\n" \
    "    <error-tag>lock-denied</error-tag>\n" \
    "    <error-severity>error</error-severity>\n" \
    "    <error-message lang=\"en\">Access to the requested lock is denied" \
    " because the lock is currently held by another entity.</error-message>\n" \
    "    <error-info>\n" \
    "      <session-id>%d</session-id>\n" \
    "    </error-info>\n" \
    "  </rpc-error>\n" \
    "</rpc-reply>\n"

#define KILL_FAIL_TEMPLATE \
    "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" " \
    "message-id=\"%ld\">\n" \
    "  <rpc-error>\n" \
    "    <error-type>application</error-type>\n" \
    "    <error-tag>access-denied</error-tag>\n" \
    "    <error-severity>error</error-severity>\n" \
    "    <error-path>/ietf-netconf:kill-session</error-path>\n" \
    "    <error-message lang=\"en\">Executing the operation is denied " \
    "because \"%s\" NACM authorization failed.</error-message>\n" \
    "  </rpc-error>\n" \
    "</rpc-reply>\n" \


static int
local_setup(void **state)
{
    sr_conn_ctx_t *conn;
    const char *features[] = {NULL};
    const char *module1 = NP_TEST_MODULE_DIR "/edit1.yang";

    /* setup environment necessary for installing module */
    NP_GLOB_SETUP_ENV_FUNC;
    assert_int_equal(setenv_rv, 0);

    /* connect to server and install test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_install_module(conn, module1, NULL, features), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* setup netopeer2 server */
    return np_glob_setup_np2(state);
}

static int
local_teardown(void **state)
{
    sr_conn_ctx_t *conn;

    /* connect to server and remove test modules */
    assert_int_equal(sr_connect(SR_CONN_DEFAULT, &conn), SR_ERR_OK);
    assert_int_equal(sr_remove_module(conn, "edit1"), SR_ERR_OK);
    assert_int_equal(sr_disconnect(conn), SR_ERR_OK);

    /* close netopeer2 server */
    return np_glob_teardown(state);
}

static void
test_lock(void **state)
{
    struct np_test *st = *state;
    char *str2;

    /* lock from first session */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(st->rpc);

    /* send request */
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* receive reply, should succeed */
    ASSERT_OK_REPLY(st);

    lyd_free_tree(st->envp);

    /* request to lock from another session should fail when lock already */
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* recieve reply, should yield error */
    ASSERT_RPC_ERROR_SESS2(st);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));

    assert_int_not_equal(-1, asprintf(&str2, LOCK_FAIL_TEMPLATE, st->msgid, nc_session_get_id(st->nc_sess)));

    /* error expected */
    assert_string_equal(st->str, str2);
    free(str2);

    FREE_TEST_VARS(st);

    /* Check if lock prevents changes */

    /* Send rpc editing module edit1 on the same session */
    SEND_EDIT_RPC(st, "<first xmlns=\"ed1\">TestFirst</first>");

    /* Receive a reply, should succeed*/
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);

    /* Send rpc editing module edit1 on the other session */
    st->rpc = nc_rpc_edit(NC_DATASTORE_RUNNING, NC_RPC_EDIT_DFLTOP_MERGE, NC_RPC_EDIT_TESTOPT_SET,
            NC_RPC_EDIT_ERROPT_ROLLBACK, "<first xmlns=\"ed1\">TestFirst</first>", NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* Receive a reply, should fail */
    st->msgtype = nc_recv_reply(st->nc_sess2, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->envp)), "rpc-error");

    FREE_TEST_VARS(st);

    /* unlock */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
}

static void
test_unlock(void **state)
{
    struct np_test *st = *state;
    char *str2;

    /* Simple locking checked in previous tests */

    /* Lock by a different session */
    st->rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* receive reply */
    ASSERT_OK_REPLY_SESS2(st);

    FREE_TEST_VARS(st);

    /* Try unlocking a lock by a different session */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);

    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(st->msgtype, NC_MSG_RPC);

    /* recieve reply, should yield error */
    ASSERT_RPC_ERROR(st);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&st->str, st->envp, LYD_XML, 0));

    /* error expected */
    assert_int_not_equal(-1, asprintf(&str2, LOCK_FAIL_TEMPLATE, st->msgid,
            nc_session_get_id(st->nc_sess2)));
    assert_string_equal(st->str, str2);
    free(str2);

    FREE_TEST_VARS(st);

    /* Try unlocking the original session, should succeed */
    st->rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);

    st->msgtype = nc_send_rpc(st->nc_sess2, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve reply, should succeed */
    ASSERT_OK_REPLY_SESS2(st);

    FREE_TEST_VARS(st);
}

static void
test_get(void **state)
{
    struct np_test *st = *state;

    /* Try to get all */
    st->rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* receive reply, should succeed */
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->op);
    assert_non_null(st->envp);

    FREE_TEST_VARS(st);
}

static void
test_kill(void **state)
{
    struct np_test *st = *state;
    FILE *file;
    char name[128], *str, *str2;

    /* Try to close a session */
    st->rpc = nc_rpc_kill(nc_session_get_id(st->nc_sess));
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve reply, should fail since wrong permissions */
    ASSERT_RPC_ERROR(st);

    /* Get the error message */
    lyd_print_mem(&str, st->envp, LYD_XML, 0);

    /* Get the current user */
    assert_non_null(file = popen("whoami", "r"));
    fscanf(file, "%127s", name);
    fclose(file);

    /* Put user and message id into error template */
    assert_int_not_equal(-1, asprintf(&str2, KILL_FAIL_TEMPLATE, st->msgid, name));

    assert_string_equal(str, str2);

    free(str);
    free(str2);
    FREE_TEST_VARS(st);
    /* TODO: NACM tests */
}

static void
test_commit(void **state)
{
    struct np_test *st = *state;

    /* try committing config, there is no candidate */
    st->rpc = nc_rpc_commit(0, 0, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve a reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
    /* Funcionality tested in test_candidate.c */
}

static void
test_discard(void **state)
{
    struct np_test *st = *state;

    /* Try to close a session */
    st->rpc = nc_rpc_discard();
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve reply, should fail since wrong permissions */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
    /* Funcionality tested in  test_candidate.c */
}

static void
test_getconfig(void **state)
{
    struct np_test *st = *state;

    /* try getting config */
    st->rpc = nc_rpc_getconfig(NC_DATASTORE_RUNNING, NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve reply, should get configuration in op*/
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 2000, &st->envp, &st->op);
    assert_int_equal(st->msgtype, NC_MSG_REPLY);
    assert_non_null(st->op);
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(lyd_child(st->op)), "data");

    FREE_TEST_VARS(st);

    /* Functionality tested in test_edit.c */
}

static void
test_validate(void **state)
{
    struct np_test *st = *state;

    /* try validating config of the running datastore */
    st->rpc = nc_rpc_validate(NC_DATASTORE_RUNNING, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);

    /* recieve reply, should succeed */
    ASSERT_OK_REPLY(st);

    FREE_TEST_VARS(st);
    /* Funcionality tested in test_candidate.c */
}

static void
test_unsuported(void **state)
{
    struct np_test *st = *state;

    /* Testing RPCs unsupported by netopeer, all should fail */
    st->rpc = nc_rpc_cancel(NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_ERROR, st->msgtype);

    nc_rpc_free(st->rpc);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lock),
        cmocka_unit_test(test_unlock),
        cmocka_unit_test(test_get),
        cmocka_unit_test(test_kill),
        cmocka_unit_test(test_commit),
        cmocka_unit_test(test_discard),
        cmocka_unit_test(test_getconfig),
        cmocka_unit_test(test_validate),
        cmocka_unit_test(test_unsuported),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
