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
#include "np_test_config.h"

NP_GLOB_SETUP_FUNC

static void
test_lock(void **state)
{
    struct np_test *st = *state;
    struct nc_session *nc_sess2;
    struct nc_rpc *rpc;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;
    struct lyd_node *envp, *op;
    char *str, *str2;

    /* create another NETCONF session */
    nc_sess2 = nc_connect_unix(NP_SOCKET_PATH, NULL);
    assert_non_null(nc_sess2);

    /* lock RPC */
    rpc = nc_rpc_lock(NC_DATASTORE_RUNNING);
    assert_non_null(rpc);

    /* send request on session #1 */
    msgtype = nc_send_rpc(st->nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* receive reply */
    msgtype = nc_recv_reply(st->nc_sess, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_string_equal(LYD_NAME(lyd_child(envp)), "ok");
    lyd_free_tree(envp);

    /* send request on session #2 */
    msgtype = nc_send_rpc(nc_sess2, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* receive reply */
    msgtype = nc_recv_reply(nc_sess2, rpc, msgid, 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_null(op);
    assert_int_equal(LY_SUCCESS, lyd_print_mem(&str, envp, LYD_XML, LYD_PRINT_SHRINK));
    lyd_free_tree(envp);

    /* error expected */
    asprintf(&str2,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%d\">"
            "  <rpc-error>"
            "    <error-type>protocol</error-type>"
            "    <error-tag>lock-denied</error-tag>"
            "    <error-severity>error</error-severity>"
            "    <error-message lang=\"en\">Access to the requested lock is denied because the lock is currently held by another entity.</error-message>"
            "    <error-info>"
            "      <session-id>1</session-id>"
            "    </error-info>"
            "  </rpc-error>"
            "</rpc-reply>", (int)msgid);
    assert_string_equal(str, str2);
    free(str);
    free(str2);

    nc_rpc_free(rpc);

    /* unlock RPC */
    rpc = nc_rpc_unlock(NC_DATASTORE_RUNNING);
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

    nc_rpc_free(rpc);

    nc_session_free(nc_sess2, NULL);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_lock),
    };

    nc_verbosity(NC_VERB_WARNING);
    return cmocka_run_group_tests(tests, np_glob_setup, np_glob_teardown);
}
