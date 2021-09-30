/**
 * @file test_parallel_sessions.c
 * @author * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for sending parallel requests on more threads
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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>

#include "np_test.h"
#include "np_test_config.h"

#define THREAD_COUNT 3

static int
local_setup(void **state)
{
    char test_name[256];
    int rv;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rv = np_glob_setup_env(test_name);
    assert_int_equal(rv, 0);

    return np_glob_setup_np2(state, test_name);
}

struct thread_arg {
    const char *socket_path;
    pthread_barrier_t barrier;
};

static void *
send_get_rpc(void *arg)
{
    struct thread_arg *targ = arg;
    struct nc_rpc *rpc;
    struct nc_session *nc_sess;
    struct lyd_node *envp, *op;
    NC_MSG_TYPE msgtype;
    uint64_t msgid;

    /* create a NETCONF session */
    nc_sess = nc_connect_unix(targ->socket_path, NULL);
    assert_non_null(nc_sess);
    pthread_barrier_wait(&targ->barrier);

    /* Send get rpc */
    rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* recieve reply, should succeed */
    msgtype = nc_recv_reply(nc_sess, rpc, msgid, THREAD_COUNT * 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    assert_non_null(op);
    assert_non_null(envp);

    nc_rpc_free(rpc);
    lyd_free_tree(op);
    lyd_free_tree(envp);

    /* stop the NETCONF session */
    nc_session_free(nc_sess, NULL);

    return NULL;
}

static void
test_first(void **state)
{
    struct np_test *st = *state;
    pthread_t t[THREAD_COUNT];
    struct thread_arg targ;

    targ.socket_path = st->socket_path;
    pthread_barrier_init(&targ.barrier, NULL, THREAD_COUNT);

    for (uint32_t i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&t[i], NULL, send_get_rpc, &targ);
    }
    for (uint32_t i = 0; i < THREAD_COUNT; i++) {
        pthread_join(t[i], NULL);
    }
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_first),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, np_glob_teardown);
}
