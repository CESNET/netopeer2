/**
 * @file test_parallel_sessions.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for sending parallel requests on more threads
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

#include <pthread.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
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
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    return np_glob_setup_np2(state, test_name, NULL, 0);
}

static int
local_teardown(void **state)
{
    if (!*state) {
        return 0;
    }

    /* close netopeer2 server */
    return np_glob_teardown(state, NULL, 0);
}

struct thread_arg {
    struct np_test *st;
    pthread_barrier_t barrier;
};

/* TEST */
static void *
send_get_thread(void *arg)
{
    struct thread_arg *targ = arg;
    struct np_test state = {0}, *st = &state;
    struct nc_session *nc_sess;
    NC_MSG_TYPE msgtype;

    /* create a NETCONF session */
    nc_sess = nc_connect_unix(targ->st->socket_path, NULL);
    assert_non_null(nc_sess);
    pthread_barrier_wait(&targ->barrier);

    /* send get rpc */
    st->rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);
    ASSERT_DATA_REPLY_PARAM(nc_sess, THREAD_COUNT * 2000, st);
    FREE_TEST_VARS(st);

    /* stop the NETCONF session */
    nc_session_free(nc_sess, NULL);

    return NULL;
}

static void
test_get(void **state)
{
    struct np_test *st = *state;
    pthread_t t[THREAD_COUNT];
    struct thread_arg targ;
    uint32_t i;

    targ.st = st;
    pthread_barrier_init(&targ.barrier, NULL, THREAD_COUNT);

    for (i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&t[i], NULL, send_get_thread, &targ);
    }
    for (i = 0; i < THREAD_COUNT; i++) {
        pthread_join(t[i], NULL);
    }
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_get),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
