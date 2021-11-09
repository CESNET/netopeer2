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

static void
recv_reply_error_print(struct np_test *st, const struct lyd_node *op, const struct lyd_node *envp)
{
    char *path, *line = NULL;
    size_t line_len = 0;
    FILE *f;

    /* print op */
    printf("op:\n");
    if (op) {
        lyd_print_file(stdout, op, LYD_XML, 0);
    }
    printf("\n");

    /* print envelope */
    printf("envp:\n");
    if (envp) {
        lyd_print_file(stdout, envp, LYD_XML, 0);
    }
    printf("\n");

    /* print netopeer2 log */
    printf("np2 log:\n");
    assert_int_not_equal(-1, asprintf(&path, "%s/%s/%s", NP_SR_REPOS_DIR, st->test_name, NP_LOG_FILE));
    f = fopen(path, "r");
    free(path);
    if (!f) {
        printf("Opening netopeer2 log file failed.\n");
        return;
    }
    while (getline(&line, &line_len, f) != -1) {
        fputs(line, stdout);
    }
    free(line);
    fclose(f);
}

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
    nc_sess = nc_connect_unix(targ->st->socket_path, NULL);
    assert_non_null(nc_sess);
    pthread_barrier_wait(&targ->barrier);

    /* Send get rpc */
    rpc = nc_rpc_get(NULL, NC_WD_ALL, NC_PARAMTYPE_CONST);
    msgtype = nc_send_rpc(nc_sess, rpc, 1000, &msgid);
    assert_int_equal(msgtype, NC_MSG_RPC);

    /* recieve reply, should succeed */
    msgtype = nc_recv_reply(nc_sess, rpc, msgid, THREAD_COUNT * 2000, &envp, &op);
    assert_int_equal(msgtype, NC_MSG_REPLY);
    if (!op || !envp) {
        recv_reply_error_print(targ->st, op, envp);
        fail();
    }

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

    targ.st = st;
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
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
