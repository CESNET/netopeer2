/**
 * @file test_start.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv start.
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"

#define main server_main
#include "../config.h"
#undef NP2SRV_PIDFILE
#define NP2SRV_PIDFILE "/tmp/test_np2srv.pid"

#include "../main.c"

#undef main

/*
 * SYSREPO WRAPPER FUNCTIONS
 */

int
__wrap_sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_ctx)
{
    (void)app_name;
    (void)opts;
    (void)conn_ctx;
    return SR_ERR_OK;
}

int
__wrap_sr_session_start(sr_conn_ctx_t *conn_ctx, const sr_datastore_t datastore,
                        const sr_sess_options_t opts, sr_session_ctx_t **session)
{
    (void)conn_ctx;
    (void)datastore;
    (void)opts;
    (void)session;
    return SR_ERR_OK;
}

int
__wrap_sr_list_schemas(sr_session_ctx_t *session, sr_schema_t **schemas, size_t *schema_cnt)
{
    (void)session;
    *schemas = NULL;
    *schema_cnt = 0;
    return SR_ERR_OK;
}

int
__wrap_sr_get_schema(sr_session_ctx_t *session, const char *module_name, const char *revision,
                     const char *submodule_name, sr_schema_format_t format, char **schema_content)
{
    (void)session;
    (void)module_name;
    (void)revision;
    (void)submodule_name;
    (void)format;
    (void)schema_content;
    return SR_ERR_OK;
}

void
__wrap_sr_free_schemas(sr_schema_t *schemas, size_t count)
{
    (void)schemas;
    (void)count;
}

int
__wrap_sr_session_start_user(sr_conn_ctx_t *conn_ctx, const char *user_name, const sr_datastore_t datastore,
                             const sr_sess_options_t opts, sr_session_ctx_t **session)
{
    (void)conn_ctx;
    (void)user_name;
    (void)datastore;
    (void)opts;
    (void)session;
    return SR_ERR_OK;
}

int
__wrap_sr_session_stop(sr_session_ctx_t *session)
{
    (void)session;
    return SR_ERR_OK;
}

void
__wrap_sr_disconnect(sr_conn_ctx_t *conn_ctx)
{
    (void)conn_ctx;
}

/*
 * LIBNETCONF2 WRAPPER FUNCTIONS
 */
int
__wrap_nc_server_ssh_add_endpt_listen(const char *name, const char *address, uint16_t port)
{
    (void)name;
    (void)address;
    (void)port;
    return 0;
}

int
__wrap_nc_server_ssh_endpt_set_hostkey(const char *endpt_name, const char *privkey_path)
{
    (void)endpt_name;
    (void)privkey_path;
    return 0;
}

/*
 * SERVER THREAD
 */
pthread_t server_tid;
static void *
server_thread(void *arg)
{
    (void)arg;
    char *argv[] = {"netopeer2-server", "-d", "-v2"};

    return (void *)(int64_t)server_main(3, argv);
}

/*
 * TEST
 */
static int
np_start(void **state)
{
    (void)state; /* unused */

    return pthread_create(&server_tid, NULL, server_thread, NULL);
}

static int
np_stop(void **state)
{
    (void)state; /* unused */
    int64_t ret;

    control = LOOP_STOP;
    assert_int_equal(pthread_join(server_tid, (void **)&ret), 0);
    return ret;
}

static void
test_dummy(void **state)
{
    (void)state; /* unused */
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
                    cmocka_unit_test_setup_teardown(test_dummy, np_start, np_stop),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
