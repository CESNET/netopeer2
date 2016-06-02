/**
 * @file test_close_session.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv <close-session> test.
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
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

#include "config.h"

#define main server_main
#include "../config.h"
#undef NP2SRV_PIDFILE
#define NP2SRV_PIDFILE "/tmp/test_np2srv.pid"

#include "../main.c"

#undef main

volatile int initialized;
int pipes[2][2], p_in, p_out;

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
struct nc_session {
    NC_STATUS status;
    NC_SESSION_TERM_REASON term_reason;
    int side;

    uint32_t id;
    int version;
    volatile pthread_t *ntf_tid;

    NC_TRANSPORT_IMPL ti_type;
    pthread_mutex_t *ti_lock;
    union {
        struct {
            int in;
            int out;
        } fd;
#ifdef NC_ENABLED_SSH
        struct {
            void *channel;
            void *session;
            struct nc_session *next;
        } libssh;
#endif
#ifdef NC_ENABLED_TLS
        void *tls;
#endif
    } ti;
    const char *username;
    const char *host;
    uint16_t port;

    struct ly_ctx *ctx;
    void *data;
    uint8_t flags;

    /* client side only data */
    uint64_t msgid;
    const char **cpblts;
    struct nc_msg_cont *replies;
    struct nc_msg_cont *notifs;

    /* server side only data */
    time_t session_start;
    time_t last_rpc;
};

struct nc_pollsession {
    struct pollfd *pfds;
    struct nc_session **sessions;
    uint16_t session_count;

    pthread_cond_t cond;
    pthread_mutex_t lock;
    uint8_t queue[6];
    uint8_t queue_begin;
    uint8_t queue_len;
};

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

NC_MSG_TYPE
__wrap_nc_accept(int timeout, struct nc_session **session)
{
    (void)timeout;
    static int calls = 0;
    NC_MSG_TYPE ret;

    if (!calls) {
        pipe(pipes[0]);
        pipe(pipes[1]);

        fcntl(pipes[0][0], F_SETFL, O_NONBLOCK);
        fcntl(pipes[0][1], F_SETFL, O_NONBLOCK);
        fcntl(pipes[1][0], F_SETFL, O_NONBLOCK);
        fcntl(pipes[1][1], F_SETFL, O_NONBLOCK);

        p_in = pipes[0][0];
        p_out = pipes[1][1];

        *session = calloc(1, sizeof **session);
        (*session)->status = NC_STATUS_RUNNING;
        (*session)->side = 1;
        (*session)->id = 1;
        (*session)->ti_lock = malloc(sizeof *(*session)->ti_lock);
        pthread_mutex_init((*session)->ti_lock, NULL);
        (*session)->ti_type = NC_TI_FD;
        (*session)->ti.fd.in = pipes[1][0];
        (*session)->ti.fd.out = pipes[0][1];
        (*session)->ctx = np2srv.ly_ctx;
        (*session)->flags = 1; //shared ctx
        (*session)->username = "user1";
        (*session)->host = "localhost";
        (*session)->session_start = (*session)->last_rpc = time(NULL);
        printf("test: New session 1\n");
        initialized = 1;
        ret = NC_MSG_HELLO;
    } else {
        ret = NC_MSG_WOULDBLOCK;
    }

    ++calls;
    return ret;
}

void
__wrap_nc_session_free(struct nc_session *session, void (*data_free)(void *))
{
    if (data_free) {
        data_free(session->data);
    }
    pthread_mutex_destroy(session->ti_lock);
    free(session->ti_lock);
    free(session);
}

void
__wrap_nc_ps_clear(struct nc_pollsession *ps, int all, void (*data_free)(void *))
{
    int i;

    if (!all) {
        fail();
    }

    for (i = 0; i < ps->session_count; ++i) {
        for (i = 0; i < ps->session_count; i++) {
            nc_session_free(ps->sessions[i], data_free);
        }
        free(ps->sessions);
        ps->sessions = NULL;
        free(ps->pfds);
        ps->pfds = NULL;
        ps->session_count = 0;
    }
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
test_new_session(void **state)
{
    (void)state; /* unused */
    const char *close_session_rpc = "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><close-session/></rpc>";
    const char *close_session_rpl = "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><ok/></rpc-reply>";
    char buf[1024];

    while (!initialized) {
        usleep(100000);
    }

    assert_int_equal(write(p_out, close_session_rpc, strlen(close_session_rpc)), strlen(close_session_rpc));
    assert_int_equal(write(p_out, "]]>]]>", 6), 6);

    while ((read(p_in, buf, strlen(close_session_rpl)) == -1) && (errno == EAGAIN)) {
        usleep(100000);
    }
    buf[strlen(close_session_rpl)] = '\0';
    assert_string_equal(buf, close_session_rpl);
    assert_int_equal(read(p_in, buf, 6), 6);
    buf[6] = '\0';
    assert_string_equal(buf, "]]>]]>");

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
                    cmocka_unit_test_setup_teardown(test_new_session, np_start, np_stop),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
