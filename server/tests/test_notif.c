/**
 * @file test_notif.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv notification test.
 *
 * Copyright (c) 2016-2017 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
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

sr_event_notif_cb notif_clb;
void *notif_clb_data;

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

    *schema_cnt = 6;
    *schemas = calloc(6, sizeof **schemas);

    (*schemas)[0].module_name = strdup("ietf-netconf-server");
    (*schemas)[0].installed = 1;

    (*schemas)[1].module_name = strdup("ietf-netconf");
    (*schemas)[1].ns = strdup("urn:ietf:params:xml:ns:netconf:base:1.0");
    (*schemas)[1].prefix = strdup("nc");
    (*schemas)[1].revision.revision = strdup("2011-06-01");
    (*schemas)[1].revision.file_path_yin = strdup(TESTS_DIR"/files/ietf-netconf.yin");
    (*schemas)[1].installed = 1;

    (*schemas)[2].module_name = strdup("ietf-netconf-notifications");
    (*schemas)[2].ns = strdup("urn:ietf:params:xml:ns:yang:ietf-netconf-notifications");
    (*schemas)[2].prefix = strdup("ncn");
    (*schemas)[2].revision.revision = strdup("2012-02-06");
    (*schemas)[2].revision.file_path_yin = strdup(TESTS_DIR"/files/ietf-netconf-notifications.yin");
    (*schemas)[2].installed = 1;

    (*schemas)[3].module_name = strdup("notifications");
    (*schemas)[3].ns = strdup("urn:ietf:params:xml:ns:netconf:notification:1.0");
    (*schemas)[3].prefix = strdup("ncEvent");
    (*schemas)[3].revision.revision = strdup("2008-07-14");
    (*schemas)[3].revision.file_path_yin = strdup(TESTS_DIR"/files/notifications.yin");
    (*schemas)[3].installed = 1;

    (*schemas)[4].module_name = strdup("nc-notifications");
    (*schemas)[4].ns = strdup("urn:ietf:params:xml:ns:netmod:notification");
    (*schemas)[4].prefix = strdup("manageEvent");
    (*schemas)[4].revision.revision = strdup("2008-07-14");
    (*schemas)[4].revision.file_path_yin = strdup(TESTS_DIR"/files/nc-notifications.yin");
    (*schemas)[4].installed = 1;

    (*schemas)[5].module_name = strdup("test-notif");
    (*schemas)[5].ns = strdup("urn:libyang:test:notif");
    (*schemas)[5].prefix = strdup("tn");
    (*schemas)[5].revision.revision = strdup("2017-03-22");
    (*schemas)[5].revision.file_path_yin = strdup(TESTS_DIR"/files/test-notif.yin");
    (*schemas)[5].installed = 1;

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

int
__wrap_sr_session_refresh(sr_session_ctx_t *session)
{
    (void)session;
    return SR_ERR_OK;
}

int
__wrap_sr_module_install_subscribe(sr_session_ctx_t *session, sr_module_install_cb callback, void *private_ctx,
                                   sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    (void)session;
    (void)callback;
    (void)private_ctx;
    (void)opts;
    (void)subscription;
    return SR_ERR_OK;
}

int
__wrap_sr_feature_enable_subscribe(sr_session_ctx_t *session, sr_feature_enable_cb callback, void *private_ctx,
                                   sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    (void)session;
    (void)callback;
    (void)private_ctx;
    (void)opts;
    (void)subscription;
    return SR_ERR_OK;
}

int
__wrap_sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, sr_module_change_cb callback,
                                  void *private_ctx, uint32_t priority, sr_subscr_options_t opts,
                                  sr_subscription_ctx_t **subscription)
{
    (void)session;
    (void)module_name;
    (void)callback;
    (void)private_ctx;
    (void)priority;
    (void)opts;
    (void)subscription;
    return SR_ERR_OK;
}

int
__wrap_sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt)
{
    (void)session;
    (void)xpath;
    *values = NULL;
    *value_cnt = 0;
    return SR_ERR_OK;
}

int
__wrap_sr_event_notif_send(sr_session_ctx_t *session, const char *xpath, const sr_val_t *values,
                           const size_t values_cnt, sr_ev_notif_flag_t opts)
{
    (void)session;
    (void)xpath;
    (void)values;
    (void)values_cnt;
    (void)opts;
    return SR_ERR_OK;
}

int
__wrap_sr_event_notif_subscribe(sr_session_ctx_t *session, const char *xpath, sr_event_notif_cb callback,
                                void *private_ctx, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription)
{
    (void)session;
    (void)opts;
    (void)subscription;

    printf("test: New subscription to %s\n", xpath);
    notif_clb = callback;
    notif_clb_data = private_ctx;
    return SR_ERR_OK;
}

int
__wrap_sr_event_notif_replay(sr_session_ctx_t *session, sr_subscription_ctx_t *subscription, time_t start_time,
                             time_t stop_time)
{
    (void)session;
    (void)subscription;
    (void)start_time;
    (void)stop_time;
    return SR_ERR_OK;
}

int
__wrap_sr_check_exec_permission(sr_session_ctx_t *session, const char *xpath, bool *permitted)
{
    (void)session;
    (void)xpath;
    *permitted = true;
    return SR_ERR_OK;
}

/*
 * LIBNETCONF2 WRAPPER FUNCTIONS
 */
NC_MSG_TYPE
__wrap_nc_accept(int timeout, struct nc_session **session)
{
    static int no = 1;
    NC_MSG_TYPE ret;

    if (!initialized) {
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
        (*session)->id = no;
        (*session)->ti_lock = malloc(sizeof *(*session)->ti_lock);
        pthread_mutex_init((*session)->ti_lock, NULL);
        (*session)->ti_cond = malloc(sizeof *(*session)->ti_cond);
        pthread_cond_init((*session)->ti_cond, NULL);
        (*session)->ti_inuse = malloc(sizeof *(*session)->ti_inuse);
        *(*session)->ti_inuse = 0;
        (*session)->ti_type = NC_TI_FD;
        (*session)->ti.fd.in = pipes[1][0];
        (*session)->ti.fd.out = pipes[0][1];
        (*session)->ctx = np2srv.ly_ctx;
        (*session)->flags = 1; //shared ctx
        (*session)->username = "user1";
        (*session)->host = "localhost";
        (*session)->opts.server.session_start = (*session)->opts.server.last_rpc = time(NULL);
        printf("test: New session %d\n", no++);
        initialized = 1;
        ret = NC_MSG_HELLO;
    } else {
        usleep(timeout * 1000);
        ret = NC_MSG_WOULDBLOCK;
    }

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
    pthread_cond_destroy(session->ti_cond);
    free(session->ti_cond);
    free((int *)session->ti_inuse);
    free(session);
}

int
__wrap_nc_server_endpt_count(void)
{
    return 1;
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
static void
test_write(int fd, const char *data, int line)
{
    int ret, written, to_write;

    written = 0;
    to_write = strlen(data);
    do {
        ret = write(fd, data + written, to_write - written);
        if (ret == -1) {
            if (errno != EAGAIN) {
                fprintf(stderr, "write fail (%s, line %d)\n", strerror(errno), line);
                fail();
            }
            usleep(100000);
            ret = 0;
        }
        written += ret;
    } while (written < to_write);

    while (((ret = write(fd, "]]>]]>", 6)) == -1) && (errno == EAGAIN));
    if (ret == -1) {
        fprintf(stderr, "write fail (%s, line %d)\n", strerror(errno), line);
        fail();
    } else if (ret < 6) {
        fprintf(stderr, "write fail (end tag, written only %d bytes, line %d)\n", ret, line);
        fail();
    }
}

static void
test_read(int fd, const char *template, int line)
{
    char *buf, *ptr;
    int ret, red, to_read;

    red = 0;
    to_read = strlen(template);
    buf = malloc(to_read + 1);
    do {
        ret = read(fd, buf + red, to_read - red);
        if (ret == -1) {
            if (errno != EAGAIN) {
                fprintf(stderr, "read fail (%s, line %d)\n", strerror(errno), line);
                fail();
            }
            usleep(100000);
            ret = 0;
        }
        red += ret;

        /* premature ending tag check */
        if ((red > 5) && !strncmp((buf + red) - 6, "]]>]]>", 6)) {
            break;
        }
    } while (red < to_read);
    buf[red] = '\0';

    /* unify all datetimes */
    for (ptr = strchr(buf, '-'); ptr; ptr = strchr(ptr + 1, '-')) {
        if ((ptr[3] == '-') && (ptr[6] == 'T') && (ptr[9] == ':') && (ptr[12] == ':')) {
            strncpy(ptr - 4, "0000-00-00T00:00:00", 19);
        }
    }

    for (red = 0; buf[red]; ++red) {
        if (buf[red] != template[red]) {
            fprintf(stderr, "read fail (non-matching template, line %d)\n\"%s\"(%d)\nvs. template\n\"%s\"\n",
                    line, buf + red, red, template + red);
            fail();
        }
    }

    /* read ending tag */
    while (((ret = read(fd, buf, 6)) == -1) && (errno == EAGAIN));
    if (ret == -1) {
        fprintf(stderr, "read fail (%s, line %d)\n", strerror(errno), line);
        fail();
    }
    buf[ret] = '\0';
    if ((ret < 6) || strcmp(buf, "]]>]]>")) {
        fprintf(stderr, "read fail (end tag \"%s\", line %d)\n", buf, line);
        fail();
    }

    free(buf);
}

static int
np_start(void **state)
{
    (void)state;
    control = LOOP_CONTINUE;
    initialized = 1;
    assert_int_equal(pthread_create(&server_tid, NULL, server_thread, NULL), 0);

    return 0;
}

static int
np_stop(void **state)
{
    (void)state;
    int64_t ret;

    control = LOOP_STOP;
    assert_int_equal(pthread_join(server_tid, (void **)&ret), 0);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    return 0;
}

static void
test_basic(void **state)
{
    (void)state; /* unused */
    sr_val_t *vals;
    size_t val_cnt;
    const char *subsc_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
            "<stream>NETCONF</stream>"
        "</create-subscription>"
    "</rpc>";
    const char *subsc_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *notif_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<netconf-session-start xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
          "<username>test</username>"
          "<session-id>1</session-id>"
          "<source-host>127.0.0.1</source-host>"
        "</netconf-session-start>"
    "</notification>";

    initialized = 0;
    while (!initialized) {
        usleep(100000);
    }

    test_write(p_out, subsc_rpc, __LINE__);
    test_read(p_in, subsc_rpl, __LINE__);

    /* send notif */
    val_cnt = 3;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/username");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("test");

    vals[1].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/session-id");
    vals[1].type = SR_UINT32_T;
    vals[1].data.uint32_val = 1;

    vals[2].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/source-host");
    vals[2].type = SR_STRING_T;
    vals[2].data.string_val = strdup("127.0.0.1");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/ietf-netconf-notifications:netconf-session-start", vals, val_cnt, time(NULL), notif_clb_data);

    sr_free_values(vals, val_cnt);

    /* read notif */
    test_read(p_in, notif_data, __LINE__);
}

static void
test_filter_xpath(void **state)
{
    (void)state; /* unused */
    sr_val_t *vals;
    size_t val_cnt;
    const char *subsc_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
            "<stream>NETCONF</stream>"
            "<filter xmlns:ncn=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\" type=\"xpath\" select=\"/ncn:netconf-session-start/username\"/>"
        "</create-subscription>"
    "</rpc>";
    const char *subsc_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *notif_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<netconf-session-start xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
          "<username>test</username>"
        "</netconf-session-start>"
    "</notification>";

    initialized = 0;
    while (!initialized) {
        usleep(100000);
    }

    test_write(p_out, subsc_rpc, __LINE__);
    test_read(p_in, subsc_rpl, __LINE__);

    /* send notif 1 */
    val_cnt = 3;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/username");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("test");

    vals[1].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/session-id");
    vals[1].type = SR_UINT32_T;
    vals[1].data.uint32_val = 1;

    vals[2].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/source-host");
    vals[2].type = SR_STRING_T;
    vals[2].data.string_val = strdup("127.0.0.1");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/ietf-netconf-notifications:netconf-session-start", vals, val_cnt, time(NULL), notif_clb_data);

    sr_free_values(vals, val_cnt);

    /* send notif 2 */
    val_cnt = 1;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/test-notif:test-notif1/l1");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("value");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/test-notif:test-notif1", vals, val_cnt, time(NULL), notif_clb_data);

    sr_free_values(vals, val_cnt);

    /* read filtered notif */
    test_read(p_in, notif_data, __LINE__);
}

static void
test_filter_subtree(void **state)
{
    (void)state; /* unused */
    sr_val_t *vals;
    size_t val_cnt;
    const char *subsc_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
            "<stream>NETCONF</stream>"
            "<filter xmlns:ncn=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\" type=\"subtree\">"
                "<netconf-session-start xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
                    "<session-id/>"
                "</netconf-session-start>"
            "</filter>"
        "</create-subscription>"
    "</rpc>";
    const char *subsc_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *notif_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<netconf-session-start xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
          "<session-id>1</session-id>"
        "</netconf-session-start>"
    "</notification>";

    initialized = 0;
    while (!initialized) {
        usleep(100000);
    }

    test_write(p_out, subsc_rpc, __LINE__);
    test_read(p_in, subsc_rpl, __LINE__);

    /* send notif 1 */
    val_cnt = 3;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/username");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("test");

    vals[1].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/session-id");
    vals[1].type = SR_UINT32_T;
    vals[1].data.uint32_val = 1;

    vals[2].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/source-host");
    vals[2].type = SR_STRING_T;
    vals[2].data.string_val = strdup("127.0.0.1");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/ietf-netconf-notifications:netconf-session-start", vals, val_cnt, time(NULL), notif_clb_data);

    sr_free_values(vals, val_cnt);

    /* send notif 2 */
    val_cnt = 1;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/test-notif:test-notif1/l1");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("value");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/test-notif:test-notif1", vals, val_cnt, time(NULL), notif_clb_data);

    sr_free_values(vals, val_cnt);

    /* read filtered notif */
    test_read(p_in, notif_data, __LINE__);
}

static void
test_replay(void **state)
{
    (void)state; /* unused */
    sr_val_t *vals;
    time_t cur_time;
    size_t val_cnt;
    char *subsc_rpc, *start, *end;
    const char *subsc_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *notif1_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<netconf-session-start xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<username>test</username>"
            "<session-id>1</session-id>"
            "<source-host>127.0.0.1</source-host>"
        "</netconf-session-start>"
    "</notification>";
    const char *notif2_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<test-notif1 xmlns=\"urn:libyang:test:notif\">"
          "<l1>value</l1>"
        "</test-notif1>"
    "</notification>";
    const char *rpl_comp_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<replayComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>"
    "</notification>";
    const char *notif_comp_data =
    "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
        "<eventTime>0000-00-00T00:00:00Z</eventTime>"
        "<notificationComplete xmlns=\"urn:ietf:params:xml:ns:netmod:notification\"/>"
    "</notification>";

    /* new session */
    initialized = 0;
    while (!initialized) {
        usleep(100000);
    }

    /* subscribe */
    cur_time = time(NULL);
    start = nc_time2datetime(cur_time - 5, NULL, NULL);
    end = nc_time2datetime(cur_time + 5, NULL, NULL);
    asprintf(&subsc_rpc,
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<create-subscription xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">"
            "<stream>NETCONF</stream>"
            "<startTime>%s</startTime>"
            "<stopTime>%s</stopTime>"
        "</create-subscription>"
    "</rpc>", start, end);
    free(start);
    free(end);

    test_write(p_out, subsc_rpc, __LINE__);
    free(subsc_rpc);

    test_read(p_in, subsc_rpl, __LINE__);

    /* send notif 1 */
    val_cnt = 3;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/username");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("test");

    vals[1].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/session-id");
    vals[1].type = SR_UINT32_T;
    vals[1].data.uint32_val = 1;

    vals[2].xpath = strdup("/ietf-netconf-notifications:netconf-session-start/source-host");
    vals[2].type = SR_STRING_T;
    vals[2].data.string_val = strdup("127.0.0.1");

    notif_clb(SR_EV_NOTIF_T_REPLAY, "/ietf-netconf-notifications:netconf-session-start", vals, val_cnt, cur_time - 1, notif_clb_data);
    sr_free_values(vals, val_cnt);

    /* send notif 2 */
    val_cnt = 1;
    vals = calloc(val_cnt, sizeof *vals);

    vals[0].xpath = strdup("/test-notif:test-notif1/l1");
    vals[0].type = SR_STRING_T;
    vals[0].data.string_val = strdup("value");

    notif_clb(SR_EV_NOTIF_T_REALTIME, "/test-notif:test-notif1", vals, val_cnt, cur_time - 3, notif_clb_data);
    sr_free_values(vals, val_cnt);

    /* send 2 replay complete */
    notif_clb(SR_EV_NOTIF_T_REPLAY_COMPLETE, "does-not-matter", NULL, 0, cur_time, notif_clb_data);
    notif_clb(SR_EV_NOTIF_T_REPLAY_COMPLETE, "does-not-matter", NULL, 0, cur_time, notif_clb_data);

    /* send 2 notification complete */
    notif_clb(SR_EV_NOTIF_T_REPLAY_STOP, "does-not-matter", NULL, 0, cur_time + 5, notif_clb_data);
    notif_clb(SR_EV_NOTIF_T_REPLAY_STOP, "does-not-matter", NULL, 0, cur_time + 5, notif_clb_data);

    /* read notif 2 */
    test_read(p_in, notif2_data, __LINE__);
    /* read notif 1 */
    test_read(p_in, notif1_data, __LINE__);
    /* read replay complete */
    test_read(p_in, rpl_comp_data, __LINE__);
    /* read notification complete */
    test_read(p_in, notif_comp_data, __LINE__);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
                    cmocka_unit_test_setup(test_basic, np_start),
                    cmocka_unit_test(test_filter_xpath),
                    cmocka_unit_test(test_filter_subtree),
                    cmocka_unit_test_teardown(test_replay, np_stop),
    };

    if (setenv("CMOCKA_TEST_ABORT", "1", 1)) {
        fprintf(stderr, "Cannot set Cmocka thread environment variable.\n");
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
