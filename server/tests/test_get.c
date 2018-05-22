/**
 * @file test_get.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv <get> test.
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
#include <errno.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>

#include "tests/config.h"

#define main server_main
#include "config.h"
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

    *schemas = calloc(1, sizeof **schemas);
    *schema_cnt = 1;
    (*schemas)[0].module_name = strdup("ietf-netconf-server");
    (*schemas)[0].installed = 1;

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
        (*session)->id = 1;
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
        printf("test: New session 1\n");
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
    for (ptr = strchr(buf, '+'); ptr; ptr = strchr(ptr + 1, '+')) {
        if ((ptr[-3] == ':') && (ptr[-6] == ':') && (ptr[-9] == 'T') && (ptr[-12] == '-') && (ptr[-15] == '-')) {
            strncpy(ptr - 19, "0000-00-00T00:00:00+00:00", 25);
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
    (void)state; /* unused */

    control = LOOP_CONTINUE;
    initialized = 0;
    assert_int_equal(pthread_create(&server_tid, NULL, server_thread, NULL), 0);

    while (!initialized) {
        usleep(100000);
    }

    return 0;
}

static int
np_stop(void **state)
{
    (void)state; /* unused */
    int64_t ret;

    control = LOOP_STOP;
    assert_int_equal(pthread_join(server_tid, (void **)&ret), 0);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);
    return ret;
}

static void
test_get(void **state)
{
    (void)state; /* unused */
    const char *get_rpc = "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><get/></rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<yang-library xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
            "<module-set>"
                "<name>complete</name>"
                "<checksum>15</checksum>"
                "<import-only-module>"
                    "<name>ietf-yang-metadata</name>"
                    "<revision>2016-08-05</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                "</import-only-module>"
                "<module>"
                    "<name>yang</name>"
                    "<revision>2017-02-20</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                "</module>"
                "<import-only-module>"
                    "<name>ietf-inet-types</name>"
                    "<revision>2013-07-15</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                "</import-only-module>"
                "<import-only-module>"
                    "<name>ietf-yang-types</name>"
                    "<revision>2013-07-15</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                "</import-only-module>"
                "<import-only-module>"
                    "<name>ietf-datastores</name>"
                    "<revision>2017-08-17</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                "</import-only-module>"
                "<module>"
                    "<name>ietf-yang-library</name>"
                    "<revision>2018-01-17</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-server</name>"
                    "<namespace>ns</namespace>"
                "</module>"
                "<import-only-module>"
                    "<name>ietf-netconf-acm</name>"
                    "<revision>2012-02-22</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                "</import-only-module>"
                "<module>"
                    "<name>ietf-netconf</name>"
                    "<revision>2011-06-01</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                    "<feature>"
                        "<name>writable-running</name>"
                    "</feature>"
                    "<feature>"
                        "<name>candidate</name>"
                    "</feature>"
                    "<feature>"
                        "<name>rollback-on-error</name>"
                    "</feature>"
                    "<feature>"
                        "<name>validate</name>"
                    "</feature>"
                    "<feature>"
                        "<name>startup</name>"
                    "</feature>"
                    "<feature>"
                        "<name>xpath</name>"
                    "</feature>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-monitoring</name>"
                    "<revision>2010-10-04</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-with-defaults</name>"
                    "<revision>2011-06-01</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                "</module>"
                "<module>"
                    "<name>notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                "</module>"
                "<module>"
                    "<name>nc-notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-notifications</name>"
                    "<revision>2012-02-06</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                "</module>"
            "</module-set>"
            "<checksum>15</checksum>"
        "</yang-library>"
        "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
            "<module>"
                "<name>ietf-yang-metadata</name>"
                "<revision>2016-08-05</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                "<conformance-type>import</conformance-type>"
            "</module>"
            "<module>"
                "<name>yang</name>"
                "<revision>2017-02-20</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-inet-types</name>"
                "<revision>2013-07-15</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                "<conformance-type>import</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-yang-types</name>"
                "<revision>2013-07-15</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                "<conformance-type>import</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-datastores</name>"
                "<revision>2017-08-17</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                "<conformance-type>import</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-yang-library</name>"
                "<revision>2018-01-17</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf-server</name>"
                "<revision/>"
                "<namespace>ns</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf-acm</name>"
                "<revision>2012-02-22</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                "<conformance-type>import</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf</name>"
                "<revision>2011-06-01</revision>"
                "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                "<feature>writable-running</feature>"
                "<feature>candidate</feature>"
                "<feature>rollback-on-error</feature>"
                "<feature>validate</feature>"
                "<feature>startup</feature>"
                "<feature>xpath</feature>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf-monitoring</name>"
                "<revision>2010-10-04</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf-with-defaults</name>"
                "<revision>2011-06-01</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>notifications</name>"
                "<revision>2008-07-14</revision>"
                "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>nc-notifications</name>"
                "<revision>2008-07-14</revision>"
                "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module>"
                "<name>ietf-netconf-notifications</name>"
                "<revision>2012-02-06</revision>"
                "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                "<conformance-type>implement</conformance-type>"
            "</module>"
            "<module-set-id>15</module-set-id>"
        "</modules-state>"
        "<netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
            "<capabilities>"
                "<capability>urn:ietf:params:netconf:base:1.0</capability>"
                "<capability>urn:ietf:params:netconf:base:1.1</capability>"
                "<capability>urn:ietf:params:netconf:capability:writable-running:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:candidate:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:rollback-on-error:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:validate:1.1</capability>"
                "<capability>urn:ietf:params:netconf:capability:startup:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:xpath:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:with-defaults:1.0?basic-mode=explicit&amp;also-supported=report-all,report-all-tagged,trim,explicit</capability>"
                "<capability>urn:ietf:params:netconf:capability:notification:1.0</capability>"
                "<capability>urn:ietf:params:netconf:capability:interleave:1.0</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-yang-metadata?module=ietf-yang-metadata&amp;revision=2016-08-05</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:1?module=yang&amp;revision=2017-02-20</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-inet-types?module=ietf-inet-types&amp;revision=2013-07-15</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-yang-types?module=ietf-yang-types&amp;revision=2013-07-15</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-yang-library?revision=2018-01-17&amp;module-set-id=15</capability>"
                "<capability>ns?module=ietf-netconf-server</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-acm?module=ietf-netconf-acm&amp;revision=2012-02-22</capability>"
                "<capability>urn:ietf:params:xml:ns:netconf:base:1.0?module=ietf-netconf&amp;revision=2011-06-01&amp;features=writable-running,candidate,rollback-on-error,validate,startup,xpath</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&amp;revision=2010-10-04</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults?module=ietf-netconf-with-defaults&amp;revision=2011-06-01</capability>"
                "<capability>urn:ietf:params:xml:ns:netconf:notification:1.0?module=notifications&amp;revision=2008-07-14</capability>"
                "<capability>urn:ietf:params:xml:ns:netmod:notification?module=nc-notifications&amp;revision=2008-07-14</capability>"
                "<capability>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications?module=ietf-netconf-notifications&amp;revision=2012-02-06</capability>"
            "</capabilities>"
            "<datastores>"
                "<datastore>"
                    "<name>running</name>"
                "</datastore>"
                "<datastore>"
                    "<name>startup</name>"
                "</datastore>"
                "<datastore>"
                    "<name>candidate</name>"
                "</datastore>"
            "</datastores>"
            "<schemas>"
                "<schema>"
                    "<identifier>ietf-yang-metadata</identifier>"
                    "<version>2016-08-05</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-yang-metadata</identifier>"
                    "<version>2016-08-05</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>yang</identifier>"
                    "<version>2017-02-20</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>yang</identifier>"
                    "<version>2017-02-20</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-inet-types</identifier>"
                    "<version>2013-07-15</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-inet-types</identifier>"
                    "<version>2013-07-15</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-yang-types</identifier>"
                    "<version>2013-07-15</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-yang-types</identifier>"
                    "<version>2013-07-15</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-datastores</identifier>"
                    "<version>2017-08-17</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-datastores</identifier>"
                    "<version>2017-08-17</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-yang-library</identifier><version>2018-01-17</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-yang-library</identifier>"
                    "<version>2018-01-17</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-server</identifier>"
                    "<version/>"
                    "<format>yang</format>"
                    "<namespace>ns</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-server</identifier>"
                    "<version/>"
                    "<format>yin</format>"
                    "<namespace>ns</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-acm</identifier>"
                    "<version>2012-02-22</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-acm</identifier>"
                    "<version>2012-02-22</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf</identifier>"
                    "<version>2011-06-01</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf</identifier>"
                    "<version>2011-06-01</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-monitoring</identifier>"
                    "<version>2010-10-04</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-monitoring</identifier>"
                    "<version>2010-10-04</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-with-defaults</identifier>"
                    "<version>2011-06-01</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-with-defaults</identifier>"
                    "<version>2011-06-01</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>notifications</identifier>"
                    "<version>2008-07-14</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>notifications</identifier>"
                    "<version>2008-07-14</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>nc-notifications</identifier>"
                    "<version>2008-07-14</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>nc-notifications</identifier>"
                    "<version>2008-07-14</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-notifications</identifier>"
                    "<version>2012-02-06</version>"
                    "<format>yang</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
                "<schema>"
                    "<identifier>ietf-netconf-notifications</identifier>"
                    "<version>2012-02-06</version>"
                    "<format>yin</format>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                    "<location>NETCONF</location>"
                "</schema>"
            "</schemas>"
            "<statistics>"
                "<netconf-start-time>0000-00-00T00:00:00+00:00</netconf-start-time>"
                "<in-bad-hellos>0</in-bad-hellos>"
                "<in-sessions>0</in-sessions>"
                "<dropped-sessions>0</dropped-sessions>"
                "<in-rpcs>0</in-rpcs>"
                "<in-bad-rpcs>0</in-bad-rpcs>"
                "<out-rpc-errors>0</out-rpc-errors>"
                "<out-notifications>0</out-notifications>"
            "</statistics>"
        "</netconf-state>"
        "<netconf xmlns=\"urn:ietf:params:xml:ns:netmod:notification\">"
            "<streams>"
                "<stream>"
                    "<name>NETCONF</name>"
                    "<description>Default NETCONF stream containing all the Event Notifications.</description>"
                    "<replaySupport>true</replaySupport>"
                "</stream>"
                "<stream>"
                    "<name>ietf-yang-library</name>"
                    "<replaySupport>false</replaySupport>"
                "</stream>"
                "<stream>"
                    "<name>nc-notifications</name>"
                    "<replaySupport>true</replaySupport>"
                "</stream>"
                "<stream>"
                    "<name>ietf-netconf-notifications</name>"
                    "<replaySupport>true</replaySupport>"
                "</stream>"
            "</streams>"
        "</netconf>"
    "</data>"
"</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter1(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter2(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
                "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                    "<module>"
                        "<conformance-type>implement</conformance-type>"
                    "</module>"
                "</modules-state>"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                "<module>"
                    "<name>yang</name>"
                    "<revision>2017-02-20</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-yang-library</name>"
                    "<revision>2018-01-17</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-server</name>"
                    "<revision/>"
                    "<namespace>ns</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf</name>"
                    "<revision>2011-06-01</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                    "<feature>writable-running</feature>"
                    "<feature>candidate</feature>"
                    "<feature>rollback-on-error</feature>"
                    "<feature>validate</feature>"
                    "<feature>startup</feature>"
                    "<feature>xpath</feature>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-monitoring</name>"
                    "<revision>2010-10-04</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-with-defaults</name>"
                    "<revision>2011-06-01</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>nc-notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-notifications</name>"
                    "<revision>2012-02-06</revision>"
                    "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
            "</modules-state>"
        "</data>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter3(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
                "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                    "<module>"
                        "<name/>"
                        "<conformance-type>implement</conformance-type>"
                    "</module>"
                "</modules-state>"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                "<module>"
                    "<name>yang</name>"
                    "<revision>2017-02-20</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-yang-library</name>"
                    "<revision>2018-01-17</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-server</name>"
                    "<revision/>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf</name>"
                    "<revision>2011-06-01</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-monitoring</name>"
                    "<revision>2010-10-04</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-with-defaults</name>"
                    "<revision>2011-06-01</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>nc-notifications</name>"
                    "<revision>2008-07-14</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-notifications</name>"
                    "<revision>2012-02-06</revision>"
                    "<conformance-type>implement</conformance-type>"
                "</module>"
            "</modules-state>"
        "</data>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter4(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
                "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                    "<module>"
                        "<name/>"
                        "<feature/>"
                    "</module>"
                "</modules-state>"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<modules-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-library\">"
                "<module>"
                    "<name>ietf-yang-metadata</name>"
                    "<revision>2016-08-05</revision>"
                "</module>"
                "<module>"
                    "<name>yang</name>"
                    "<revision>2017-02-20</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-inet-types</name>"
                    "<revision>2013-07-15</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-yang-types</name>"
                    "<revision>2013-07-15</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-datastores</name>"
                    "<revision>2017-08-17</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-yang-library</name>"
                    "<revision>2018-01-17</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-server</name>"
                    "<revision/>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-acm</name>"
                    "<revision>2012-02-22</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf</name>"
                    "<revision>2011-06-01</revision>"
                    "<feature>writable-running</feature>"
                    "<feature>candidate</feature>"
                    "<feature>rollback-on-error</feature>"
                    "<feature>validate</feature>"
                    "<feature>startup</feature>"
                    "<feature>xpath</feature>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-monitoring</name>"
                    "<revision>2010-10-04</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-with-defaults</name>"
                    "<revision>2011-06-01</revision>"
                "</module>"
                "<module>"
                    "<name>notifications</name>"
                    "<revision>2008-07-14</revision>"
                "</module>"
                "<module>"
                    "<name>nc-notifications</name>"
                    "<revision>2008-07-14</revision>"
                "</module>"
                "<module>"
                    "<name>ietf-netconf-notifications</name>"
                    "<revision>2012-02-06</revision>"
                "</module>"
            "</modules-state>"
        "</data>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter5(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
                "<netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
                    "<schemas>"
                        "<schema/>"
                    "</schemas>"
                "</netconf-state>"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
                "<schemas>"
                    "<schema>"
                        "<identifier>ietf-yang-metadata</identifier>"
                        "<version>2016-08-05</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-yang-metadata</identifier>"
                        "<version>2016-08-05</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-metadata</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>yang</identifier>"
                        "<version>2017-02-20</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>yang</identifier>"
                        "<version>2017-02-20</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:1</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-inet-types</identifier>"
                        "<version>2013-07-15</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-inet-types</identifier>"
                        "<version>2013-07-15</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-inet-types</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-yang-types</identifier>"
                        "<version>2013-07-15</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-yang-types</identifier>"
                        "<version>2013-07-15</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-types</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-datastores</identifier>"
                        "<version>2017-08-17</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-datastores</identifier>"
                        "<version>2017-08-17</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-datastores</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-yang-library</identifier>"
                        "<version>2018-01-17</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-yang-library</identifier>"
                        "<version>2018-01-17</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-yang-library</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-server</identifier>"
                        "<version/>"
                        "<format>yang</format>"
                        "<namespace>ns</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-server</identifier>"
                        "<version/>"
                        "<format>yin</format>"
                        "<namespace>ns</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-acm</identifier>"
                        "<version>2012-02-22</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-acm</identifier>"
                        "<version>2012-02-22</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-acm</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf</identifier>"
                        "<version>2011-06-01</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf</identifier>"
                        "<version>2011-06-01</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:netconf:base:1.0</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-monitoring</identifier>"
                        "<version>2010-10-04</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-monitoring</identifier>"
                        "<version>2010-10-04</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-with-defaults</identifier>"
                        "<version>2011-06-01</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-with-defaults</identifier>"
                        "<version>2011-06-01</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-with-defaults</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>notifications</identifier>"
                        "<version>2008-07-14</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>notifications</identifier>"
                        "<version>2008-07-14</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:netconf:notification:1.0</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>nc-notifications</identifier>"
                        "<version>2008-07-14</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>nc-notifications</identifier>"
                        "<version>2008-07-14</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:netmod:notification</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-notifications</identifier>"
                        "<version>2012-02-06</version>"
                        "<format>yang</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                    "<schema>"
                        "<identifier>ietf-netconf-notifications</identifier>"
                        "<version>2012-02-06</version>"
                        "<format>yin</format>"
                        "<namespace>urn:ietf:params:xml:ns:yang:ietf-netconf-notifications</namespace>"
                        "<location>NETCONF</location>"
                    "</schema>"
                "</schemas>"
            "</netconf-state>"
        "</data>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

static void
test_get_filter6(void **state)
{
    (void)state; /* unused */
    const char *get_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get>"
            "<filter type=\"subtree\">"
                "<netconf-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">"
                    "<schemas>"
                        "<schema>"
                            "<identifier>ietf-yang-metadata</identifier>"
                            "<version>2016-08-08</version>"
                        "</schema>"
                    "</schemas>"
                "</netconf-state>"
            "</filter>"
        "</get>"
    "</rpc>";
    const char *get_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"/>"
    "</rpc-reply>";

    test_write(p_out, get_rpc, __LINE__);
    test_read(p_in, get_rpl, __LINE__);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
                    cmocka_unit_test_setup(test_get, np_start),
                    cmocka_unit_test(test_get_filter1),
                    cmocka_unit_test(test_get_filter2),
                    cmocka_unit_test(test_get_filter3),
                    cmocka_unit_test(test_get_filter4),
                    cmocka_unit_test(test_get_filter5),
                    cmocka_unit_test_teardown(test_get_filter6, np_stop),
    };

    if (setenv("CMOCKA_TEST_ABORT", "1", 1)) {
        fprintf(stderr, "Cannot set Cmocka thread environment variable.\n");
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
