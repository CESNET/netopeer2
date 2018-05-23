/**
 * @file test_copy_config.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv <copy-config> test.
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
#include <string.h>
#include <cmocka.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <fcntl.h>
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

    *schema_cnt = 4;

    *schemas = calloc(4, sizeof **schemas);

    (*schemas)[0].module_name = strdup("ietf-netconf-server");
    (*schemas)[0].installed = 1;

    (*schemas)[1].module_name = strdup("ietf-interfaces");
    (*schemas)[1].ns = strdup("urn:ietf:params:xml:ns:yang:ietf-interfaces");
    (*schemas)[1].prefix = strdup("if");
    (*schemas)[1].revision.revision = strdup("2014-05-08");
    (*schemas)[1].revision.file_path_yin = strdup(TESTS_DIR"/files/ietf-interfaces.yin");
    (*schemas)[1].enabled_features = malloc(sizeof(char *));
    (*schemas)[1].enabled_features[0] = strdup("if-mib");
    (*schemas)[1].enabled_feature_cnt = 1;
    (*schemas)[1].installed = 1;

    (*schemas)[2].module_name = strdup("ietf-ip");
    (*schemas)[2].ns = strdup("urn:ietf:params:xml:ns:yang:ietf-ip");
    (*schemas)[2].prefix = strdup("ip");
    (*schemas)[2].revision.revision = strdup("2014-06-16");
    (*schemas)[2].revision.file_path_yin = strdup(TESTS_DIR"/files/ietf-ip.yin");
    (*schemas)[2].enabled_features = malloc(2 * sizeof(char *));
    (*schemas)[2].enabled_features[0] = strdup("ipv4-non-contiguous-netmasks");
    (*schemas)[2].enabled_features[1] = strdup("ipv6-privacy-autoconf");
    (*schemas)[2].enabled_feature_cnt = 2;
    (*schemas)[2].installed = 1;

    (*schemas)[3].module_name = strdup("iana-if-type");
    (*schemas)[3].ns = strdup("urn:ietf:params:xml:ns:yang:iana-if-type");
    (*schemas)[3].prefix = strdup("if");
    (*schemas)[3].revision.revision = strdup("2014-05-08");
    (*schemas)[3].revision.file_path_yin = strdup(TESTS_DIR"/files/iana-if-type.yin");
    (*schemas)[3].installed = 1;

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
__wrap_sr_session_switch_ds(sr_session_ctx_t *session, sr_datastore_t ds)
{
    (void)session;
    (void)ds;

    return SR_ERR_OK;
}

void
__wrap_sr_free_val_iter(sr_val_iter_t *iter)
{
    if (iter) {
        free(iter);
    }
}

int
__wrap_sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts)
{
    (void)session;
    (void)value;
    (void)opts;
    static int count = 0;

    switch (count) {
    case 0:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']");
        break;
    case 1:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/description");
        break;
    case 2:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/type");
        break;
    case 3:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/enabled");
        break;
    case 4:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/link-up-down-trap-enable");
        break;
    case 5:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4");
        break;
    case 6:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4/enabled");
        break;
    case 7:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4/forwarding");
        break;
    case 8:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4/mtu");
        break;
    case 9:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4/neighbor[ip='10.0.0.2']");
        break;
    case 10:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv4/neighbor[ip='10.0.0.2']/link-layer-address");
        break;
    case 11:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6");
        break;
    case 12:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/enabled");
        break;
    case 13:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/forwarding");
        break;
    case 14:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/dup-addr-detect-transmits");
        break;
    case 15:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/autoconf/create-global-addresses");
        break;
    case 16:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/autoconf/create-temporary-addresses");
        break;
    case 17:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/autoconf/temporary-valid-lifetime");
        break;
    case 18:
        assert_string_equal(xpath, "/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6/autoconf/temporary-preferred-lifetime");
        break;
    }
    ++count;

    return SR_ERR_OK;
}

int
__wrap_sr_commit(sr_session_ctx_t *session)
{
    (void)session;
    return SR_ERR_OK;
}

int
__wrap_sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    (void)session;
    (void)xpath;
    (void)opts;

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
    for (ptr = strstr(buf, "+02:00"); ptr; ptr = strstr(ptr + 1, "+02:00")) {
        if ((ptr[-3] == ':') && (ptr[-6] == ':') && (ptr[-9] == 'T') && (ptr[-12] == '-') && (ptr[-15] == '-')) {
            strncpy(ptr - 19, "0000-00-00T00:00:00", 19);
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

    optind = 1;
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
test_edit_config(void **state)
{
    (void)state; /* unused */
    const char *copy_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<copy-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<source>"
                "<config>"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
    "<enabled>true</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
      "<enabled>true</enabled>"
      "<forwarding>true</forwarding>"
      "<mtu>68</mtu>"
      "<neighbor>"
        "<ip>10.0.0.2</ip>"
        "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
      "</neighbor>"
    "</ipv4>"
    "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
      "<enabled>true</enabled>"
      "<forwarding>false</forwarding>"
    "</ipv6>"
  "</interface>"
"</interfaces>"
                "</config>"
            "</source>"
        "</copy-config>"
    "</rpc>";
    const char *copy_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, copy_rpc, __LINE__);
    test_read(p_in, copy_rpl, __LINE__);
}

static void
test_startstop(void **state)
{
    (void)state; /* unused */
    return;
}


int
main(void)
{
    const struct CMUnitTest tests[] = {
                    cmocka_unit_test_setup(test_startstop, np_start),
                    cmocka_unit_test(test_edit_config),
                    cmocka_unit_test_teardown(test_startstop, np_stop),
    };

    if (setenv("CMOCKA_TEST_ABORT", "1", 1)) {
        fprintf(stderr, "Cannot set Cmocka thread environment variable.\n");
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
