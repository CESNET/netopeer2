/**
 * @file test_edit_config.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief Cmocka np2srv <edit-config> test.
 *
 * Copyright (c) 2016 CESNET, z.s.p.o.
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

#include "config.h"
#include "tests/config.h"

#define main server_main
#undef NP2SRV_PIDFILE
#define NP2SRV_PIDFILE "/tmp/test_np2srv.pid"

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
#define URL_TESTFILE "/tmp/nc2_validate_config.xml"
#endif

#include "../main.c"

#undef main

/* should be accessed from one thread only */
struct lyd_node *data = NULL;
ATOMIC_UINT32_T initialized;
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

int
__wrap_sr_get_items_iter(sr_session_ctx_t *session, const char *xpath, sr_val_iter_t **iter)
{
    (void)session;

    *iter = (sr_val_iter_t *)strdup(xpath);

    return SR_ERR_OK;
}

int
__wrap_sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value)
{
    static struct ly_set *ietf_if_set = NULL;
    const char *xpath = (const char *)iter;
    char *path;
    const char *ietf_interfaces_xpath = "/ietf-interfaces:";
    size_t ietf_interfaces_xpath_len = strlen(ietf_interfaces_xpath);
    const char *test_feature_c_xpath = "/test-feature-c:";
    size_t test_feature_c_xpath_len = strlen(test_feature_c_xpath);
    const char *simplified_melt_xpath = "/simplified-melt:";
    size_t simplified_melt_xpath_len = strlen(simplified_melt_xpath);
    (void)session;

    if (!strncmp(xpath, ietf_interfaces_xpath, ietf_interfaces_xpath_len) ||
        !strncmp(xpath, test_feature_c_xpath, test_feature_c_xpath_len) ||
        !strncmp(xpath, simplified_melt_xpath, simplified_melt_xpath_len)) {

        if (data == NULL) {
            return SR_ERR_NOT_FOUND;
        }

        if (!ietf_if_set) {
            ietf_if_set = lyd_find_path(data, xpath);
        }

        if (!ietf_if_set->number) {
            ly_set_free(ietf_if_set);
            ietf_if_set = NULL;
            return SR_ERR_NOT_FOUND;
        }

        path = lyd_path(ietf_if_set->set.d[0]);

        /* Copied from sysrepo rp_dt_create_xpath_for_node() */

        /* remove leaf-list predicate */
        if (LYS_LEAFLIST & ietf_if_set->set.d[0]->schema->nodetype) {
           char *leaf_list_name = strstr(path, "[.='");
           if (NULL != leaf_list_name) {
               *leaf_list_name = 0;
           } else if (NULL != (leaf_list_name = strstr(path, "[.=\""))) {
               *leaf_list_name = 0;
           }
        }
        /* End copy */

        *value = calloc(1, sizeof **value);
        op_set_srval(ietf_if_set->set.d[0], path, 1, *value, NULL);
        (*value)->dflt = ietf_if_set->set.d[0]->dflt;
        free(path);

        --ietf_if_set->number;
        if (ietf_if_set->number) {
            memmove(ietf_if_set->set.d, ietf_if_set->set.d + 1, ietf_if_set->number * sizeof(void *));
        }
    } else {
        *value = NULL;
        return SR_ERR_NOT_FOUND;
    }

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
    char buf[128];
    int opt = 0;

    if (opts & SR_EDIT_NON_RECURSIVE) {
        opt |= LYD_PATH_OPT_NOPARENT;
    }
    if (!(opts & SR_EDIT_STRICT)) {
        opt |= LYD_PATH_OPT_UPDATE;
    }

    switch (value->type) {
    case SR_LIST_T:
    case SR_CONTAINER_T:
    case SR_CONTAINER_PRESENCE_T:
    case SR_LEAF_EMPTY_T:
        ly_errno = LY_SUCCESS;
        lyd_new_path(data, np2srv.ly_ctx, xpath, NULL, 0, opt);
        if ((ly_errno == LY_EVALID) && (ly_vecode(np2srv.ly_ctx) == LYVE_PATH_EXISTS)) {
            return SR_ERR_DATA_EXISTS;
        }
        assert_int_equal(ly_errno, LY_SUCCESS);
        break;
    default:
        ly_errno = LY_SUCCESS;
        lyd_new_path(data, np2srv.ly_ctx, xpath, op_get_srval(np2srv.ly_ctx, (sr_val_t *)value, buf), 0, opt);
        if ((ly_errno == LY_EVALID) && (ly_vecode(np2srv.ly_ctx) == LYVE_PATH_EXISTS)) {
            return SR_ERR_DATA_EXISTS;
        }
        assert_int_equal(ly_errno, LY_SUCCESS);
        break;
    }

    return SR_ERR_OK;
}

int
__wrap_sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts)
{
    (void)session;
    struct ly_set *set;
    uint32_t i;

    if (data == NULL) {
        if (opts & SR_EDIT_STRICT) {
            return SR_ERR_DATA_MISSING;
        }
        return SR_ERR_OK;
    }

    set = lyd_find_path(data, xpath);
    if ((opts & SR_EDIT_STRICT) && (set == NULL)) {
        return SR_ERR_DATA_MISSING;
    }
    if ((opts & SR_EDIT_STRICT) && !set->number) {
        ly_set_free(set);
        return SR_ERR_DATA_MISSING;
    }
    for (i = 0; i < set->number; ++i) {
        if ((opts & SR_EDIT_NON_RECURSIVE) && set->set.d[i]->child) {
            ly_set_free(set);
            return SR_ERR_UNSUPPORTED;
        }

        if (set->set.d[i] == data) {
            data = set->set.d[i]->next;
        }
        lyd_free(set->set.d[i]);
    }
    ly_set_free(set);

    return SR_ERR_OK;
}

int
__wrap_sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *relative_item)
{
    (void)session;
    struct ly_set *set, *set2 = NULL;
    struct lyd_node *node;

    set = lyd_find_path(data, xpath);
    assert_ptr_not_equal(set, NULL);
    assert_int_equal(set->number, 1);

    switch (position) {
    case SR_MOVE_BEFORE:
        set2 = lyd_find_path(data, relative_item);
        assert_ptr_not_equal(set2, NULL);
        assert_int_equal(set2->number, 1);

        assert_int_equal(lyd_insert_before(set2->set.d[0], set->set.d[0]), 0);
        break;
    case SR_MOVE_AFTER:
        set2 = lyd_find_path(data, relative_item);
        assert_ptr_not_equal(set2, NULL);
        assert_int_equal(set2->number, 1);

        assert_int_equal(lyd_insert_after(set2->set.d[0], set->set.d[0]), 0);
        break;
    case SR_MOVE_FIRST:
        node = set->set.d[0]->parent->child;

        assert_int_equal(lyd_insert_before(node, set->set.d[0]), 0);
        break;
    case SR_MOVE_LAST:
        node = set->set.d[0]->parent->child->prev;

        assert_int_equal(lyd_insert_after(node, set->set.d[0]), 0);
        break;
    }

    ly_set_free(set);
    ly_set_free(set2);
    return SR_ERR_OK;
}

int
__wrap_sr_commit(sr_session_ctx_t *session)
{
    (void)session;
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

int
__wrap_sr_session_set_options(sr_session_ctx_t *session, const sr_sess_options_t opts)
{
    (void)session;
    (void)opts;
    return SR_ERR_OK;
}

/*
 * LIBNETCONF2 WRAPPER FUNCTIONS
 */
NC_MSG_TYPE
__wrap_nc_accept(int timeout, struct nc_session **session)
{
    NC_MSG_TYPE ret;

    if (!ATOMIC_LOAD(initialized)) {
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
        (*session)->io_lock = malloc(sizeof *(*session)->io_lock);
        pthread_mutex_init((*session)->io_lock, NULL);
        (*session)->opts.server.rpc_lock = malloc(sizeof *(*session)->opts.server.rpc_lock);
        pthread_mutex_init((*session)->opts.server.rpc_lock, NULL);
        (*session)->opts.server.rpc_cond = malloc(sizeof *(*session)->opts.server.rpc_cond);
        pthread_cond_init((*session)->opts.server.rpc_cond, NULL);
        (*session)->opts.server.rpc_inuse = malloc(sizeof *(*session)->opts.server.rpc_inuse);
        *(*session)->opts.server.rpc_inuse = 0;
        (*session)->ti_type = NC_TI_FD;
        (*session)->ti.fd.in = pipes[1][0];
        (*session)->ti.fd.out = pipes[0][1];
        (*session)->ctx = np2srv.ly_ctx;
        (*session)->flags = 1; //shared ctx
        (*session)->username = "user1";
        (*session)->host = "localhost";
        (*session)->opts.server.session_start = (*session)->opts.server.last_rpc = time(NULL);
        printf("test: New session 1\n");
        ATOMIC_STORE(initialized, 1);
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
    pthread_mutex_destroy(session->io_lock);
    free(session->io_lock);
    pthread_mutex_destroy(session->opts.server.rpc_lock);
    free(session->opts.server.rpc_lock);
    pthread_cond_destroy(session->opts.server.rpc_cond);
    free(session->opts.server.rpc_cond);
    free((int *)session->opts.server.rpc_inuse);
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

static int
np_start(void **state)
{
    (void)state; /* unused */

    optind = 1;
    control = LOOP_CONTINUE;
    ATOMIC_STORE(initialized, 0);
    assert_int_equal(pthread_create(&server_tid, NULL, server_thread, NULL), 0);

    while (!ATOMIC_LOAD(initialized)) {
        usleep(100000);
    }

    return 0;
}

static int
np_stop(void **state)
{
    (void)state; /* unused */
    int64_t ret;

    lyd_free_withsiblings(data);

    control = LOOP_STOP;
    assert_int_equal(pthread_join(server_tid, (void **)&ret), 0);

    close(pipes[0][0]);
    close(pipes[0][1]);
    close(pipes[1][0]);
    close(pipes[1][1]);

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
    unlink(URL_TESTFILE);
#endif
    return ret;
}

static void
test_validate_config(void **state)
{
    (void)state; /* unused */

    const char *validate_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<validate>"
        "<source>"
          "<config>"
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">"
              "<interface>"
                "<name>iface1</name>"
                "<description>iface1 dsc</description>"
                "<type>ianaift:ethernetCsmacd</type>"
                "<enabled>true</enabled>"
                "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
                "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                  "<enabled>true</enabled>"
                  "<forwarding>true</forwarding>"
                  "<mtu>68</mtu>"
                  "<address>"
                    "<ip>10.0.0.1</ip>"
                    "<netmask>255.0.0.0</netmask>"
                  "</address>"
                  "<address>"
                    "<ip>172.0.0.1</ip>"
                    "<prefix-length>16</prefix-length>"
                  "</address>"
                  "<neighbor>"
                    "<ip>10.0.0.2</ip>"
                    "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
                  "</neighbor>"
                "</ipv4>"
                "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                  "<enabled>true</enabled>"
                  "<forwarding>false</forwarding>"
                  "<mtu>1280</mtu>"
                  "<address>"
                    "<ip>2001:abcd:ef01:2345:6789:0:1:1</ip>"
                    "<prefix-length>64</prefix-length>"
                  "</address>"
                  "<neighbor>"
                    "<ip>2001:abcd:ef01:2345:6789:0:1:2</ip>"
                    "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
                  "</neighbor>"
                  "<dup-addr-detect-transmits>52</dup-addr-detect-transmits>"
                  "<autoconf>"
                    "<create-global-addresses>true</create-global-addresses>"
                    "<create-temporary-addresses>false</create-temporary-addresses>"
                    "<temporary-valid-lifetime>600</temporary-valid-lifetime>"
                    "<temporary-preferred-lifetime>300</temporary-preferred-lifetime>"
                  "</autoconf>"
                "</ipv6>"
              "</interface>"
              "<interface>"
                "<name>iface2</name>"
                "<description>iface2 dsc</description>"
                "<type>ianaift:softwareLoopback</type>"
                "<enabled>false</enabled>"
                "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
                "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                  "<mtu>2000</mtu>"
                  "<address>"
                    "<ip>10.0.0.5</ip>"
                    "<netmask>255.0.0.0</netmask>"
                  "</address>"
                  "<address>"
                    "<ip>172.0.0.5</ip>"
                    "<prefix-length>16</prefix-length>"
                  "</address>"
                  "<neighbor>"
                    "<ip>10.0.0.1</ip>"
                    "<link-layer-address>01:34:56:78:9a:bc:de:fa</link-layer-address>"
                  "</neighbor>"
                "</ipv4>"
                "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                  "<address>"
                    "<ip>2001:abcd:ef01:2345:6789:0:1:5</ip>"
                    "<prefix-length>64</prefix-length>"
                  "</address>"
                  "<neighbor>"
                    "<ip>2001:abcd:ef01:2345:6789:0:1:1</ip>"
                    "<link-layer-address>01:34:56:78:9a:bc:de:fa</link-layer-address>"
                  "</neighbor>"
                  "<dup-addr-detect-transmits>100</dup-addr-detect-transmits>"
                  "<autoconf>"
                    "<create-global-addresses>true</create-global-addresses>"
                    "<create-temporary-addresses>false</create-temporary-addresses>"
                    "<temporary-valid-lifetime>600</temporary-valid-lifetime>"
                    "<temporary-preferred-lifetime>300</temporary-preferred-lifetime>"
                  "</autoconf>"
                "</ipv6>"
              "</interface>"
            "</interfaces>"
            "<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
              "<test-leaf>green</test-leaf>"
            "</test-container>"
            "<melt xmlns=\"urn:ietf:params:xml:ns:yang:simplified-melt\">"
              "<pmd-profile>"
                "<name>melt-pmd-01</name>"
                "<measurement-class>melt-cdcr</measurement-class>"
              "</pmd-profile>"
            "</melt>"
          "</config>"
        "</source>"
      "</validate>"
    "</rpc>";
    const char *validate_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, validate_config_rpc, __LINE__);
    test_read(p_in, validate_config_rpl, __LINE__);
}

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
static void
test_validate_url(void **state)
{
    (void)state; /* unused */

    const char *validate_config_data =
    "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\" xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">"
        "<interface>"
          "<name>iface1</name>"
          "<description>iface1 dsc</description>"
          "<type>ianaift:ethernetCsmacd</type>"
          "<enabled>true</enabled>"
          "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
          "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "<enabled>true</enabled>"
            "<forwarding>true</forwarding>"
            "<mtu>68</mtu>"
            "<address>"
              "<ip>10.0.0.1</ip>"
              "<netmask>255.0.0.0</netmask>"
            "</address>"
            "<address>"
              "<ip>172.0.0.1</ip>"
              "<prefix-length>16</prefix-length>"
            "</address>"
            "<neighbor>"
              "<ip>10.0.0.2</ip>"
              "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
            "</neighbor>"
          "</ipv4>"
          "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "<enabled>true</enabled>"
            "<forwarding>false</forwarding>"
            "<mtu>1280</mtu>"
            "<address>"
              "<ip>2001:abcd:ef01:2345:6789:0:1:1</ip>"
              "<prefix-length>64</prefix-length>"
            "</address>"
            "<neighbor>"
              "<ip>2001:abcd:ef01:2345:6789:0:1:2</ip>"
              "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
            "</neighbor>"
            "<dup-addr-detect-transmits>52</dup-addr-detect-transmits>"
            "<autoconf>"
              "<create-global-addresses>true</create-global-addresses>"
              "<create-temporary-addresses>false</create-temporary-addresses>"
              "<temporary-valid-lifetime>600</temporary-valid-lifetime>"
              "<temporary-preferred-lifetime>300</temporary-preferred-lifetime>"
            "</autoconf>"
          "</ipv6>"
        "</interface>"
        "<interface>"
          "<name>iface2</name>"
          "<description>iface2 dsc</description>"
          "<type>ianaift:softwareLoopback</type>"
          "<enabled>false</enabled>"
          "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
          "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "<mtu>2000</mtu>"
            "<address>"
              "<ip>10.0.0.5</ip>"
              "<netmask>255.0.0.0</netmask>"
            "</address>"
            "<address>"
              "<ip>172.0.0.5</ip>"
              "<prefix-length>16</prefix-length>"
            "</address>"
            "<neighbor>"
              "<ip>10.0.0.1</ip>"
              "<link-layer-address>01:34:56:78:9a:bc:de:fa</link-layer-address>"
            "</neighbor>"
          "</ipv4>"
          "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
            "<address>"
              "<ip>2001:abcd:ef01:2345:6789:0:1:5</ip>"
              "<prefix-length>64</prefix-length>"
            "</address>"
            "<neighbor>"
              "<ip>2001:abcd:ef01:2345:6789:0:1:1</ip>"
              "<link-layer-address>01:34:56:78:9a:bc:de:fa</link-layer-address>"
            "</neighbor>"
            "<dup-addr-detect-transmits>100</dup-addr-detect-transmits>"
            "<autoconf>"
              "<create-global-addresses>true</create-global-addresses>"
              "<create-temporary-addresses>false</create-temporary-addresses>"
              "<temporary-valid-lifetime>600</temporary-valid-lifetime>"
              "<temporary-preferred-lifetime>300</temporary-preferred-lifetime>"
            "</autoconf>"
          "</ipv6>"
        "</interface>"
      "</interfaces>"
      "<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
        "<test-leaf>green</test-leaf>"
      "</test-container>"
      "<melt xmlns=\"urn:ietf:params:xml:ns:yang:simplified-melt\">"
        "<pmd-profile>"
          "<name>melt-pmd-01</name>"
          "<measurement-class>melt-cdcr</measurement-class>"
        "</pmd-profile>"
      "</melt>"
    "</config>";

    const char *validate_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<validate>"
            "<source>"
                "<url>file://" URL_TESTFILE "</url>"
            "</source>"
        "</validate>"
    "</rpc>";
    const char *validate_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    FILE *f = fopen(URL_TESTFILE, "w");
    fprintf(f, "%s", validate_config_data);
    fclose(f);

    test_write(p_out, validate_config_rpc, __LINE__);
    test_read(p_in, validate_config_rpl, __LINE__);
}
#endif

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
                    cmocka_unit_test(test_validate_config),

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
                    cmocka_unit_test(test_validate_url),
#endif

                    cmocka_unit_test_teardown(test_startstop, np_stop),
    };

    if (setenv("CMOCKA_TEST_ABORT", "1", 1)) {
        fprintf(stderr, "Cannot set Cmocka thread environment variable.\n");
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
