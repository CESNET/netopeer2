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
#define URL_TESTFILE "/tmp/nc2_edit_config.xml"
#endif

#include "../main.c"

#undef main

struct lyd_node *data;
ATOMIC_T initialized;
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

    set = lyd_find_path(data, xpath);
    assert_ptr_not_equal(set, NULL);

    if ((opts & SR_EDIT_STRICT) && !set->number) {
        ly_set_free(set);
        return SR_ERR_DATA_MISSING;
    }
    for (i = 0; i < set->number; ++i) {
        if ((opts & SR_EDIT_NON_RECURSIVE) && set->set.d[i]->child) {
            ly_set_free(set);
            return SR_ERR_UNSUPPORTED;
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

    if (!ATOMIC_LOAD_FENCE(initialized)) {
        pipe(pipes[0]);
        pipe(pipes[1]);

        fcntl(pipes[0][0], F_SETFL, O_NONBLOCK);
        fcntl(pipes[0][1], F_SETFL, O_NONBLOCK);
        fcntl(pipes[1][0], F_SETFL, O_NONBLOCK);
        fcntl(pipes[1][1], F_SETFL, O_NONBLOCK);

        p_in = pipes[0][0];
        p_out = pipes[1][1];

        ATOMIC_STORE_FENCE(initialized, 1);

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
    const char *ietf_if_data =
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
"</interfaces>";
    (void)state; /* unused */

    optind = 1;
    ATOMIC_STORE_RELAXED(control, LOOP_CONTINUE);
    ATOMIC_STORE_FENCE(initialized, 0);
    assert_int_equal(pthread_create(&server_tid, NULL, server_thread, NULL), 0);

    while (!ATOMIC_LOAD_FENCE(initialized)) {
        usleep(100000);
    }

    data = lyd_parse_mem(np2srv.ly_ctx, ietf_if_data, LYD_XML, LYD_OPT_CONFIG);
    assert_ptr_not_equal(data, NULL);

    return 0;
}

static int
np_stop(void **state)
{
    (void)state; /* unused */
    int64_t ret;

    lyd_free_withsiblings(data);

    ATOMIC_STORE_RELAXED(control, LOOP_STOP);
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
test_edit_delete1(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
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
  "</interface>"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
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
  "</interface>"
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface>"
                        "<name>iface1</name>"
                        "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\" op:operation=\"delete\"/>"
                    "</interface>"
                    "<interface>"
                        "<name>iface2</name>"
                        "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\" op:operation=\"delete\"/>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_delete2(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
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
  "</interface>"
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface op:operation=\"delete\">"
                        "<name>iface1</name>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_delete3(void **state)
{
    (void)state; /* unused */
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface op:operation=\"delete\">"
                        "<name>non-existent</name>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<rpc-error>"
            "<error-type>application</error-type>"
            "<error-tag>data-missing</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-path>/ietf-interfaces:interfaces/interface[name='non-existent']</error-path>"
            "<error-message xml:lang=\"en\">Request could not be completed because the relevant data model content does not exist.</error-message>"
        "</rpc-error>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);
}

static void
test_edit_delete4(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "</interface>"
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface>"
                        "<name>iface2</name>"
                        "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                            "<mtu op:operation=\"delete\"/>"
                        "</ipv4>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_create1(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "</interface>"
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
  "</interface>"
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface op:operation=\"create\">"
                        "<name>iface1</name>"
                        "<description>iface1 dsc</description>"
                        "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_create2(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "</interface>"
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
    "<enabled>true</enabled>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\"/>"
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
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface>"
                        "<name>iface1</name>"
                        "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
                        "<enabled>true</enabled>"
                        "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\" op:operation=\"create\"/>"
                        "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\" op:operation=\"create\">"
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
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_create3(void **state)
{
    (void)state; /* unused */
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface>"
                        "<name>iface1</name>"
                        "<ipv6 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\" op:operation=\"create\"/>"
                    "</interface>"
                "</interfaces>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<rpc-error>"
            "<error-type>application</error-type>"
            "<error-tag>data-exists</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-path>/ietf-interfaces:interfaces/interface[name='iface1']/ietf-ip:ipv6</error-path>"
            "<error-message xml:lang=\"en\">Request could not be completed because the relevant data model content already exists.</error-message>"
        "</rpc-error>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);
}

static void
test_edit_merge1(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
    "<enabled>true</enabled>"
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
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
  "</interface>"
"</interfaces>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
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
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_merge2(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
    "<enabled>true</enabled>"
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
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
  "</interface>"
"</interfaces>"
"<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
  "<test-leaf>green</test-leaf>"
"</test-container>"
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config>"
"<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
  "<test-leaf>green</test-leaf>"
"</test-container>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_merge3(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
"<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
  "<interface>"
    "<name>iface2</name>"
    "<description>iface2 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
    "<enabled>false</enabled>"
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
    "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
  "<interface>"
    "<name>iface1</name>"
    "<description>iface1 dsc</description>"
    "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
    "<enabled>true</enabled>"
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
    "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
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
        "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<config>"
"<melt xmlns=\"urn:ietf:params:xml:ns:yang:simplified-melt\">"
  "<pmd-profile>"
    "<name>melt-pmd-01</name>"
    "<measurement-class>melt-cdcr</measurement-class>"
  "</pmd-profile>"
"</melt>"
            "</config>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
static void
test_edit_delete_url(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
          "<interface>"
            "<name>iface2</name>"
            "<description>iface2 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
            "<enabled>false</enabled>"
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
          "<interface>"
            "<name>iface1</name>"
            "<description>iface1 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>true</enabled>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
              "<enabled>true</enabled>"
              "<forwarding>true</forwarding>"
              "<mtu>68</mtu>"
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
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
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
      "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<url>file://" URL_TESTFILE "</url>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *edit_data =
    "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "<interface>"
                "<name>iface1</name>"
                "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                    "<address op:operation=\"delete\">"
                      "<ip>10.0.0.1</ip>"
                      "<netmask>255.0.0.0</netmask>"
                    "</address>"
                "</ipv4>"
            "</interface>"
        "</interfaces>"
    "</config>";

    FILE* xmlfile = fopen(URL_TESTFILE, "w");
    fprintf(xmlfile, "%s", edit_data);
    fclose(xmlfile);

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_create_url(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
          "<interface>"
            "<name>iface2</name>"
            "<description>iface2 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
            "<enabled>false</enabled>"
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
          "<interface>"
            "<name>iface1</name>"
            "<description>iface1 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>true</enabled>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
              "<enabled>true</enabled>"
              "<forwarding>true</forwarding>"
              "<mtu>68</mtu>"
              "<address>"
                "<ip>172.0.0.1</ip>"
                "<prefix-length>16</prefix-length>"
              "</address>"
              "<neighbor>"
                "<ip>10.0.0.2</ip>"
                "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
              "</neighbor>"
              "<address>"
                "<ip>10.0.0.6</ip>"
                "<netmask>255.255.255.0</netmask>"
              "</address>"
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
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
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
      "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<url>file://" URL_TESTFILE "</url>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *edit_data =
    "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" xmlns:op=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
            "<interface>"
                "<name>iface1</name>"
                "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
                    "<address op:operation=\"create\">"
                      "<ip>10.0.0.6</ip>"
                      "<netmask>255.255.255.0</netmask>"
                    "</address>"
                "</ipv4>"
            "</interface>"
        "</interfaces>"
    "</config>";

    FILE* xmlfile = fopen(URL_TESTFILE, "w");
    fprintf(xmlfile, "%s", edit_data);
    fclose(xmlfile);

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_edit_merge_url(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
          "<interface>"
            "<name>iface2</name>"
            "<description>iface2 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
            "<enabled>false</enabled>"
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
          "<interface>"
            "<name>iface1</name>"
            "<description>iface1 dsc</description>"
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:ethernetCsmacd</type>"
            "<enabled>true</enabled>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
              "<enabled>true</enabled>"
              "<forwarding>true</forwarding>"
              "<mtu>68</mtu>"
              "<address>"
                "<ip>172.0.0.1</ip>"
                "<prefix-length>16</prefix-length>"
              "</address>"
              "<neighbor>"
                "<ip>10.0.0.2</ip>"
                "<link-layer-address>01:34:56:78:9a:bc:de:f0</link-layer-address>"
              "</neighbor>"
              "<address>"
                "<ip>10.0.0.6</ip>"
                "<netmask>255.255.255.0</netmask>"
              "</address>"
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
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
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
      "</data>"
    "</rpc-reply>";
    const char *edit_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<edit-config>"
            "<target>"
                "<running/>"
            "</target>"
            "<url>file://" URL_TESTFILE "</url>"
        "</edit-config>"
    "</rpc>";
    const char *edit_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<ok/>"
    "</rpc-reply>";
    const char *edit_data =
    "<config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
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
            "<type xmlns:ianaift=\"urn:ietf:params:xml:ns:yang:iana-if-type\">ianaift:softwareLoopback</type>"
            "<enabled>false</enabled>"
            "<link-up-down-trap-enable>disabled</link-up-down-trap-enable>"
            "<ipv4 xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ip\">"
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
    "</config>";

    FILE* xmlfile = fopen(URL_TESTFILE, "w");
    fprintf(xmlfile, "%s", edit_data);
    fclose(xmlfile);

    test_write(p_out, edit_rpc, __LINE__);
    test_read(p_in, edit_rpl, __LINE__);

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

#endif

static void
test_get_filter1(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<get-config>"
            "<source>"
                "<running/>"
            "</source>"
            "<filter type=\"subtree\">"
                "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                    "<interface>"
                        "<name/>"
                    "</interface>"
                "</interfaces>"
            "</filter>"
        "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"1\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
                "<interface>"
                    "<name>iface2</name>"
                "</interface>"
                "<interface>"
                    "<name>iface1</name>"
                "</interface>"
            "</interfaces>"
        "</data>"
    "</rpc-reply>";

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
}

static void
test_get_filter2(void **state)
{
    (void)state; /* unused */
    const char *get_config_rpc =
    "<rpc msgid=\"2\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<get-config>"
        "<source>"
          "<running/>"
         "</source>"
         "<filter type=\"subtree\">"
           "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
             "<interface>"
               "<name/>"
             "</interface>"
           "</interfaces>"
           "<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
             "<test-leaf/>"
           "</test-container>"
         "</filter>"
      "</get-config>"
    "</rpc>";
    const char *get_config_rpl =
    "<rpc-reply msgid=\"2\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
      "<data xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
        "<interfaces xmlns=\"urn:ietf:params:xml:ns:yang:ietf-interfaces\">"
          "<interface>"
            "<name>iface2</name>"
          "</interface>"
          "<interface>"
            "<name>iface1</name>"
          "</interface>"
        "</interfaces>"
        "<test-container xmlns=\"urn:ietf:params:xml:ns:yang:test-feature-c\">"
          "<test-leaf>green</test-leaf>"
        "</test-container>"
      "</data>"
    "</rpc-reply>";

    test_write(p_out, get_config_rpc, __LINE__);
    test_read(p_in, get_config_rpl, __LINE__);
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
                    cmocka_unit_test(test_edit_delete1),
                    cmocka_unit_test(test_edit_delete2),
                    cmocka_unit_test(test_edit_delete3),
                    cmocka_unit_test(test_edit_delete4),
                    cmocka_unit_test(test_edit_create1),
                    cmocka_unit_test(test_edit_create2),
                    cmocka_unit_test(test_edit_create3),
                    cmocka_unit_test(test_edit_merge1),
                    cmocka_unit_test(test_edit_merge2),
                    cmocka_unit_test(test_edit_merge3),
                    cmocka_unit_test(test_get_filter1),
                    cmocka_unit_test(test_get_filter2),

#ifdef NP2SRV_ENABLED_URL_CAPABILITY
                    cmocka_unit_test(test_edit_delete_url),
                    cmocka_unit_test(test_edit_create_url),
                    cmocka_unit_test(test_edit_merge_url),
#endif

                    cmocka_unit_test_teardown(test_startstop, np_stop),
    };

    if (setenv("CMOCKA_TEST_ABORT", "1", 1)) {
        fprintf(stderr, "Cannot set Cmocka thread environment variable.\n");
    }
    return cmocka_run_group_tests(tests, NULL, NULL);
}
