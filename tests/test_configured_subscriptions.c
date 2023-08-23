/**
 * @file test_configured_subscriptions.c
 * @author Jeremie Leska <jeremie.leska@6wind.com>
 * @brief tests for configured subscriptions.
 *
 * @copyright
 * Copyright 2023 6WIND S.A.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include <setjmp.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>
#include <sysrepo/netconf_acm.h>

#include "np_test.h"
#include "np_test_config.h"

#define MAX_MSG_SIZE 8192
#define MAX_NB_MSG 10

struct test_collector_t {
    int nb_expected;
    char xml_data[MAX_NB_MSG][MAX_MSG_SIZE];
    pthread_t th_read;
    int sockfd;
    char buffer[65535];
    struct sockaddr_storage msg_name;
    struct mmsghdr message;
    struct iovec iovec;
} tc_12345, tc_12346, tc_12347;

pthread_barrier_t barrier_read;

static void
collector_stop(struct test_collector_t *tc)
{
    if (!tc) {
        return;
    }

    close(tc->sockfd);
}

static int
udp_create_socket(char *address, char *port, uint64_t buffer_size)
{
    struct addrinfo *addr_info;
    struct addrinfo hints;

    memset(&hints, 0, sizeof(hints));

    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;

    // Using getaddrinfo to support both IPv4 and IPv6
    int rc = getaddrinfo(address, port, &hints, &addr_info);

    if (rc != 0) {
        printf("getaddrinfo error: %s\n", gai_strerror(rc));
        exit(EXIT_FAILURE);
    }

    fprintf(stderr, "Address type: %s | %d\n", (addr_info->ai_family == AF_INET) ? "IPv4" : "IPv6", ntohs(((struct sockaddr_in *)addr_info->ai_addr)->sin_port));

    // create socket on UDP protocol
    int sockfd = socket(addr_info->ai_family, addr_info->ai_socktype, addr_info->ai_protocol);

    // handle error
    if (sockfd < 0) {
        perror("Cannot create socket");
        exit(EXIT_FAILURE);
    }

    // Use SO_REUSEPORT to be able to launch multiple collector on the same address
    int optval = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &optval, sizeof(int)) < 0) {
        perror("Cannot set SO_REUSEPORT option on socket");
        exit(EXIT_FAILURE);
    }

    uint64_t receive_buf_size = buffer_size;
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &receive_buf_size, sizeof(receive_buf_size)) < 0) {
        perror("Cannot set buffer size");
        exit(EXIT_FAILURE);
    }

    if (bind(sockfd, addr_info->ai_addr, (int)addr_info->ai_addrlen) == -1) {
        perror("Bind failed");
        close(sockfd);
        exit(EXIT_FAILURE);
    }

    // free addr_info after usage
    freeaddrinfo(addr_info);

    struct sockaddr_storage sin;
    socklen_t len = sizeof(sin);
    if (getsockname(sockfd, (struct sockaddr *)&sin, &len) == -1) {
        perror("getsockname");
        exit(EXIT_FAILURE);
    }

    optval = 1;
    // get ip header IPv4
    if (setsockopt(sockfd, IPPROTO_IP, IP_PKTINFO, &optval, sizeof(int)) < 0) {
        perror("Cannot set IP_PKTINFO option on socket");
        exit(EXIT_FAILURE);
    }

    // get ip header IPv6
    if ((((struct sockaddr *)&sin)->sa_family == AF_INET6) && (setsockopt(sockfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &optval, sizeof(int)) < 0)) {
        perror("Cannot set IPV6_RECVPKTINFO option on socket");
        exit(EXIT_FAILURE);
    }

    return sockfd;
}

static int
collector_msg_get(struct test_collector_t *tc, char *xml_data)
{
    tc->message.msg_hdr.msg_iov = &tc->iovec;
    tc->message.msg_hdr.msg_iovlen = 1;

    tc->message.msg_hdr.msg_control = NULL;
    tc->message.msg_hdr.msg_controllen = 0;

    tc->message.msg_hdr.msg_iov->iov_base = tc->buffer;
    tc->message.msg_hdr.msg_iov->iov_len = 65535;

    tc->message.msg_hdr.msg_name = &tc->msg_name;
    tc->message.msg_hdr.msg_namelen = sizeof(struct sockaddr_storage);

    if (recvmmsg(tc->sockfd, &tc->message, 1, 0, NULL) == -1) {
        perror("recvmmsg failed");
        close(tc->sockfd);
        return -1;
    }

    memcpy(xml_data, tc->message.msg_hdr.msg_iov->iov_base + 12, tc->message.msg_len - 12);
    xml_data[tc->message.msg_len - 12] = '\0';

    return 0;
}

static int
collector_get(struct test_collector_t *tc)
{
    int c = 0;

    /* check if notification was sent */
    while (c < tc->nb_expected) {
        if (collector_msg_get(tc, tc->xml_data[c])) {
            return -1;
        }
        c++;
    }

    pthread_barrier_wait(&barrier_read);

    return 0;
}

static int
collector_start(struct test_collector_t *tc, char *port)
{
    tc->sockfd = udp_create_socket("127.0.0.1", port, 20971520);
    if (tc->sockfd < 0) {
        fprintf(stderr, "cannot create socket %s\n", port);
        return -1;
    }

    return 0;
}

static void
test_collector_display_received_data()
{
#ifdef DEBUG_TEST_CONFIGURED_SUBSCRIPTIONS
    fprintf(stderr, "tc_12345\n");
    for (int c = 0; c < MAX_NB_MSG; c++) {
        if (tc_12345.xml_data[c][0]) {
            fprintf(stderr, "%s\n", tc_12345.xml_data[c]);
        }
    }

    fprintf(stderr, "tc_12346\n");
    for (int c = 0; c < MAX_NB_MSG; c++) {
        if (tc_12346.xml_data[c][0]) {
            fprintf(stderr, "%s\n", tc_12346.xml_data[c]);
        }
    }

    fprintf(stderr, "tc_12347\n");
    for (int c = 0; c < MAX_NB_MSG; c++) {
        if (tc_12347.xml_data[c][0]) {
            fprintf(stderr, "%s\n", tc_12347.xml_data[c]);
        }
    }
#endif
}

void *
test_collector_read(void *tc)
{
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    collector_get((struct test_collector_t *)tc);
    pthread_exit(NULL);
}

static int
test_collectors_start()
{
    int ret;
    ret = collector_start(&tc_12345, "12345");
    if (ret) {
        fprintf(stderr, "cannot init collector\n");
        return -1;
    }

    ret = collector_start(&tc_12346, "12346");
    if (ret) {
        fprintf(stderr, "cannot init collector\n");
        goto stop;
    }

    ret = collector_start(&tc_12347, "12347");
    if (ret) {
        fprintf(stderr, "cannot init collector\n");
        goto stop;
    }

    pthread_barrier_init(&barrier_read, NULL, 4);

    return 0;

stop:
    collector_stop(&tc_12345);
    collector_stop(&tc_12346);
    collector_stop(&tc_12347);

    return -1;
}

static void
test_collectors_stop()
{
    collector_stop(&tc_12345);
    collector_stop(&tc_12346);
    collector_stop(&tc_12347);

    pthread_barrier_destroy(&barrier_read);
}

static void
test_collector_start_read_threads()
{
    unsigned int b = 0;
    pthread_attr_t attr;

    for (b = 0; b < MAX_NB_MSG; b++) {
        memset(tc_12345.xml_data[b], 0, MAX_MSG_SIZE);
        memset(tc_12346.xml_data[b], 0, MAX_MSG_SIZE);
        memset(tc_12347.xml_data[b], 0, MAX_MSG_SIZE);
    }

    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, 1);
    pthread_create(&tc_12345.th_read, &attr, test_collector_read, (void *)&tc_12345);
    pthread_create(&tc_12346.th_read, &attr, test_collector_read, (void *)&tc_12346);
    pthread_create(&tc_12347.th_read, &attr, test_collector_read, (void *)&tc_12347);
}

static void
test_collector_stop_read_threads()
{
    pthread_barrier_wait(&barrier_read);
    pthread_join(tc_12345.th_read, NULL);
    pthread_join(tc_12346.th_read, NULL);
    pthread_join(tc_12346.th_read, NULL);

}

static void
delete_subscription_config(void **state)
{
    struct np_test *st = *state;
    const char *config;

    test_collector_start_read_threads();

    /* remove subscriptions */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\" nc:operation=\"replace\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* remove receivers */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\" nc:operation=\"replace\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();
}

static int
local_setup(void **state)
{
    struct np_test *st;
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/notif1.yang", NP_TEST_MODULE_DIR "/notif2.yang", NULL};
    int rc;

    /* get test name */
    np_glob_setup_test_name(test_name);

    /* setup environment */
    rc = np_glob_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np_glob_setup_np2(state, test_name, modules);
    assert_int_equal(rc, 0);
    st = *state;

    /* second session */
    assert_int_equal(sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->sr_sess2), SR_ERR_OK);

    /* enable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));

    /* setup NACM */
    rc = setup_nacm(state);
    assert_int_equal(rc, 0);

    rc = test_collectors_start();
    assert_int_equal(rc, 0);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);

    return 0;
}

static int
teardown_common(void **state)
{
    struct np_test *st = *state;
    char *cmd;
    int ret;

    /* Remove the notifications */
    if (asprintf(&cmd, "rm -rf %s/%s/data/notif/notif1.notif*", NP_SR_REPOS_DIR, st->test_name) == -1) {
        return 1;
    }

    ret = system(cmd);
    free(cmd);

    if (ret == -1) {
        return 1;
    } else if (!WIFEXITED(ret) || WEXITSTATUS(ret)) {
        return 1;
    }

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, NULL);
    assert_non_null(st->nc_sess);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    const char *modules[] = {"notif1", "notif2", NULL};

    if (!st) {
        return 0;
    }

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);

    /* disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* Remove the notifications */
    teardown_common(state);

    test_collectors_stop();

    /* close netopeer2 server */
    return np_glob_teardown(state, modules);
}

static void
test_configured_subscriptions_receivers(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    np_assert_string_equal(st->str, EMPTY_GETCONFIG);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    np_assert_string_equal(st->str, EMPTY_GET);
    FREE_TEST_VARS(st);

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check if merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions/receiver-instances");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";
    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_receivers_modif(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* merge without 3rd receiver and modify 2nd receiver port */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions/receiver-instances");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* Check state merged successfully */
    GET_FILTER(st, "/subscriptions/receiver-instances");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_add(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 3;

    test_collector_start_read_threads();

    /* add 3 subscriptions, first subscription has 2 receivers */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12347.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[0], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12345.xml_data[1][0] == '\0');
    assert_non_null(tc_12347.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id></subscription-started></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";
    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>2</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 3;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_reset(void **state)
{
    struct np_test *st = *state;
    const char *config;

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 3;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 2;

    test_collector_start_read_threads();

    /* reset a receiver in a subscription */
    config =
            "<action xmlns=\"urn:ietf:params:xml:ns:yang:1\">\n"
            "  <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "    <subscription>\n"
            "      <id>3</id>\n"
            "      <receivers> \n"
            "        <receiver>\n"
            "          <name>name2</name>\n"
            "          <reset></reset>\n"
            "        </receiver>\n"
            "      </receivers>\n"
            "    </subscription>\n"
            "  </subscriptions>\n"
            "</action>\n";

    st->rpc = nc_rpc_act_generic_xml(config, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(st->nc_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    st->msgtype = nc_recv_reply(st->nc_sess, st->rpc, st->msgid, 1000, &st->envp, &st->op);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12347.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12347.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id></subscription-terminated></notification>");

    assert_non_null(tc_12347.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id></subscription-started></notification>");

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 3;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_modif(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 3;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 3;

    test_collector_start_read_threads();

    /* replace port of receiver 2 , should restart the 3 subscriptions because they use receiver2 */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12347.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-terminated></notification>");

    assert_non_null(tc_12347.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[1], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id></subscription-terminated></notification>");

    assert_non_null(tc_12347.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12347.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12347.xml_data[2], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>4</id></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12346.xml_data[2], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>4</id></subscription-started></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>4</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_modif2(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 1;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    /* change source address of subscription 1 also change the name of receiver used use receiver2 instead of receiver1 */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.2</source-address>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[2], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.2</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.2</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>2</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 4;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_modif3(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 4;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.2</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    /* change source address of subscription 1 also change the name of receiver used use again receiver1 */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_yang_push(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 4;
    tc_12346.nb_expected = 2;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "    <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "    <on-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\"/>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "        <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "        <on-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "          <dampening-period>0</dampening-period>\n"
            "          <sync-on-start>true</sync-on-start>\n"
            "        </on-change>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "        <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "        <on-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "          <dampening-period>0</dampening-period>\n"
            "          <sync-on-start>true</sync-on-start>\n"
            "        </on-change>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_yang_push_modif(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;
    char *pos;

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "    <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <on-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "      <dampening-period>0</dampening-period>\n"
            "      <sync-on-start>true</sync-on-start>\n"
            "    </on-change>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 4;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();
    /* modify from on_change to periodic */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "    <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "    <periodic xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "      <period>1000</period>\n"
            "    </periodic>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12345.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[1], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12345.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[2], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");

    pos = strstr(tc_12346.xml_data[2], "</eventTime><push-update xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\"><id>1</id><datastore-contents/></push-update></notification>");

    /* at least one push update event should be received */
    assert_non_null(pos);

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "        <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "        <periodic xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "          <period>1000</period>\n"
            "        </periodic>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "        <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>6</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "        <periodic xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "          <period>1000</period>\n"
            "        </periodic>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 4;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);

    /* in case there are more yang push update notif */
    usleep(200000);
}

static void
test_configured_subscriptions_back(void **state)
{
    struct np_test *st = *state;
    const char *expected;
    const char *config;

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <datastore xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\" xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:operational</datastore>\n"
            "    <datastore-xpath-filter xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">/state/vrf/interface/physical/enabled</datastore-xpath-filter>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <on-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yang-push\">\n"
            "      <dampening-period>1000</dampening-period>\n"
            "      <sync-on-start>false</sync-on-start>\n"
            "    </on-change>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 4;
    tc_12346.nb_expected = 2;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    /* switch back to stream NETCONF for sub 1 */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "  </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12345.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[1], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12345.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[2], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12345.xml_data[3][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[3], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[3], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-started xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id></subscription-started></notification>");

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get-config>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "      <subscription>\n"
            "        <id>1</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name1</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>name3</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 1</name>\n"
            "            <sent-event-records>3</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>3</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name2</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 3</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <subscription>\n"
            "        <id>4</id>\n"
            "        <stream>notif1</stream>\n"
            "        <encoding>encode-xml</encoding>\n"
            "        <purpose>send notifications</purpose>\n"
            "        <source-address>127.0.0.1</source-address>\n"
            "        <configured-subscription-state>valid</configured-subscription-state>\n"
            "        <receivers>\n"
            "          <receiver>\n"
            "            <name>name4</name>\n"
            "            <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "          </receiver>\n"
            "          <receiver>\n"
            "            <name>CONFIG notif 4</name>\n"
            "            <sent-event-records>1</sent-event-records>\n"
            "            <excluded-event-records>0</excluded-event-records>\n"
            "            <state>active</state>\n"
            "          </receiver>\n"
            "        </receivers>\n"
            "      </subscription>\n"
            "      <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "        <receiver-instance>\n"
            "          <name>receiver1</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12345</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver2</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12346</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "        <receiver-instance>\n"
            "          <name>receiver3</name>\n"
            "          <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "            <remote-address>127.0.0.1</remote-address>\n"
            "            <remote-port>12347</remote-port>\n"
            "          </udp-notif-receiver>\n"
            "        </receiver-instance>\n"
            "      </receiver-instances>\n"
            "    </subscriptions>\n"
            "  </data>\n"
            "</get>\n";

    np_assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
}

static void
test_configured_subscriptions_remove(void **state)
{
    struct np_test *st = *state;
    const char *config;

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <subscription>\n"
            "    <id>1</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name1</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "      <receiver>\n"
            "        <name>name3</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver1</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>3</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name2</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <subscription>\n"
            "    <id>4</id>\n"
            "    <stream>notif1</stream>\n"
            "    <encoding>encode-xml</encoding>\n"
            "    <purpose>send notifications</purpose>\n"
            "    <source-address>127.0.0.1</source-address>\n"
            "    <receivers>\n"
            "      <receiver>\n"
            "        <name>name4</name>\n"
            "        <receiver-instance-ref xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">receiver2</receiver-instance-ref>\n"
            "      </receiver>\n"
            "    </receivers>\n"
            "  </subscription>\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12346</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    tc_12345.nb_expected = 2;
    tc_12346.nb_expected = 3;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    /* end : remove subscriptions */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "    <subscription nc:operation=\"delete\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "        '/ietf-subscribed-notifications:subscriptions/subscription[id=1]'\n"
            "    </subscription>\n"
            "    <subscription nc:operation=\"delete\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "        '/ietf-subscribed-notifications:subscriptions/subscription[id=3]'\n"
            "    </subscription>\n"
            "    <subscription nc:operation=\"delete\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "        '/ietf-subscribed-notifications:subscriptions/subscription[id=4]'\n"
            "    </subscription>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    assert_non_null(tc_12345.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12345.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    np_assert_strstr(tc_12345.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12345.xml_data[1], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[0][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[0], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[0], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>1</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[1][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[1], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[1], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>3</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    assert_non_null(tc_12346.xml_data[2][0] != '\0');
    np_assert_strstr(tc_12346.xml_data[2], "<notification xmlns:\"urn:ietf:params:xml:ns:netconf:notification:1.0\"><eventTime>");
    np_assert_strstr(tc_12346.xml_data[2], "</eventTime><subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\"><id>4</id><reason>no-such-subscription</reason></subscription-terminated></notification>");

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);
    assert_non_null(tc_12345.xml_data[0][0] == '\0');
    assert_non_null(tc_12346.xml_data[0][0] == '\0');
    assert_non_null(tc_12346.xml_data[0][0] == '\0');
}

static void
test_configured_subscriptions_remove_receivers(void **state)
{
    struct np_test *st = *state;
    const char *config;

    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\">\n"
            "    <receiver-instance>\n"
            "      <name>receiver1</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12345</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver2</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "    <receiver-instance>\n"
            "      <name>receiver3</name>\n"
            "      <udp-notif-receiver xmlns=\"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport\">\n"
            "        <remote-address>127.0.0.1</remote-address>\n"
            "        <remote-port>12347</remote-port>\n"
            "      </udp-notif-receiver>\n"
            "    </receiver-instance>\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";

    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    test_collector_start_read_threads();

    /* end : remove receivers */
    config =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <receiver-instances xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers\" nc:operation=\"replace\" xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  </receiver-instances>\n"
            "</subscriptions>\n";
    SEND_EDIT_RPC(st, config);
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    test_collector_stop_read_threads();
    test_collector_display_received_data();

    /* Check config merged successfully */
    GET_CONFIG_FILTER(st, "/subscriptions");
    np_assert_string_equal(st->str, EMPTY_GETCONFIG);
    FREE_TEST_VARS(st);

    GET_FILTER(st, "/subscriptions");
    np_assert_string_equal(st->str, EMPTY_GET);
    FREE_TEST_VARS(st);

    tc_12345.nb_expected = 0;
    tc_12346.nb_expected = 0;
    tc_12347.nb_expected = 0;

    delete_subscription_config(state);

    assert_non_null(tc_12345.xml_data[0][0] == '\0');
    assert_non_null(tc_12346.xml_data[0][0] == '\0');
    assert_non_null(tc_12346.xml_data[0][0] == '\0');
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_configured_subscriptions_receivers, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_receivers_modif, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_add, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_reset, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_modif, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_modif2, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_modif3, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_yang_push, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_yang_push_modif, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_back, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_remove, teardown_common),
        cmocka_unit_test_teardown(test_configured_subscriptions_remove_receivers, teardown_common)
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
