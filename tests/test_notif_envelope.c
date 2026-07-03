/**
 * @file test_notif_envelope.c
 * @author Roman <roman@example.com>
 * @brief tests for notification envelope (ietf-yp-notification) support
 *
 * @copyright
 * Copyright (c) 2019 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2025 CESNET, z.s.p.o.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>

#include "np2_test.h"
#include "np2_test_config.h"

static int
local_setup(void **state)
{
    struct np2_test *st;
    const char *modules[] = {NP_TEST_MODULE_DIR "/notif1.yang", NP_TEST_MODULE_DIR "/notif2.yang", NULL};
    char test_name[256];
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, NULL, 0);
    assert_int_equal(rc, 0);
    st = *state;

    /* start second session for the tests */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &st->sr_sess2), SR_ERR_OK);

    /* enable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 1));

    return 0;
}

static void disable_envelope(struct np2_test *st);

static int
teardown_common(void **state)
{
    struct np2_test *st = *state;

    /* remove notifications */
    if (np2_glob_test_teardown_notif(st->test_name)) {
        return 1;
    }

    /* reset notification envelope to disabled */
    disable_envelope(st);

    /* reestablish NETCONF connection */
    nc_session_free(st->nc_sess, NULL);
    st->nc_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(st->nc_sess);

    return 0;
}

static int
local_teardown(void **state)
{
    struct np2_test *st = *state;
    const char *modules[] = {"notif1", "notif2", NULL};

    if (!st) {
        return 0;
    }

    /* disable replay support */
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif1", 0));
    assert_int_equal(SR_ERR_OK, sr_set_module_replay_support(st->conn, "notif2", 0));

    /* close the session */
    assert_int_equal(sr_session_stop(st->sr_sess2), SR_ERR_OK);

    /* remove the notifications */
    teardown_common(state);

    /* close netopeer2 server */
    return np2_glob_test_teardown(state, modules);
}

/**
 * @brief Enable the notification envelope via sysrepo.
 */
static void
enable_envelope(struct np2_test *st)
{
    const char *data =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <enable-notification-envelope xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yp-notification\">true</enable-notification-envelope>\n"
            "</subscriptions>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
}

/**
 * @brief Disable the notification envelope via sysrepo.
 */
static void
disable_envelope(struct np2_test *st)
{
    const char *data =
            "<subscriptions xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <enable-notification-envelope xmlns=\"urn:ietf:params:xml:ns:yang:ietf-yp-notification\">false</enable-notification-envelope>\n"
            "</subscriptions>\n";

    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that by default (envelope disabled) notifications use the legacy RFC 5277 format.
 */
static void
test_default_legacy_format(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Test</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive the notification - should be in legacy format (just the notification, no envelope) */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that when the envelope is enabled, notifications are wrapped in the envelope structure.
 */
static void
test_envelope_enabled(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    const char *template;
    struct lyd_node *child;
    uint32_t seq1, seq2;

    /* Enable the notification envelope */
    enable_envelope(st);

    /* Establish subscription (after envelope is enabled) */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Envelope</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive the notification - op should be the notification content (extracted from envelope) */
    RECV_NOTIF(st);
    assert_string_equal(data, st->str);
    /* capture the first sequence number for relative comparison */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &child));
    seq1 = strtoul(lyd_get_value(child), NULL, 10);
    FREE_TEST_VARS(st);

    /* The envelope should be in envp - check it has the expected structure */
    /* envp was freed by RECV_NOTIF's print, but we can verify via a second notification */

    /* Send another notification and check the envelope structure this time */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Envelope2</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive notification - this time check the envelope */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);

    /* envp should be the envelope with event-time, hostname, sequence-number, and empty contents */
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(st->envp), "envelope");
    assert_string_equal(st->envp->schema->module->name, "ietf-yp-notification");

    /* Check that event-time exists */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "event-time", 0, &child));
    assert_non_null(child);

    /* Check that hostname exists (feature is enabled) */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "hostname", 0, &child));
    assert_non_null(child);

    /* Check that sequence-number exists and increments relative to the first notification */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &child));
    assert_non_null(child);
    seq2 = strtoul(lyd_get_value(child), NULL, 10);
    assert_int_equal(seq2, seq1 + 1);

    /* Check that contents exists (should be empty since op was detached) */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "contents", 0, &child));
    assert_non_null(child);

    /* op should be the inner notification */
    while (st->op->parent) {
        st->op = lyd_parent(st->op);
    }
    assert_int_equal(lyd_print_mem(&st->str, st->op, LYD_XML, 0), LY_SUCCESS);
    template =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Envelope2</first>\n"
            "</n1>\n";
    assert_string_equal(template, st->str);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope */
    disable_envelope(st);
}

/**
 * @brief Test that sequence numbers increment correctly across multiple notifications.
 */
static void
test_sequence_increment(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct lyd_node *seq_node;
    uint32_t seq1, seq2;

    /* Enable the notification envelope */
    enable_envelope(st);

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send and receive first notification - get sequence number */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Seq1</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    /* Skip the notification content, check envp */
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq1 = strtoul(lyd_get_value(seq_node), NULL, 10);
    assert_true(seq1 > 0);
    FREE_TEST_VARS(st);

    /* Send and receive second notification - get the next sequence number */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>Seq2</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq2 = strtoul(lyd_get_value(seq_node), NULL, 10);
    assert_true(seq2 > seq1);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope */
    disable_envelope(st);
}

/**
 * @brief Test that enabling the envelope terminates existing subscriptions.
 *
 * Per the YANG module description: "Enabling or disabling this leaf terminates all
 * existing active dynamic and configured YANG-Push subscriptions."
 */
static void
test_enable_terminates_subscriptions(void **state)
{
    struct np2_test *st = *state;
    const char *template;
    char *ntf;

    /* Establish subscription (envelope is off by default) */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Enable the envelope - should terminate the existing subscription */
    enable_envelope(st);

    /* Expect a subscription-terminated notification (in legacy format, since the
     * subscription was created with envelope disabled) */
    RECV_NOTIF(st);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(ntf, st->str);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No more notifications */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope */
    disable_envelope(st);
}

/**
 * @brief Test that disabling the envelope terminates existing subscriptions.
 */
static void
test_disable_terminates_subscriptions(void **state)
{
    struct np2_test *st = *state;
    const char *template;
    char *ntf;

    /* Enable the envelope first */
    enable_envelope(st);

    /* Establish subscription (with envelope enabled) */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Disable the envelope - should terminate the existing subscription */
    disable_envelope(st);

    /* Expect a subscription-terminated notification.
     * Since the subscription was created with envelope enabled, the terminated
     * notification should also be in envelope format. */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);

    /* op should be the subscription-terminated notification */
    while (st->op->parent) {
        st->op = lyd_parent(st->op);
    }
    assert_int_equal(lyd_print_mem(&st->str, st->op, LYD_XML, 0), LY_SUCCESS);
    template =
            "<subscription-terminated xmlns=\"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications\">\n"
            "  <id>%d</id>\n"
            "  <reason>no-such-subscription</reason>\n"
            "</subscription-terminated>\n";
    assert_int_not_equal(-1, asprintf(&ntf, template, st->ntf_id));
    assert_string_equal(ntf, st->str);
    free(ntf);
    FREE_TEST_VARS(st);

    /* No more notifications */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that after toggling, new subscriptions use the new format.
 */
static void
test_new_sub_after_toggle(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish subscription (after envelope is enabled) */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification and verify it comes in envelope format */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>AfterToggle</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive - should be in envelope format (envp is the envelope) */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(st->envp), "envelope");

    /* op should be the notification content */
    while (st->op->parent) {
        st->op = lyd_parent(st->op);
    }
    assert_int_equal(lyd_print_mem(&st->str, st->op, LYD_XML, 0), LY_SUCCESS);
    assert_string_equal(data, st->str);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope (this will terminate the subscription) */
    disable_envelope(st);

    /* Receive the subscription-terminated notification */
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that the subscription-modified notification respects the per-subscription
 * envelope state.
 */
static void
test_modify_sub_preserves_envelope(void **state)
{
    struct np2_test *st = *state;
    const char *filter;

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish subscription with a filter */
    filter = "<n1 xmlns=\"urn:n1\"/>\n";
    SEND_RPC_ESTABSUB(st, filter, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Modify the subscription - should generate subscription-modified in envelope format */
    filter = "<n1 xmlns=\"urn:n1\">\n  <first>Modified</first>\n</n1>\n";
    SEND_RPC_MODSUB(st, st->ntf_id, filter, NULL);

    /* Receive subscription-modified notification - should be in envelope format.
     * Loop to skip any RPC replies that may arrive before the notification. */
    do {
        st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    } while (st->msgtype == NC_MSG_REPLY);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(st->envp), "envelope");

    /* op should be subscription-modified */
    assert_string_equal(LYD_NAME(st->op), "subscription-modified");

    /* Receive the OK reply for the modify RPC */
    lyd_free_tree(st->envp);
    lyd_free_tree(st->op);
    st->envp = NULL;
    st->op = NULL;
    ASSERT_OK_REPLY(st);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope (terminates subscription) */
    disable_envelope(st);

    /* Receive subscription-terminated */
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that the server advertises notification envelope capabilities correctly.
 *
 * The <get> response for ietf-system-capabilities should contain:
 * - notification-metadata/envelope = true
 * - notification-metadata/metadata/hostname-sequence-number = true
 */
static void
test_capabilities_advertisement(void **state)
{
    struct np2_test *st = *state;
    struct lyd_node *node, *data;

    /* Query system capabilities via <get> with a filter */
    GET_FILTER(st, "/ietf-system-capabilities:system-capabilities");

    /* Extract the data tree from the <data> anydata node */
    data = lyd_child_any(lyd_child(st->op));
    assert_non_null(data);

    /* Verify notification-metadata/envelope = true */
    assert_int_equal(LY_SUCCESS, lyd_find_path(data,
            "ietf-notification-capabilities:subscription-capabilities"
            "/ietf-yp-notification:notification-metadata/envelope", 0, &node));
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), "true");

    /* Verify notification-metadata/metadata/hostname-sequence-number = true */
    assert_int_equal(LY_SUCCESS, lyd_find_path(data,
            "ietf-notification-capabilities:subscription-capabilities"
            "/ietf-yp-notification:notification-metadata/metadata/hostname-sequence-number", 0, &node));
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), "true");

    /* Verify yang-push-observation-time-supported = true */
    assert_int_equal(LY_SUCCESS, lyd_find_path(data,
            "ietf-notification-capabilities:subscription-capabilities"
            "/ietf-yp-observation:yang-push-observation-time-supported", 0, &node));
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), "true");

    FREE_TEST_VARS(st);
}

/**
 * @brief Test that the hostname in the envelope matches the actual server hostname.
 */
static void
test_hostname_value(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct lyd_node *host_node;
    char hostbuf[256];
    char *hostname_str;

    /* Get the real hostname */
    assert_int_equal(0, gethostname(hostbuf, sizeof hostbuf));

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>HostnameCheck</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive and check the hostname value */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);

    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "hostname", 0, &host_node));
    assert_non_null(host_node);
    hostname_str = strdup(lyd_get_value(host_node));
    assert_string_equal(hostname_str, hostbuf);
    free(hostname_str);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope */
    disable_envelope(st);
}

/**
 * @brief Test that multiple subscriptions share the global sequence counter.
 *
 * Two subscriptions are established. When notifications are sent, each
 * notification should get a unique sequence number from the shared global
 * counter, regardless of which subscription delivers it.
 */
static void
test_multiple_subscriptions_shared_seq(void **state)
{
    struct np2_test *st = *state;
    struct nc_session *tmp_sess;
    const char *data;
    struct lyd_node *seq_node;
    char *seq_str;
    uint32_t seq1, seq2;

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish first subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Create a second NETCONF session and establish a second subscription */
    tmp_sess = nc_connect_unix(st->socket_path, (struct ly_ctx *)nc_session_get_ctx(st->nc_sess2));
    assert_non_null(tmp_sess);
    st->rpc = nc_rpc_establishsub(NULL, "notif1", NULL, NULL, NULL, NC_PARAMTYPE_CONST);
    st->msgtype = nc_send_rpc(tmp_sess, st->rpc, 1000, &st->msgid);
    assert_int_equal(NC_MSG_RPC, st->msgtype);
    /* receive ok reply with sub ID */
    st->msgtype = nc_recv_reply(tmp_sess, st->rpc, st->msgid, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_REPLY, st->msgtype);
    assert_non_null(st->op);
    assert_string_equal(LYD_NAME(lyd_child(st->op)), "id");
    FREE_TEST_VARS(st);

    /* Send one notification - both subscriptions should receive it */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>MultiSeq</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive on first session - check sequence number */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq_str = strdup(lyd_get_value(seq_node));
    seq1 = strtoul(seq_str, NULL, 10);
    free(seq_str);
    FREE_TEST_VARS(st);

    /* Receive on second session - check sequence number */
    st->msgtype = nc_recv_notif(tmp_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq_str = strdup(lyd_get_value(seq_node));
    seq2 = strtoul(seq_str, NULL, 10);
    free(seq_str);
    FREE_TEST_VARS(st);

    /* Both deliveries of the same notification event should have the same sequence number */
    assert_int_equal(seq1, seq2);

    /* Send another notification - sequence should increment */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>MultiSeq2</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Receive on first session */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq_str = strdup(lyd_get_value(seq_node));
    assert_int_equal(seq1 + 1, (int) strtoul(seq_str, NULL, 10));
    free(seq_str);
    FREE_TEST_VARS(st);

    /* Drain the second session */
    st->msgtype = nc_recv_notif(tmp_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope (terminates subscriptions) */
    disable_envelope(st);

    /* Receive subscription-terminated on first session */
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Receive subscription-terminated on second session */
    st->msgtype = nc_recv_notif(tmp_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    FREE_TEST_VARS(st);

    /* Close the second session */
    nc_session_free(tmp_sess, NULL);
}

/**
 * @brief Test that enabling the envelope when it is already enabled does not
 * terminate existing subscriptions (no-op toggle).
 */
static void
test_enable_noop(void **state)
{
    struct np2_test *st = *state;
    const char *data;

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Enable the envelope again (no-op) */
    enable_envelope(st);

    /* Subscription should still be active - send and receive a notification */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>NoOpTest</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    /* Should receive the notification, not a subscription-terminated */
    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_non_null(st->envp);
    assert_string_equal(LYD_NAME(st->envp), "envelope");
    FREE_TEST_VARS(st);

    /* No more notifications (no subscription-terminated) */
    ASSERT_NO_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Clean up: disable envelope */
    disable_envelope(st);

    /* Receive subscription-terminated */
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);
}

/**
 * @brief Test that the sequence counter persists across a disable/re-enable cycle.
 *
 * The global sequence counter is initialized once at server startup and is not
 * reset when the envelope is toggled off and on again.
 */
static void
test_seq_persistence_across_toggle(void **state)
{
    struct np2_test *st = *state;
    const char *data;
    struct lyd_node *seq_node;
    char *seq_str;
    uint32_t first_seq, after_reenable_seq;

    /* Enable the envelope */
    enable_envelope(st);

    /* Establish subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification and record the sequence number */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>BeforeToggle</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq_str = strdup(lyd_get_value(seq_node));
    first_seq = strtoul(seq_str, NULL, 10);
    free(seq_str);
    FREE_TEST_VARS(st);

    /* Disable the envelope (terminates subscription) */
    disable_envelope(st);
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);

    /* Re-enable the envelope */
    enable_envelope(st);

    /* Establish a new subscription */
    SEND_RPC_ESTABSUB(st, NULL, "notif1", NULL, NULL);
    ASSERT_OK_SUB_NTF(st);
    FREE_TEST_VARS(st);

    /* Send a notification - sequence should be greater than first_seq */
    data =
            "<n1 xmlns=\"urn:n1\">\n"
            "  <first>AfterToggle</first>\n"
            "</n1>\n";
    NOTIF_PARSE(st, data);
    assert_int_equal(sr_notif_send_tree(st->sr_sess, st->node, 1000, 1), SR_ERR_OK);
    FREE_TEST_VARS(st);

    st->msgtype = nc_recv_notif(st->nc_sess, 3000, &st->envp, &st->op);
    assert_int_equal(NC_MSG_NOTIF, st->msgtype);
    assert_int_equal(LY_SUCCESS, lyd_find_path(st->envp, "sequence-number", 0, &seq_node));
    seq_str = strdup(lyd_get_value(seq_node));
    after_reenable_seq = strtoul(seq_str, NULL, 10);
    free(seq_str);
    FREE_TEST_VARS(st);

    /* The sequence number after re-enabling should be greater than before disabling
     * (it was incremented by the first notification, plus possibly by the
     * subscription-terminated notification during disable) */
    assert_int_not_equal(first_seq, after_reenable_seq);
    assert_true(after_reenable_seq > first_seq);

    /* Clean up: disable envelope */
    disable_envelope(st);
    RECV_NOTIF(st);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_teardown(test_default_legacy_format, teardown_common),
        cmocka_unit_test_teardown(test_envelope_enabled, teardown_common),
        cmocka_unit_test_teardown(test_sequence_increment, teardown_common),
        cmocka_unit_test_teardown(test_enable_terminates_subscriptions, teardown_common),
        cmocka_unit_test_teardown(test_disable_terminates_subscriptions, teardown_common),
        cmocka_unit_test_teardown(test_new_sub_after_toggle, teardown_common),
        cmocka_unit_test_teardown(test_modify_sub_preserves_envelope, teardown_common),
        cmocka_unit_test_teardown(test_capabilities_advertisement, teardown_common),
        cmocka_unit_test_teardown(test_hostname_value, teardown_common),
        cmocka_unit_test_teardown(test_multiple_subscriptions_shared_seq, teardown_common),
        cmocka_unit_test_teardown(test_enable_noop, teardown_common),
        cmocka_unit_test_teardown(test_seq_persistence_across_toggle, teardown_common),
    };

    nc_verbosity(NC_VERB_WARNING);
    sr_log_stderr(SR_LL_WRN);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
