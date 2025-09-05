/**
 * @file test_other_client.h
 * @author Adam Piecek <piecek@cesnet.cz>
 * @brief An alternative client which communicate with NETCONF server.
 *
 * @copyright
 * Copyright (c) 2019 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2024 CESNET, z.s.p.o.
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
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "np2_other_client.h"
#include "np2_test.h"
#include "np2_test_config.h"

static int
local_setup(void **state)
{
    char test_name[256];
    const char *modules[] = {NP_TEST_MODULE_DIR "/errors.yang", NULL};
    int rc;

    /* get test name */
    np2_glob_test_setup_test_name(test_name);

    /* setup environment necessary for installing module */
    rc = np2_glob_test_setup_env(test_name);
    assert_int_equal(rc, 0);

    /* setup netopeer2 server */
    rc = np2_glob_test_setup_server(state, test_name, modules, NULL, NP_GLOB_SETUP_OTHER_CLIENT);
    assert_int_equal(rc, 0);

    /* setup NACM */
    rc = np2_glob_test_setup_nacm(state);
    assert_int_equal(rc, 0);

    return 0;
}

static int
local_teardown(void **state)
{
    const char *modules[] = {"errors", NULL};

    /* close netopeer2 server */
    if (*state) {
        return np2_glob_test_teardown(state, modules);
    }

    return 0;
}

static void
test_message_id(void **state)
{
    int rc;
    char *msg, *exp;
    struct np2_test *st = *state;
    struct np_other_client *sess = st->oc_sess;

    /* send malformed message */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn&ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);

    /* then send valid message */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp, "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\""
            " message-id=\"%" PRIu64 "\"><ok/></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);
}

static void
test_missing_attribute(void **state)
{
    int rc;
    char *msg, *exp;
    struct np2_test *st = *state;
    struct np_other_client *sess = st->oc_sess;

    /* missing attribute 'message-id' in the rpc layer */
    msg =
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "  <discard-changes/>"
            "</rpc>";
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    assert_string_equal(msg,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><rpc-error>"
            "<error-type>rpc</error-type>"
            "<error-tag>missing-attribute</error-tag><error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">An expected attribute is missing.</error-message>"
            "<error-info><bad-attribute>message-id</bad-attribute>"
            "<bad-element>rpc</bad-element>"
            "</error-info></rpc-error></rpc-reply>");

    /* missing attribute 'xmlns' in the rpc layer */
    rc = asprintf(&msg,
            "<rpc message-id=\"%" PRIu64 "\">"
            "  <discard-changes/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    assert_string_equal(msg,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\"><rpc-error>"
            "<error-type>rpc</error-type>"
            "<error-tag>missing-attribute</error-tag><error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">An expected attribute is missing.</error-message>"
            "<error-info><bad-attribute>xmlns</bad-attribute>"
            "<bad-element>rpc</bad-element></error-info>"
            "</rpc-error></rpc-reply>");

    /* missing attribute 'select' in the protocol layer */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <get-config>"
            "    <source>"
            "      <running/>"
            "    </source>"
            "    <filter type=\"xpath\"/>"
            "  </get-config>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>missing-attribute</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">An expected attribute is missing.</error-message>"
            "<error-info><bad-attribute>select</bad-attribute>"
            "<bad-element>filter</bad-element></error-info></rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);
}

static void
test_unknown_attribute(void **state)
{
    int rc;
    char *msg, *exp;
    struct np2_test *st = *state;
    struct np_other_client *sess = st->oc_sess;

    /* unknown attribute 'att' in the rpc layer,
     * but in this case it's ok because rfc 6241 is benevolent towards attributes.
     */
    rc = asprintf(&msg,
            "<rpc att=\"4\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" att=\"4\" message-id=\"%" PRIu64 "\">"
            "<ok/></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);

    /* unknown attribute 'att' in the protocol layer: annotation not found */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes xmlns:el=\"urn:ietf:params:xml:ns:netconf:base:1.0\" el:att=\"4\"/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>unknown-attribute</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">Annotation definition for attribute \"ietf-netconf:att\" not found.</error-message>"
            "<error-info><bad-attribute>att</bad-attribute>"
            "<bad-element>discard-changes</bad-element></error-info>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);

    /* unknown attribute 'att' in the protocol layer: missing prefix */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes att=\"4\"/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>unknown-attribute</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">Missing mandatory prefix for XML metadata \"att\".</error-message>"
            "<error-info><bad-attribute>att</bad-attribute>"
            "<bad-element>discard-changes</bad-element></error-info>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);

    /* unknown attribute 'att' in the protocol layer: unknown XML prefix */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes el:att=\"4\"/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>unknown-attribute</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">Unknown XML prefix \"el\" at attribute \"att\".</error-message>"
            "<error-info><bad-attribute>att</bad-attribute>"
            "<bad-element>discard-changes</bad-element></error-info>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);
}

static void
test_missing_element(void **state)
{
    int rc;
    char *msg, *exp;
    struct np2_test *st = *state;
    struct np_other_client *sess = st->oc_sess;

    /* missing element in 'edit-content' in the protocol layer: missing mandatory node in the choice-stmt */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <edit-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">"
            "    <datastore xmlns:ds=\"urn:ietf:params:xml:ns:yang:ietf-datastores\">ds:running</datastore>"
            "  </edit-data>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>data-missing</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-app-tag>mandatory-choice</error-app-tag>"
            "<error-path xmlns:ncds=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">/ncds:edit-data</error-path>"
            "<error-message xml:lang=\"en\">Missing mandatory choice.</error-message>"
            "<error-info>"
            "<missing-choice xmlns=\"urn:ietf:params:xml:ns:yang:1\">edit-content</missing-choice>"
            "</error-info></rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);

    /* missing element 'identifier' in the protocol layer */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <get-schema xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\"/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>missing-element</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-path xmlns:ncm=\"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring\">/ncm:get-schema</error-path>"
            "<error-message xml:lang=\"en\">An expected element is missing.</error-message>"
            "<error-info><bad-element>identifier</bad-element></error-info>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);

    /* missing element in 'config-choice' in the application layer: missing mandatory node in the choice-stmt */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <get-config>"
            "    <source/>"
            "  </get-config>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\"><rpc-error>"
            "<error-type>protocol</error-type>"
            "<error-tag>data-missing</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-app-tag>mandatory-choice</error-app-tag>"
            "<error-path xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">/nc:get-config/nc:source</error-path>"
            "<error-message xml:lang=\"en\">Missing mandatory choice.</error-message>"
            "<error-info><missing-choice xmlns=\"urn:ietf:params:xml:ns:yang:1\">config-source</missing-choice></error-info>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);
}

static void
test_malformed_message(void **state)
{
    int rc;
    char *msg, *exp;
    struct np2_test *st = *state;
    struct np_other_client *sess = st->oc_sess;

    /* malformed-message xmlns in the rpc layer */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn&ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-changes/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    assert_string_equal(msg,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">"
            "<rpc-error>"
            "<error-type>rpc</error-type>"
            "<error-tag>malformed-message</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">A message could not be handled because it failed to be parsed correctly.</error-message>"
            "</rpc-error></rpc-reply>");

    /* malformed-message in the non-rpc layer */
    rc = asprintf(&msg,
            "<rpc xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "  <discard-cha&ges/>"
            "</rpc>", sess->msgid);
    assert_int_not_equal(rc, -1);
    rc = oc_send_msg(sess, msg);
    assert_int_equal(rc, 0);
    free(msg);
    rc = oc_recv_msg(sess, &msg);
    assert_int_equal(rc, 0);
    rc = asprintf(&exp,
            "<rpc-reply xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"%" PRIu64 "\">"
            "<rpc-error>"
            "<error-type>rpc</error-type>"
            "<error-tag>malformed-message</error-tag>"
            "<error-severity>error</error-severity>"
            "<error-message xml:lang=\"en\">Invalid character sequence \"&amp;ges/&gt;&lt;/rpc&gt;\","
            " expected element tag end ('&gt;' or '/&gt;') or an attribute.</error-message>"
            "</rpc-error></rpc-reply>", sess->msgid);
    assert_int_not_equal(rc, -1);
    assert_string_equal(msg, exp);
    free(exp);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_message_id),
        cmocka_unit_test(test_missing_attribute),
        cmocka_unit_test(test_unknown_attribute),
        cmocka_unit_test(test_missing_element),
        cmocka_unit_test(test_malformed_message),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
