/**
 * @file test_filter.c
 * @author Tadeas Vintrlik <xvintr04@stud.fit.vutbr.cz>
 * @brief tests for filter in get and get-config rpc
 *
 * @copyright
 * Copyright (c) 2019 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2017 - 2021 CESNET, z.s.p.o.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>
#include <nc_client.h>
#include <sysrepo.h>

#include "np_test.h"
#include "np_test_config.h"

static void
setup_data(void **state)
{
    struct np_test *st = *state;
    char *data;

    data =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>0.0.0.0</name>\n"
            "        <interfaces>\n"
            "          <interface>\n"
            "            <name>192.0.2.1</name>\n"
            "          </interface>\n"
            "          <interface>\n"
            "            <name>192.0.2.4</name>\n"
            "          </interface>\n"
            "        </interfaces>\n"
            "      </area>\n"
            "      <area>\n"
            "        <name>192.168.0.0</name>\n"
            "        <interfaces>\n"
            "          <interface>\n"
            "            <name>192.168.0.1</name>\n"
            "          </interface>\n"
            "          <interface>\n"
            "            <name>192.168.0.12</name>\n"
            "          </interface>\n"
            "          <interface>\n"
            "            <name>192.168.0.25</name>\n"
            "          </interface>\n"
            "        </interfaces>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"x1\">\n"
            "  <item>\n"
            "    <price>2</price>\n"
            "  </item>\n"
            "  <item>\n"
            "    <price>3</price>\n"
            "  </item>\n"
            "  <item>\n"
            "    <price>4</price>\n"
            "  </item>\n"
            "  <item>\n"
            "    <price>6</price>\n"
            "  </item>\n"
            "  <item>\n"
            "    <price>8</price>\n"
            "  </item>\n"
            "  <item>\n"
            "    <price>13</price>\n"
            "  </item>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data =
            "<hardware xmlns=\"i1\">\n"
            "  <component>\n"
            "    <name>ComponentName</name>\n"
            "    <class>O-RAN-RADIO</class>\n"
            "      <feature>\n"
            "        <wireless>true</wireless>\n"
            "      </feature>\n"
            "  </component>\n"
            "</hardware>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data =
            "<top xmlns=\"f1\">\n"
            "  <devices>\n"
            "    <servers>\n"
            "      <server>\n"
            "        <name>First</name>\n"
            "        <address>192.168.0.4</address>\n"
            "        <port>80</port>\n"
            "        <attributes>\n"
            "          <attr1>value</attr1>\n"
            "        </attributes>\n"
            "      </server>\n"
            "      <server>\n"
            "        <name>Second</name>\n"
            "        <address>192.168.0.12</address>\n"
            "        <port>80</port>\n"
            "      </server>\n"
            "      <server>\n"
            "        <name>Fourth</name>\n"
            "        <address>192.168.0.50</address>\n"
            "        <port>22</port>\n"
            "      </server>\n"
            "      <server>\n"
            "        <name>Fifth</name>\n"
            "        <address>192.168.0.50</address>\n"
            "        <port>443</port>\n"
            "      </server>\n"
            "      <server>\n"
            "        <name>Sixth</name>\n"
            "        <address>192.168.0.102</address>\n"
            "        <port>22</port>\n"
            "      </server>\n"
            "    </servers>\n"
            "    <desktops>\n"
            "      <desktop>\n"
            "        <name>Seventh</name>\n"
            "        <address>192.168.0.130</address>\n"
            "      </desktop>\n"
            "      <desktop>\n"
            "        <name>Sixth</name>\n"
            "        <address>192.168.0.142</address>\n"
            "      </desktop>\n"
            "    </desktops>\n"
            "  </devices>\n"
            "  <some-list>\n"
            "    <k>a</k>\n"
            "    <val xmlns:f1i=\"urn:f1i\">f1i:ident-val1</val>\n"
            "  </some-list>\n"
            "  <some-list>\n"
            "    <k>b</k>\n"
            "    <val xmlns:f1i=\"urn:f1i\">f1i:ident-val2</val>\n"
            "  </some-list>\n"
            "</top>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);

    data = "<first xmlns=\"ed1\">Test</first>\n";
    SR_EDIT(st, data);
    FREE_TEST_VARS(st);
}

static int
change_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *xpath, sr_event_t event,
        uint32_t request_id, void *private_data)
{
    (void) session; (void) sub_id; (void) module_name; (void) xpath;
    (void) event; (void) request_id; (void) private_data;

    return SR_ERR_OK;
}

static int
oper_get_serial_num(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    (void) session; (void) sub_id; (void) module_name; (void) path;
    (void) request_xpath; (void) request_id; (void) private_data;

    if (!lyd_new_path(*parent, NULL, "serial-num", "1234", 0, NULL)) {
        return SR_ERR_OK;
    } else {
        return SR_ERR_LY;
    }
}

static int
oper_get_routing_state(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    const struct ly_ctx *ly_ctx;
    const char *xml;
    struct lyd_node *data;
    LY_ERR lyrc;

    (void) sub_id; (void) module_name; (void) path;
    (void) request_xpath; (void) request_id; (void) private_data;

    xml =
            "<routing-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-routing\">\n"
            "  <ribs>\n"
            "    <rib>\n"
            "      <name>default</name>\n"
            "      <address-family xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:ipv4</address-family>\n"
            "      <routes>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">172.17.0.1</next-hop-address>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:static</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.0/0</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.1</next-hop-address>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:static</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">172.17.0.0/16</destination-prefix>\n"
            "        </route>\n"
            "      </routes>\n"
            "    </rib>\n"
            "    <rib>\n"
            "      <name>outband</name>\n"
            "      <address-family xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:ipv4</address-family>\n"
            "      <routes>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">10.161.164.1</next-hop-address>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:static</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.0/0</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:static</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">1.2.3.0/24</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <outgoing-interface>management 0/1</outgoing-interface>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:direct</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">10.161.164.0/24</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:direct</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.0.0/24</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:static</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.0.0/16</destination-prefix>\n"
            "        </route>\n"
            "        <route>\n"
            "          <next-hop>\n"
            "            <special-next-hop>receive</special-next-hop>\n"
            "          </next-hop>\n"
            "          <source-protocol xmlns:rt=\"urn:ietf:params:xml:ns:yang:ietf-routing\">rt:direct</source-protocol>\n"
            "          <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.1.0/24</destination-prefix>\n"
            "        </route>\n"
            "      </routes>\n"
            "    </rib>\n"
            "  </ribs>\n"
            "</routing-state>\n";

    ly_ctx = sr_session_acquire_context(session);
    lyrc = lyd_parse_data_mem(ly_ctx, xml, LYD_XML, LYD_PARSE_ONLY, 0, &data);
    sr_session_release_context(session);
    if (lyrc) {
        return SR_ERR_LY;
    }

    *parent = data;
    return SR_ERR_OK;
}

static int
local_setup(void **state)
{
    struct np_test *st;
    char test_name[256];
    const char *modules[] = {
        NP_TEST_MODULE_DIR "/example2.yang", NP_TEST_MODULE_DIR "/filter1-imp.yang", NP_TEST_MODULE_DIR "/filter1.yang",
        NP_TEST_MODULE_DIR "/xpath.yang", NP_TEST_MODULE_DIR "/issue1.yang", NP_TEST_MODULE_DIR "/edit1.yang",
        NP_TEST_MODULE_DIR "/ietf-routing@2018-03-13.yang", NP_TEST_MODULE_DIR "/ietf-ipv4-unicast-routing@2018-03-13.yang",
        NP_TEST_MODULE_DIR "/oper-data.yang", NULL
    };
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

    /* setup data */
    setup_data(state);

    /* setup subscriptions */
    assert_int_equal(SR_ERR_OK, sr_oper_get_subscribe(st->sr_sess, "issue1",
            "/issue1:hardware/component/serial-num", oper_get_serial_num, NULL, 0, &st->sub));
    assert_int_equal(SR_ERR_OK, sr_oper_get_subscribe(st->sr_sess, "ietf-routing", "/ietf-routing:routing-state",
            oper_get_routing_state, NULL, 0, &st->sub));
    assert_int_equal(SR_ERR_OK, sr_module_change_subscribe(st->sr_sess, "issue1", NULL, change_cb, NULL, 0, 0, &st->sub));

    return 0;
}

static int
local_teardown(void **state)
{
    struct np_test *st = *state;
    const char *modules[] = {
        "example2", "filter1-imp", "filter1", "xpath", "issue1", "edit1", "ietf-routing",
        "ietf-ipv4-unicast-routing", "oper-data", NULL
    };

    if (!st) {
        return 0;
    }

    /* unsubscribe */
    sr_unsubscribe(st->sub);

    /* close netopeer2 server */
    return np_glob_teardown(state, modules);
}

static void
test_xpath_basic(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    /* Filter first by xpath */
    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[1]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* since there are two last()-1 should be same as 1 */
    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[last()-1]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* filter by area name same as the two before */
    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[name='0.0.0.0']");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    /* use arithmetic operators should also be the first */
    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[3-2]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[5 mod 2]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[-1 + 2]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[name!='192.168.0.0']");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_xpath_boolean_operator(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"x1\">\n"
            "      <item>\n"
            "        <price>3</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>4</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>6</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>8</price>\n"
            "      </item>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    GET_CONFIG_FILTER(st, "/top/item[price > 2 and price <= 8]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"x1\">\n"
            "      <item>\n"
            "        <price>2</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>3</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>8</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>13</price>\n"
            "      </item>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    GET_CONFIG_FILTER(st, "/top/item[price < 4 or price >= 8]");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_xpath_union(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get-config>\n";

    GET_CONFIG_FILTER(st, "/example2:top/protocols/ospf/area[name='0.0.0.0']|"
            "/issue1:hardware/component[name='ComponentName']");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_xpath_namespaces(void **state)
{
    struct np_test *st = *state;
    const char *expected;

    expected =
            "<get-config "
            "xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get-config>\n";

    /* test namespaces */
    GET_CONFIG_FILTER(st, "/top/protocols/ospf/area[name='0.0.0.0']|"
            "/hardware/component[name='ComponentName']");
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    GET_CONFIG_FILTER(st, "/top");

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "          <area>\n"
            "            <name>192.168.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.168.0.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.168.0.12</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.168.0.25</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "    <top xmlns=\"f1\">\n"
            "      <devices>\n"
            "        <desktops>\n"
            "          <desktop>\n"
            "            <name>Seventh</name>\n"
            "            <address>192.168.0.130</address>\n"
            "          </desktop>\n"
            "          <desktop>\n"
            "            <name>Sixth</name>\n"
            "            <address>192.168.0.142</address>\n"
            "          </desktop>\n"
            "        </desktops>\n"
            "        <servers>\n"
            "          <server>\n"
            "            <name>Fifth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>443</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>First</name>\n"
            "            <address>192.168.0.4</address>\n"
            "            <port>80</port>\n"
            "            <attributes>\n"
            "              <attr1>value</attr1>\n"
            "            </attributes>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Fourth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Second</name>\n"
            "            <address>192.168.0.12</address>\n"
            "            <port>80</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Sixth</name>\n"
            "            <address>192.168.0.102</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "        </servers>\n"
            "      </devices>\n"
            "      <some-list>\n"
            "        <k>a</k>\n"
            "        <val xmlns:f1i=\"urn:f1i\">f1i:ident-val1</val>\n"
            "      </some-list>\n"
            "      <some-list>\n"
            "        <k>b</k>\n"
            "        <val xmlns:f1i=\"urn:f1i\">f1i:ident-val2</val>\n"
            "      </some-list>\n"
            "    </top>\n"
            "    <top xmlns=\"x1\">\n"
            "      <item>\n"
            "        <price>2</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>3</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>4</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>6</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>8</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>13</price>\n"
            "      </item>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_xpath_top_level_leaf_match(void **state)
{
    struct np_test *st = *state;
    char *expected;

    GET_CONFIG_FILTER(st, "/edit1:first[.='Test']");

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_subtree_content_match(void **state)
{
    struct np_test *st = *state;
    const char *filter, *expected;

    filter =
            "<top xmlns=\"ex2\">\n"
            "  <protocols>\n"
            "    <ospf>\n"
            "      <area>\n"
            "        <name>0.0.0.0</name>\n"
            "      </area>\n"
            "    </ospf>\n"
            "  </protocols>\n"
            "</top>\n";

    GET_CONFIG_FILTER(st, filter);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);

    filter =
            "<top xmlns=\"f1\" xmlns:f1i=\"urn:f1i\">\n"
            "  <some-list>\n"
            "    <val>f1i:ident-val1</val>\n"
            "  </some-list>\n"
            "</top>\n";

    GET_CONFIG_FILTER(st, filter);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"f1\">\n"
            "      <some-list>\n"
            "        <k>a</k>\n"
            "        <val xmlns:f1i=\"urn:f1i\">f1i:ident-val1</val>\n"
            "      </some-list>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_subtree_content_match_top_level_leaf(void **state)
{
    const char *expected;
    struct np_test *st = *state;

    GET_CONFIG_FILTER(st, "<first xmlns=\"ed1\">Test</first>");

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <first xmlns=\"ed1\">Test</first>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_subtree_selection_node(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<top xmlns=\"f1\">\n"
            "  <devices>\n"
            "    <servers/>\n"
            "  </devices>\n"
            "</top>\n";

    GET_CONFIG_FILTER(st, filter);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"f1\">\n"
            "      <devices>\n"
            "        <servers>\n"
            "          <server>\n"
            "            <name>Fifth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>443</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>First</name>\n"
            "            <address>192.168.0.4</address>\n"
            "            <port>80</port>\n"
            "            <attributes>\n"
            "              <attr1>value</attr1>\n"
            "            </attributes>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Fourth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Second</name>\n"
            "            <address>192.168.0.12</address>\n"
            "            <port>80</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Sixth</name>\n"
            "            <address>192.168.0.102</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "        </servers>\n"
            "      </devices>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_subtree_nested_selection_node(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<top xmlns=\"f1\">\n"
            "  <devices>\n"
            "    <servers>\n"
            "      <server>\n"
            "        <name>First</name>\n"
            "        <attributes>\n"
            "          <attr1/>\n"
            "        </attributes>\n"
            "      </server>\n"
            "    </servers>\n"
            "  </devices>\n"
            "</top>\n";

    GET_CONFIG_FILTER(st, filter);

    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"f1\">\n"
            "      <devices>\n"
            "        <servers>\n"
            "          <server>\n"
            "            <name>First</name>\n"
            "            <attributes>\n"
            "              <attr1>value</attr1>\n"
            "            </attributes>\n"
            "          </server>\n"
            "        </servers>\n"
            "      </devices>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_subtree_no_namespace(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter = "<top/>\n";
    GET_CONFIG_FILTER(st, filter);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"ex2\">\n"
            "      <protocols>\n"
            "        <ospf>\n"
            "          <area>\n"
            "            <name>0.0.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.0.2.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.0.2.4</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "          <area>\n"
            "            <name>192.168.0.0</name>\n"
            "            <interfaces>\n"
            "              <interface>\n"
            "                <name>192.168.0.1</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.168.0.12</name>\n"
            "              </interface>\n"
            "              <interface>\n"
            "                <name>192.168.0.25</name>\n"
            "              </interface>\n"
            "            </interfaces>\n"
            "          </area>\n"
            "        </ospf>\n"
            "      </protocols>\n"
            "    </top>\n"
            "    <top xmlns=\"f1\">\n"
            "      <devices>\n"
            "        <desktops>\n"
            "          <desktop>\n"
            "            <name>Seventh</name>\n"
            "            <address>192.168.0.130</address>\n"
            "          </desktop>\n"
            "          <desktop>\n"
            "            <name>Sixth</name>\n"
            "            <address>192.168.0.142</address>\n"
            "          </desktop>\n"
            "        </desktops>\n"
            "        <servers>\n"
            "          <server>\n"
            "            <name>Fifth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>443</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>First</name>\n"
            "            <address>192.168.0.4</address>\n"
            "            <port>80</port>\n"
            "            <attributes>\n"
            "              <attr1>value</attr1>\n"
            "            </attributes>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Fourth</name>\n"
            "            <address>192.168.0.50</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Second</name>\n"
            "            <address>192.168.0.12</address>\n"
            "            <port>80</port>\n"
            "          </server>\n"
            "          <server>\n"
            "            <name>Sixth</name>\n"
            "            <address>192.168.0.102</address>\n"
            "            <port>22</port>\n"
            "          </server>\n"
            "        </servers>\n"
            "      </devices>\n"
            "      <some-list>\n"
            "        <k>a</k>\n"
            "        <val xmlns:f1i=\"urn:f1i\">f1i:ident-val1</val>\n"
            "      </some-list>\n"
            "      <some-list>\n"
            "        <k>b</k>\n"
            "        <val xmlns:f1i=\"urn:f1i\">f1i:ident-val2</val>\n"
            "      </some-list>\n"
            "    </top>\n"
            "    <top xmlns=\"x1\">\n"
            "      <item>\n"
            "        <price>2</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>3</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>4</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>6</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>8</price>\n"
            "      </item>\n"
            "      <item>\n"
            "        <price>13</price>\n"
            "      </item>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    filter =
            "<top>\n"
            "  <devices>\n"
            "    <servers>\n"
            "      <server>\n"
            "        <name>First</name>\n"
            "        <attributes>\n"
            "          <attr1/>\n"
            "        </attributes>\n"
            "      </server>\n"
            "    </servers>\n"
            "  </devices>\n"
            "</top>\n";
    GET_CONFIG_FILTER(st, filter);
    expected =
            "<get-config xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <top xmlns=\"f1\">\n"
            "      <devices>\n"
            "        <servers>\n"
            "          <server>\n"
            "            <name>First</name>\n"
            "            <attributes>\n"
            "              <attr1>value</attr1>\n"
            "            </attributes>\n"
            "          </server>\n"
            "        </servers>\n"
            "      </devices>\n"
            "    </top>\n"
            "  </data>\n"
            "</get-config>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    filter =
            "<invalid-name>\n"
            "  <node/>\n"
            "</invalid-name>\n";
    SEND_GET_CONFIG_PARAM(st, NC_DATASTORE_RUNNING, NC_WD_ALL, filter);
    ASSERT_ERROR_REPLY(st);
    expected =
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">Subtree filter node \"invalid-name\" without a namespace does not match any YANG nodes.</error-message>\n"
            "</rpc-error>\n"
            "<rpc-error xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <error-type>application</error-type>\n"
            "  <error-tag>operation-failed</error-tag>\n"
            "  <error-severity>error</error-severity>\n"
            "  <error-message xml:lang=\"en\">User callback failed.</error-message>\n"
            "</rpc-error>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

static void
test_get_selection_node(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<hardware xmlns=\"i1\">\n"
            "  <component>\n"
            "    <serial-num/>"
            "  </component>\n"
            "</hardware>";

    GET_FILTER(st, filter);

    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <serial-num>1234</serial-num>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_get_containment_node(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter = "<hardware xmlns=\"i1\"/>\n";

    GET_FILTER(st, filter);

    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <serial-num>1234</serial-num>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_get_content_match_node(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<hardware xmlns=\"i1\">\n"
            "  <component>\n"
            "    <class>O-RAN-RADIO</class>\n"
            "    <feature/>\n"
            "    <serial-num/>\n"
            "  </component>\n"
            "</hardware>\n";

    GET_FILTER(st, filter);

    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <serial-num>1234</serial-num>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_get_oper_data(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<hardware xmlns=\"i1\">\n"
            "  <component>\n"
            "    <class>O-RAN-RADIO</class>\n"
            "    <serial-num>1234</serial-num>\n"
            "    <feature>\n"
            "      <wireless>true</wireless>\n"
            "    </feature>\n"
            "  </component>\n"
            "</hardware>\n";

    GET_FILTER(st, filter);

    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <serial-num>1234</serial-num>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_get_oper_data2(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<RptSubsInfos xmlns=\"urn:oper-data\">\n"
            "  <RptSubsInfo>\n"
            "    <Type>SUBS_CONFIG</Type>\n"
            "    <SubsPolicyId/>\n"
            "    <Result/>\n"
            "    <SubsConfigType>CONFIG_TYPE_FILTERGROUP</SubsConfigType>\n"
            "  </RptSubsInfo>\n"
            "</RptSubsInfos>\n";

    GET_FILTER(st, filter);

    expected =
            "<get xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\n"
            "  <data/>\n"
            "</get>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_getdata_oper_data(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter =
            "<hardware xmlns=\"i1\">\n"
            "  <component>\n"
            "    <class>O-RAN-RADIO</class>\n"
            "    <serial-num>1234</serial-num>\n"
            "    <feature>\n"
            "      <wireless>true</wireless>\n"
            "    </feature>\n"
            "  </component>\n"
            "</hardware>\n";

    GET_DATA_FILTER(st, "ietf-datastores:operational", filter, NULL, NULL, 0, 0, 0, 0, NC_WD_ALL);

    expected =
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">\n"
            "  <data>\n"
            "    <hardware xmlns=\"i1\">\n"
            "      <component>\n"
            "        <name>ComponentName</name>\n"
            "        <class>O-RAN-RADIO</class>\n"
            "        <serial-num>1234</serial-num>\n"
            "        <feature>\n"
            "          <wireless>true</wireless>\n"
            "        </feature>\n"
            "      </component>\n"
            "    </hardware>\n"
            "  </data>\n"
            "</get-data>\n";

    assert_string_equal(st->str, expected);

    FREE_TEST_VARS(st);
}

static void
test_keyless_list(void **state)
{
    struct np_test *st = *state;
    char *filter, *expected;

    filter = "/ietf-routing:routing-state//ietf-ipv4-unicast-routing:next-hop-address";
    GET_DATA_FILTER(st, "ietf-datastores:operational", filter, NULL, NULL, 0, 0, 0, 0, NC_WD_ALL);
    expected =
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">\n"
            "  <data>\n"
            "    <routing-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-routing\">\n"
            "      <ribs>\n"
            "        <rib>\n"
            "          <name>default</name>\n"
            "          <routes>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">172.17.0.1</next-hop-address>\n"
            "              </next-hop>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.1</next-hop-address>\n"
            "              </next-hop>\n"
            "            </route>\n"
            "          </routes>\n"
            "        </rib>\n"
            "        <rib>\n"
            "          <name>outband</name>\n"
            "          <routes>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">10.161.164.1</next-hop-address>\n"
            "              </next-hop>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "              </next-hop>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "              </next-hop>\n"
            "            </route>\n"
            "          </routes>\n"
            "        </rib>\n"
            "      </ribs>\n"
            "    </routing-state>\n"
            "  </data>\n"
            "</get-data>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);

    filter = "/ietf-routing:routing-state//*";
    GET_DATA_FILTER(st, "ietf-datastores:operational", filter, NULL, NULL, 0, 0, 0, 0, NC_WD_ALL);
    expected =
            "<get-data xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-nmda\">\n"
            "  <data>\n"
            "    <routing-state xmlns=\"urn:ietf:params:xml:ns:yang:ietf-routing\">\n"
            "      <ribs>\n"
            "        <rib>\n"
            "          <name>default</name>\n"
            "          <address-family>ipv4</address-family>\n"
            "          <routes>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">172.17.0.1</next-hop-address>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>static</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.0/0</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.1</next-hop-address>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>static</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">172.17.0.0/16</destination-prefix>\n"
            "            </route>\n"
            "          </routes>\n"
            "        </rib>\n"
            "        <rib>\n"
            "          <name>outband</name>\n"
            "          <address-family>ipv4</address-family>\n"
            "          <routes>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">10.161.164.1</next-hop-address>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>static</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">0.0.0.0/0</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>static</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">1.2.3.0/24</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <outgoing-interface>management 0/1</outgoing-interface>\n"
            "              </next-hop>\n"
            "              <source-protocol>direct</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">10.161.164.0/24</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>direct</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.0.0/24</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <next-hop-address xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.0.0.8</next-hop-address>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>static</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.0.0/16</destination-prefix>\n"
            "            </route>\n"
            "            <route>\n"
            "              <next-hop>\n"
            "                <special-next-hop>receive</special-next-hop>\n"
            "              </next-hop>\n"
            "              <source-protocol>direct</source-protocol>\n"
            "              <destination-prefix xmlns=\"urn:ietf:params:xml:ns:yang:ietf-ipv4-unicast-routing\">192.168.1.0/24</destination-prefix>\n"
            "            </route>\n"
            "          </routes>\n"
            "        </rib>\n"
            "      </ribs>\n"
            "    </routing-state>\n"
            "  </data>\n"
            "</get-data>\n";
    assert_string_equal(st->str, expected);
    FREE_TEST_VARS(st);
}

int
main(int argc, char **argv)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_xpath_basic),
        cmocka_unit_test(test_xpath_boolean_operator),
        cmocka_unit_test(test_xpath_union),
        cmocka_unit_test(test_xpath_namespaces),
        cmocka_unit_test(test_xpath_top_level_leaf_match),
        cmocka_unit_test(test_subtree_content_match),
        cmocka_unit_test(test_subtree_content_match_top_level_leaf),
        cmocka_unit_test(test_subtree_selection_node),
        cmocka_unit_test(test_subtree_nested_selection_node),
        cmocka_unit_test(test_subtree_no_namespace),
        cmocka_unit_test(test_get_selection_node),
        cmocka_unit_test(test_get_containment_node),
        cmocka_unit_test(test_get_content_match_node),
        cmocka_unit_test(test_get_oper_data),
        cmocka_unit_test(test_get_oper_data2),
        cmocka_unit_test(test_getdata_oper_data),
        cmocka_unit_test(test_keyless_list),
    };

    nc_verbosity(NC_VERB_WARNING);
    parse_arg(argc, argv);
    return cmocka_run_group_tests(tests, local_setup, local_teardown);
}
