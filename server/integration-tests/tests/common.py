import time
import syslog
import time
from lxml import etree

import requests
from ncclient.manager import connect_ssh


def wait_for(f, timeout=10, period=0.5):
    while timeout > 0:
        try:
            return f()
        except Exception:
            pass
        time.sleep(period)
        timeout -= period

    return f()


def connect_mgr():
    return connect_ssh(
        host="localhost",
        port=830,
        username="root",
        password="password",
        hostkey_verify=False,
    )


NS_MAP = {
    "nc": "urn:ietf:params:xml:ns:netconf:base:1.0",
    "sys": "urn:ietf:params:xml:ns:yang:ietf-system",
    "nc-mon": "urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring",
    "test-referer": "http://example.com/netopeer2-integration-tests/test-referer",
    "test-referee": "http://example.com/netopeer2-integration-tests/test-referee",
    "test-notification": "http://www.example.com/ns/yang/test-notifications",
    "notif": "urn:ietf:params:xml:ns:netconf:notification:1.0",
    "nc-notif": "urn:ietf:params:xml:ns:yang:ietf-netconf-notifications",
    "test-actions": "http://example.com/netopeer2-integration-tests/test-actions",
    "test-actions-aug": "http://example.com/netopeer2-integration-tests/test-actions-augment",
    "test-when": "http://example.com/netopeer2-integration-tests/test-when",
    "test-cand-cfg": "http://example.com/netopeer2-integration-tests/test-candidate-config",
    "test-validation": "http://example.com/netopeer2-integration-tests/test-validation",
    "test-module": "http://example.com/netopeer2-integration-tests/test-module",
    "ietf-hw": "urn:ietf:params:xml:ns:yang:ietf-hardware",
    "ks": "urn:ietf:params:xml:ns:yang:ietf-keystore",
    "ncs": "urn:ietf:params:xml:ns:yang:ietf-netconf-server",
}


def change_contact(mgr, operation, value=""):
    mgr.edit_config(
        target="running",
        config="""
    <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <system xmlns="urn:ietf:params:xml:ns:yang:ietf-system">
        <contact nc:operation="{op}">{value}</contact>
      </system>
    </nc:config>
    """.format(
            value=value, op=operation
        ),
    )


def get_contact(mgr):
    r = mgr.get_config(
        source="running",
        filter="""
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <system xmlns="urn:ietf:params:xml:ns:yang:ietf-system">
        <contact />
      </system>
    </filter>
    """,
    )

    node = r.data_ele.xpath("//sys:contact", namespaces=NS_MAP)
    if not node:
        return "Not Present"
    else:
        return node[0].text


def xml_to_dict(root):
    """Converts an lxml tree to a dictionary for easier comparison"""
    children = root.getchildren()
    if not children:
        return root.text

    d = {}
    for child in children:
        name = child.tag
        converted = xml_to_dict(child)
        if name not in d:
            d[name] = converted
        else:
            if not isinstance(d[name], list):
                d[name] = [d[name], converted]
            else:
                d[name].append(converted)

    return d


def send_notification(notification):
    result = requests.post("http://localhost:9080/send-notification", json=notification)
    assert result.ok


def set_action_reply(action):
    result = requests.post("http://localhost:9080/set-action-reply", json=action)
    assert result.ok


def test_send_notification_service_ready():
    result = requests.post(
        "http://localhost:9080/send-notification", json={"no-op": None}
    )
    assert result.ok


def test_set_action_reply_service_ready():
    result = requests.post(
        "http://localhost:9080/set-action-reply", json={"no-op": None}
    )
    assert result.ok


def find_single_xpath(data_xml, xpath):
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(xpath, namespaces=NS_MAP)
    if len(results) > 0:
        return results[0].text
    else:
        return "Not Found"


def get_test_notification_simple_string_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-notification:string-container/test-notification:simple-string",
    )


def get_test_notification_simple_string(mgr):
    return get_test_notification_simple_string_from_data_xml(mgr.get().data_xml)


def get_test_notification_container_notification_string(mgr):
    return find_single_xpath(
        mgr.get().data_xml,
        (
            "/nc:data/test-notification:notification-from-container"
            "/test-notification:notification-string"
        ),
    )


def get_notification_list(mgr):
    data_xml = mgr.get().data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        (
            "/nc:data/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
        ),
        namespaces=NS_MAP,
    )

    ret = {}
    for entry in results:
        key = entry.find("{http://www.example.com/ns/yang/test-notifications}name")
        foo = entry.find("{http://www.example.com/ns/yang/test-notifications}foo")

        ret[key.text] = {"foo": foo.text}

    return ret


def get_embedded_list(mgr):
    data_xml = mgr.get().data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        (
            "/nc:data/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
        ),
        namespaces=NS_MAP,
    )

    ret = {}
    for entry in results:
        key = entry.find("{http://www.example.com/ns/yang/test-notifications}name")
        item = entry.find(
            "{http://www.example.com/ns/yang/test-notifications}embedded-list"
        )
        if item is not None:
            key2 = item.find("{http://www.example.com/ns/yang/test-notifications}name")
            item2 = item.find(
                "{http://www.example.com/ns/yang/test-notifications}embedded-foo"
            )
            ret[key.text] = {key2.text: item2.text}

    return ret


def set_test_notification_simple_string(
    mgr, message, target="running", test_option=None
):
    mgr.edit_config(
        target=target,
        test_option=test_option,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <string-container xmlns="http://www.example.com/ns/yang/test-notifications">
        <simple-string>{}</simple-string>
    </string-container>
</config>
        """.format(
            message
        ),
    )


def set_test_notification_container_notification_string(mgr, message, target="running"):
    mgr.edit_config(
        target=target,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <notification-from-container xmlns="http://www.example.com/ns/yang/test-notifications">
        <notification-string>{}</notification-string>
    </notification-from-container>
</config>
        """.format(
            message
        ),
    )


def set_notification_list_item(mgr, key, foo, error_option=None):
    mgr.edit_config(
        target="running",
        error_option=error_option,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <notification-from-list xmlns="http://www.example.com/ns/yang/test-notifications">
        <notification-from-list>
            <name>{}</name>
            <foo>{}</foo>
        </notification-from-list>
    </notification-from-list>
</config>
    """.format(
            key, foo
        ),
    )


def set_embedded_list_item(mgr, key1, key2, foo, error_option=None):
    mgr.edit_config(
        target="running",
        error_option=error_option,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <notification-from-list xmlns="http://www.example.com/ns/yang/test-notifications">
        <notification-from-list>
            <name>{}</name>
            <embedded-list>
                <name>{}</name>
                <embedded-foo>{}</embedded-foo>
            </embedded-list>
        </notification-from-list>
    </notification-from-list>
</config>
    """.format(
            key1, key2, foo
        ),
    )


def clear_test_notification_simple_string(mgr, datastore="running"):
    mgr.edit_config(
        target=datastore,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <string-container xmlns="http://www.example.com/ns/yang/test-notifications">
        <simple-string nc:operation="delete" />
    </string-container>
</nc:config>""",
    )


def clear_test_notification_container_notification_string(mgr, datastore="running"):
    mgr.edit_config(
        target=datastore,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <notification-from-container xmlns="http://www.example.com/ns/yang/test-notifications">
        <notification-string nc:operation="delete" />
    </notification-from-container>
</nc:config>""",
    )


def clear_notification_list_item(mgr, name):
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <notification-from-list xmlns="http://www.example.com/ns/yang/test-notifications">
        <notification-from-list nc:operation="delete">
            <name>{}</name>
        </notification-from-list>
    </notification-from-list>
</nc:config>""".format(
            name
        ),
    )


def dict_to_xml(name, value, ns=NS_MAP):
    if isinstance(value, str):
        inner = value
        attributes = ""
    elif isinstance(value, list):
        return "".join(dict_to_xml(name, x, None) for x in value)
    else:
        all_keys = value.keys()
        list_keys = [x for x in all_keys if x.startswith("^")]
        attr_keys = [x for x in all_keys if x.startswith("@")]
        other_keys = [
            x for x in all_keys if not x.startswith("^") and not x.startswith("@")
        ]

        inner = "".join(dict_to_xml(k[1:], value[k], None) for k in list_keys)
        inner += "".join(dict_to_xml(k, value[k], None) for k in other_keys)

        if attr_keys:
            attributes = " " + "".join(
                ['{}="{}"'.format(k[1:], value[k]) for k in attr_keys]
            )
        else:
            attributes = ""

    if ns:
        attributes += " " + " ".join(
            ['xmlns:{}="{}"'.format(key, value) for key, value in ns.items()]
        )

    at_index = name.find("@")
    if at_index != -1:
        attributes += " " + name[at_index + 1 :]
        name = name[:at_index]

    return "<{name}{attributes}>{inner}</{name}>".format(
        name=name, attributes=attributes, inner=inner
    )


def edit_config_dict(mgr, values):
    xml = dict_to_xml("nc:config", values, NS_MAP)
    mgr.edit_config(target="running", config=xml)
