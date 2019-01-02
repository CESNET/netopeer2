"""
Tests for leafref data validation
"""
import pytest
from lxml import etree
from ncclient.operations import RPCError

from common import NS_MAP


def test_create_unresolved_data_is_error(mgr, cleanup):
    with pytest.raises(RPCError):
        edit_referer(mgr, "create", "Foo", "RefFoo")

    assert get_referee_list(mgr) == {}
    assert get_referer_list(mgr) == {}


def test_create_resolved_data_is_ok(mgr, cleanup):
    edit_referee(mgr, "create", "Foo", "Bar")
    edit_referer(mgr, "create", "Foo", "RefFoo")

    assert get_referee_list(mgr) == {"Foo": "Bar"}
    assert get_referer_list(mgr) == {"Foo": "RefFoo"}


def test_create_resolved_data_and_removing_in_reverse_order_is_ok(mgr, cleanup):
    edit_referee(mgr, "create", "Foo", "Bar")
    edit_referer(mgr, "create", "Foo", "RefFoo")
    edit_referer(mgr, "delete", "Foo", "RefFoo")
    edit_referee(mgr, "delete", "Foo", "Bar")

    assert get_referee_list(mgr) == {}
    assert get_referer_list(mgr) == {}


def test_create_resolved_data_and_removing_referenced_data_is_error(mgr, cleanup):
    edit_referee(mgr, "create", "Foo", "Bar")
    edit_referer(mgr, "create", "Foo", "RefFoo")
    with pytest.raises(RPCError):
        edit_referee(mgr, "delete", "Foo", "Bar")

    assert get_referee_list(mgr) == {"Foo": "Bar"}
    assert get_referer_list(mgr) == {"Foo": "RefFoo"}


def edit_referee(mgr, operation, name, value):
    mgr.edit_config(
        target="running",
        config="""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <contain-1 xmlns="http://example.com/netopeer2-integration-tests/test-referee">
        <data nc:operation="{op}">
          <name>{name}</name>
          <value>{value}</value>
        </data>
      </contain-1>
    </config>
    """.format(
            name=name, value=value, op=operation
        ),
    )


def edit_referer(mgr, operation, name, value):
    mgr.edit_config(
        target="running",
        config="""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <contain-2 xmlns="http://example.com/netopeer2-integration-tests/test-referer">
        <data-ref nc:operation="{op}">
          <name>{name}</name>
          <another-value>{value}</another-value>
        </data-ref>
      </contain-2>
    </config>
    """.format(
            name=name, value=value, op=operation
        ),
    )


@pytest.fixture
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <contain-1 xmlns="http://example.com/netopeer2-integration-tests/test-referee" nc:operation="remove" />
      <contain-2 xmlns="http://example.com/netopeer2-integration-tests/test-referer" nc:operation="remove" />
    </config>
    """,
    )


def get_referee_list(mgr):
    data_xml = mgr.get_config(source="running").data_xml
    doc = etree.fromstring(data_xml.encode("ascii"))
    results = doc.xpath(
        "/nc:data/test-referee:contain-1/test-referee:data", namespaces=NS_MAP
    )

    ret = {}
    for entry in results:
        key = entry.find(
            "{http://example.com/netopeer2-integration-tests/test-referee}name"
        )
        value = entry.find(
            "{http://example.com/netopeer2-integration-tests/test-referee}value"
        )

        ret[key.text] = value.text

    return ret


def get_referer_list(mgr):
    data_xml = mgr.get_config(source="running").data_xml
    doc = etree.fromstring(data_xml.encode("ascii"))
    results = doc.xpath(
        "/nc:data/test-referer:contain-2/test-referer:data-ref", namespaces=NS_MAP
    )

    ret = {}
    for entry in results:
        key = entry.find(
            "{http://example.com/netopeer2-integration-tests/test-referer}name"
        )
        value = entry.find(
            "{http://example.com/netopeer2-integration-tests/test-referer}another-value"
        )

        ret[key.text] = value.text

    return ret
