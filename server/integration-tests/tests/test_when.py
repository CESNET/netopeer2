import pytest
from lxml import etree

from common import NS_MAP, find_single_xpath
from ncclient.operations import RPCError


def test_when_statement_met(mgr, cleanup):
    set_test_container_when_check(mgr, "true")
    set_test_container_gated_data(mgr, 100)
    assert get_test_container_when_check(mgr) == 'true'
    assert get_test_container_gated_data(mgr) == '100'


def test_when_statement_unmet(mgr, cleanup):
    assert get_test_container_when_check(mgr) == 'Not Found'
    with pytest.raises(RPCError) as excinfo:
        set_test_container_gated_data(mgr, 100)
    assert get_test_container_gated_data(mgr) == 'Not Found'


def test_when_statement_remove_check(mgr, cleanup):
    set_test_container_when_check(mgr, "true")
    set_test_container_gated_data(mgr, 100)
    assert get_test_container_when_check(mgr) == 'true'
    assert get_test_container_gated_data(mgr) == '100'

    clear_test_container_gated_data(mgr)
    set_test_container_when_check(mgr, "false")
    assert get_test_container_when_check(mgr) == 'false'
    assert get_test_container_gated_data(mgr) != '100'


def test_when_statement_remove_data_on_false_statement(mgr, cleanup):
    set_test_container_when_check(mgr, "true")
    set_test_container_gated_data(mgr, 100)
    assert get_test_container_when_check(mgr) == 'true'
    assert get_test_container_gated_data(mgr) == '100'

    # We should be able to change the when statement and it will remove
    # the gated data behind the scenes
    set_test_container_when_check(mgr, "false")
    assert get_test_container_when_check(mgr) == 'false'
    assert get_test_container_gated_data(mgr) == 'Not Found'


def test_when_statement_becomes_false_error_on_modification(mgr, cleanup):
    set_test_container_when_check(mgr, "true")
    set_test_container_gated_data(mgr, 100)
    assert get_test_container_when_check(mgr) == 'true'
    assert get_test_container_gated_data(mgr) == '100'

    clear_test_container_gated_data(mgr)
    set_test_container_when_check(mgr, "false")
    with pytest.raises(RPCError) as excinfo:
        set_test_container_gated_data(mgr, 100)
    assert get_test_container_gated_data(mgr) == 'Not Found'


def get_test_container_gated_data_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-when:test-when/test-when:gated-data",
    )

def get_test_container_when_check_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-when:test-when/test-when:when-check",
    )


def get_test_container_gated_data(mgr):
    return get_test_container_gated_data_from_data_xml(mgr.get().data_xml)

def get_test_container_when_check(mgr):
    return get_test_container_when_check_from_data_xml(mgr.get().data_xml)


def clear_test_container_when_check(mgr, target="running", test_option=None):
    mgr.edit_config(
        target=target,
        test_option=test_option,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-when xmlns="http://example.com/netopeer2-integration-tests/test-when">
        <when-check nc:operation="delete" />
    </test-when>
</nc:config>
        """)


def clear_test_container_gated_data(mgr, target="running", test_option=None):
    mgr.edit_config(
        target=target,
        test_option=test_option,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-when xmlns="http://example.com/netopeer2-integration-tests/test-when">
        <gated-data nc:operation="delete" />
    </test-when>
</nc:config>
        """)


def set_test_container_when_check(mgr, message, target="running", test_option=None):
    mgr.edit_config(
        target=target,
        test_option=test_option,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-when xmlns="http://example.com/netopeer2-integration-tests/test-when">
        <when-check>{}</when-check>
    </test-when>
</config>
        """.format(
            message
        ),
    )


def set_test_container_gated_data(mgr, message, target="running", test_option=None):
    mgr.edit_config(
        target=target,
        test_option=test_option,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-when xmlns="http://example.com/netopeer2-integration-tests/test-when">
        <gated-data>{}</gated-data>
    </test-when>
</config>
        """.format(
            message
        ),
    )


@pytest.fixture()
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <test-when xmlns="http://example.com/netopeer2-integration-tests/test-when" nc:operation="remove" />
      </nc:config>
    """,
    )
