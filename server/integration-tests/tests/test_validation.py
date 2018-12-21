import pytest
from lxml import etree
from ncclient.operations import RPCError
from common import find_single_xpath, NS_MAP


def test_validation_string_pattern(mgr, cleanup):
    set_validation_field(mgr, "pattern-validated-string", "AbcdeAccepted")
    with pytest.raises(RPCError):
        set_validation_field(mgr, "pattern-validated-string", "Spaces Rejected")

    clear_validation_field(mgr, "pattern-validated-string")


def test_validation_string_length(mgr, cleanup):
    set_validation_field(mgr, "length-validated-string", "9Accepted")
    with pytest.raises(RPCError):
        set_validation_field(mgr, "length-validated-string", "TooLongRejected")
    with pytest.raises(RPCError):
        set_validation_field(mgr, "length-validated-string", "Short")

    clear_validation_field(mgr, "length-validated-string")


def test_validation_int_range(mgr, cleanup):
    set_validation_field(mgr, "range-validated-int", "0")
    set_validation_field(mgr, "range-validated-int", "1")
    set_validation_field(mgr, "range-validated-int", "-1")
    for out_of_range_value in ["100", "-100"]:
        try:
            set_validation_field(mgr, "range-validated-int", out_of_range_value)
            assert False
        except RPCError as e:
            assert e.tag == "invalid-value"

    clear_validation_field(mgr, "range-validated-int")


def test_feature_disable_leaf(mgr, cleanup):
    assert get_disabled_leaf(mgr) == "Not Found"
    assert get_config_disabled_leaf(mgr) == "Not Found"

    try:
        mgr.edit_config(
            target="running",
            config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <disabled-leaf>test</disabled-leaf>
            </disabled-elements>
        </config>""",
        )
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == "unknown-element"
        assert e.severity == "error"
        assert "bad-element" in e.info
        assert "/test-validation:disabled-elements/disabled-leaf" in e.info

    assert get_disabled_leaf(mgr) == "Not Found"
    assert get_config_disabled_leaf(mgr) == "Not Found"


def test_feature_disable_list(mgr, cleanup):
    assert get_disabled_list(mgr) == []
    assert get_config_disabled_list(mgr) == []

    try:
        mgr.edit_config(
            target="running",
            config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <disabled-list>
                    <name>test</name>
                </disabled-list>
            </disabled-elements>
        </config>""",
        )
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == "unknown-element"
        assert e.severity == "error"
        assert "bad-element" in e.info
        assert "/test-validation:disabled-elements/disabled-list" in e.info

    assert get_disabled_list(mgr) == []
    assert get_config_disabled_list(mgr) == []


def test_feature_disable_container_leaf(mgr, cleanup):
    assert get_disabled_container_leaf(mgr) == "Not Found"
    assert get_config_disabled_container_leaf(mgr) == "Not Found"

    try:
        mgr.edit_config(
            target="running",
            config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-container xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <disabled-container-leaf>test</disabled-container-leaf>
            </disabled-container>
        </config>""",
        )
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == "unknown-element"
        assert e.severity == "error"
        assert "bad-element" in e.info
        assert "/test-validation:disabled-container" in e.info

    assert get_disabled_container_leaf(mgr) == "Not Found"
    assert get_config_disabled_container_leaf(mgr) == "Not Found"


def test_feature_disable_container_list(mgr, cleanup):
    assert get_disabled_container_list(mgr) == []
    assert get_config_disabled_container_list(mgr) == []

    try:
        mgr.edit_config(
            target="running",
            config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-container xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <disabled-container-list>
                    <name>test</name>
                </disabled-container-list>
            </disabled-container>
        </config>""",
        )
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == "unknown-element"
        assert e.severity == "error"
        assert "bad-element" in e.info
        assert "/test-validation:disabled-container" in e.info

    assert get_disabled_container_list(mgr) == []
    assert get_config_disabled_container_list(mgr) == []


def test_feature_disabled_and_valid_config(mgr, cleanup):
    response_xml = mgr.get().data_xml
    running_config = mgr.get_config(source="running").data_xml
    assert get_disabled_leaf_from_data_xml(response_xml) == "Not Found"
    assert get_disabled_leaf_from_data_xml(running_config) == "Not Found"
    assert get_enabled_leaf_from_data_xml(response_xml) == "Not Found"
    assert get_enabled_leaf_from_data_xml(running_config) == "Not Found"

    mgr.edit_config(
        target="running",
        config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <enabled-leaf>a</enabled-leaf>
            </disabled-elements>
        </config>""",
    )

    assert get_enabled_leaf(mgr) == "a"
    assert get_config_enabled_leaf(mgr) == "a"

    try:
        mgr.edit_config(
            target="running",
            config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <disabled-leaf>test</disabled-leaf>
                <enabled-leaf>b</enabled-leaf>
            </disabled-elements>
        </config>""",
        )
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == "unknown-element"
        assert e.severity == "error"
        assert "bad-element" in e.info
        assert "/test-validation:disabled-elements/disabled-leaf" in e.info

    response_xml = mgr.get().data_xml
    running_config = mgr.get_config(source="running").data_xml
    assert get_disabled_leaf_from_data_xml(response_xml) == "Not Found"
    assert get_disabled_leaf_from_data_xml(running_config) == "Not Found"
    assert get_enabled_leaf_from_data_xml(response_xml) == "a"
    assert get_enabled_leaf_from_data_xml(running_config) == "a"

    mgr.edit_config(
        target="running",
        config="""
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation">
                <enabled-leaf nc:operation="delete"></enabled-leaf>
            </disabled-elements>
        </config>""",
    )

    response_xml = mgr.get().data_xml
    running_config = mgr.get_config(source="running").data_xml
    assert get_disabled_leaf_from_data_xml(response_xml) == "Not Found"
    assert get_disabled_leaf_from_data_xml(running_config) == "Not Found"
    assert get_enabled_leaf_from_data_xml(response_xml) == "Not Found"
    assert get_enabled_leaf_from_data_xml(running_config) == "Not Found"


def test_validation_in_submodule_with_feature(mgr, cleanup):
    mgr.edit_config(target='running', config='''
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
            <enabled-container xmlns="http://example.com/netopeer2-integration-tests/test-module">
                <enabled-container-leaf>foo</enabled-container-leaf>
            </enabled-container>
        </config>''')

    mgr.edit_config(target='running', config='''
        <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"
                xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
            <enabled-container xmlns="http://example.com/netopeer2-integration-tests/test-module" nc:operation="delete" />
        </config>''')

    try:
        mgr.edit_config(target='running', config='''
            <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
                <disabled-container xmlns="http://example.com/netopeer2-integration-tests/test-module">
                    <disabled-container-leaf>foo</disabled-container-leaf>
                </disabled-container>
            </config>''')

        # The edit_config MUST fail
        assert False
    except RPCError as e:
        # RFCs 6020 & 6241 do not specify a specific error message,
        # so we do not assert one here.
        # RFC 6020 section 8.3.1 mandates an error-tag of "unknown-element" here.
        # Other assertions come from RFC 6241 Appendix A.
        assert e.tag == 'unknown-element'
        assert e.severity == 'error'
        assert 'bad-element' in e.info
        assert '/test-module:disabled-container' in e.info


def set_validation_field(mgr, field, value):
    mgr.edit_config(target="running", config=make_validation_xml(field, value))


def make_validation_xml(field, value):
    return """
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <validation xmlns="http://example.com/netopeer2-integration-tests/test-validation">
        <{field}>{value}</{field}>
    </validation>
</config>
    """.format(
        field=field, value=value
    )


def clear_validation_field(mgr, field):
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <validation xmlns="http://example.com/netopeer2-integration-tests/test-validation">
        <{} nc:operation="delete" />
    </validation>
</nc:config>""".format(
            field
        ),
    )


def get_disabled_leaf(mgr):
    return get_disabled_leaf_from_data_xml(mgr.get().data_xml)


def get_disabled_leaf_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-validation:disabled-elements/test-validation:disabled-leaf",
    )


def get_config_disabled_leaf(mgr, datastore="running"):
    return find_single_xpath(
        mgr.get_config(source=datastore).data_xml,
        "/nc:data/test-validation:disabled-elements/test-validation:disabled-leaf",
    )


def get_enabled_leaf(mgr):
    return get_enabled_leaf_from_data_xml(mgr.get().data_xml)


def get_enabled_leaf_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-validation:disabled-elements/test-validation:enabled-leaf",
    )


def get_config_enabled_leaf(mgr, datastore="running"):
    return find_single_xpath(
        mgr.get_config(source=datastore).data_xml,
        "/nc:data/test-validation:disabled-elements/test-validation:enabled-leaf",
    )


def get_disabled_list(mgr):
    data_xml = mgr.get().data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        "/nc:data/test-validation:disabled-elements/test-validation:disabled-list",
        namespaces=NS_MAP,
    )
    return results


def get_config_disabled_list(mgr, source="running"):
    data_xml = mgr.get_config(source=source).data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        "/nc:data/test-validation:disabled-elements/test-validation:disabled-list",
        namespaces=NS_MAP,
    )
    return results


def get_disabled_container_leaf(mgr):
    return find_single_xpath(
        mgr.get().data_xml,
        "/nc:data/test-validation:disabled-container/test-validation:disabled-container-leaf",
    )


def get_config_disabled_container_leaf(mgr, datastore="running"):
    return find_single_xpath(
        mgr.get_config(source=datastore).data_xml,
        "/nc:data/test-validation:disabled-container/test-validation:disabled-container-leaf",
    )


def get_disabled_container_list(mgr):
    data_xml = mgr.get().data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        "/nc:data/test-validation:disabled-container/test-validation:disabled-container-list",
        namespaces=NS_MAP,
    )
    return results


def get_config_disabled_container_list(mgr, source="running"):
    data_xml = mgr.get_config(source=source).data_xml
    doc = etree.fromstring(data_xml.encode("utf-8"))
    results = doc.xpath(
        "/nc:data/test-validation:disabled-container/test-validation:disabled-container-list",
        namespaces=NS_MAP,
    )
    return results


@pytest.fixture()
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <validation xmlns="http://example.com/netopeer2-integration-tests/test-validation" nc:operation="remove" />
</nc:config>
    """,
    )
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <disabled-elements xmlns="http://example.com/netopeer2-integration-tests/test-validation" nc:operation="remove" />
</nc:config>
    """,
    )
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <enabled-container xmlns="http://example.com/netopeer2-integration-tests/test-module" nc:operation="remove" />
</nc:config>
    """,
    )
