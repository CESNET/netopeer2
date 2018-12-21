import pytest
from common import find_single_xpath


def test_candidate_config_simple_copy(mgr, cleanup):
    set_simple_both(mgr, "START", "111")
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(response_xml) == "START"
    assert get_simple_int_from_data_xml(response_xml) == "111"

    set_simple_both(mgr, "candidate value", "222", target="candidate")
    candidate_config = mgr.get_config(source='candidate').data_xml
    assert get_simple_int_from_data_xml(candidate_config) == '222'
    assert get_simple_string_from_data_xml(candidate_config) == 'candidate value'

    # Copy candidate to running
    mgr.copy_config(source="candidate", target="running")

    running_config = mgr.get_config(source='running').data_xml
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(running_config) == 'candidate value'
    assert get_simple_string_from_data_xml(response_xml) == 'candidate value'
    assert get_simple_int_from_data_xml(running_config) == '222'
    assert get_simple_int_from_data_xml(response_xml) == '222'

    clear_data(mgr)
    check_data_cleared(mgr)


def test_candidate_config_simple_commit(mgr):
    set_simple_both(mgr, "START", "111")
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(response_xml) == "START"
    assert get_simple_int_from_data_xml(response_xml) == "111"

    set_simple_both(mgr, "candidate value", "222", target="candidate")
    candidate_config = mgr.get_config(source='candidate').data_xml
    assert get_simple_int_from_data_xml(candidate_config) == '222'
    assert get_simple_string_from_data_xml(candidate_config) == 'candidate value'

    # Send commit message
    mgr.commit()

    running_config = mgr.get_config(source='running').data_xml
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(running_config) == 'candidate value'
    assert get_simple_string_from_data_xml(response_xml) == 'candidate value'
    assert get_simple_int_from_data_xml(running_config) == '222'
    assert get_simple_int_from_data_xml(response_xml) == '222'

    clear_data(mgr)
    check_data_cleared(mgr)


def test_candidate_config_copy_leaf_edit(mgr):
    set_simple_string(mgr, 'START')
    assert get_simple_string(mgr) == 'START'

    set_simple_string(mgr, 'candidate value', target='candidate')
    assert get_config_simple_string(mgr, 'candidate') == 'candidate value'

    # Copy candidate to running
    mgr.copy_config(source='candidate', target='running')

    assert get_config_simple_string(mgr) == 'candidate value'
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(response_xml) == 'candidate value'

    clear_simple_string(mgr, 'candidate')
    clear_simple_string(mgr, 'running')
    check_data_cleared(mgr)


def test_candidate_config_commit_leaf_edit(mgr):
    set_simple_string(mgr, 'START')
    assert get_simple_string(mgr) == 'START'

    set_simple_string(mgr, 'candidate value', target='candidate')
    assert get_config_simple_string(mgr, 'candidate') == 'candidate value'

    # Send commit message
    mgr.commit()

    assert get_config_simple_string(mgr) == 'candidate value'
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(response_xml) == 'candidate value'

    clear_simple_string(mgr, 'candidate')
    clear_simple_string(mgr, 'running')
    check_data_cleared(mgr)


def clear_data(mgr):
    clear_simple_int(mgr, "candidate")
    clear_simple_string(mgr, "candidate")
    clear_simple_int(mgr, "running")
    clear_simple_string(mgr, "running")


def check_data_cleared(mgr):
    candidate_config = mgr.get_config(source='candidate').data_xml
    assert get_simple_int_from_data_xml(candidate_config) == 'Not Found'
    assert get_simple_string_from_data_xml(candidate_config) == 'Not Found'
    response_xml = mgr.get().data_xml
    assert get_simple_string_from_data_xml(response_xml) == 'Not Found'
    assert get_simple_int_from_data_xml(response_xml) == 'Not Found'


def clear_simple_int(mgr, datastore="running"):
    mgr.edit_config(
        target=datastore,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-candidate-config-container xmlns="http://example.com/netopeer2-integration-tests/test-candidate-config">
        <simple-int nc:operation="delete" />
    </test-candidate-config-container>
</nc:config>""",
    )


def clear_simple_string(mgr, datastore="running"):
    mgr.edit_config(
        target=datastore,
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-candidate-config-container xmlns="http://example.com/netopeer2-integration-tests/test-candidate-config">
        <simple-string nc:operation="delete" />
    </test-candidate-config-container>
</nc:config>""",
    )


def set_simple_both(mgr, message, num, target="running"):
    mgr.edit_config(
        target=target,
        error_option="continue-on-error",
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-candidate-config-container xmlns="http://example.com/netopeer2-integration-tests/test-candidate-config">
        <simple-string>{}</simple-string>
        <simple-int>{}</simple-int>
    </test-candidate-config-container>
</config>
        """.format(
            message, num
        ),
    )


def set_simple_string(mgr, message, target="running"):
    mgr.edit_config(
        target=target,
        config="""
<config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
    <test-candidate-config-container xmlns="http://example.com/netopeer2-integration-tests/test-candidate-config">
        <simple-string>{}</simple-string>
    </test-candidate-config-container>
</config>
        """.format(message)
    )


def get_simple_int_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml, "/nc:data/test-cand-cfg:test-candidate-config-container/test-cand-cfg:simple-int"
    )


def get_simple_string_from_data_xml(data_xml):
    return find_single_xpath(
        data_xml,
        "/nc:data/test-cand-cfg:test-candidate-config-container/test-cand-cfg:simple-string",
    )


def get_simple_string(mgr):
    return get_simple_string_from_data_xml(mgr.get().data_xml)


def get_config_simple_string(mgr, datastore='running'):
    return get_simple_string_from_data_xml(
        mgr.get_config(source=datastore).data_xml)


@pytest.fixture()
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
<nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <test-candidate-config-container xmlns="http://example.com/netopeer2-integration-tests/test-candidate-config" nc:operation="remove" />
</nc:config>
    """,
    )
