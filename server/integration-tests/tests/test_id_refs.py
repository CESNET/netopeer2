"""
Tests for identityref data validation
"""
import pytest
from ncclient.operations import RPCError


def test_id_ref_set_local(mgr, cleanup):
    """
    Set values defined (or not defined) in the module that uses the identity
    """
    with pytest.raises(RPCError):
        edit_id_referer(mgr, "base-id")
    edit_id_referer(mgr, "derived-id")

    with pytest.raises(RPCError):
        edit_id_referer(mgr, "unknown-id")


def test_id_ref_set_foreign(mgr, cleanup):
    """
    Set values defined outside the module that uses the identity
    """
    edit_id_referer(mgr, "f:foreign-derived-from-base-id")
    edit_id_referer(mgr, "f:foreign-derived-from-derived-id")


def edit_id_referer(mgr, value):
    mgr.edit_config(
        target="running",
        config="""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <contain xmlns="http://example.com/netopeer2-integration-tests/test-id-ref"
               xmlns:f="http://example.com/netopeer2-integration-tests/test-id-ref-foreign">
        <id-ref>{value}</id-ref>
      </contain>
    </config>
    """.format(
            value=value
        ),
    )


@pytest.fixture
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
    <config xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
      <contain xmlns="http://example.com/netopeer2-integration-tests/test-id-ref" nc:operation="remove" />
    </config>
    """,
    )
