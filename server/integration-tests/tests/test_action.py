import pytest
from ncclient.xml_ import to_ele

from common import NS_MAP, set_action_reply


def test_action_in_config_list(mgr, cleanup):
    set_action_reply(
        {
            "xpath": "/test-actions:config-data/config-list/ct-config-action",
            "values": [
                {
                    "xpath": "/test-actions:config-data/config-list[name='foo']/ct-config-action/action-output",
                    "value": "TestOutput1",
                }
            ],
        }
    )
    edit_config_list(mgr, "create", "foo")
    r = send_config_list_action(mgr, "foo", "TestInput")
    assert r == "TestOutput1"


def test_action_in_config_container(mgr, cleanup):
    set_action_reply(
        {
            "xpath": "/test-actions:config-data/config-container/ct-config-container-action",
            "values": [
                {
                    "xpath": "/test-actions:config-data/config-container/ct-config-container-action/action-output",
                    "value": "TestOutput2",
                }
            ],
        }
    )
    edit_config_container(mgr, "create", "foo")
    r = send_config_container_action(mgr, "TestInput2")
    assert r == "TestOutput2"


# TODO: Not implemented due to not currently having an implemented way to fake state data
#
# def test_action_in_state(mgr, cleanup):
#     set_action_reply({
#         "xpath": "/test-actions:state-data/state-list/ct-state-action",
#         "values": [
#             {
#                 "xpath": "/test-actions:state-data/state-list[name='foo']/ct-state-action/action-output",
#                 "value": "TestOutput3",
#             }
#         ]
#     })
#     r = send_state_list_action(mgr, "foo", "TestInput3")
#     assert r == "TestOutput3"


def test_action_in_augment(mgr, cleanup):
    set_action_reply(
        {
            "xpath": "/test-actions:config-data/config-list/test-actions-augment:aug-action",
            "values": [
                {
                    "xpath": "/test-actions:config-data/config-list[name='foo']/test-actions-augment:aug-action/action-output",
                    "value": "TestOutput4",
                }
            ],
        }
    )
    edit_config_list(mgr, "create", "foo")
    r = send_augment_action(mgr, "foo", "TestInput4")
    assert r == "TestOutput4"


def test_action_in_augmented_list(mgr, cleanup):
    set_action_reply(
        {
            "xpath": "/test-actions:config-data/config-list/test-actions-augment:augmented-list/test-actions-augment:aug-list-action",
            "values": [
                {
                    "xpath": "/test-actions:config-data/config-list[name='foo']/test-actions-augment:augmented-list[aug-name='bar']/test-actions-augment:aug-list-action/test-actions-augment:action-output",
                    "value": "TestOutput5",
                }
            ],
        }
    )
    edit_config_list(mgr, "create", "foo")
    edit_config_aug_list(mgr, "create", "foo", "bar")
    r = send_augment_list_action(mgr, "foo", "bar", "TestInput5")
    assert r == "TestOutput5"


def edit_config_list(mgr, operation, name):
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-list nc:operation="{}">
            <name>{}</name>
          </config-list>
        </config-data>
      </nc:config>
    """.format(
            operation, name
        ),
    )


def edit_config_aug_list(mgr, operation, parent, name):
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-list>
            <name>{}</name>
            <augmented-list xmlns="http://example.com/netopeer2-integration-tests/test-actions-augment" nc:operation="{}">
              <aug-name>{}</aug-name>
            </augmented-list>
          </config-list>
        </config-data>
      </nc:config>
    """.format(
            parent, operation, name
        ),
    )


def edit_config_container(mgr, operation, name):
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-container nc:operation="{}">
            <name>{}</name>
          </config-container>
        </config-data>
      </nc:config>
    """.format(
            operation, name
        ),
    )


def send_config_list_action(mgr, name, input_):
    reply = mgr.dispatch(
        to_ele(
            """
      <action xmlns="urn:ietf:params:xml:ns:yang:1">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-list>
            <name>{}</name>
            <ct-config-action>
              <action-input>{}</action-input>
            </ct-config-action>
          </config-list>
        </config-data>
      </action>
    """.format(
                name, input_
            )
        )
    )
    output = (
        to_ele(reply.xml)
        .xpath("/nc:rpc-reply/test-actions:action-output", namespaces=NS_MAP)[0]
        .text
    )
    return output


def send_config_container_action(mgr, input_):
    reply = mgr.dispatch(
        to_ele(
            """
      <action xmlns="urn:ietf:params:xml:ns:yang:1">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-container>
            <ct-config-container-action>
              <action-input>{}</action-input>
            </ct-config-container-action>
          </config-container>
        </config-data>
      </action>
    """.format(
                input_
            )
        )
    )
    output = (
        to_ele(reply.xml)
        .xpath("/nc:rpc-reply/test-actions:action-output", namespaces=NS_MAP)[0]
        .text
    )
    return output


def send_state_list_action(mgr, name, input_):
    reply = mgr.dispatch(
        to_ele(
            """
      <action xmlns="urn:ietf:params:xml:ns:yang:1">
        <state-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <state-list>
            <name>{}</name>
            <ct-state-action>
              <action-input>{}</action-input>
            </ct-state-action>
          </state-list>
        </state-data>
      </action>
    """.format(
                name, input_
            )
        )
    )
    output = (
        to_ele(reply.xml)
        .xpath("/nc:rpc-reply/test-actions:action-output", namespaces=NS_MAP)[0]
        .text
    )
    return output


def send_augment_action(mgr, name, input_):
    reply = mgr.dispatch(
        to_ele(
            """
      <action xmlns="urn:ietf:params:xml:ns:yang:1">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-list>
            <name>{}</name>
            <aug-action xmlns="http://example.com/netopeer2-integration-tests/test-actions-augment">
              <action-input>{}</action-input>
            </aug-action>
          </config-list>
        </config-data>
      </action>
    """.format(
                name, input_
            )
        )
    )
    output = (
        to_ele(reply.xml)
        .xpath("/nc:rpc-reply/test-actions-aug:action-output", namespaces=NS_MAP)[0]
        .text
    )
    return output


def send_augment_list_action(mgr, name, aug_name, input_):
    reply = mgr.dispatch(
        to_ele(
            """
      <action xmlns="urn:ietf:params:xml:ns:yang:1">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions">
          <config-list>
            <name>{}</name>
            <augmented-list xmlns="http://example.com/netopeer2-integration-tests/test-actions-augment">
              <aug-name>{}</aug-name>
              <aug-list-action>
                <action-input>{}</action-input>
              </aug-list-action>
            </augmented-list>
          </config-list>
        </config-data>
      </action>
    """.format(
                name, aug_name, input_
            )
        )
    )
    output = (
        to_ele(reply.xml)
        .xpath("/nc:rpc-reply/test-actions-aug:action-output", namespaces=NS_MAP)[0]
        .text
    )
    return output


@pytest.fixture()
def cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <config-data xmlns="http://example.com/netopeer2-integration-tests/test-actions" nc:operation="remove" />
      </nc:config>
    """,
    )
