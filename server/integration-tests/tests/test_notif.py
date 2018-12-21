import requests
from common import (
    get_test_notification_simple_string,
    set_test_notification_simple_string,
    clear_test_notification_simple_string,
    get_test_notification_container_notification_string,
    set_test_notification_container_notification_string,
    clear_test_notification_container_notification_string,
    get_notification_list,
    set_notification_list_item,
    clear_notification_list_item,
    get_embedded_list,
    set_embedded_list_item,
)
import datetime
import time
import pytest
from lxml import etree
from ncclient.xml_ import to_ele

from common import send_notification, NS_MAP


@pytest.fixture()
def notification_cleanup(mgr):
    yield
    mgr.edit_config(
        target="running",
        config="""
      <nc:config xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0">
        <string-container 
            nc:operation="remove" xmlns="http://www.example.com/ns/yang/test-notifications"
        />
        <notification-from-container 
            nc:operation="remove" xmlns="http://www.example.com/ns/yang/test-notifications"
        />
        <notification-from-list 
            nc:operation="remove" xmlns="http://www.example.com/ns/yang/test-notifications"
        />
      </nc:config>
    """,
    )


def generate_test_notification_simple_string_notif(value):
    send_notification(
        {
            "xpath": "/test-notifications:string-container-simple-string-changed",
            "values": [
                {
                    "xpath": (
                        "/test-notifications:string-container-simple-string-changed"
                        "/test-notifications:new-value"
                    ),
                    "value": value,
                }
            ],
        }
    )


def generate_test_notification_container_string_notif(value):
    send_notification(
        {
            "xpath": (
                "/test-notifications:notification-from-container"
                "/test-notifications:container-notification-string-changed"
            ),
            "values": [
                {
                    "xpath": (
                        "/test-notifications:notification-from-container"
                        "/test-notifications:container-notification-string-changed"
                        "/test-notifications:new-value"
                    ),
                    "value": value,
                }
            ],
        }
    )


def generate_test_notification_list_foo_string_notif(key, value):
    send_notification(
        {
            "xpath": (
                "/test-notifications:notification-from-list"
                "/test-notifications:notification-from-list[name='{}']"
                "/test-notifications:list-foo-changed"
            ).format(key),
            "values": [
                {
                    "xpath": (
                        "/test-notifications:notification-from-list"
                        "/test-notifications:notification-from-list[name='{}']"
                        "/test-notifications:list-foo-changed"
                        "/test-notifications:new-value"
                    ).format(key),
                    "value": value,
                }
            ],
        }
    )


def generate_test_notification_embedded_list_string_notif(key1, key2, value):
    send_notification(
        {
            "xpath": (
                "/test-notifications:notification-from-list"
                "/test-notifications:notification-from-list[name='{}']"
                "/test-notifications:embedded-list[name='{}']"
                "/test-notifications:embedded-foo-changed"
            ).format(key1, key2),
            "values": [
                {
                    "xpath": (
                        "/test-notifications:notification-from-list"
                        "/test-notifications:notification-from-list[name='{}']"
                        "/test-notifications:embedded-list[name='{}']"
                        "/test-notifications:embedded-foo-changed"
                        "/test-notifications:new-value"
                    ).format(key1, key2),
                    "value": value,
                }
            ],
        }
    )


def test_basic_notification(mgr):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <hardware-state-change xmlns="urn:ietf:params:xml:ns:yang:ietf-hardware" />
              </filter>
            </create-subscription>
            """
        )
    )
    send_notification({"xpath": "/ietf-hardware:hardware-state-change", "values": []})
    n = mgr.take_notification(timeout=10)
    assert n.notification_ele.xpath(
        "//ietf-hw:hardware-state-change", namespaces=NS_MAP
    )


def find_notifications_matching(mgr, xpath):
    while True:
        notification = mgr.take_notification(timeout=10)
        assert notification is not None

        results = notification.notification_ele.xpath(xpath, namespaces=NS_MAP)
        if len(results) > 0:
            return results


def test_config_changed_notification(mgr, notification_cleanup):
    mgr.create_subscription()
    assert get_test_notification_simple_string(mgr) == "Not Found"
    set_test_notification_simple_string(mgr, "Test Value")
    find_notifications_matching(
        mgr, "/notif:notification/nc-notif:netconf-config-change"
    )


def test_service_generated_notification(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <string-container-simple-string-changed 
                    xmlns="urn:ietf:params:xml:ns:yang:test-notifications" 
                />
              </filter>
            </create-subscription>
            """
        )
    )
    assert get_test_notification_simple_string(mgr) == "Not Found"
    set_test_notification_simple_string(mgr, "Notification Message")
    generate_test_notification_simple_string_notif("Notification Message")
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:string-container-simple-string-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"


def test_embedded_notification_container(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <container-notification-string-changed 
                    xmlns="urn:ietf:params:xml:ns:yang:test-notifications" 
                />
              </filter>
            </create-subscription>
            """
        )
    )
    assert get_test_notification_container_notification_string(mgr) == "Not Found"
    set_test_notification_container_notification_string(mgr, "Container Notification")
    assert (
        get_test_notification_container_notification_string(mgr)
        == "Container Notification"
    )
    generate_test_notification_container_string_notif("Container Notification")
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-container"
            "/test-notification:container-notification-string-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Container Notification"
    clear_test_notification_container_notification_string(mgr)
    assert get_test_notification_container_notification_string(mgr) == "Not Found"


def test_embedded_notification_list_one_item(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <list-foo-changed xmlns="urn:ietf:params:xml:ns:yang:test-notifications" />
              </filter>
            </create-subscription>
            """
        )
    )
    assert get_notification_list(mgr) == {}
    set_notification_list_item(mgr, "Notification1", "Notification Message")
    assert get_notification_list(mgr) == {
        "Notification1": {"foo": "Notification Message"}
    }

    generate_test_notification_list_foo_string_notif(
        "Notification1", "Notification Message"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"

    clear_notification_list_item(mgr, "Notification1")
    assert get_notification_list(mgr) == {}


def test_embedded_notification_list_two_items(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <list-foo-changed xmlns="urn:ietf:params:xml:ns:yang:test-notifications" />
              </filter>
            </create-subscription>
            """
        )
    )

    assert get_notification_list(mgr) == {}
    set_notification_list_item(mgr, "Notification1", "Notification Message")
    set_notification_list_item(mgr, "Notification2", "Notification Message2")
    assert get_notification_list(mgr) == {
        "Notification1": {"foo": "Notification Message"},
        "Notification2": {"foo": "Notification Message2"},
    }

    generate_test_notification_list_foo_string_notif(
        "Notification1", "Notification Message"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"
    generate_test_notification_list_foo_string_notif(
        "Notification2", "Notification Message2"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message2"

    clear_notification_list_item(mgr, "Notification1")
    clear_notification_list_item(mgr, "Notification2")
    assert get_notification_list(mgr) == {}


def test_embedded_notification_list_insert_and_delete(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <list-foo-changed 
                    xmlns="urn:ietf:params:xml:ns:yang:test-service-test-notification" 
                />
              </filter>
            </create-subscription>
            """
        )
    )
    # Add a couple elements and send a notification for each
    assert get_notification_list(mgr) == {}
    set_notification_list_item(mgr, "Notification1", "Notification Message1")
    set_notification_list_item(mgr, "Notification2", "Notification Message2")
    assert get_notification_list(mgr) == {
        "Notification1": {"foo": "Notification Message1"},
        "Notification2": {"foo": "Notification Message2"},
    }
    generate_test_notification_list_foo_string_notif(
        "Notification1", "Notification Message"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"
    generate_test_notification_list_foo_string_notif(
        "Notification2", "Notification Message2"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message2"

    # Delete the elements and try sending a notification
    clear_notification_list_item(mgr, "Notification1")
    clear_notification_list_item(mgr, "Notification2")
    assert get_notification_list(mgr) == {}
    with pytest.raises(AssertionError):
        generate_test_notification_list_foo_string_notif(
            "Notification1", "Notification Message1"
        )

    # Add a new element and send a notification
    set_notification_list_item(mgr, "Notification99", "Notification Message")
    assert get_notification_list(mgr) == {
        "Notification99": {"foo": "Notification Message"}
    }
    generate_test_notification_list_foo_string_notif(
        "Notification99", "Notification Message"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"
    clear_notification_list_item(mgr, "Notification99")
    assert get_notification_list(mgr) == {}

    # Add a couple elements back with the same keys and verify notifications work
    assert get_notification_list(mgr) == {}
    set_notification_list_item(mgr, "Notification1", "Notification Message1")
    set_notification_list_item(mgr, "Notification2", "Notification Message2")
    assert get_notification_list(mgr) == {
        "Notification1": {"foo": "Notification Message1"},
        "Notification2": {"foo": "Notification Message2"},
    }
    generate_test_notification_list_foo_string_notif(
        "Notification1", "Notification Message1"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message1"
    generate_test_notification_list_foo_string_notif(
        "Notification2", "Notification Message2"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:list-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message2"

    # Clear list again and verify notifications can't be sent for old elements
    clear_notification_list_item(mgr, "Notification1")
    clear_notification_list_item(mgr, "Notification2")
    assert get_notification_list(mgr) == {}
    with pytest.raises(AssertionError):
        generate_test_notification_list_foo_string_notif(
            "Notification1", "Notification Message1"
        )


def test_embedded_notification_list_in_list(mgr, notification_cleanup):
    mgr.dispatch(
        to_ele(
            """
            <create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">
              <filter>
                <embedded-foo-changed xmlns="urn:ietf:params:xml:ns:yang:test-notifications" />
              </filter>
            </create-subscription>
            """
        )
    )
    assert get_embedded_list(mgr) == {}
    set_embedded_list_item(
        mgr, "NotificationOuter", "NotificationInner", "Notification Message"
    )
    assert get_embedded_list(mgr) == {
        "NotificationOuter": {"NotificationInner": "Notification Message"}
    }

    generate_test_notification_embedded_list_string_notif(
        "NotificationOuter", "NotificationInner", "Notification Message"
    )
    results = find_notifications_matching(
        mgr,
        (
            "/notif:notification"
            "/test-notification:notification-from-list"
            "/test-notification:notification-from-list"
            "/test-notification:embedded-list"
            "/test-notification:embedded-foo-changed"
            "/test-notification:new-value"
        ),
    )
    assert results[0].text == "Notification Message"

    clear_notification_list_item(mgr, "NotificationOuter")
    assert get_embedded_list(mgr) == {}
