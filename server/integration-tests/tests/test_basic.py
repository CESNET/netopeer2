"""
Tests to verify basic NETCONF functionality
"""
from common import change_contact, get_contact
import event_log


def test_basic_edit(mgr):
    """
    Verifies that a single leaf can be edited, and that the appropriate sysrepo
    notifications are emitted
    """
    event_log.clear()

    # Starts with no value
    assert get_contact(mgr) == "Not Present"

    # Set a value
    change_contact(mgr, "merge", "TestValue")
    assert get_contact(mgr) == "TestValue"
    assert (
        event_log.find_change_in_log(
            event_log.load(),
            "SR_EV_VERIFY",
            {
                "operation": "SR_OP_CREATED",
                "new-value": "TestValue",
                "new-path": "/ietf-system:system/contact",
            },
        )
        is not None
    )
    event_log.clear()

    # Clear the value
    change_contact(mgr, "delete", "TestValue")
    assert get_contact(mgr) == "Not Present"
    assert (
        event_log.find_change_in_log(
            event_log.load(),
            "SR_EV_VERIFY",
            {"operation": "SR_OP_DELETED", "old-path": "/ietf-system:system/contact"},
        )
        is not None
    )
