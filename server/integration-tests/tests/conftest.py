import subprocess

import pytest
import requests

from common import (
    wait_for,
    connect_mgr,
    test_send_notification_service_ready,
    test_set_action_reply_service_ready,
)


@pytest.fixture(scope="session")
def services():
    """Start the services"""
    subprocess.check_call("echo root:password | chpasswd", shell=True)
    subprocess.check_call("supervisord")

    wait_for(connect_mgr, timeout=60, period=0.5).close_session()
    wait_for(test_send_notification_service_ready, timeout=60, period=0.5)
    wait_for(test_set_action_reply_service_ready, timeout=60, period=0.5)


@pytest.fixture()
def mgr(services):
    """Connect to the NETCONF server"""
    return connect_mgr()
