"""
Tests for ietf-netconf-monitoring
"""
from common import NS_MAP


def test_capabilities(mgr):
    """
    Verifies that the list of capabilities populated in the model matches the
    list of capabilities in the <hello> message.
    """
    r = get_netconf_state(mgr)
    capabilities_container = r.data_ele.xpath(
        "//nc-mon:capabilities", namespaces=NS_MAP
    )[0]
    capabilities = set([cap.text for cap in capabilities_container])
    assert set(mgr.server_capabilities) == capabilities


def test_sessions(mgr):
    """
    Verifies that the current session appears in the session list
    """
    r = get_netconf_state(mgr)

    # Find this session first
    sessions_container = r.data_ele.xpath("//nc-mon:sessions", namespaces=NS_MAP)[0]
    session = next(filter(lambda s: s[0].text == mgr.session_id, sessions_container))

    transport = session.xpath("./nc-mon:transport", namespaces=NS_MAP)[0].text
    username = session.xpath("./nc-mon:username", namespaces=NS_MAP)[0].text

    assert transport == "netconf-ssh"
    assert username == "root"


# TODO: Test <schemas> based on the YANG models that were installed by manifest.json

# TODO: Test <statistics> by sending various stimuli and seeing the counters increase


def get_netconf_state(mgr):
    return mgr.get(
        filter="""
    <filter xmlns="urn:ietf:params:xml:ns:netconf:base:1.0">
      <netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring" />
    </filter>
    """
    )
