import glob

import pytest
from lxml import etree

from common import xml_to_dict


def append_startup_config(expected_config, startup_config):
    # This test as written does not support the case where containers from
    # the startup config are also being altered in the snippet config.
    # (This would require more intelligently merging the containers rather than
    # the naive update call below.)
    assert 0 == len([k for k in startup_config.keys() if k in expected_config])

    expected_config.update(startup_config)


@pytest.mark.parametrize("snippet_file", glob.glob("snippets/*.xml"))
def test_snippet(mgr, snippet_file):
    """
    Performs the edit given in the snippet; checks that the response matches
    what the server thinks the current state of <running> is (if provided);
    performs the cleanup and ensures that the config was entirely removed
    """

    startup_config = xml_to_dict(mgr.get_config(source="startup").data_ele)
    initial_config = xml_to_dict(mgr.get_config(source="running").data_ele)
    assert initial_config == startup_config

    snippet = etree.parse(snippet_file)

    xfail = snippet.xpath("//xfail")

    try:
        edit = snippet.xpath("//edit")[0][0]
        mgr.edit_config(target="running", config=edit)

        response = snippet.xpath("//response")
        if response:
            expected_config = xml_to_dict(response[0][0])
            append_startup_config(expected_config, startup_config)
            current_config = xml_to_dict(mgr.get_config(source="running").data_ele)
            assert current_config == expected_config

        cleanup = snippet.xpath("//cleanup")[0][0]
        mgr.edit_config(target="running", config=cleanup)

        final_config = xml_to_dict(mgr.get_config(source="running").data_ele)
        assert final_config == startup_config
    except:
        if xfail:
            pytest.xfail("Snippet failed, but marked with xfail")
        else:
            raise
