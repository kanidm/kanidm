""" testing session header function """

import pytest

from testutils import client

from kanidm import KanidmClient


def test_session_header(client: KanidmClient) -> None:
    """tests the session_header function"""

    with pytest.raises(ValueError):
        client.session_header()

    assert client.session_header("testval") == {
        "X-KANIDM-AUTH-SESSION-ID": "testval",
    }
