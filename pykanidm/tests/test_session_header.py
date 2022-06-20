""" testing session header function """

import pytest

import aiohttp.client_exceptions
from testutils import client

from kanidm import KanidmClient


def test_session_header(client: KanidmClient) -> None:
    """tests the session_header function"""

    with pytest.raises(ValueError):
        client.session_header()

    assert client.session_header("testval") == {
        "X-KANIDM-AUTH-SESSION-ID": "testval",
    }


@pytest.mark.asyncio
async def test_session_creator(client: KanidmClient) -> None:
    """tests the session_header function"""

    client.session = None
    client.config.uri = "🦀"
    with pytest.raises(aiohttp.client_exceptions.InvalidURL):
        await client._call(method="GET", path="/")  # pylint: disable=protected-access

    #  pytest.raises(ValueError):
    #     client.session_header()

    # assert client.session_header("testval") == {
    #     "X-KANIDM-AUTH-SESSION-ID": "testval",
    # }
