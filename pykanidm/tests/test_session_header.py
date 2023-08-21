""" testing session header function """

import pytest

import aiohttp.client_exceptions
from testutils import client

from kanidm import KanidmClient


def test_session_header(client: KanidmClient) -> None:
    """tests the session_header function"""
    sessionid = "testval"
    assert client.session_header(sessionid) == {
        "authorization": f"bearer {sessionid}",
    }


@pytest.mark.asyncio
async def test_session_creator(client: KanidmClient) -> None:
    """tests the session_header function"""

    client.config.uri = "🦀"
    with pytest.raises(aiohttp.client_exceptions.InvalidURL):
        await client._call(method="GET", path="/")  # pylint: disable=protected-access
