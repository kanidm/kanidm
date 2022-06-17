""" tests the check_vlan function """

from typing import Any

import aiohttp
import pytest
from kanidm import KanidmClient
from kanidm.types import KanidmClientConfig
from kanidmradius import check_vlan

@pytest.mark.asyncio
async def test_check_vlan(event_loop: Any) -> None:
    """ test 1 """

    async with aiohttp.ClientSession(loop=event_loop) as session:
        testconfig = KanidmClientConfig.parse_toml("""
    uri='https://kanidm.example.com'
    radius_groups = [
        { name = "crabz", "vlan" = 1234 },
        { name = "hello world", "vlan" = 12345 },
    ]
    """)

        print(f"{testconfig=}")

        kanidm_client = KanidmClient(
            config = testconfig,
            session=session,
            )
        print(f"{kanidm_client.config=}")

        assert check_vlan(
            acc=12345678,
            group={'name' : 'crabz'},
            kanidm_client=kanidm_client
        ) == 1234

        assert check_vlan(
            acc=12345678,
            group={'name' : 'foo'},
            kanidm_client=kanidm_client
        ) == 12345678
