""" tests the check_vlan function """

from typing import Any

import pytest

from kanidm import KanidmClient
from kanidm.types import KanidmClientConfig, RadiusTokenGroup

from kanidm.radius import check_vlan


@pytest.mark.asyncio
async def test_check_vlan(event_loop: Any) -> None:
    """test 1"""

    testconfig = KanidmClientConfig.parse_toml(
        """
    uri='https://kanidm.example.com'
    radius_groups = [
        { name = "crabz", "vlan" = 1234 },
        { name = "hello world", "vlan" = 12345 },
    ]
    """
    )

    print(f"{testconfig=}")

    kanidm_client = KanidmClient(
        config=testconfig,
    )
    print(f"{kanidm_client.config=}")

    assert (
        check_vlan(
            acc=12345678,
            group=RadiusTokenGroup(spn="crabz@domain.com", uuid="crabz"),
            kanidm_client=kanidm_client,
        )
        == 1234
    )

    assert (
        check_vlan(
            acc=12345678,
            group=RadiusTokenGroup(spn="foo@bar.com", uuid="lol"),
            kanidm_client=kanidm_client,
        )
        == 12345678
    )
