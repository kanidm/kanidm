""" testing get_radius_token """


import json
import logging

import pytest

# pylint: disable=unused-import
from testutils import client, client_configfile
from kanidm import KanidmClient

logging.basicConfig(level=logging.DEBUG)

RADIUS_TEST_USER = "test"


@pytest.mark.network
@pytest.mark.asyncio
async def test_radius_call(client_configfile: KanidmClient) -> None:
    """tests the radius call step"""
    print("Doing auth_init using token")

    if client_configfile.config.auth_token is None:
        pytest.skip(
            "You can't test auth if you don't have an auth_token in ~/.config/kanidm"
        )
    result = await client_configfile.get_radius_token(RADIUS_TEST_USER)

    print(f"{result=}")
    print(json.dumps(result.model_dump_json(), indent=4, default=str))
