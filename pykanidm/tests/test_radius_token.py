""" testing get_radius_token """


import json
import logging
import os
# from typing import Any

import aiohttp
import pytest
# from pytest_mock import MockerFixture

#pylint: disable=unused-import
from testutils import client, client_configfile

from kanidm import KanidmClient
# from kanidm.exceptions import AuthCredFailed, AuthInitFailed
# from kanidm.types import AuthBeginResponse

logging.basicConfig(level=logging.DEBUG)

@pytest.mark.asyncio
async def test_radius_call(client_configfile: KanidmClient) -> None:
    """ tests the radius call step """
    print(f"Doing auth_init for {client_configfile.config.username}")


    if "RADIUS_USER" not in os.environ:
        pytest.skip("Skipping this test - set RADIUS_USER environment variable to a valid RADIUS user.")

    radius_user = os.environ["RADIUS_USER"]

    if client_configfile.config.username is None:
        raise ValueError("This path shouldn't be possible in the test!")
    async with aiohttp.ClientSession() as session:
        client_configfile.session = session
        radius_session = await client_configfile.authenticate_password()

        result = await client_configfile.get_radius_token(
            radius_user,
            radius_session_id=radius_session.sessionid
            )

    print(f"{result=}")
    print(json.dumps(result.dict(), indent=4, default=str))
