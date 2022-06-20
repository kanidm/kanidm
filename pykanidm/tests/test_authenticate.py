""" testing auth things """

import logging
import os

import aiohttp
import pytest
from pytest_mock import MockerFixture

# pylint: disable=unused-import
from testutils import client, client_configfile, MockResponse

from kanidm import KanidmClient
from kanidm.exceptions import AuthCredFailed, AuthInitFailed
from kanidm.types import AuthBeginResponse


logging.basicConfig(level=logging.DEBUG)


@pytest.mark.asyncio
async def test_auth_init(client_configfile: KanidmClient) -> None:
    """tests the auth init step"""
    print("Starting client...")
    print(f"Doing auth_init for {client_configfile.config.username}")

    if client_configfile.config.username is None:
        raise ValueError("This path shouldn't be possible in the test!")
    async with aiohttp.ClientSession() as session:
        client_configfile.session = session
        result = await client_configfile.auth_init(client_configfile.config.username)
    print(f"{result=}")
    print(result.dict())
    assert result.sessionid


@pytest.mark.asyncio
async def test_auth_begin(client_configfile: KanidmClient) -> None:
    """tests the auth begin step"""
    print(f"Doing auth_init for {client_configfile.config.username}")

    async with aiohttp.ClientSession() as session:
        client_configfile.session = session
        if client_configfile.config.username is None:
            raise ValueError("This path shouldn't be possible in the test!")
        result = await client_configfile.auth_init(client_configfile.config.username)
        print(f"{result=}")
        print("Result dict:")
        print(result.dict())
        assert result.sessionid

        print(f"Doing auth_begin for {client_configfile.config.username}")
        begin_result = await client_configfile.auth_begin(
            # username=client.username,
            method="password",
        )
        print(f"{begin_result=}")
        print(begin_result.data)
        retval = begin_result.data

        if retval is None:
            raise pytest.fail("Failed to do begin_result")

        retval["response"] = begin_result

        assert AuthBeginResponse.parse_obj(retval)


@pytest.mark.asyncio
async def test_authenticate_flow(client_configfile: KanidmClient) -> None:
    """tests the authenticate() flow"""
    async with aiohttp.ClientSession() as session:
        print(f"Doing client.authenticate for {client_configfile.config.username}")
        client_configfile.session = session
        result = await client_configfile.authenticate_password()
    print(result)


@pytest.mark.asyncio
async def test_authenticate_flow_fail(client_configfile: KanidmClient) -> None:
    """tests the authenticate() flow with a valid (hopefully) usernamd and invalid password"""
    if not bool(os.getenv("RUN_SCARY_TESTS", None)):
        pytest.skip(reason="Skipping because env var RUN_SCARY_TESTS isn't set")
    print("Starting client...")
    if (
        client_configfile.config.uri is None
        or client_configfile.config.username is None
        or client_configfile.config.password is None
    ):
        pytest.skip("Please ensure you have a username, password and uri in the config")
    print(f"Doing client.authenticate for {client_configfile.config.username}")

    async with aiohttp.ClientSession() as session:
        client_configfile.session = session
        with pytest.raises((AuthCredFailed, AuthInitFailed)):
            result = await client_configfile.authenticate_password(
                username=client_configfile.config.username,
                password="cheese",
            )
            print(result)


# TODO: mock a call to auth_init when a 200 response is not returned, raises AuthInitFailed
# TODO: mock a call to auth_init when "x-kanidm-auth-session-id" not in response.headers, raises ValueError


# TODO: mock a call to auth_begin when a 200 response is not returned, raises AuthBeginFailed
# TODO: mock a call to auth_step_password when a 200 response is not returned, raises AuthCredFailed


@pytest.mark.asyncio
async def test_authenticate_inputs_validation(
    client: KanidmClient, mocker: MockerFixture
) -> None:
    """tests if you pass username but not password and password but not username"""

    resp = MockResponse("crabs are cool", 200)

    mocker.patch("aiohttp.ClientSession.post", return_value=resp)

    async with aiohttp.ClientSession() as session:
        client.session = session
        with pytest.raises(ValueError):
            await client.authenticate_password(username="cheese")
        with pytest.raises(ValueError):
            await client.authenticate_password(password="cheese")
        client.config.password = None
        client.config.username = "crabby"
        with pytest.raises(ValueError):
            await client.authenticate_password()
        client.config.password = "cR4bzR0ol"
        client.config.username = None
        with pytest.raises(ValueError):
            await client.authenticate_password()

        client.config.username = None
        client.config.password = None
        with pytest.raises(ValueError):
            await client.authenticate_password()


@pytest.mark.asyncio
async def test_auth_step_password(client: KanidmClient) -> None:
    """tests things"""

    with pytest.raises(ValueError):
        async with aiohttp.ClientSession() as session:
            client.session = session
            await client.auth_step_password()
