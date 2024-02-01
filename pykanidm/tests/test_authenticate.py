""" testing auth things """

import logging
import os

import pytest
from pytest_mock import MockerFixture

# pylint: disable=unused-import
from testutils import client, client_configfile, MockResponse

from kanidm import KanidmClient
from kanidm.exceptions import AuthCredFailed, AuthInitFailed
from kanidm.types import AuthBeginResponse
from kanidm.tokens import TokenStore


logging.basicConfig(level=logging.DEBUG)


@pytest.mark.network
@pytest.mark.asyncio
async def test_auth_init(client_configfile: KanidmClient) -> None:
    """tests the auth init step"""
    print("Starting client...")
    print(f"Doing auth_init for {client_configfile.config.username}")

    if client_configfile.config.username is None:
        pytest.skip("Can't run auth test without a username/password")
    result = await client_configfile.auth_init(client_configfile.config.username)
    print(f"{result=}")
    print(result.model_dump_json())
    assert result.sessionid


@pytest.mark.network
@pytest.mark.asyncio
async def test_auth_begin(client_configfile: KanidmClient) -> None:
    """tests the auth begin step"""
    print(f"Doing auth_init for {client_configfile.config.username}")

    if client_configfile.config.username is None:
        pytest.skip("Can't run auth test without a username/password")
    result = await client_configfile.auth_init(client_configfile.config.username)
    print(f"{result=}")
    print("Result dict:")
    print(result.model_dump_json())
    assert result.sessionid

    print(f"Doing auth_begin for {client_configfile.config.username}")
    if result.response is None:
        raise ValueError("Failed to get response")
    sessionid = result.response.headers["x-kanidm-auth-session-id"]
    begin_result = await client_configfile.auth_begin(
        sessionid=sessionid,
        method="password",
    )
    print(f"{begin_result=}")
    print(begin_result.data)
    retval = begin_result.data

    if retval is None:
        raise pytest.fail("Failed to do begin_result")

    retval["response"] = begin_result.model_dump()

    assert AuthBeginResponse.model_validate(retval)


@pytest.mark.network
@pytest.mark.asyncio
async def test_authenticate_flow(client_configfile: KanidmClient) -> None:
    """tests the authenticate() flow"""
    if (
        client_configfile.config.username is None
        or client_configfile.config.password is None
    ):
        pytest.skip(
            "Can't run this without a username and password set in the config file"
        )

    client_configfile.config.auth_token = None
    print(f"Doing client.authenticate for {client_configfile.config.username}")
    result = await client_configfile.authenticate_password()
    print(result)


@pytest.mark.network
@pytest.mark.asyncio
async def test_authenticate_anonymous(client_configfile: KanidmClient) -> None:
    """tests the authenticate() flow"""

    client_configfile.config.auth_token = None
    print("Doing anonymous auth")
    await client_configfile.auth_as_anonymous()
    assert client_configfile.config.auth_token is not None


@pytest.mark.network
@pytest.mark.asyncio
async def test_authenticate_flow_fail(client_configfile: KanidmClient) -> None:
    """tests the authenticate() flow with a valid (hopefully) username and invalid password"""
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

    client_configfile.config.auth_token = None

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


@pytest.mark.network
@pytest.mark.asyncio
async def test_auth_step_password(client: KanidmClient) -> None:
    """tests things"""

    with pytest.raises(ValueError):
        await client.auth_step_password(sessionid="asdf")


@pytest.mark.network
@pytest.mark.asyncio
async def test_authenticate_with_token(client_configfile: KanidmClient) -> None:
    """tests auth with a token, needs to have a valid token in your local cache"""

    if "KANIDM_TEST_USERNAME" in os.environ:
        test_username: str = os.environ["KANIDM_TEST_USERNAME"]
        print(f"Using username {test_username} from KANIDM_TEST_USERNAME env var")
    else:
        test_username = "idm_admin"
        print(
            f"Using username {test_username} by default - set KANIDM_TEST_USERNAME env var if you want to change this."
        )

    tokens = TokenStore.model_validate({})
    tokens.load()

    if test_username not in tokens:
        print(f"Can't find {test_username} user in token store")
        raise pytest.skip(f"Can't find {test_username} user in token store")
    test_token: str = tokens[test_username]
    if not await client_configfile.check_token_valid(test_token):
        print(f"Token for {test_username} isn't valid")
        pytest.skip(f"Token for {test_username} isn't valid")
    else:
        print("Token was noted as valid, so auth works!")

    # tests the "we set a token and well it works."
    client_configfile.config.auth_token = tokens[test_username]
    result = await client_configfile.call_get("/v1/self")
    print(result)

    assert result.status_code == 200
