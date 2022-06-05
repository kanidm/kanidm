""" testing auth things """

import logging

import pytest

#pylint: disable=unused-import
from testutils import client, client_configfile

from kanidm import KanidmClient
from kanidm.exceptions import AuthCredFailed, AuthInitFailed
from kanidm.types import AuthBeginResponse

logging.basicConfig(level=logging.DEBUG)


def test_auth_init(client_configfile: KanidmClient) -> None:
    """ tests the auth init step """
    print("Starting client...")
    print(f"Doing auth_init for {client_configfile.username}")
    if client_configfile.username is None:
        raise ValueError("This path shouldn't be possible in the test!")
    result = client_configfile.auth_init(client_configfile.username)
    print(f"{result=}")
    print(result.dict())
    assert result.sessionid

def test_auth_begin(client_configfile: KanidmClient) -> None:
    """ tests the auth begin step """
    print("Starting client...")
    # client = KanidmClient(config="~/.config/kanidm")
    print(f"Doing auth_init for {client_configfile.username}")
    if client_configfile.username is None:
        raise ValueError("This path shouldn't be possible in the test!")
    result = client_configfile.auth_init(client_configfile.username)
    print(f"{result=}")
    print("Result dict:")
    print(result.dict())
    assert result.sessionid

    print(f"Doing auth_begin for {client_configfile.username}")
    begin_result = client_configfile.auth_begin(
        # username=client.username,
        method="password",
    )
    print(f"{begin_result=}")
    print(begin_result.json())
    retval = begin_result.json()
    retval["response"] = begin_result

    assert AuthBeginResponse.parse_obj(retval)


def test_authenticate_flow(client_configfile: KanidmClient) -> None:
    """ tests the authenticate() flow """
    print("Starting client...")
    print(f"Doing client.authenticate for {client_configfile.username}")
    result = client_configfile.authenticate_password()
    print(result)
    #print(f"{result=}")
    #print(result.json())




def test_authenticate_flow_fail(client_configfile: KanidmClient) -> None:
    """ tests the authenticate() flow with a valid (hopefully) usernamd and invalid password """
    print("Starting client...")
    if client_configfile.uri is None or \
        client_configfile.username is None or \
            client_configfile.password is None:
        pytest.skip("Please ensure you have a username, password and uri in the config")
    print(f"Doing client.authenticate for {client_configfile.username}")
    with pytest.raises((AuthCredFailed,AuthInitFailed)):
        result = client_configfile.authenticate_password(
            username=client_configfile.username,
            password="cheese",
            )
        print(result)
    #print(f"{result=}")
    #print(result.json())
    #assert result.json()['sessionid']


#TODO: mock a call to auth_init when a 200 response is not returned, raises AuthInitFailed
#TODO: mock a call to auth_init when "x-kanidm-auth-session-id" not in response.headers, raises ValueError


#TODO: mock a call to auth_begin when a 200 response is not returned, raises AuthBeginFailed
#TODO: mock a call to auth_step_password when a 200 response is not returned, raises AuthCredFailed


def test_authenticate_inputs_validation(client: KanidmClient) -> None:
    """ tests if you pass username but not password and password but not username """

    with pytest.raises(ValueError):
        client.authenticate_password(username="cheese")

    with pytest.raises(ValueError):
        client.authenticate_password(password="cheese")

    client.password = None
    client.username = "crabby"
    with pytest.raises(ValueError):
        client.authenticate_password()

    client.password = "cR4bzR0ol"
    client.username = None
    with pytest.raises(ValueError):
        client.authenticate_password()

    client.username = None
    client.password = None
    with pytest.raises(ValueError):
        client.authenticate_password()

def test_auth_step_password(client: KanidmClient) -> None:
    """ tests things """
    with pytest.raises(ValueError):
        client.auth_step_password()
