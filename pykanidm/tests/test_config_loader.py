""" tests the config file things """

import logging
from pathlib import Path
import sys

import pydantic
import pytest
import requests

from kanidm import KanidmClient
from kanidm.exceptions import ServerURLNotSet
from kanidm.types import KanidmClientConfig
from kanidm.utils import load_config

logging.basicConfig(level=logging.DEBUG)

EXAMPLE_CONFIG_FILE="../examples/config"

@pytest.fixture(scope="function")
def client() -> KanidmClient:
    """ sets up a client with a basic thing """
    return KanidmClient(uri="https://idm.example.com")

def test_load_config_file() -> None:
    """ tests that the file loads """
    if not Path(EXAMPLE_CONFIG_FILE).expanduser().resolve().exists():
        print("Can't find client config file", file=sys.stderr)
        pytest.skip()
    print("Loading config file")
    config = load_config(EXAMPLE_CONFIG_FILE)
    assert config.get("uri") == 'https://idm.example.com'

    print(f"{config.get('uri')=}")
    print(config)

def test_load_missing_config_file() -> None:
    """ tests that an error is raised """

    with pytest.raises(
        FileNotFoundError,
        match=EXAMPLE_CONFIG_FILE+"cheese",
        ):
        load_config(
            EXAMPLE_CONFIG_FILE+"cheese"
            )

def test_parse_config_validationerror(client: KanidmClient) -> None:
    """ tests parse_config with a faulty input """
    testdict = {"verify_ca" : "that was weird."}
    with pytest.raises(ValueError):
        client.parse_config_data(config_data=testdict)

def test_parse_config_data(client: KanidmClient) -> None:
    """ tests parse_config witha  valid input """
    testdict = {
        "uri" : "https://example.com",
        "username" : "testuser",
        "password" : "CraBzR0oL"
    }
    client.parse_config_data(config_data=testdict)

def test_uri_not_set(client: KanidmClient) -> None:
    """ tests auth url when you've somehow failed to set the uri """
    client.config.uri = None
    with pytest.raises(ServerURLNotSet):
        assert client.auth_url is not None

def test_init_with_uri() -> None:
    """ tests the class """
    testclient = KanidmClient(uri="https://example.com")
    assert testclient.config.uri == "https://example.com"

def test_init_with_session() -> None:
    """ tests the class """
    testsession = requests.Session()
    testclient = KanidmClient(
        uri="https://google.com",
        session=testsession,
        )
    assert testclient.session is testsession

def test_config_invalid_uri() -> None:
    """ tests passing an invalid uri to the config parser """

    test_input = {
        "uri" : "asdfsadfasd",
        }
    with pytest.raises(pydantic.ValidationError):
        KanidmClientConfig.parse_obj(test_input)
