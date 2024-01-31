""" tests the config file things """

import logging
from pathlib import Path
import sys

import pydantic
import pytest

from kanidm import KanidmClient
from kanidm.types import KanidmClientConfig
from kanidm.utils import load_config

logging.basicConfig(level=logging.DEBUG)

EXAMPLE_CONFIG_FILE = str(Path(__file__).parent.parent.parent / "examples/config_localhost")


@pytest.fixture(scope="function")
async def client() -> KanidmClient:
    """sets up a client with a basic thing"""
    return KanidmClient(
        uri="https://idm.example.com",
    )


def test_load_config_file() -> None:
    """tests that the file loads"""
    if not Path(EXAMPLE_CONFIG_FILE).expanduser().resolve().exists():
        print("Can't find client config file", file=sys.stderr)
        pytest.skip()
    print("Loading config file")
    config = load_config(EXAMPLE_CONFIG_FILE)
    assert config.get("uri") == "https://localhost:8443"

    print(f"{config.get('uri')=}")
    print(config)


def test_load_missing_config_file() -> None:
    """tests that an error is raised"""

    with pytest.raises(
        FileNotFoundError,
        match=EXAMPLE_CONFIG_FILE + "cheese",
    ):
        load_config(EXAMPLE_CONFIG_FILE + "cheese")


def test_parse_config_validationerror(client: KanidmClient) -> None:
    """tests parse_config with a faulty input"""
    testdict = {"verify_certificate": "that was weird."}
    with pytest.raises(ValueError):
        client.parse_config_data(config_data=testdict)


async def test_parse_config_data(client: KanidmClient) -> None:
    """tests parse_config with a valid input"""
    testdict = {
        "uri": "https://example.com",
        "username": "testuser",
        "password": "CraBzR0oL",
    }
    client.parse_config_data(config_data=testdict)


async def test_init_with_uri() -> None:
    """tests the class"""

    testclient = KanidmClient(
        uri="https://example.com",
    )
    assert testclient.config.uri == "https://example.com/"


def test_config_invalid_uri() -> None:
    """tests passing an invalid uri to the config parser"""

    test_input = {
        "uri": "asdfsadfasd",
    }
    with pytest.raises(pydantic.ValidationError):
        KanidmClientConfig.model_validate(test_input)


def test_config_none_uri() -> None:
    """tests passing an invalid uri to the config parser"""

    with pytest.raises(ValueError, match="Please initialize this with a server URI"):
        KanidmClient(uri=None)


def test_config_loader_str() -> None:
    """tests passing an invalid uri to the config parser"""

    with pytest.raises(FileNotFoundError):
        KanidmClient(config_file="hello world")


def test_config_init() -> None:
    """tests passing config object"""

    config = KanidmClientConfig(uri="https://idp.crabzrool.test")
    assert KanidmClient(config=config)
