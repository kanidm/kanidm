""" reusable widgets for testing """

from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from typing import Any

import pytest
from kanidm import KanidmClient


@pytest.fixture(scope="function")
async def client() -> KanidmClient:
    """sets up a client with a basic thing"""
    try:
        basicConfig(level=DEBUG)

        return KanidmClient(uri="https://idm.example.com")
    except FileNotFoundError:
        raise pytest.skip("Couldn't find config file...")


@pytest.fixture(scope="function")
async def client_configfile() -> KanidmClient:
    """sets up a client from a config file"""
    try:
        return KanidmClient(config_file=Path("~/.config/kanidm"))
    except FileNotFoundError:
        raise pytest.skip("Couldn't find config file...")


class MockResponse:
    """mock the things"""

    def __init__(self, text: str, status: int) -> None:
        self._text = text
        self.status = status

    async def text(self) -> str:
        """mock the things"""
        return self._text

    # pylint: disable=invalid-name
    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """mock the things"""

    async def __aenter__(self) -> Any:
        """mock the things"""
        return self
