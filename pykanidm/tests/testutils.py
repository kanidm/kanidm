""" reusable widgets for testing """

import pytest
from kanidm import KanidmClient

@pytest.fixture(scope="function")
def client() -> KanidmClient:
    """ sets up a client with a basic thing """
    return KanidmClient(uri="https://idm.example.com")

@pytest.fixture(scope="function")
def client_configfile() -> KanidmClient:
    """ sets up a client from a config file """
    return KanidmClient(config="~/.config/kanidm")
