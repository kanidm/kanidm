""" tests the config file things """

from pathlib import Path
import sys
import toml

import pytest

from kanidm.types import KanidmClientConfig
from kanidm.utils import load_config


EXAMPLE_CONFIG_FILE = Path(__file__).parent.parent.parent / "examples/config"

def test_radius_groups() -> None:
    """testing loading a config file with radius groups defined"""

    config_toml = """
radius_groups = [
    { spn = "hello world", "vlan" = 1234 },
]

"""
    config_parsed = toml.loads(config_toml)
    print(config_parsed)
    kanidm_config = KanidmClientConfig.model_validate(config_parsed)
    for group in kanidm_config.radius_groups:
        print(group.spn)
        assert group.spn == "hello world"


def test_radius_clients() -> None:
    """testing loading a config file with radius groups defined"""

    config_toml = """
radius_clients = [ { name = "hello world", ipaddr = "10.0.0.5", secret = "cr4bj0oz" },
]

"""
    config_parsed = toml.loads(config_toml)
    print(config_parsed)
    kanidm_config = KanidmClientConfig.model_validate(config_parsed)
    client = kanidm_config.radius_clients[0]
    print(client.name)
    assert client.name == "hello world"
    assert client.ipaddr == "10.0.0.5"
    assert client.secret == "cr4bj0oz"
