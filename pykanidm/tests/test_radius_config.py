""" tests the config file things """

from pathlib import Path
import sys
import toml

import pytest

from kanidm.types import KanidmClientConfig
from kanidm.utils import load_config


EXAMPLE_CONFIG_FILE = "../../kanidm_rlm_python/examples/config"


def test_load_config_file() -> None:
    """tests that the file loads"""
    if not Path(EXAMPLE_CONFIG_FILE).expanduser().resolve().exists():
        print("Can't find client config file", file=sys.stderr)
        pytest.skip()
    config = load_config(EXAMPLE_CONFIG_FILE)
    kanidm_config = KanidmClientConfig.parse_obj(config)
    assert kanidm_config.uri == "https://idm.example.com/"
    print(f"{kanidm_config.uri=}")
    print(kanidm_config)


def test_radius_groups() -> None:
    """testing loading a config file with radius groups defined"""

    config_toml = """
radius_groups = [
    { name = "hello world", "vlan" = 1234 },
]

"""
    config_parsed = toml.loads(config_toml)
    print(config_parsed)
    kanidm_config = KanidmClientConfig.parse_obj(config_parsed)
    for group in kanidm_config.radius_groups:
        print(group.name)
        assert group.name == "hello world"


def test_radius_clients() -> None:
    """testing loading a config file with radius groups defined"""

    config_toml = """
radius_clients = [ { name = "hello world", ipaddr = "10.0.0.5", secret = "cr4bj0oz" },
]

"""
    config_parsed = toml.loads(config_toml)
    print(config_parsed)
    kanidm_config = KanidmClientConfig.parse_obj(config_parsed)
    client = kanidm_config.radius_clients[0]
    print(client.name)
    assert client.name == "hello world"
    assert client.ipaddr == "10.0.0.5"
    assert client.secret == "cr4bj0oz"
