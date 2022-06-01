""" tests the config file things """

from pathlib import Path
import sys

import pytest

from kanidmradius.utils import load_config

EXAMPLE_CONFIG_FILE="../examples/config"

def test_load_config_file() -> None:
    """ tests that the file loads """
    if not Path(EXAMPLE_CONFIG_FILE).expanduser().resolve().exists():
        print("Can't find client config file", file=sys.stderr)
        pytest.skip()
    config = load_config(EXAMPLE_CONFIG_FILE)
    assert config.get("uri") == 'https://idm.example.com'
    print(f"{config.get('uri')=}")
    print(config)
