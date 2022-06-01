""" tests the config file things """

import logging
from pathlib import Path
import sys

import pytest

from kanidm.utils import load_config

logging.basicConfig(level=logging.DEBUG)

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

def test_load_missing_config_file() -> None:
    """ tests that an error is raised """

    with pytest.raises(
        FileNotFoundError,
        match=EXAMPLE_CONFIG_FILE+"cheese",
        ):
        load_config(
            EXAMPLE_CONFIG_FILE+"cheese"
            )
