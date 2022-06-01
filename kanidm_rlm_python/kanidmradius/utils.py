""" utility functions """
import logging

import sys

from pathlib import Path
from typing import Dict, Any

import toml

def load_config(filename: str="/etc/kanidm/config") -> Dict[str, Any]:
    """ loads the configuration file """
    config_filepath = Path(filename).expanduser().resolve()

    if not config_filepath.exists():
        print(f"what {config_filepath}")
        logging.error("Failed to find configuration file (%s), quitting!", config_filepath)
        sys.exit(1)
    config_data: Dict[str, Any] = toml.load(config_filepath.open(encoding="utf-8"))
    return config_data
