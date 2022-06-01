""" utility functions """

from pathlib import Path
from typing import Any, Dict

import toml

def load_config(filename: str="/etc/kanidm/config") -> Dict[str, Any]:
    """ loads the configuration file """
    config_filepath = Path(filename).expanduser().resolve()

    if not config_filepath.exists():
        raise FileNotFoundError(
            f"Failed to find configuration file ({config_filepath}), quitting!",
            )
    config_data: Dict[str, Any] = toml.load(config_filepath.open(encoding="utf-8"))
    return config_data
