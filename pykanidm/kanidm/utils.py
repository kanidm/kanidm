""" utility functions """

from pathlib import Path
from typing import Any, Dict, Union

import toml

def load_config(filename: Union[str,Path]="/etc/kanidm/config") -> Dict[str, Any]:
    """ loads the configuration file """
    if isinstance(filename, Path):
        config_filepath = filename
    else:
        config_filepath = Path(filename).expanduser().resolve()

    if not config_filepath.exists():
        raise FileNotFoundError(
            f"Failed to find configuration file ({config_filepath}), quitting!",
            )
    config_data: Dict[str, Any] = toml.load(config_filepath.open(encoding="utf-8"))
    return config_data

def parse_toml(input_string: str) -> Dict[str, Any]:
    """ pass it a TOML and get back the result """
    return toml.loads(input_string)
