""" kanidm RADIUS module """
import asyncio
from functools import reduce
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional, Union

from kanidm.exceptions import NoMatchingEntries
from kanidm.types import AuthStepPasswordResponse, RadiusTokenResponse

from .. import KanidmClient
from . import radiusd
from .utils import check_vlan

# the list of places to try
CONFIG_PATHS = [
    os.getenv("KANIDM_RLM_CONFIG", "/data/kanidm"),  # container goodness
    "~/.config/kanidm",  # for a user
    "/etc/kanidm/kanidm",  # system-wide
    "../examples/kanidm",  # test mode
]


def instantiate(_: Any) -> Any:
    """start up radiusd"""
    logging.basicConfig(
        level=logging.DEBUG,
        stream=sys.stderr,
    )
    logging.info("Starting up!")

    config_path = None
    for config_file_path in CONFIG_PATHS:
        config_path = Path(config_file_path).expanduser().resolve()
        if config_path.exists():
            break

    if (config_path is None) or (not config_path.exists()):
        logging.error(
            "Failed to find configuration file, checked (%s), quitting!", CONFIG_PATHS
        )
        sys.exit(1)

    kanidm_client = KanidmClient(config_file=config_path)
    if kanidm_client.config.auth_token is None:
        logging.error("You need to specify auth_token in the configuration file!")
        sys.exit(1)
    os.environ["KANIDM_CONFIG_FILE"] = config_path.as_posix()
    logging.info("Config file: %s", config_path.as_posix())
    return radiusd.RLM_MODULE_OK


async def _get_radius_token(
    username: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """pulls the radius token for a client username"""
    kanidm_client = KanidmClient(config_file=os.environ["KANIDM_CONFIG_FILE"])
    if username is None:
        raise ValueError("Didn't get a username for _get_radius_token")
    # authenticate as the radius service account
    logging.debug("Getting RADIUS token for %s", username)
    response = await kanidm_client.get_radius_token(username=username)
    logging.debug("Got radius token for %s", username)

    if response.status_code != 200:
        logging.error("got response status code: %s", response.status_code)
        logging.error("Response content: %s", response.json())
        raise Exception("Failed to get RadiusAuthToken")
    logging.debug("Success getting RADIUS token: %s", response.json())
    logging.debug(response.data)
    return response.data


# pylint: disable=too-many-locals
def authorize(
    args: Any = Dict[Any, Any],
) -> Any:
    """does the kanidm authorize step"""
    logging.info("kanidm python module called")
    kanidm_client = KanidmClient(config_file=os.environ["KANIDM_CONFIG_FILE"])
    # args comes in like this
    # (
    #   ('User-Name', '<username>'),
    #   ('User-Password', '<radius_password>'),
    #   ('NAS-IP-Address', '<client IP>'),
    #   ('NAS-Port', '<the'),
    #   ('Message-Authenticator', '0xaabbccddeeff00112233445566778899'),
    #   ('Event-Timestamp', 'Jun  9 2022 12:07:50 UTC')
    # )

    dargs = dict(args)
    logging.error("Authorise: %s", json.dumps(dargs))
    cn_uuid = dargs.get("TLS-Client-Cert-Common-Name", None)
    username = dargs["User-Name"]

    if cn_uuid is not None:
        logging.debug("Using TLS-Client-Cert-Common-Name")
        user_id = cn_uuid
    else:
        logging.debug("Using User-Name")
        user_id = username

    tok = None
    try:
        loop = asyncio.get_event_loop()
        tok = RadiusTokenResponse.parse_obj(
            loop.run_until_complete(_get_radius_token(username=user_id))
        )
        logging.debug("radius information token: %s", tok)
    except NoMatchingEntries as error_message:
        logging.info(
            "kanidm RLM_MODULE_NOTFOUND after NoMatchingEntries for user_id %s: %s",
            user_id,
            error_message,
        )
        return radiusd.RLM_MODULE_NOTFOUND
    except Exception as error_message:  # pylint: disable=broad-except
        logging.error("kanidm exception: %s, %s", type(error_message), error_message)
    if tok is None:
        logging.info(
            "kanidm RLM_MODULE_REJECT - unable to retrieve radius information token"
        )
        return radiusd.RLM_MODULE_REJECT

    # Get values out of the token
    name = tok.name
    secret = tok.secret
    uuid = tok.uuid

    # Are they in the required group?
    req_sat = False
    required_groups = kanidm_client.config.radius_required_groups
    for group in tok.groups:
        if group.uuid in required_groups or group.spn in required_groups:
            req_sat = True
            logging.info("User %s has a required group (%s)", name, group.spn)
    if req_sat is not True:
        logging.info("User %s doesn't have a group from the required list.", name)
        return radiusd.RLM_MODULE_REJECT

    # look up them in config for group vlan if possible.
    # TODO: work out the typing on this, WTF.
    uservlan: int = reduce(
        check_vlan,
        tok.groups,
        kanidm_client.config.radius_default_vlan,
    )
    if uservlan == int(0):
        logging.info("Invalid uservlan of 0")

    logging.info("selected vlan %s:%s", name, uservlan)

    reply = (
        ("User-Name", str(name)),
        ("Reply-Message", f"Kanidm-Uuid: {uuid}"),
        ("Tunnel-Type", "13"),
        ("Tunnel-Medium-Type", "6"),
        ("Tunnel-Private-Group-ID", str(uservlan)),
    )
    config_object = (("Cleartext-Password", str(secret)),)

    logging.info("OK! Returning details to radius for %s ...", name)
    return (radiusd.RLM_MODULE_OK, reply, config_object)


def authenticate(
    acct: str,
    password: str,
) -> Union[int, AuthStepPasswordResponse]:
    """authenticate the RADIUS service account to Kanidm"""
    kanidm_client = KanidmClient(config_file=os.environ["KANIDM_CONFIG_FILE"])
    logging.error("authenticate - %s:%s", acct, password)

    try:
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(kanidm_client.check_token_valid())
    except Exception as error_message:  # pylint: disable=broad-except
        logging.error("Failed to run kanidm.check_token_valid: %s", error_message)
    return radiusd.RLM_MODULE_FAIL
