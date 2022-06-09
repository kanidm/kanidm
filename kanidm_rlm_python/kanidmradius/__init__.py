""" kanidm RADIUS module """

from functools import reduce
import json
import logging
import os
from pathlib import Path
import sys
from typing import Any, Dict, Optional

from kanidm import KanidmClient
from kanidm.types import AuthStepPasswordResponse
from kanidm.utils import load_config

from . import radiusd

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stderr,
    )


#TODO: change the config file to TOML to match the rest of Kanidm
#TODO: allow some things to be set by environment variables, maybe?



# if we're running in the container
    # config_toml = load_config()

config_paths = [
    os.getenv("KANIDM_RLM_CONFIG", "/data/kanidm"),
    "~/.config/kanidm",
]

config_path = None
for config_file_path in config_paths:
    config_path = Path(config_file_path).expanduser().resolve()
    if config_path.exists():
        break

if not config_path.exists():
    logging.error("Failed to find configuration file, checked (%s), quitting!", config_paths)
    sys.exit(1)
config = load_config(str(config_path))

KANIDM_CLIENT = KanidmClient(config_file=config_path)


# if os.getcwd() == "/etc/raddb":
# GROUPS = [
#     {
#         "name": x.split('.')[1],
#         "vlan": config.get(x, "vlan")
#     }
#     for x in config
#     if x.startswith('group.')
# ]

# REQ_GROUP = config.get("radiusd", "required_group")

# if config.get("verify_ca", True):
#     CA = config.get("kanidm_client", "ca", fallback=True)
# else:
#     CA = False

# USER = CONFIG.get("kanidm_client", "user")
# SECRET = CONFIG.get("kanidm_client", "secret")
# DEFAULT_VLAN = CONFIG.get("radiusd", "vlan")
# TIMEOUT = 8

#URL = CONFIG.get('kanidm_client', 'url')
#AUTH_URL = f"{URL}/v1/auth"

def authenticate(
    acct: str,
    password: str,
    kanidm_client: KanidmClient = KANIDM_CLIENT,
    ) -> AuthStepPasswordResponse:

    logging.error("authenticate - %s:%s", acct, password)

    try:
        return kanidm_client.authenticate_password(
            username=acct,
            password=password
        )
    except Exception as error_message:
        logging.error("Failed to run kanidm.authenticate_password: %s", error_message)
    return radiusd.RLM_MODULE_FAIL

#TODO: work out typing for _get_radius_token - it should have a solid type
def _get_radius_token(
    username: Optional[str]=None,
    kanidm_client: KanidmClient=KANIDM_CLIENT,
    ) -> Dict[str, Any]:
    if username is None:
        raise ValueError("Didn't get a username for _get_radius_token")
    # authenticate as the radius service account
    logging.debug("kanidm authenticate_password for %s", username)
    radius_auth_response = kanidm_client.authenticate_password()

    logging.debug("Getting RADIUS token for %s", username)
    response = kanidm_client.get_radius_token(
        username=username,
        radius_session_id = radius_auth_response.sessionid,
    )
    if response.status_code != 200:
        logging.error("got response status code: %s", response.status_code)
        logging.error("Response content: %s", response.json())
        raise Exception("Failed to get RadiusAuthToken")
    logging.debug("Success getting RADIUS token: %s", response.json())
    retval: Dict[str, Any] = response.json()
    return retval

def check_vlan(
    acc: int, #TODO: why is this called ACC?
    group: Dict[str, str],
    kanidm_client: Optional[KanidmClient] = None,
    ) -> int:
    """ checks if a vlan is in the config,

        acc is the default vlan
    """
    logging.debug(f"{acc=}")
    if kanidm_client is None:
        kanidm_client = KANIDM_CLIENT
        # raise ValueError("Need to pass this a kanidm_client")

    for radius_group in kanidm_client.config.radius_groups:
        logging.debug("Checking '%s' radius_group against group %s", radius_group, group['name'])
        if radius_group.name == group['name']:
            return radius_group.vlan
    #if CONFIG.has_section(f"group.{group['name']}"):
    #    if CONFIG.has_option(f"group.{group['name']}", "vlan"):
    #        vlan = CONFIG.getint(f"group.{group['name']}", "vlan")
    #        logging.debug("assigning vlan %s from group %s", vlan, group)
    #        return vlan
    logging.debug("returning default vlan: %s", acc)
    return acc

def instantiate(args: Any) -> Any:
    """ start up radiusd """
    logging.info("Starting up!")
    print(f"{args=}", file=sys.stderr)
    return radiusd.RLM_MODULE_OK

def authorize(
    args: Any=Dict[Any,Any],
    kanidm_client: KanidmClient=KANIDM_CLIENT,
    ) -> Any:
    """ does the kanidm authorize step """
    logging.info('kanidm python module called')
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
    logging.debug(f"Authorise: {json.dumps(dargs)}")
    username = dargs['User-Name']

    tok = None
    try:
        tok = _get_radius_token(username=username)
        logging.debug("radius_token: %s", tok)
    except Exception as error_message: # pylint: disable=broad-except
        logging.error("kanidm exception: %s", error_message)

    if tok is None:
        logging.info('kanidm RLM_MODULE_NOTFOUND due to no auth token')
        return radiusd.RLM_MODULE_NOTFOUND

    # Are they in the required group?
    req_sat = False
    for group in tok["groups"]:
        if group['name'] in kanidm_client.config.radius_required_groups:
            req_sat = True
            logging.info("User %s has a required group (%s)", username, group['name'])
    if req_sat is not True:
        logging.info("User %s doesn't have a group from the required list.", username)
        return radiusd.RLM_MODULE_NOTFOUND

    # look up them in config for group vlan if possible.
    #TODO: work out the typing on this, WTF.
    uservlan: int = reduce(
       check_vlan,
       tok["groups"],
       kanidm_client.config.radius_default_vlan,
       )
    if uservlan == int(0):
       logging.info("Invalid uservlan of 0")


    logging.info("selected vlan %s:%s", username, uservlan)
    # Convert the tok groups to groups.
    name = tok["name"]
    secret = tok["secret"]

    reply = (
        ('User-Name', str(name)),
        ('Reply-Message', 'Welcome'),
        ('Tunnel-Type', '13'),
        ('Tunnel-Medium-Type', '6'),
        ('Tunnel-Private-Group-ID', str(uservlan)),
    )
    config = (
        ('Cleartext-Password', str(secret)),
    )

    logging.info("OK! Returning details to radius for %s ...", username)
    return (radiusd.RLM_MODULE_OK, reply, config)
