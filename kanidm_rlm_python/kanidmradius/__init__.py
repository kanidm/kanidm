""" kanidm RADIUS module """

import configparser
from functools import reduce
import os
from pathlib import Path
import sys
from typing import Any, Dict

import logging
import requests
import toml
# import json

from . import radiusd
from .utils import load_config

logging.basicConfig(
    level=logging.DEBUG,
    stream=sys.stderr,
    )

logging.info("Hello world")
logging.error("error!")
logging.debug("Debug!")


#TODO: change the config file to TOML to match the rest of Kanidm
#TODO: allow some things to be set by environment variables, maybe?



# if we're running in the container
if os.getcwd() == "/etc/raddb":
    config_toml = load_config()

    CONFIG_PATH = Path(
        os.getenv('KANIDM_RLM_CONFIG', '/data/config.ini'),
        ).expanduser().resolve()

    if not CONFIG_PATH.exists():
        logging.error("Failed to find configuration file (%s), quitting!", CONFIG_PATH)
        sys.exit(1)
    CONFIG_PATH = Path(
        os.getenv('KANIDM_RLM_CONFIG', '/data/config.ini'),
        ).expanduser().resolve()
    CONFIG = configparser.ConfigParser(interpolation=None)
    CONFIG.read(CONFIG_PATH)

    GROUPS = [
        {
            "name": x.split('.')[1],
            "vlan": CONFIG.get(x, "vlan")
        }
        for x in CONFIG.sections()
        if x.startswith('group.')
    ]

    REQ_GROUP = CONFIG.get("radiusd", "required_group")

    if config_toml.get("verify_ca", True):
        CA = CONFIG.get("kanidm_client", "ca", fallback=True)
    else:
        CA = False
    USER = CONFIG.get("kanidm_client", "user")
    SECRET = CONFIG.get("kanidm_client", "secret")
    DEFAULT_VLAN = CONFIG.get("radiusd", "vlan")
    TIMEOUT = 8

    URL = CONFIG.get('kanidm_client', 'url')
    AUTH_URL = f"{URL}/v1/auth"

def _authenticate(
    session: requests.Session,
    acct: str,
    password: str,
    ) -> str:
    init_auth = {"step": {"init": acct}}

    response = session.post(AUTH_URL, json=init_auth, verify=CA, timeout=TIMEOUT)
    if response.status_code != 200:
        logging.error("Failed to authenticate, response from sever: %s", response.json())
        raise Exception("AuthInitFailed")

    session_id = response.headers["x-kanidm-auth-session-id"]
    headers = {"X-KANIDM-AUTH-SESSION-ID": session_id}

    # {'sessionid': '00000000-5fe5-46e1-06b6-b830dd035a10', 'state': {'choose': ['password']}}
    #TODO: actually handle the response properly
    if 'password' not in response.json().get('state', {'choose': None}).get('choose', None):
        logging.error("Invalid auth mech presented: %s", response.json())
        raise Exception("AuthMechUnknown")

    begin_auth = {"step": {"begin": "password"}}

    response = session.post(AUTH_URL, json=begin_auth, verify=CA, timeout=TIMEOUT, headers=headers)
    if response.status_code != 200:
        logging.error("Failed to authenticate: %s", response.json())
        raise Exception("AuthBeginFailed")

    cred_auth = {"step": { "cred": {"password": password}}}
    response = session.post(AUTH_URL, json=cred_auth, verify=CA, timeout=TIMEOUT, headers=headers)
    json_response = response.json()
    if response.status_code != 200:
        logging.error("Failed to authenticate, response: %s", json_response)
        raise Exception("AuthCredFailed")

    # Get the token
    try:
        return_token: str = json_response['state']['success']
        return return_token
    except KeyError:
        logging.error(
            "Authentication failed, couldn't find token in response: %s",
            response.content,
            )
        raise Exception("AuthCredFailed") # pylint: disable=raise-missing-from

#TODO: work out typing for _get_radius_token - it should have a solid type
def _get_radius_token(username: str) -> Dict[str, Any]:
    logging.debug("Getting rtok for %s ...", username)
    #TODO: handle disabling TLS verification
    session = requests.session()
    # First authenticate a connection
    bearer_token = _authenticate(
        session,
        USER, #TODO: rename the service account username field
        SECRET, #TODO: rename the service account password field
        )
    # Now get the radius token
    rtok_url = f"{URL}/v1/account/{username}/_radius/_token"
    headers = {
        'Authorization': f"Bearer {bearer_token}",
    }
    response = session.get(rtok_url, verify=CA, timeout=TIMEOUT, headers=headers)
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
    ) -> int:
    """ checks if a vlan is in the config """
    if CONFIG.has_section(f"group.{group['name']}"):
        if CONFIG.has_option(f"group.{group['name']}", "vlan"):
            vlan = CONFIG.getint(f"group.{group['name']}", "vlan")
            logging.debug("assigning vlan %s from group %s", vlan, group)
            return vlan
    return acc

def instantiate(args: Any) -> Any:
    """ start up radiusd """
    print(args, file=sys.stderr)
    return radiusd.RLM_MODULE_OK

#TODO: figure out typing/return values
def authorize(args: Any) -> Any:
    """ does the kanidm authorize step """
    logging.info('kanidm python module called')

    dargs = dict(args)
    # print(dargs)

    username = dargs['User-Name']

    tok = None

    try:
        tok = _get_radius_token(username)
    except Exception as error_message: # pylint: disable=broad-except
        logging.info("kanidm exception %s", error_message)

    if tok is None:
        logging.info('kanidm RLM_MODULE_NOTFOUND due to no auth token')
        return radiusd.RLM_MODULE_NOTFOUND

    # print("got token %s" % tok)

    # Are they in the required group?

    req_sat = False
    for group in tok["groups"]:
        if group['name'] == REQ_GROUP:
            req_sat = True
    logging.info("required group satisfied -> %s:%s", username, req_sat)
    if req_sat is not True:
        return radiusd.RLM_MODULE_NOTFOUND

    # look up them in config for group vlan if possible.
    #TODO: work out the typing on this, WTF.
    uservlan: int = reduce(check_vlan, tok["groups"], DEFAULT_VLAN)
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
