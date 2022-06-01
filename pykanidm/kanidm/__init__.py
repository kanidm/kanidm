""" Kanidm python module """

import json
import logging
from typing import Any, Dict, List, Optional, TypedDict

import requests

from .exceptions import AuthInitFailed, AuthMechUnknown, AuthCredFailed, ServerURLNotSet
from .types import KanidmClientConfig, AuthInitResponse
from .utils import load_config

class KanidmClient():
    """ Kanidm ciient module """

    def __init__(
        self,
        config: Optional[str]=None,
        uri: Optional[str]=None,
        session: Optional[requests.Session]=None,
        ) -> None:
        """ set up the client module"""

        self.uri: Optional[str] = None
        self.username: Optional[str] = None
        self.password: Optional[str] = None
        self.connect_timeout = 30

        if config is not None:
            config_data = load_config(config)
            self.parse_config_data(config_data)

        if uri is not None:
            self.uri = uri

        if session is None:
            self.session = requests.Session()
        else:
            self.session = session


    def parse_config_data(
        self,
        config_data: Dict[str, Any],
        ) -> None:
        """ hand it a config dict and it'll configure the client """
        config_object = KanidmClientConfig.parse_obj(config_data)
        if config_object.uri:
            self.uri = config_object.uri
        if config_object.connect_timeout:
            self.connect_timeout = config_object.connect_timeout
        if config_object.verify_ca:
            self.verify_ca = config_object.verify_ca
        if config_object.verify_hostnames:
            self.verify_hostnames = config_object.verify_hostnames

        if config_object.username:
            self.username = config_object.username
        if config_object.password:
            self.password = config_object.password

        if config_object.radius_service_username:
            self.username = config_object.radius_service_username
        if config_object.radius_service_password:
            self.password = config_object.radius_service_password


    @property
    def auth_url(self) -> str:
        """ gets the authentication url endpoint """
        if self.uri is None:
            raise ServerURLNotSet("You didn't set the server URL")
        return f"{self.uri}/v1/auth"

    def _auth_init(self, username: str) -> requests.Response:
        """ init step """
        init_auth = {"step": {"init": username}}

        response = self.session.post(
            self.auth_url,
            json=init_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            )
        if response.status_code != 200:
            logging.debug("Failed to authenticate, response from sever: %s", response.json())
            raise AuthInitFailed
        response.raise_for_status()
        if "x-kanidm-auth-session-id" not in response.headers:
            raise ValueError("Missing x-kanidm-auth-session-id header in init auth response")
        return response

    def authenticate(
        self,
        username: Optional[str]=None,
        password: Optional[str]=None,
        ) -> str:
        """ authenticates with a username and password, returns the auth token """
        if (username is None and password is not None) or \
            (username is not None and password is None):
            #pylint: disable=line-too-long
            raise ValueError("If authenticate() call with username is none, password has to be as well, to use class-internal values")
        if username is None and password is None:
            if self.username is None or self.password is None:
                raise ValueError("Need username and password to be specified somewhere before calling authenticate")
            username = self.username
            password = self.password
        if username is None or password is None:
            raise ValueError(f"Username and Password need to be set somewhere, got {username}:{password}")

        response = self._auth_init(username)
        headers = {
            "X-KANIDM-AUTH-SESSION-ID": response.headers["x-kanidm-auth-session-id"],
        }

        # {'sessionid': '00000000-5fe5-46e1-06b6-b830dd035a10', 'state': {'choose': ['password']}}
        #TODO: actually type the response properly
        auth_init_response = AuthInitResponse.parse_obj(response.json())
        #if "state" not in response_json:
        #    raise ValueError("'state' field missing from auth response")
        #if "choose" not in response_json['state']:
        #    raise ValueError("'choose' field missing from auth response")
        if 'password' not in auth_init_response.state.choose:
            logging.error("Invalid auth mech presented: %s", auth_init_response.dict())
            raise AuthMechUnknown

        begin_auth = {"step": {"begin": "password"}}

        response = self.session.post(
            self.auth_url,
            json=begin_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            headers=headers,
            )
        if response.status_code != 200:
            logging.error("Failed to authenticate: %s", response.json())
            raise Exception("AuthBeginFailed")

        cred_auth = {"step": { "cred": {"password": password}}}
        response = self.session.post(
            self.auth_url,
            json=cred_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            headers=headers,
            )
        json_response = response.json()
        if response.status_code != 200:
            logging.error("Failed to authenticate, response: %s", json_response)
            raise AuthCredFailed

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


#TODO: ssl validation validate
