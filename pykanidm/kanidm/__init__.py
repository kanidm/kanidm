""" Kanidm python module """

import logging
from typing import Any, Dict, Optional

from pydantic import ValidationError
import requests

from .exceptions import AuthBeginFailed, AuthInitFailed, AuthCredFailed, AuthMechUnknown, ServerURLNotSet
from .types import AuthBeginResponse, AuthStepPasswordResponse, KanidmClientConfig, AuthInitResponse
from .utils import load_config

#TODO: going to make this asyncio, once the flows and stuff are worked out

class KanidmClient():
    """ Kanidm ciient module """

    # pylint: disable=too-many-instance-attributes
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
        self.sessionid: Optional[str] = None


    def parse_config_data(
        self,
        config_data: Dict[str, Any],
        ) -> None:
        """ hand it a config dict and it'll configure the client """
        try:
            config_object = KanidmClientConfig.parse_obj(config_data)
        except ValidationError as validation_error:
            raise ValueError(f"Failed to validate configuration: {validation_error}")

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

    def auth_init(self, username: str) -> AuthInitResponse:
        """ init step, starts the auth session, sets the class-local session ID """
        init_auth = {"step": {"init": username}}

        response = self.session.post(
            self.auth_url,
            json=init_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            )
        if response.status_code != 200:

            logging.debug(
                "Failed to authenticate, response from server: %s",
                response.content,
                )
            #TODO: mock test this
            raise AuthInitFailed(response.content)
        response.raise_for_status()

        if "x-kanidm-auth-session-id" not in response.headers:
            logging.debug("response.content: %s", response.content)
            logging.debug("response.headers: %s", response.headers)
            raise ValueError(f"Missing x-kanidm-auth-session-id header in init auth response: {response.headers}")
        #TODO: setting the class-local session id, do we want this?
        self.sessionid = response.headers['x-kanidm-auth-session-id']
        retval = AuthInitResponse.parse_obj(response.json())
        retval.response = response
        return retval

    def auth_begin(
        self,
        method: str="password", #TODO: do we want a default auth mech to be set?
        ) -> requests.Response:
        """ the 'begin' step """

        begin_auth = {
            "step": {
                "begin": method,
                }
            }

        response = self.session.post(
            self.auth_url,
            json=begin_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            headers=self.session_header(),
            )
        if response.status_code != 200:
            #TODO: write mocked test for this
            raise AuthBeginFailed(response.content)
        response.raise_for_status()

        retobject = AuthBeginResponse.parse_obj(response.json())
        retobject.response = response
        return response

    def authenticate_password(
        self,
        username: Optional[str]=None,
        password: Optional[str]=None,
        ) -> AuthStepPasswordResponse:
        """ authenticates with a username and password, returns the auth token """
        if username is None and password is None:
            if self.username is None or self.password is None:
                raise ValueError("Need username/password to be in caller or class settings before calling authenticate_password")
            username = self.username
            password = self.password
        if username is None or password is None:
            raise ValueError(f"Username and Password need to be set somewhere, got {username}:{password}")

        auth_init = self.auth_init(username)

        if len(auth_init.state.choose) == 0:
            # there's no mechanisms at all?
            raise AuthMechUnknown(f"No auth mechanisms for {username}")
        auth_begin = self.auth_begin(
            method="password",
            )
        # does a little bit of validation
        auth_begin_object = AuthBeginResponse.parse_obj(auth_begin.json())
        auth_begin_object.response = auth_begin
        return self.auth_step_password(password=password)

    def auth_step_password(
        self,
        password: Optional[str] = None,
        ) -> AuthStepPasswordResponse:
        """ does the password auth step """

        if password is None:
            password=self.password
        if password is None:
            raise ValueError("Password has to be passed to auth_step_password or in self.password!")

        cred_auth = {"step": { "cred": {"password": password}}}
        response = self.session.post(
            self.auth_url,
            json=cred_auth,
            verify=self.verify_ca,
            timeout=self.connect_timeout,
            headers=self.session_header(),
            )
        if response.status_code != 200:
            logging.error("Failed to authenticate, response: %s", response.content)
            raise AuthCredFailed("Failed password authentication!")

        #TODO: handle json dump fail
        result = AuthStepPasswordResponse.parse_obj(response.json())
        result.response = response
        print(f"auth_step_password: {result.dict()}")
        # Get the token
        if result.state.success is not None:
            return result
        raise AuthCredFailed

    def session_header(
        self,
        sessionid: Optional[str]=None,
        ) -> Dict[str, str]:
        """ create a headers dict from a session id """
        #TODO: perhaps allow session_header to take a dict and update it, too?

        if sessionid is not None:
            return {
                "X-KANIDM-AUTH-SESSION-ID": sessionid,
            }

        if self.sessionid is not None:
            return {
                "X-KANIDM-AUTH-SESSION-ID": self.sessionid,
            }
        raise ValueError("Class doesn't have a sessionid stored and none was provided")

#TODO: ssl validation validate
