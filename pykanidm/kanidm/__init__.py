""" Kanidm python module """

from json import dumps, loads, JSONDecodeError
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from pydantic import BaseModel, ValidationError
import requests
import aiohttp

from .exceptions import AuthBeginFailed, AuthInitFailed, AuthCredFailed, AuthMechUnknown, NoMatchingEntries
from .types import AuthBeginResponse, AuthStepPasswordResponse, AuthInitResponse, ClientResponse, KanidmClientConfig
from .utils import load_config

#TODO: going to make this asyncio, once the flows and stuff are worked out

KANIDMURLS = {
    "auth" : "/v1/auth",
}
class KanidmClient():
    """ Kanidm ciient module """

    # pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        config_file: Optional[Path]=None,
        uri: Optional[str]=None,
        session: Optional[aiohttp.client.ClientSession] = None,
        ) -> None:
        """ set up the client module"""

        self.config = KanidmClientConfig(uri=uri)

        if config_file is not None:
            if not isinstance(config_file, Path):
                config_file = Path(config_file)
            config_data = load_config(config_file.expanduser().resolve())
            self.config = self.config.parse_obj(config_data)

        print(self.config.dict())

        self.session = session

        self.sessionid: Optional[str] = None

        if self.config.uri is None:
            raise ValueError("Please intitialize this with a server URI")

    def parse_config_data(
        self,
        config_data: Dict[str, Any],
        ) -> None:
        """ hand it a config dict and it'll configure the client """
        try:
            self.config.parse_obj(config_data)
        except ValidationError as validation_error:
            raise ValueError(f"Failed to validate configuration: {validation_error}")

    def get_path_uri(self, path: str) -> str:
        """ turns a path into a full URI """
        if path.startswith("/"):
            path = path[1:]
        return f"{self.config.uri}{path}"

    #pylint: disable=too-many-arguments
    async def _call(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        json: Optional[Dict[str, str]] = None,
    ) -> ClientResponse:

        if timeout is None:
            timeout = self.config.connect_timeout
        if self.session is None:
            self.session = aiohttp.client.ClientSession()
        async with self.session.request(
            method=method,
            url=self.get_path_uri(path),
            headers=headers,
            timeout=timeout,
            json=json,
            # verify=self.config.verify_ca, #TODO: ssl verify setting
        ) as request:
            content = await request.content.read()
            try:
                response_json = loads(content)
                if not isinstance(response_json, dict):
                    response_json = None
            except JSONDecodeError as json_error:
                logging.error("Failed to JSON Decode Response: %s", json_error)
                response_json = {}
            response_input = {
                "data" : response_json,
                "content": content.decode("utf-8"),
                "headers" : request.headers,
                "status_code" : request.status,
            }
            logging.debug(dumps(response_input, default=str, indent=4))
            response = ClientResponse.parse_obj(response_input)
        return response

    async def call_get(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        ) -> ClientResponse:
        """ does a get call to the server """
        return await self._call( "GET", path, headers, timeout )

    async def call_post(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
        ) -> ClientResponse:
        """ does a get call to the server """

        return await self._call(
            method="POST", path=path, headers=headers, json=json, timeout=timeout
        )

    async def auth_init(self, username: str) -> AuthInitResponse:
        """ init step, starts the auth session, sets the class-local session ID """
        init_auth = {"step": {"init": username}}

        response = await self.call_post(
            path=KANIDMURLS['auth'],
            json=init_auth,
        )
        if response.status_code != 200:
            logging.debug(
                "Failed to authenticate, response from server: %s",
                response.content,
                )
            #TODO: mock test this
            raise AuthInitFailed(response.content)

        if "x-kanidm-auth-session-id" not in response.headers:
            logging.debug("response.content: %s", response.content)
            logging.debug("response.headers: %s", response.headers)
            raise ValueError(f"Missing x-kanidm-auth-session-id header in init auth response: {response.headers}")
        #TODO: setting the class-local session id, do we want this?
        self.sessionid = response.headers['x-kanidm-auth-session-id']
        retval = AuthInitResponse.parse_obj(response.data)
        retval.response = response
        return retval

    async def auth_begin(
        self,
        method: str="password", #TODO: do we want a default auth mech to be set?
        ) -> ClientResponse:
        """ the 'begin' step """

        begin_auth = {
            "step": {
                "begin": method,
                }
            }

        response = await self.call_post(
            KANIDMURLS["auth"],
            json=begin_auth,
            headers=self.session_header(),
            )
        if response.status_code != 200:
            #TODO: write mocked test for this
            raise AuthBeginFailed(response.content)

        retobject = AuthBeginResponse.parse_obj(response.data)
        retobject.response = response
        return response

    async def authenticate_password(
        self,
        username: Optional[str]=None,
        password: Optional[str]=None,
        ) -> AuthStepPasswordResponse:
        """ authenticates with a username and password, returns the auth token """
        if username is None and password is None:
            if self.config.username is None or self.config.password is None:
                raise ValueError("Need username/password to be in caller or class settings before calling authenticate_password")
            username = self.config.username
            password = self.config.password
        if username is None or password is None:
            raise ValueError("Username and Password need to be set somewhere!")

        auth_init = await self.auth_init(username)

        if len(auth_init.state.choose) == 0:
            # there's no mechanisms at all?
            raise AuthMechUnknown(f"No auth mechanisms for {username}")
        auth_begin = await self.auth_begin(
            method="password",
            )
        # does a little bit of validation
        auth_begin_object = AuthBeginResponse.parse_obj(auth_begin.data)
        auth_begin_object.response = auth_begin
        return await self.auth_step_password(password=password)

    async def auth_step_password(
        self,
        password: Optional[str] = None,
        ) -> AuthStepPasswordResponse:
        """ does the password auth step """

        if password is None:
            password=self.config.password
        if password is None:
            raise ValueError("Password has to be passed to auth_step_password or in self.password!")

        cred_auth = {"step": { "cred": {"password": password}}}
        response = await self.call_post(
            path="/v1/auth",
            json=cred_auth,
            )
        if response.status_code != 200:
            logging.debug("Failed to authenticate, response: %s", response.content)
            raise AuthCredFailed("Failed password authentication!")

        #TODO: handle json dump fail
        result = AuthStepPasswordResponse.parse_obj(response.data)
        result.response = response
        print(f"auth_step_password: {result.dict()}")

        # pull the token out and set it
        #TODO: try and build this into the pydantic model
        if result.state.success is None:
            raise AuthCredFailed
        result.sessionid = result.state.success
        return result


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

    async def get_radius_token(
        self,
        username: str,
        radius_session_id: str) -> ClientResponse:
        """ does the call to the radius token endpoint """
        path = f"/v1/account/{username}/_radius/_token"
        headers = {
            'Authorization': f"Bearer {radius_session_id}",
        }
        response = await self.call_get(
            path,
            headers,
            )
        if response.status_code == 404:
            raise NoMatchingEntries(f"No user found: '{username}' {response.headers['x-kanidm-opid']}")
        return response

#TODO: ssl validation validate
