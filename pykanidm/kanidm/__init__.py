""" Kanidm python module """

from functools import lru_cache
import json as json_lib  # because we're taking a field "json" at various points
import logging
from pathlib import Path
import ssl
import sys
from typing import Any, Dict, List, Optional, Union

import aiohttp
from pydantic import ValidationError

from .exceptions import (
    AuthBeginFailed,
    AuthInitFailed,
    AuthCredFailed,
    AuthMechUnknown,
    NoMatchingEntries,
)
from .types import (
    AuthBeginResponse,
    AuthState,
    AuthInitResponse,
    ClientResponse,
    GroupInfo,
    KanidmClientConfig,
    GroupList,
)
from .utils import load_config

KANIDMURLS = {
    "auth": "/v1/auth",
    "person": "/v1/person",
    "service_account": "/v1/person",
}

TOKEN_PATH = Path("~/.cache/kanidm_tokens")


class KanidmClient:
    """Kanidm client module

    config: a `KanidmClientConfig` object, if this is set, everything else is ignored
    config_file: a `pathlib.Path` object pointing to a configuration file
    uri: kanidm base URL
    session: a `aiohttp.client.ClientSession`
    verify_hostnames: verify the hostname is correct
    verify_certificate: verify the validity of the certificate and its CA
    ca_path: set this to a trusted CA certificate (PEM format)
    token: a JWS from an authentication session
    """

    # pylint: disable=too-many-instance-attributes,too-many-arguments
    def __init__(
        self,
        config: Optional[KanidmClientConfig] = None,
        config_file: Optional[Union[Path, str]] = None,
        uri: Optional[str] = None,
        verify_hostnames: bool = True,
        verify_certificate: bool = True,
        ca_path: Optional[str] = None,
        token: Optional[str] = None,
    ) -> None:
        """Constructor for KanidmClient"""

        if config is not None:
            self.config = config

        else:
            self.config = KanidmClientConfig(
                uri=uri,
                verify_hostnames=verify_hostnames,
                verify_certificate=verify_certificate,
                ca_path=ca_path,
                auth_token=token,
            )

            if config_file is not None:
                if not isinstance(config_file, Path):
                    config_file = Path(config_file)
                config_data = load_config(config_file.expanduser().resolve())
                self.config = self.config.model_validate(config_data)

        if self.config.uri is None:
            raise ValueError("Please initialize this with a server URI")

        self._ssl: Optional[Union[bool, ssl.SSLContext]] = None
        self._configure_ssl()

    def _configure_ssl(self) -> None:
        """Sets up SSL configuration for the client"""
        if self.config.verify_certificate is False:
            self._ssl = False
        else:
            if (
                self.config.ca_path is not None
                and not Path(self.config.ca_path).expanduser().resolve().exists()
            ):
                raise FileNotFoundError(f"CA Path not found: {self.config.ca_path}")
            self._ssl = ssl.create_default_context(cafile=self.config.ca_path)
        if self._ssl is not False:
            # ignoring this for typing because mypy is being weird
            # ssl.SSLContext.check_hostname is totally a thing
            # https://docs.python.org/3/library/ssl.html#ssl.SSLContext.check_hostname
            self._ssl.check_hostname = self.config.verify_hostnames  # type: ignore

    def parse_config_data(
        self,
        config_data: Dict[str, Any],
    ) -> None:
        """hand it a config dict and it'll configure the client"""
        try:
            self.config.model_validate(config_data)
        except ValidationError as validation_error:
            # pylint: disable=raise-missing-from
            raise ValueError(f"Failed to validate configuration: {validation_error}")

    async def check_token_valid(self, token: Optional[str] = None) -> bool:
        """checks if a given token is valid, or the local one if you don't pass it"""
        url = "/v1/auth/valid"
        if token is not None:
            headers = {
                "authorization": f"Bearer {token}",
                "content-type": "application/json",
            }
        else:
            headers = None
        result = await self.call_get(url, headers=headers)
        logging.debug(result)
        if result.status_code == 200:
            return True
        return False

    @lru_cache()
    def get_path_uri(self, path: str) -> str:
        """turns a path into a full URI"""
        if path.startswith("/"):
            path = path[1:]
        return f"{self.config.uri}{path}"

    @property
    def _token_headers(self) -> Dict[str, str]:
        """returns an auth header with the token in it"""
        if self.config.auth_token is None:
            raise ValueError("Token is not set")
        return {
            "authorization": f"Bearer {self.config.auth_token}",
            "X-KANIDM-AUTH-SESSION-ID": self.config.auth_token,
        }

    # pylint: disable=too-many-arguments
    async def _call(
        self,
        method: str,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
        json: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> ClientResponse:
        if timeout is None:
            timeout = self.config.connect_timeout
        async with aiohttp.client.ClientSession() as session:
            # if we have a token set, we send it.
            if self.config.auth_token is not None:
                logging.debug("Found a token internally %s", self.config.auth_token)
                if headers is None:
                    logging.debug("Using self._token_headers")
                    headers = self._token_headers
                elif headers.get("authorization") is None:
                    logging.debug("Setting auth headers as authorization not in keys")
                    headers.update(self._token_headers)
                    logging.info("headers: %s", headers)
            logging.debug(
                "_call method=%s to %s, headers=%s",
                method,
                self.get_path_uri(path),
                json_lib.dumps(headers),
            )
            async with session.request(
                method=method,
                url=self.get_path_uri(path),
                headers=headers,
                timeout=timeout,
                json=json,
                params=params,
                ssl=self._ssl,
            ) as request:
                content = await request.content.read()
                try:
                    response_json = json_lib.loads(content)
                    if not isinstance(response_json, dict):
                        response_json = None
                except json_lib.JSONDecodeError as json_error:
                    logging.error("Failed to JSON Decode Response: %s", json_error)
                    logging.error("Response data: %s", content)
                    response_json = {}
                response_input = {
                    "data": response_json,
                    "content": content.decode("utf-8"),
                    "headers": request.headers,
                    "status_code": request.status,
                }
                logging.debug(json_lib.dumps(response_input, default=str, indent=4))
                response = ClientResponse.model_validate(response_input)
            return response

    async def call_get(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None,
    ) -> ClientResponse:
        """does a get call to the server"""
        return await self._call("GET", path, headers, timeout, params=params)

    async def call_post(
        self,
        path: str,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Dict[str, Any]] = None,
        timeout: Optional[int] = None,
    ) -> ClientResponse:
        """does a get call to the server"""

        return await self._call(
            method="POST", path=path, headers=headers, json=json, timeout=timeout
        )

    async def auth_init(
        self, username: str, update_internal_auth_token: bool = False
    ) -> AuthInitResponse:
        """init step, starts the auth session, sets the class-local session ID"""
        init_auth = {"step": {"init": username}}

        response = await self.call_post(
            path=KANIDMURLS["auth"],
            json=init_auth,
        )
        if response.status_code != 200:
            logging.debug(
                "Failed to authenticate, response from server: %s",
                response.content,
            )
            # TODO: mock test auth_init raises AuthInitFailed
            raise AuthInitFailed(response.content)

        if "x-kanidm-auth-session-id" not in response.headers:
            logging.debug("response.content: %s", response.content)
            logging.debug("response.headers: %s", response.headers)
            raise ValueError(
                f"Missing x-kanidm-auth-session-id header in init auth response: {response.headers}"
            )
        else:
            self.config.auth_token = response.headers["x-kanidm-auth-session-id"]

        data = getattr(response, "data", {})
        data["response"] = response
        retval = AuthInitResponse.model_validate(data)
        return retval

    async def auth_begin(
        self,
        method: str,
        sessionid: Optional[str] = None,
        update_internal_auth_token: bool = False,
    ) -> ClientResponse:
        """the 'begin' step"""

        begin_auth = {
            "step": {
                "begin": method,
            },
        }

        if sessionid is not None:
            headers = self.session_header(sessionid)
        else:
            headers = None
        response = await self.call_post(
            KANIDMURLS["auth"],
            json=begin_auth,
            headers=headers,
        )
        if response.status_code != 200:
            # TODO: mock test for auth_begin raises AuthBeginFailed
            raise AuthBeginFailed(response.content)
        if response.data is not None:
            response.data["sessionid"] = response.headers.get(
                "x-kanidm-auth-session-id", ""
            )

        if update_internal_auth_token:
            self.config.auth_token = response.headers.get(
                "x-kanidm-auth-session-id", ""
            )

        logging.debug(json_lib.dumps(response.data, indent=4))

        try:
            retobject = AuthBeginResponse.model_validate(response.data)
        except ValidationError as exc:
            logging.debug(repr(exc.errors()[0]))
            raise exc

        retobject.response = response
        return response

    async def authenticate_password(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> AuthState:
        """authenticates with a username and password, returns the auth token"""
        if username is None and password is None:
            if self.config.username is None or self.config.password is None:
                # pylint: disable=line-too-long
                raise ValueError(
                    "Need username/password to be in caller or class settings before calling authenticate_password"
                )
            username = self.config.username
            password = self.config.password
        if username is None or password is None:
            raise ValueError("Username and Password need to be set somewhere!")

        auth_init: AuthInitResponse = await self.auth_init(username)

        if auth_init.response is None:
            raise NotImplementedError("This should throw a really cool response")

        sessionid = auth_init.response.headers["x-kanidm-auth-session-id"]

        if len(auth_init.state.choose) == 0:
            # there's no mechanisms at all - bail
            # TODO: write test coverage for authenticate_password raises AuthMechUnknown
            raise AuthMechUnknown(f"No auth mechanisms for {username}")
        auth_begin = await self.auth_begin(method="password", sessionid=sessionid)
        # does a little bit of validation
        auth_begin_object = AuthBeginResponse.model_validate(auth_begin.data)
        auth_begin_object.response = auth_begin
        return await self.auth_step_password(password=password, sessionid=sessionid)

    async def auth_step_password(
        self,
        sessionid: str,
        password: Optional[str] = None,
    ) -> AuthState:
        """does the password auth step"""

        if password is None:
            password = self.config.password
        if password is None:
            raise ValueError(
                "Password has to be passed to auth_step_password or in self.password!"
            )

        cred_auth = {"step": {"cred": {"password": password}}}
        response = await self.call_post(path="/v1/auth", json=cred_auth)

        if response.status_code != 200:
            # TODO: write test coverage auth_step_password raises AuthCredFailed
            logging.debug("Failed to authenticate, response: %s", response.content)
            raise AuthCredFailed("Failed password authentication!")

        result = AuthState.model_validate(response.data)
        result.response = response

        # pull the token out and set it
        if result.state.success is None:
            # TODO: write test coverage for AuthCredFailed
            raise AuthCredFailed
        result.sessionid = result.state.success
        return result

    def session_header(
        self,
        sessionid: str,
    ) -> Dict[str, str]:
        """create a headers dict from a session id"""
        # TODO: perhaps allow session_header to take a dict and update it, too?
        return {
            "authorization": f"bearer {sessionid}",
        }

    # TODO: write tests for get_groups
    async def get_radius_token(self, username: str) -> ClientResponse:
        """does the call to the radius token endpoint"""
        path = f"/v1/account/{username}/_radius/_token"
        response = await self.call_get(path)
        if response.status_code == 404:
            raise NoMatchingEntries(
                f"No user found: '{username}' {response.headers['x-kanidm-opid']}"
            )
        return response

    # TODO: write tests for get_groups
    async def get_groups(self) -> List[GroupInfo]:
        """does the call to the group endpoint"""
        path = f"/v1/group"
        response = await self.call_get(path)
        if response.content is None:
            return []
        grouplist = GroupList.model_validate(json_lib.loads(response.content))
        return [group.as_nice_object() for group in grouplist.root]

    async def auth_as_anonymous(self) -> None:
        """authenticate as the anonymous user"""

        init = await self.auth_init("anonymous", update_internal_auth_token=True)
        await self.auth_begin(
            method=init.state.choose[0], update_internal_auth_token=True
        )
        logging.debug(
            "\n\n#######\n\nauth_begin completed, moving onto cred step\n\n#######\n\n"
        )
        cred_auth = {"step": {"cred": "anonymous"}}
        response = await self.call_post(path="/v1/auth", json=cred_auth)
        state = AuthState.model_validate(response.data)
        self.config.auth_token = state.state.success
