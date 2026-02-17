"""Kanidm python module"""

from datetime import datetime
from functools import lru_cache
import json as json_lib  # because we're taking a field "json" at various points
from logging import Logger, getLogger
import logging
import os
from pathlib import Path
import platform
import ssl
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union
from uuid import UUID

from kanidm_openapi_client.api.account_api import AccountApi
from kanidm_openapi_client.api.scim_api import ScimApi
from kanidm_openapi_client.api.system_api import SystemApi
from kanidm_openapi_client.api.auth_api import AuthApi
from kanidm_openapi_client.api.domain_api import DomainApi
from kanidm_openapi_client.api.group_api import GroupApi
from kanidm_openapi_client.api.group_attr_api import GroupAttrApi
from kanidm_openapi_client.api.oauth2_api import Oauth2Api
from kanidm_openapi_client.api.person_api import PersonApi
from kanidm_openapi_client.api.person_credential_api import PersonCredentialApi
from kanidm_openapi_client.api.person_ssh_pubkeys_api import PersonSshPubkeysApi
from kanidm_openapi_client.api.service_account_api import ServiceAccountApi
from kanidm_openapi_client.exceptions import ApiException as OpenApiException
from kanidm_openapi_client.models.auth_credential import AuthCredential
from kanidm_openapi_client.models.auth_credential_one_of import AuthCredentialOneOf
from kanidm_openapi_client.models.auth_mech import AuthMech
from kanidm_openapi_client.models.auth_request import AuthRequest
from kanidm_openapi_client.models.auth_step import AuthStep
from kanidm_openapi_client.models.auth_step_one_of import AuthStepOneOf
from kanidm_openapi_client.models.auth_step_one_of2 import AuthStepOneOf2
from kanidm_openapi_client.models.auth_step_one_of3 import AuthStepOneOf3
from kanidm_openapi_client.models.api_token_generate import ApiTokenGenerate
from kanidm_openapi_client.models.entry import Entry as OpenApiEntry
from pydantic import ValidationError
import yarl

from kanidm.models.group import Group, GroupList, RawGroup
from kanidm.models.oauth2_rs import OAuth2Rs, Oauth2RsList, RawOAuth2Rs
from kanidm.models.person import (
    Person,
    PersonList,
    RawPerson,
    PersonCredentialResetToken,
)
from kanidm.models.service_account import (
    ServiceAccount,
    RawServiceAccount,
    ServiceAccountList,
)

from .exceptions import (
    AuthBeginFailed,
    AuthCredFailed,
    AuthInitFailed,
    AuthMechUnknown,
    NoMatchingEntries,
)
from .openapi import ApiClient as OpenApiClient
from .openapi import openapi_client_from_client_config
from .types import (
    AuthBeginResponse,
    AuthInitResponse,
    AuthState,
    ClientResponse,
    KanidmClientConfig,
)
from .utils import load_config

if TYPE_CHECKING:
    from kanidm_openapi_client.models.scim_entry import ScimEntry as OpenApiScimEntry
    from kanidm_openapi_client.models.scim_list_response import ScimListResponse as OpenApiScimListResponse

K_AUTH_SESSION_ID = "x-kanidm-auth-session-id"

XDG_CACHE_HOME = (
    Path(os.getenv("LOCALAPPDATA", "~/AppData/Local")) / "cache" if platform.system() == "Windows" else Path(os.getenv("XDG_CACHE_HOME", "~/.cache"))
)

TOKEN_PATH = XDG_CACHE_HOME / "kanidm_tokens"


class KanidmClient:
    """Kanidm client module

    config: a `KanidmClientConfig` object, if this is set, everything else is ignored
    config_file: a `pathlib.Path` object pointing to a configuration file
    uri: kanidm base URL
    session: a `aiohttp.client.ClientSession`
    verify_hostnames: verify the hostname is correct
    verify_certificate: verify the validity of the certificate and its CA
    ca_path: set this to a trusted CA certificate (PEM format)
    token: a JWS from an authentication session or the API token for a service-account (note: in case of an API token, no auth* functions need to be used)
    openapi_client: OpenAPI-generated client instance
    """

    # pylint: disable=too-many-instance-attributes,too-many-arguments
    def __init__(
        self,
        instance_name: Optional[str] = None,
        config: Optional[KanidmClientConfig] = None,
        config_file: Optional[Union[Path, str]] = None,
        uri: Optional[str] = None,
        verify_hostnames: bool = True,
        verify_certificate: bool = True,
        verify_ca: bool = True,
        ca_path: Optional[str] = None,
        token: Optional[str] = None,
        logger: Optional[Logger] = None,
    ) -> None:
        """Constructor for KanidmClient"""

        self.logger = logger or getLogger(__name__)
        self.instance_name = instance_name  # TODO: use this in loaders etc
        if config is not None:
            self.config = config
        else:
            self.config = KanidmClientConfig.model_validate(
                {
                    "uri": uri,
                    "verify_hostnames": verify_hostnames,
                    "verify_certificate": verify_certificate,
                    "verify_ca": verify_ca,
                    "ca_path": ca_path,
                    "auth_token": token,
                }
            )
            self.logger.debug(self.config)

            if config_file is not None:
                if not isinstance(config_file, Path):
                    config_file = Path(config_file)
                config_data = load_config(config_file.expanduser().resolve())
                self.config = self.config.model_validate(config_data)

        if self.config.uri is None:
            raise ValueError("Please initialize this with a server URI")

        self._ssl_context: Optional[Union[bool, ssl.SSLContext]] = None
        self._configure_ssl()
        self.openapi_client: OpenApiClient = openapi_client_from_client_config(self.config)

    def _sync_openapi_access_token(self) -> None:
        """Keep the generated OpenAPI client auth token in sync with this client."""
        self.openapi_client.configuration.access_token = self.config.auth_token

    def _set_auth_token(self, token: Optional[str]) -> None:
        self.config.auth_token = token
        self._sync_openapi_access_token()

    def _configure_ssl(self) -> None:
        """Sets up SSL configuration for the client"""
        if False in [self.config.verify_certificate, self.config.verify_hostnames]:
            logging.debug("Setting up SSL context with no verification")
            self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
            self._ssl_context.hostname_checks_common_name = False
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE
        else:
            if self.config.ca_path is not None:
                if not Path(self.config.ca_path).expanduser().resolve().exists():
                    raise FileNotFoundError(f"CA Path not found: {self.config.ca_path}")
                else:
                    self.logger.debug("Setting up SSL context with CA path=%s", self.config.ca_path)
                    self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=self.config.ca_path)
            else:
                logging.debug("Setting up default SSL context")
                self._ssl_context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

            logging.debug("SSL context verify_hostnames=%s", self.config.verify_hostnames)
            self._ssl_context.check_hostname = self.config.verify_hostnames

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
        request_auth = None
        if token is not None:
            request_auth = {
                "type": "bearer",
                "in": "header",
                "format": "JWT",
                "key": "Authorization",
                "value": f"Bearer {token}",
            }
        else:
            self._sync_openapi_access_token()
        try:
            response = await AuthApi(self.openapi_client).auth_valid_with_http_info(_request_auth=request_auth)
            return response.status_code == 200
        except OpenApiException as error:
            self.logger.debug("Token validation failed via OpenAPI client: %s", error)
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
        }

    async def _auth_post_compat(self, auth_request: AuthRequest, headers: Optional[Dict[str, str]] = None) -> ClientResponse[Any]:
        """POST /v1/auth via OpenAPI without model deserialization."""
        response = await AuthApi(self.openapi_client).auth_post_without_preload_content(
            auth_request,
            _headers=headers,
        )

        raw_data = await response.read()
        raw_content = raw_data.decode("utf-8", errors="replace") if raw_data else None
        response_data: Optional[Dict[str, Any]] = {}
        if raw_data:
            try:
                decoded = json_lib.loads(raw_data)
                response_data = decoded if isinstance(decoded, dict) else {}
            except json_lib.JSONDecodeError:
                response_data = None

        return ClientResponse[Any](
            content=raw_content,
            data=response_data,
            headers=dict(response.headers),
            status_code=response.status,
        )

    @staticmethod
    def _normalise_openapi_data(data: Any) -> Any:
        if isinstance(data, list):
            return [KanidmClient._normalise_openapi_data(item) for item in data]
        if isinstance(data, tuple):
            return tuple(KanidmClient._normalise_openapi_data(item) for item in data)
        if isinstance(data, dict):
            return {key: KanidmClient._normalise_openapi_data(value) for key, value in data.items()}
        if hasattr(data, "to_dict") and callable(getattr(data, "to_dict")):
            return KanidmClient._normalise_openapi_data(data.to_dict())
        return data

    @classmethod
    def _openapi_response_to_client_response(cls, response: Any) -> ClientResponse[Any]:
        raw_data = getattr(response, "raw_data", b"")
        return ClientResponse[Any](
            content=raw_data.decode("utf-8", errors="replace") if raw_data else None,
            data=cls._normalise_openapi_data(getattr(response, "data", None)),
            headers=dict(getattr(response, "headers", {}) or {}),
            status_code=int(getattr(response, "status_code", -1)),
        )

    @classmethod
    def _openapi_exception_to_client_response(cls, error: OpenApiException) -> ClientResponse[Any]:
        return ClientResponse[Any](
            content=error.body,
            data=cls._normalise_openapi_data(getattr(error, "data", None)),
            headers=dict(getattr(error, "headers", {}) or {}),
            status_code=int(error.status) if error.status is not None else -1,
        )

    async def _openapi_call_to_client_response(self, call: Any) -> ClientResponse[Any]:
        try:
            return self._openapi_response_to_client_response(await call)
        except OpenApiException as error:
            return self._openapi_exception_to_client_response(error)

    @staticmethod
    def _header_value(headers: Dict[str, Any], header_name: str) -> Optional[str]:
        return next((str(value) for key, value in headers.items() if key.lower() == header_name.lower()), None)

    async def auth_init(self, username: str, update_internal_auth_token: bool = False) -> AuthInitResponse:
        """init step, starts the auth session, sets the class-local session ID"""
        self.logger.debug("auth_init called")

        init_auth = AuthRequest(step=AuthStep(AuthStepOneOf(init=username)))
        try:
            response = await AuthApi(self.openapi_client).auth_post_with_http_info(init_auth)
        except OpenApiException as error:
            self.logger.debug("Failed to authenticate via OpenAPI client: %s", error)
            # TODO: mock test auth_init raises AuthInitFailed
            raise AuthInitFailed(str(error)) from error

        if response.status_code != 200:
            raw_content = response.raw_data.decode("utf-8", errors="replace") if response.raw_data else None
            self.logger.debug("Failed to authenticate, response from server: %s", raw_content)
            # TODO: mock test auth_init raises AuthInitFailed
            raise AuthInitFailed(raw_content)

        response_headers: Dict[str, Any] = dict(response.headers or {})
        header_sessionid = next((value for key, value in response_headers.items() if key.lower() == K_AUTH_SESSION_ID), None)
        payload_sessionid = str(response.data.sessionid)
        sessionid = header_sessionid or payload_sessionid
        response_headers.setdefault(K_AUTH_SESSION_ID, sessionid)

        self._set_auth_token(sessionid)

        data = response.data.to_dict()
        data["sessionid"] = sessionid
        raw_content = response.raw_data.decode("utf-8", errors="replace") if response.raw_data else None
        typed_response = ClientResponse[Any](
            content=raw_content,
            data=data,
            headers=response_headers,
            status_code=response.status_code,
        )
        data["response"] = typed_response.model_dump()
        retval = AuthInitResponse.model_validate(data)

        if update_internal_auth_token:
            self._set_auth_token(sessionid)
        return retval

    async def auth_begin(
        self,
        method: str,
        sessionid: Optional[str] = None,
        update_internal_auth_token: bool = False,
    ) -> ClientResponse[Any]:
        """the 'begin' step"""
        headers: Optional[Dict[str, str]] = None
        if sessionid is not None:
            headers = {K_AUTH_SESSION_ID: sessionid}
        elif self.config.auth_token is not None:
            headers = {K_AUTH_SESSION_ID: self.config.auth_token}

        try:
            begin_auth = AuthRequest(step=AuthStep(AuthStepOneOf2(begin=AuthMech(method))))
            response = await self._auth_post_compat(begin_auth, headers=headers)
        except (OpenApiException, ValueError) as error:
            raise AuthBeginFailed(str(error)) from error

        if response.status_code != 200:
            raise AuthBeginFailed(response.content)

        response_headers: Dict[str, Any] = dict(response.headers or {})
        header_sessionid = next((value for key, value in response_headers.items() if key.lower() == K_AUTH_SESSION_ID), None)
        data = dict(response.data or {})
        payload_sessionid = data.get("sessionid")
        resolved_sessionid = header_sessionid or payload_sessionid or ""
        if resolved_sessionid:
            response_headers.setdefault(K_AUTH_SESSION_ID, resolved_sessionid)

        if update_internal_auth_token and resolved_sessionid:
            self._set_auth_token(resolved_sessionid)

        data["sessionid"] = resolved_sessionid
        typed_response = ClientResponse[Any](
            content=response.content,
            data=data,
            headers=response_headers,
            status_code=response.status_code,
        )

        self.logger.debug(json_lib.dumps(data, indent=4))

        try:
            retobject = AuthBeginResponse.model_validate(data)
        except ValidationError as exc:
            self.logger.debug(repr(exc.errors()[0]))
            raise exc

        retobject.response = typed_response
        return typed_response

    async def authenticate_password(
        self,
        username: Optional[str] = None,
        password: Optional[str] = None,
        update_internal_auth_token: bool = False,
    ) -> AuthState:
        """authenticates with a username and password, returns the auth token"""
        if username is None and password is None:
            if self.config.username is None or self.config.password is None:
                # pylint: disable=line-too-long
                raise ValueError("Need username/password to be in caller or class settings before calling authenticate_password")
            username = self.config.username
            password = self.config.password
        if username is None or password is None:
            raise ValueError("Username and Password need to be set somewhere!")

        auth_init: AuthInitResponse = await self.auth_init(username, update_internal_auth_token=update_internal_auth_token)

        if auth_init.response is None:
            raise NotImplementedError("This should throw a really cool response")

        sessionid = auth_init.response.headers[K_AUTH_SESSION_ID]

        if len(auth_init.state.choose) == 0:
            # there's no mechanisms at all - bail
            # TODO: write test coverage for authenticate_password raises AuthMechUnknown
            raise AuthMechUnknown(f"No auth mechanisms for {username}")
        auth_begin = await self.auth_begin(method="password", sessionid=sessionid)
        # does a little bit of validation
        auth_begin_object = AuthBeginResponse.model_validate(auth_begin.data)
        auth_begin_object.response = auth_begin
        return await self.auth_step_password(
            password=password,
            sessionid=sessionid,
            update_internal_auth_token=update_internal_auth_token,
        )

    async def auth_step_password(
        self,
        sessionid: Optional[str] = None,
        password: Optional[str] = None,
        update_internal_auth_token: bool = False,
    ) -> AuthState:
        """does the password auth step"""
        self.logger.debug("auth_step_password called")
        if password is None:
            password = self.config.password
        if password is None:
            raise ValueError("Password has to be passed to auth_step_password or in self.password!")

        headers: Optional[Dict[str, str]] = None
        if sessionid is not None:
            headers = {K_AUTH_SESSION_ID: sessionid}
        elif self.config.auth_token is not None:
            headers = {K_AUTH_SESSION_ID: self.config.auth_token}

        try:
            cred_auth = AuthRequest(
                step=AuthStep(
                    AuthStepOneOf3(
                        cred=AuthCredential(AuthCredentialOneOf(password=password)),
                    )
                )
            )
            response = await self._auth_post_compat(cred_auth, headers=headers)
        except (OpenApiException, ValueError) as error:
            raise AuthCredFailed(str(error)) from error

        if response.status_code != 200:
            # TODO: write test coverage auth_step_password raises AuthCredFailed
            self.logger.debug("Failed to authenticate, response: %s", response.content)
            raise AuthCredFailed("Failed password authentication!")

        response_headers: Dict[str, Any] = dict(response.headers or {})
        header_sessionid = next((value for key, value in response_headers.items() if key.lower() == K_AUTH_SESSION_ID), None)
        data = dict(response.data or {})
        payload_sessionid = data.get("sessionid")
        data["sessionid"] = header_sessionid or (str(payload_sessionid) if payload_sessionid is not None else None)
        typed_response = ClientResponse[Any](
            content=response.content,
            data=data,
            headers=response_headers,
            status_code=response.status_code,
        )

        result = AuthState.model_validate(data)
        result.response = typed_response

        if result.state is None:
            raise AuthCredFailed
        if update_internal_auth_token:
            self._set_auth_token(result.state.success)

        # pull the token out and set it
        if result.state.success is None:
            # TODO: write test coverage for AuthCredFailed
            raise AuthCredFailed
        result.sessionid = result.state.success
        return result

    async def auth_as_anonymous(self) -> None:
        """Authenticate as the anonymous user"""

        auth_init = await self.auth_init("anonymous", update_internal_auth_token=True)

        await self.auth_begin(
            method=auth_init.state.choose[0],
            update_internal_auth_token=True,
        )

        if self.config.auth_token is None:
            raise AuthBeginFailed
        headers = {K_AUTH_SESSION_ID: self.config.auth_token}

        try:
            cred_auth = AuthRequest(
                step=AuthStep(
                    AuthStepOneOf3(
                        cred=AuthCredential("anonymous"),
                    )
                )
            )
            response = await self._auth_post_compat(cred_auth, headers=headers)
        except (OpenApiException, ValueError) as error:
            raise AuthCredFailed(str(error)) from error

        if response.status_code != 200:
            self.logger.debug("Failed to authenticate anonymous user, response: %s", response.content)
            raise AuthCredFailed("Failed anonymous authentication!")

        state = AuthState.model_validate(response.data)
        self.logger.debug("anonymous auth completed, setting token")
        if state.state is None:
            raise AuthCredFailed
        if state.state.success is None:
            raise AuthCredFailed
        self._set_auth_token(state.state.success)

    # TODO: write tests for get_groups
    async def get_radius_token(self, username: str) -> ClientResponse[Any]:
        """does the call to the radius token endpoint"""
        response = await self._openapi_call_to_client_response(AccountApi(self.openapi_client).account_id_radius_token_get_with_http_info(username))
        if response.status_code == 404:
            opid = self._header_value(response.headers, "x-kanidm-opid") or ""
            raise NoMatchingEntries(f"No user found: '{username}' {opid}")
        return response

    async def status(self) -> bool:
        """Return server health status."""
        return await SystemApi(self.openapi_client).status()

    async def scim_application_list(self) -> "OpenApiScimListResponse":
        """List SCIM applications."""
        return await ScimApi(self.openapi_client).scim_application_get()

    async def scim_application_get(self, entry_id: str) -> "OpenApiScimEntry":
        """Get a single SCIM application by id."""
        return await ScimApi(self.openapi_client).scim_application_id_get(entry_id)

    async def scim_entry_list(self) -> "OpenApiScimListResponse":
        """List SCIM entries."""
        return await ScimApi(self.openapi_client).scim_entry_get()

    async def scim_class_list(self) -> "OpenApiScimListResponse":
        """List SCIM classes."""
        return await ScimApi(self.openapi_client).scim_schema_class_get()

    async def scim_attribute_list(self) -> "OpenApiScimListResponse":
        """List SCIM attributes."""
        return await ScimApi(self.openapi_client).scim_schema_attribute_get()

    async def scim_message_list(self) -> "OpenApiScimListResponse":
        """List SCIM messages."""
        return await ScimApi(self.openapi_client).scim_message_get()

    async def scim_message_ready_list(self) -> "OpenApiScimListResponse":
        """List ready SCIM messages."""
        return await ScimApi(self.openapi_client).scim_message_ready_get()

    async def oauth2_rs_list(self) -> List[OAuth2Rs]:
        """gets the list of oauth2 resource servers"""
        try:
            entries = await Oauth2Api(self.openapi_client).oauth2_get()
        except OpenApiException as error:
            raise ValueError(f"Failed to get oauth2 resource servers: {error.body or error}") from error
        if not entries:
            return []
        oauth2_rs_list = Oauth2RsList.model_validate([entry.to_dict() for entry in entries])
        return [oauth2_rs.as_oauth2_rs for oauth2_rs in oauth2_rs_list.root]

    async def oauth2_rs_get(self, rs_name: str) -> OAuth2Rs:
        """get an OAuth2 client"""
        try:
            response = await Oauth2Api(self.openapi_client).oauth2_id_get(rs_name)
        except OpenApiException as error:
            raise ValueError(f"Failed to get oauth2 resource server: {error.body or error}") from error
        return RawOAuth2Rs.model_validate(response.to_dict()).as_oauth2_rs

    async def oauth2_rs_secret_get(self, rs_name: str) -> str:
        """get an OAuth2 client secret"""
        try:
            return await Oauth2Api(self.openapi_client).oauth2_id_get_basic_secret(rs_name)
        except OpenApiException as error:
            raise ValueError(f"Failed to get oauth2 resource server secret: {error.body or error}") from error

    async def oauth2_rs_delete(self, rs_name: str) -> ClientResponse[None]:
        """delete an oauth2 resource server"""
        return await self._openapi_call_to_client_response(Oauth2Api(self.openapi_client).oauth2_id_delete_with_http_info(rs_name))

    async def oauth2_rs_basic_create(self, rs_name: str, displayname: str, origin: str) -> ClientResponse[None]:
        """Create a basic OAuth2 RS"""

        self._validate_is_valid_origin_url(origin)

        payload = OpenApiEntry(
            attrs={
                "oauth2_rs_name": [rs_name],
                "oauth2_rs_origin": [origin],
                "displayname": [displayname],
            }
        )
        return await self._openapi_call_to_client_response(Oauth2Api(self.openapi_client).oauth2_basic_post_with_http_info(payload))

    @classmethod
    def _validate_is_valid_origin_url(cls, url: str) -> None:
        """Check if it's HTTPS and a valid URL as far as we can tell"""
        parsed_url = yarl.URL(url)
        if parsed_url.scheme not in ["http", "https"]:
            raise ValueError(f"Invalid scheme: {parsed_url.scheme} for origin URL: {url}")
        if parsed_url.host is None:
            raise ValueError(f"Empty/invalid host for origin URL: {url}")
        if parsed_url.user is not None:
            raise ValueError(f"Can't have username in origin URL: {url}")
        if parsed_url.password is not None:
            raise ValueError(f"Can't have password in origin URL: {url}")

    async def service_account_list(self) -> List[ServiceAccount]:
        """List service accounts"""
        try:
            entries = await ServiceAccountApi(self.openapi_client).service_account_get()
        except OpenApiException as error:
            raise ValueError(f"Failed to get service accounts: {error.body or error}") from error
        if not entries:
            return []
        service_account_list = ServiceAccountList.model_validate([entry.to_dict() for entry in entries])
        return [service_account.as_service_account for service_account in service_account_list.root]

    async def service_account_get(self, name: str) -> ServiceAccount:
        """Get a service account"""
        try:
            response = await ServiceAccountApi(self.openapi_client).service_account_id_get(name)
        except OpenApiException as error:
            raise ValueError(f"Failed to get service account: {error.body or error}") from error
        return RawServiceAccount.model_validate(response.to_dict()).as_service_account

    async def service_account_create(self, name: str, displayname: str) -> ClientResponse[None]:
        """Create a service account"""
        payload = OpenApiEntry(
            attrs={
                "name": [name],
                "displayname": [
                    displayname,
                ],
            }
        )
        return await self._openapi_call_to_client_response(ServiceAccountApi(self.openapi_client).service_account_post_with_http_info(payload))

    async def service_account_delete(self, name: str) -> ClientResponse[None]:
        """Create a service account"""
        return await self._openapi_call_to_client_response(ServiceAccountApi(self.openapi_client).service_account_id_delete_with_http_info(name))

    async def service_account_post_ssh_pubkey(
        self,
        id: str,
        tag: str,
        pubkey: str,
    ) -> ClientResponse[None]:
        payload = [tag, pubkey]
        return await self._openapi_call_to_client_response(
            ServiceAccountApi(self.openapi_client).service_account_id_ssh_pubkeys_post_with_http_info(id=id, request_body=payload)
        )

    async def service_account_delete_ssh_pubkey(self, id: str, tag: str) -> ClientResponse[None]:
        return await self._openapi_call_to_client_response(
            ServiceAccountApi(self.openapi_client).service_account_id_ssh_pubkeys_tag_delete_with_http_info(tag=tag, id=id)
        )

    async def service_account_generate_api_token(self, account_id: str, label: str, expiry: str, read_write: bool = False) -> ClientResponse[None]:
        """Create a service account API token, expiry needs to be in RFC3339 format."""

        # parse the expiry as rfc3339
        try:
            parsed_expiry = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ")
        except Exception as error:
            raise ValueError(f"Failed to parse expiry from {expiry} (needs to be RFC3339 format): {error}")
        payload = ApiTokenGenerate(label=label, expiry=parsed_expiry, read_write=read_write)
        return await self._openapi_call_to_client_response(
            ServiceAccountApi(self.openapi_client).service_account_api_token_post_with_http_info(id=account_id, api_token_generate=payload)
        )

    async def service_account_destroy_api_token(
        self,
        id: str,
        token_id: str,
    ) -> ClientResponse[None]:
        token_uuid = UUID(token_id)
        return await self._openapi_call_to_client_response(
            ServiceAccountApi(self.openapi_client).service_account_api_token_delete_with_http_info(id=id, token_id=token_uuid)
        )

    async def get_groups(self) -> List[Group]:
        """Lists all groups"""
        # For compatibility reasons
        # TODO: delete this method
        return await self.group_list()

    # TODO: write tests for get_groups
    # Renamed to keep it consistent with the rest of the Client
    async def group_list(self) -> List[Group]:
        """does the call to the group endpoint"""
        try:
            entries = await GroupApi(self.openapi_client).group_get()
        except OpenApiException as error:
            raise ValueError(f"Failed to get groups: {error.body or error}") from error
        if not entries:
            return []
        grouplist = GroupList.model_validate([entry.to_dict() for entry in entries])
        return [group.as_group for group in grouplist.root]

    async def group_get(self, name: str) -> Group:
        """Get a group"""
        try:
            response = await GroupApi(self.openapi_client).group_id_get(name)
        except OpenApiException as error:
            raise ValueError(f"Failed to get group: {error.body or error}") from error
        return RawGroup.model_validate(response.to_dict()).as_group

    async def group_create(self, name: str) -> ClientResponse[None]:
        """Create a group"""
        payload = OpenApiEntry(attrs={"name": [name]})
        return await self._openapi_call_to_client_response(GroupApi(self.openapi_client).group_post_with_http_info(payload))

    async def group_delete(self, name: str) -> ClientResponse[None]:
        """Delete a group"""
        return await self._openapi_call_to_client_response(GroupApi(self.openapi_client).group_id_delete_with_http_info(name))

    async def group_set_members(self, id: str, members: List[str]) -> ClientResponse[None]:
        """Set group member list"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_put_with_http_info(id=id, attr="member", request_body=members)
        )

    async def group_add_members(self, id: str, members: List[str]) -> ClientResponse[None]:
        """Add members to a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_post_with_http_info(id=id, attr="member", request_body=members)
        )

    async def group_delete_members(self, id: str, members: List[str]) -> ClientResponse[None]:
        """Remove members from a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_delete_with_http_info(id=id, attr="member", request_body=members)
        )

    async def person_account_list(self) -> List[Person]:
        """List all people"""
        try:
            entries = await PersonApi(self.openapi_client).person_get()
        except OpenApiException as error:
            raise ValueError(f"Failed to get people: {error.body or error}") from error
        if not entries:
            return []
        personlist = PersonList.model_validate([entry.to_dict() for entry in entries])
        return [person.as_person for person in personlist.root]

    async def person_account_get(self, name: str) -> Person:
        """Get a person by name"""
        try:
            response = await PersonApi(self.openapi_client).person_id_get(name)
        except OpenApiException as error:
            raise ValueError(f"Failed to get person: {error.body or error}") from error
        return RawPerson.model_validate(response.to_dict()).as_person

    async def person_account_create(self, name: str, displayname: str) -> ClientResponse[None]:
        """Create a person account"""
        payload = OpenApiEntry(
            attrs={
                "name": [name],
                "displayname": [displayname],
            }
        )
        return await self._openapi_call_to_client_response(PersonApi(self.openapi_client).person_post_with_http_info(payload))

    async def person_account_update(
        self,
        id: str,
        newname: Optional[str] = None,
        displayname: Optional[str] = None,
        legalname: Optional[str] = None,
        mail: Optional[List[str]] = None,
    ) -> ClientResponse[None]:
        """Update details of a person"""
        attrs = {}
        if newname is not None:
            attrs["name"] = [newname]
        if displayname is not None:
            attrs["displayname"] = [displayname]
        if legalname is not None:
            attrs["legalname"] = [legalname]
        if mail is not None:
            attrs["mail"] = mail

        if not attrs:
            raise ValueError("You need to specify something to update!")
        payload = OpenApiEntry(attrs=attrs)
        return await self._openapi_call_to_client_response(PersonApi(self.openapi_client).person_id_patch_with_http_info(id=id, entry=payload))

    async def person_account_delete(self, id: str) -> ClientResponse[None]:
        """Delete a person"""
        return await self._openapi_call_to_client_response(PersonApi(self.openapi_client).person_id_delete_with_http_info(id))

    async def person_account_credential_update_token(self, id: str, ttl: Optional[int] = None) -> PersonCredentialResetToken:
        """Create a password reset token for person with an optional time to live in seconds"""
        if ttl is None:
            response = await self._openapi_call_to_client_response(
                PersonCredentialApi(self.openapi_client).person_id_credential_update_intent_get_with_http_info(id)
            )
        else:
            response = await self._openapi_call_to_client_response(
                PersonCredentialApi(self.openapi_client).person_id_credential_update_intent_ttl_get_with_http_info(ttl=ttl, id=id)
            )
        if response.status_code != 200 or response.content is None:
            raise ValueError(f"Failed to get token: {response.content}")
        token = PersonCredentialResetToken.model_validate(json_lib.loads(response.content))

        return token

    async def person_account_post_ssh_key(self, id: str, tag: str, pubkey: str) -> ClientResponse[None]:
        """Create an SSH key for a user"""
        payload = [tag, pubkey]
        return await self._openapi_call_to_client_response(
            PersonSshPubkeysApi(self.openapi_client).person_id_ssh_pubkeys_post_with_http_info(id=id, request_body=payload)
        )

    async def person_account_delete_ssh_key(self, id: str, tag: str) -> ClientResponse[None]:
        """Delete an SSH key for a user"""
        return await self._openapi_call_to_client_response(
            PersonSshPubkeysApi(self.openapi_client).person_id_ssh_pubkeys_tag_delete_with_http_info(tag=tag, id=id)
        )

    async def group_account_policy_enable(self, id: str) -> ClientResponse[None]:
        """Enable account policy for a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_post_with_http_info(
                id=id,
                attr="class",
                request_body=["account_policy"],
            )
        )

    async def group_account_policy_authsession_expiry_set(
        self,
        id: str,
        expiry: int,
    ) -> ClientResponse[None]:
        """set the account policy authenticated session expiry length (seconds) for a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_put_with_http_info(
                id=id,
                attr="authsession_expiry",
                request_body=[str(expiry)],
            )
        )

    async def group_account_policy_password_minimum_length_set(self, id: str, minimum_length: int) -> ClientResponse[None]:
        """set the account policy password minimum length for a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_put_with_http_info(
                id=id,
                attr="auth_password_minimum_length",
                request_body=[str(minimum_length)],
            )
        )

    async def group_account_policy_privilege_expiry_set(self, id: str, expiry: int) -> ClientResponse[None]:
        """set the account policy privilege expiry for a group"""
        return await self._openapi_call_to_client_response(
            GroupAttrApi(self.openapi_client).group_id_attr_put_with_http_info(
                id=id,
                attr="privilege_expiry",
                request_body=[str(expiry)],
            )
        )

    async def system_password_badlist_get(self) -> List[str]:
        """Get the password badlist"""
        try:
            badlist = await SystemApi(self.openapi_client).system_attr_get("badlist_password")
        except OpenApiException:
            return []
        if badlist is None:
            return []
        return badlist

    async def system_password_badlist_append(self, new_passwords: List[str]) -> ClientResponse[None]:
        """Add new items to the password badlist"""
        return await self._openapi_call_to_client_response(
            SystemApi(self.openapi_client).system_attr_post_with_http_info(attr="badlist_password", request_body=new_passwords)
        )

    async def system_password_badlist_remove(self, items: List[str]) -> ClientResponse[None]:
        """Remove items from the password badlist"""
        return await self._openapi_call_to_client_response(
            SystemApi(self.openapi_client).system_attr_delete_with_http_info(attr="badlist_password", request_body=items)
        )

    async def system_denied_names_get(self) -> List[str]:
        """Get the denied names list"""
        try:
            response = await SystemApi(self.openapi_client).system_attr_get("denied_name")
        except OpenApiException:
            return []
        if response is None:
            return []
        return response

    async def system_denied_names_append(self, names: List[str]) -> ClientResponse[None]:
        """Add items to the denied names list"""
        return await self._openapi_call_to_client_response(
            SystemApi(self.openapi_client).system_attr_post_with_http_info(attr="denied_name", request_body=names)
        )

    async def system_denied_names_remove(self, names: List[str]) -> ClientResponse[None]:
        """Remove items from the denied names list"""
        return await self._openapi_call_to_client_response(
            SystemApi(self.openapi_client).system_attr_delete_with_http_info(attr="denied_name", request_body=names)
        )

    async def domain_set_display_name(
        self,
        new_display_name: str,
    ) -> ClientResponse[None]:
        """Set the Domain Display Name - this requires admin privs"""
        return await self._openapi_call_to_client_response(
            DomainApi(self.openapi_client).domain_attr_put_with_http_info(
                attr="domain_display_name",
                request_body=[new_display_name],
            )
        )

    async def domain_set_ldap_basedn(self, new_basedn: str) -> ClientResponse[None]:
        """Set the domain LDAP base DN."""
        return await self._openapi_call_to_client_response(
            DomainApi(self.openapi_client).domain_attr_put_with_http_info(
                attr="domain_ldap_basedn",
                request_body=[new_basedn],
            )
        )

    async def oauth2_rs_get_basic_secret(self, rs_name: str) -> ClientResponse[Any]:
        """get the basic secret for an OAuth2 resource server"""
        return await self._openapi_call_to_client_response(Oauth2Api(self.openapi_client).oauth2_id_get_basic_secret_with_http_info(rs_name))

    async def oauth2_rs_update(
        self,
        id: str,
        name: Optional[str] = None,
        displayname: Optional[str] = None,
        origin: Optional[str] = None,
        landing: Optional[str] = None,
        reset_secret: bool = False,
        reset_token_key: bool = False,
        reset_sign_key: bool = False,
    ) -> ClientResponse[None]:
        """Update an OAuth2 Resource Server"""

        attrs = {}

        if name is not None:
            attrs["name"] = [name]
        if displayname is not None:
            attrs["displayname"] = [displayname]
        if origin is not None:
            attrs["oauth2_rs_origin"] = [origin]
        if landing is not None:
            attrs["oauth2_rs_landing"] = [landing]
        if reset_secret:
            attrs["oauth2_rs_basic_secret"] = []
        if reset_token_key:
            attrs["oauth2_rs_token_key"] = []
        if reset_sign_key:
            attrs["es256_private_key_der"] = []
            attrs["rs256_private_key_der"] = []

        if not attrs:
            raise ValueError("You need to set something to change!")
        payload = OpenApiEntry(attrs=attrs)
        return await self._openapi_call_to_client_response(Oauth2Api(self.openapi_client).oauth2_id_patch_with_http_info(rs_name=id, entry=payload))

    async def oauth2_rs_update_scope_map(self, id: str, group: str, scopes: List[str]) -> ClientResponse[None]:
        """Update an OAuth2 scope map"""
        return await self._openapi_call_to_client_response(
            Oauth2Api(self.openapi_client).oauth2_id_scopemap_post_with_http_info(
                rs_name=id,
                group=group,
                request_body=scopes,
            )
        )

    async def oauth2_rs_delete_scope_map(
        self,
        id: str,
        group: str,
    ) -> ClientResponse[None]:
        """Delete an OAuth2 scope map"""
        return await self._openapi_call_to_client_response(
            Oauth2Api(self.openapi_client).oauth2_id_scopemap_delete_with_http_info(rs_name=id, group=group)
        )

    async def oauth2_rs_update_sup_scope_map(self, id: str, group: str, scopes: List[str]) -> ClientResponse[None]:
        """Update an OAuth2 supplemental scope map"""
        return await self._openapi_call_to_client_response(
            Oauth2Api(self.openapi_client).oauth2_id_sup_scopemap_post_with_http_info(
                rs_name=id,
                group=group,
                request_body=scopes,
            )
        )

    async def oauth2_rs_delete_sup_scope_map(
        self,
        id: str,
        group: str,
    ) -> ClientResponse[None]:
        """Delete an OAuth2 supplemental scope map"""
        return await self._openapi_call_to_client_response(
            Oauth2Api(self.openapi_client).oauth2_id_sup_scopemap_delete_with_http_info(rs_name=id, group=group)
        )
