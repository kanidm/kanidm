""" type objects """
# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from ipaddress import IPv4Address, IPv6Address, IPv6Network, IPv4Network
import socket
from typing import Any, Dict, List, Optional, Generic, TypeVar
from urllib.parse import urlparse

from pydantic import field_validator, ConfigDict, BaseModel, Field
import toml

from kanidm.models.group import Group as GroupInfo, RawGroup as RawGroupInfo, GroupList  # noqa


T = TypeVar("T", Dict[str, Any], None)


class ClientResponse(BaseModel, Generic[T]):
    """response from an API call, includes the following fields:
    content: Optional[str]
    data: Optional[Dict[str, Any]]
    headers: Dict[str, Any]
    status_code: int
    """

    content: Optional[str] = None
    # the data field is used for the json-parsed response
    data: Optional[T] = None
    headers: Dict[str, Any]
    status_code: int
    model_config = ConfigDict(arbitrary_types_allowed=True)


class AuthInitResponse(BaseModel):
    """Aelps parse the response from the Auth 'init' stage"""

    class _AuthInitState(BaseModel):
        """sub-class for the AuthInitResponse model"""

        # TODO: can we add validation for AuthInitResponse.state.choose?
        choose: List[str]

    sessionid: str
    state: _AuthInitState
    response: Optional[ClientResponse] = None
    # model_config = ConfigDict(arbitrary_types_allowed=True)


class AuthBeginResponse(BaseModel):
    """Helps parse the response from the Auth 'begin' stage"""

    class _AuthBeginState(BaseModel):
        """Helps parse the response from the Auth 'begin' stage

        'continue' had to be renamed 'continue_list'
        because 'continue' is a reserved python term
        """

        continue_list: List[str] = Field(..., title="continue", alias="continue")

    # TODO: can we add validation for AuthBeginResponse.state.continue_list?
    # this should be pulled from the response headers as x-kanidm-auth-session-id
    sessionid: Optional[str]
    state: _AuthBeginState
    response: Optional[ClientResponse] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class AuthState(BaseModel):
    """authstate struct"""

    class _InternalState(BaseModel):
        """subclass to help parse the response from the auth step stage"""

        success: Optional[str] = None

    state: _InternalState
    sessionid: Optional[str] = None
    response: Optional[ClientResponse] = None
    model_config = ConfigDict(arbitrary_types_allowed=True)


class RadiusGroup(BaseModel):
    """group for kanidm radius"""

    spn: str
    vlan: int

    @field_validator("vlan")
    @classmethod
    def validate_vlan(cls, value: int) -> int:
        """validate the vlan option is above 0"""
        if not value > 0:
            raise ValueError(f"VLAN setting has to be above 0! Got: {value}")
        return value


class RadiusTokenGroup(BaseModel):
    """A single group"""

    spn: str
    uuid: str


class RadiusTokenResponse(BaseModel):
    """model capturing the groups in a response from a token request for a user"""

    name: str
    secret: str
    displayname: Optional[str] = None
    uuid: str

    groups: List[RadiusTokenGroup]
    model_config = ConfigDict(arbitrary_types_allowed=True)


class RadiusClient(BaseModel):
    """Client config for Kanidm FreeRADIUS integration,
    this is a pydantic model.

    name: (str) An identifier for the client definition

    ipaddr: (str) A single IP Address, CIDR or
    DNS hostname (which will be resolved on startup,
    preferring A records over AAAA).
    FreeRADIUS doesn't recommend using DNS.

    secret: (str) The password the client should use to
    authenticate.
    """

    name: str
    ipaddr: str
    secret: str  # TODO: this should probably be renamed to token

    @field_validator("ipaddr")
    @classmethod
    def validate_ipaddr(cls, value: str) -> str:
        """validates the ipaddr field is an IP address, CIDR or valid hostname"""
        for typedef in (IPv6Network, IPv6Address, IPv4Address, IPv4Network):
            try:
                typedef(value)
                return value
            except ValueError:
                pass
        try:
            socket.gethostbyname(value)
            return value
        except socket.gaierror as error:
            raise ValueError(
                f"ipaddr value ({value}) wasn't an IP Address, Network or valid hostname: {error}"
            )


class KanidmClientConfig(BaseModel):
    """Configuration file definition for Kanidm client config
    Based on struct KanidmClientConfig in kanidm_client/src/lib.rs

    See source code for fields
    """

    uri: Optional[str] = None

    auth_token: Optional[str] = None

    verify_hostnames: bool = True
    verify_certificate: bool = True
    ca_path: Optional[str] = Field(default=None, alias="verify_ca")

    username: Optional[str] = None
    password: Optional[str] = None

    radius_cert_path: str = "/data/cert.pem"
    radius_key_path: str = "/data/key.pem"  # the signing key for radius TLS
    radius_dh_path: str = "/data/dh.pem"  # the diffie-hellman output
    radius_ca_path: Optional[str] = None
    radius_ca_dir: Optional[str] = None

    radius_required_groups: List[str] = []
    radius_default_vlan: int = 1
    radius_groups: List[RadiusGroup] = []
    radius_clients: List[RadiusClient] = []

    connect_timeout: int = 30

    @classmethod
    def parse_toml(cls, input_string: str) -> Any:
        """loads from a string"""
        return super().model_validate(toml.loads(input_string))

    @field_validator("uri")
    @classmethod
    def validate_uri(cls, value: Optional[str]) -> Optional[str]:
        """validator for the uri field"""
        if value is not None:
            uri = urlparse(value)
            valid_schemes = ["http", "https"]
            if uri.scheme not in valid_schemes:
                raise ValueError(
                    f"Invalid URL Scheme for uri='{value}': '{uri.scheme}' - expected one of {valid_schemes}"
                )

            # make sure the URI ends with a /
            if not value.endswith("/"):
                value = f"{value}/"

        return value
