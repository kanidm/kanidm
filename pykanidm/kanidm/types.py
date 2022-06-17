""" type objects """
# pylint: disable=too-few-public-methods

from ipaddress import IPv4Address,IPv6Address, IPv6Network, IPv4Network
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, validator
import toml

class ClientResponse(BaseModel):
    """response from an API call"""

    content: Optional[str]
    data: Optional[Dict[str, Any]]
    headers: Dict[str, Any]
    status_code: int


class AuthInitResponse(BaseModel):
    """Aelps parse the response from the Auth 'init' stage"""

    class _AuthInitState(BaseModel):
        """sub-class for the AuthInitResponse model"""

        # TODO: can we add validation for AuthInitResponse.state.choose?
        choose: List[str]

    sessionid: str
    state: _AuthInitState
    response: Optional[ClientResponse]

    class Config:
        """config class"""

        arbitrary_types_allowed = True


class AuthBeginResponse(BaseModel):
    """Helps parse the response from the Auth 'begin' stage

    """

    class _AuthBeginState(BaseModel):
        """Helps parse the response from the Auth 'begin' stage

        'continue' had to be renamed 'continue_list'
        because 'continue' is a reserved python term
        """

        continue_list: List[str] = Field(..., title="continue", alias="continue")

    # TODO: can we add validation for AuthBeginResponse.state.continue_list?
    sessionid: str
    state: _AuthBeginState
    response: Optional[ClientResponse]

    class Config:
        """config class"""

        arbitrary_types_allowed = True


class AuthStepPasswordResponse(BaseModel):
    """helps parse the response from the auth 'password' stage"""

    class _AuthStepPasswordState(BaseModel):
        """subclass to help parse the response from the auth 'step password' stage"""
        success: Optional[str]

    sessionid: str
    state: _AuthStepPasswordState
    response: Optional[ClientResponse]

    class Config:
        """config class"""

        arbitrary_types_allowed = True


class RadiusGroup(BaseModel):
    """group for kanidm radius"""

    name: str
    vlan: int

    @validator("vlan")
    def validate_vlan(cls, value: int) -> int:
        """validate the vlan option is above 0"""
        if not value > 0:
            raise ValueError(f"VLAN setting has to be above 0! Got: {value}")
        return value


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
    secret: str

    @validator("ipaddr")
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
        except socket.gaierror as error:
            raise ValueError(f"ipaddr value ({value}) wasn't an IP Address, Network or valid hostname: {error}")

        raise ValueError(f"ipaddr ({value}) wasn't an IP Address, Network or valid hostname")

class KanidmClientConfig(BaseModel):
    """Configuration file definition for Kanidm client config
    Based on struct KanidmClientConfig in kanidm_client/src/lib.rs

    See source code for fields
    """

    uri: Optional[str] = None

    verify_hostnames: bool = True
    verify_certificate: bool = True
    ca_path: Optional[str] = None

    username: Optional[str] = None
    password: Optional[str] = None

    radius_cert_path: str = "/etc/raddb/certs/cert.pem"
    radius_key_path: str = "/etc/raddb/certs/key.pem"  # the signing key for radius TLS
    radius_dh_path: str = "/etc/raddb/certs/dh.pem"  # the diffie-hellman output
    radius_ca_path: str = "/etc/raddb/certs/ca.pem"  # the diffie-hellman output

    radius_required_groups: List[str] = []
    radius_default_vlan: int = 1
    radius_groups: List[RadiusGroup] = []
    radius_clients: List[RadiusClient] = []

    connect_timeout: int = 30

    @classmethod
    def parse_toml(cls, input_string: str) -> Any:
        """loads from a string"""
        return super().parse_obj(toml.loads(input_string))

    @validator("uri")
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
