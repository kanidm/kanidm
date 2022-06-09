""" type objects """

#pylint: disable=too-few-public-methods


from ipaddress import IPv4Address, IPv6Address
from typing import List, Optional, Union
from urllib.parse import urlparse

from pydantic import BaseModel, Field, validator
import toml

import requests


# TODO: add validation for state
class AuthInitResponse(BaseModel):
    """ helps parse the response from the auth init stage """
    class _AuthInitState(BaseModel):
        """ sub-class for the AuthInitResponse model """
        choose: List[str]
    sessionid: str
    state: _AuthInitState
    response: Optional[requests.Response]

    class Config:
        """ config class """
        arbitrary_types_allowed=True

class AuthBeginResponse(BaseModel):
    """ helps parse the response from the auth 'begin' stage

    continue had to be continue_list because continue is a reserved word """

    class _AuthBeginState(BaseModel):
        """ helps parse the response from the auth 'begin' stage"""
        continue_list: List[str] = Field(..., title="continue", alias="continue")
    # TODO: add validation for continue_list
    sessionid: str
    state: _AuthBeginState
    response: Optional[requests.Response]
    class Config:
        """ config class """
        arbitrary_types_allowed=True

class AuthStepPasswordResponse(BaseModel):
    """ helps parse the response from the auth 'password' stage"""
    class _AuthStepPasswordState(BaseModel):
        """ subclass to help parse the response from the auth 'step password' stage"""
        success: Optional[str]
        # TODO: add validation for continue_list


    sessionid: str
    state: _AuthStepPasswordState
    response: Optional[requests.Response]
    class Config:
        """ config class """
        arbitrary_types_allowed = True

class RadiusGroup(BaseModel):
    """ group for kanidm radius """
    name: str
    vlan: int

    @validator("vlan")
    def validate_vlan(cls, value: int) -> int:
        """ validate the vlan option is above 0 """
        if not value > 0:
            raise ValueError(f"VLAN setting has to be above 0! Got: {value}")
        return value

class RadiusClient(BaseModel):
    """ permitted clients for kanidm radius """
    name : str # the name of the client
    ipaddr : str # the allowed client address
    secret : str # the password for that particular client

    @validator("ipaddr")
    def validate_ipaddr(cls, value: str) -> str:
        IPv4Address(value)
        return value


class KanidmClientConfig(BaseModel):
    """ configuration file definition for kanidm client config
    from struct KanidmClientConfig in kanidm_client/src/lib.rs
    """
    uri: Optional[str] = None
    verify_ca: bool = True
    verify_hostnames: bool = True
    ca_path: Optional[str] = None

    radius_service_username: Optional[str] = None
    radius_service_password: Optional[str] = None

    radius_cert_path: str = "/etc/raddb/certs/cert.pem"
    radius_key_path: str = "/etc/raddb/certs/key.pem"  # the signing key for radius TLS
    radius_dh_path: str = "/etc/raddb/certs/dh.pem"   # the diffie-hellman output
    radius_ca_path: str = "/etc/raddb/certs/ca.pem"   # the diffie-hellman output

    radius_required_groups: List[str] = []
    radius_default_vlan: int = 1
    radius_groups: List[RadiusGroup] = []
    radius_clients: List[RadiusClient] = []

    username: Optional[str] = None
    password: Optional[str] = None

    connect_timeout: int = 30

    # pylint: disable=too-few-public-methods
    class Config:
        """ configuration for the settings class """
        env_prefix = 'kanidm_'

    @classmethod
    def parse_toml(cls, input_string: str):
        """ loads from a string """
        return super().parse_obj(toml.loads(input_string))

    @validator("uri")
    def validate_uri(cls, value: Optional[str]) -> Optional[str]:
        """ validator """
        if value is not None:
            uri = urlparse(value)
            valid_schemes = ["http", "https"]
            if uri.scheme not in valid_schemes:
                raise ValueError(f"Invalid URL Scheme for uri='{value}': '{uri.scheme}' - expected one of {valid_schemes}")

            # make sure the URI ends with a /
            if not value.endswith("/"):
                value = f"{value}/"

        return value
