""" type objects """

#pylint: disable=too-few-public-methods


from typing import List, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field, validator

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
    username: Optional[str] = None
    password: Optional[str] = None

    connect_timeout: int = 30

    # pylint: disable=too-few-public-methods
    class Config:
        """ configuration for the settings class """
        env_prefix = 'kanidm_'

    @validator("uri")
    def validate_uri(cls, value: Optional[str]) -> str:
        """ validator """
        if value is not None:
            uri = urlparse(value)
            valid_schemes = ["http", "https"]
            if uri.scheme not in valid_schemes:
                raise ValueError(f"Invalid URL Scheme for uri='{value}': '{uri.scheme}' - expected one of {valid_schemes}")

        return value
