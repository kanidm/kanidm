""" type objects """

from typing import Dict, List, Optional, TypedDict

from pydantic import BaseModel

        # {'sessionid': '00000000-5fe5-46e1-06b6-b830dd035a10', 'state': {'choose': ['password']}}

class _AuthInitState(BaseModel):
    choose: List[str]

# TODO: add validation for state

class AuthInitResponse(BaseModel):
    sessionid: str
    state: _AuthInitState

    class Meta:
        allow_arbitrary_classes=True


class KanidmClientConfig(BaseModel):
    """ configuration file definition for kanidm client config """
    uri: str
    verify_ca: bool = True
    verify_hostnames: bool = True
    ca_cert_path: Optional[str]

    radius_service_username: Optional[str]
    radius_service_password: Optional[str]
    username: Optional[str]
    password: Optional[str]

    #TODO: make sure this parses and sets
    connect_timeout: int = 30
