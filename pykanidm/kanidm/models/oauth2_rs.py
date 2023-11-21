# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import Dict, List, TypedDict

from pydantic import BaseModel, ConfigDict, RootModel


class OAuth2Rs(BaseModel):
    classes: List[str]
    displayname: str
    es256_private_key_der: str
    oauth2_rs_basic_secret: str
    oauth2_rs_name: str
    oauth2_rs_origin: str
    oauth2_rs_token_key: str


class RawOAuth2Rs(BaseModel):
    attrs: Dict[str, List[str]]
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_oauth2_rs(self) -> OAuth2Rs:
        """return it as the Person object which has nicer fields"""
        required_fields = (
            "displayname",
            "es256_private_key_der",
            "oauth2_rs_basic_secret",
            "oauth2_rs_name",
            "oauth2_rs_origin",
            "oauth2_rs_token_key",
        )
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")

        return OAuth2Rs(
            classes=self.attrs["class"],
            displayname=self.attrs["displayname"][0],
            es256_private_key_der=self.attrs["es256_private_key_der"][0],
            oauth2_rs_basic_secret=self.attrs["oauth2_rs_basic_secret"][0],
            oauth2_rs_name=self.attrs["oauth2_rs_name"][0],
            oauth2_rs_origin=self.attrs["oauth2_rs_origin"][0],
            oauth2_rs_token_key=self.attrs["oauth2_rs_token_key"][0],
        )

Oauth2RsList = RootModel[List[RawOAuth2Rs]]


class IOauth2Rs(TypedDict):
    attrs: Dict[str, List[str]]
