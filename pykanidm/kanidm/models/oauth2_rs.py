# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

import json
from typing import Dict, List, TypedDict

from pydantic import BaseModel, ConfigDict, RootModel


class OAuth2RsClaimMap(BaseModel):
    name: str
    group: str
    join: str
    values: List[str]

    @classmethod
    def from_entry(cls, entry: str) -> "OAuth2RsClaimMap":
        name, group, join, values = entry.split(":")
        values = json.loads(values).split(",")
        return cls(name=name, group=group, join=join, values=values)


class OAuth2RsScopeMap(BaseModel):
    group: str
    values: List[str]

    @classmethod
    def from_entry(cls, entry: str) -> "OAuth2RsScopeMap":
        group, values = entry.split(":")
        values = values.replace("{", "[").replace("}", "]")
        values = json.loads(values.strip())
        return cls(group=group, values=values)


class OAuth2Rs(BaseModel):
    classes: List[str]
    displayname: str
    es256_private_key_der: str
    name: str
    oauth2_rs_basic_secret: str
    oauth2_rs_origin: str
    oauth2_rs_token_key: str
    oauth2_rs_scope_map: List[OAuth2RsScopeMap]
    oauth2_rs_sup_scope_map: List[OAuth2RsScopeMap]
    oauth2_rs_claim_map: List[OAuth2RsClaimMap]


class RawOAuth2Rs(BaseModel):
    attrs: Dict[str, List[str]]
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_oauth2_rs(self) -> OAuth2Rs:
        """return it as the Person object which has nicer fields"""
        required_fields = (
            "displayname",
            "es256_private_key_der",
            "name",
            "oauth2_rs_basic_secret",
            "oauth2_rs_origin",
            "oauth2_rs_token_key",
        )
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")

        oauth2_rs_scope_map = [
            OAuth2RsScopeMap.from_entry(entry)
            for entry in self.attrs.get("oauth2_rs_scope_map", [])
        ]
        oauth2_rs_sup_scope_map = [
            OAuth2RsScopeMap.from_entry(entry)
            for entry in self.attrs.get("oauth2_rs_sup_scope_map", [])
        ]
        oauth2_rs_claim_map = [
            OAuth2RsClaimMap.from_entry(entry)
            for entry in self.attrs.get("oauth2_rs_claim_map", [])
        ]

        return OAuth2Rs(
            classes=self.attrs["class"],
            displayname=self.attrs["displayname"][0],
            es256_private_key_der=self.attrs["es256_private_key_der"][0],
            name=self.attrs["name"][0],
            oauth2_rs_basic_secret=self.attrs["oauth2_rs_basic_secret"][0],
            oauth2_rs_origin=self.attrs["oauth2_rs_origin"][0],
            oauth2_rs_token_key=self.attrs["oauth2_rs_token_key"][0],
            oauth2_rs_scope_map=oauth2_rs_scope_map,
            oauth2_rs_sup_scope_map=oauth2_rs_sup_scope_map,
            oauth2_rs_claim_map=oauth2_rs_claim_map,
        )


Oauth2RsList = RootModel[List[RawOAuth2Rs]]


class IOauth2Rs(TypedDict):
    attrs: Dict[str, List[str]]
