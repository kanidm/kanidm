# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

import json
from typing import List

from kanidm_openapi_client.models.entry import Entry as OpenApiEntry
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
    es256_private_key_der: str | None
    name: str
    oauth2_rs_basic_secret: str | None
    oauth2_rs_origin: str | None
    oauth2_rs_token_key: str | None
    oauth2_rs_scope_map: List[OAuth2RsScopeMap]
    oauth2_rs_sup_scope_map: List[OAuth2RsScopeMap]
    oauth2_rs_claim_map: List[OAuth2RsClaimMap]


class RawOAuth2Rs(OpenApiEntry):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_oauth2_rs(self) -> OAuth2Rs:
        """return it as the Person object which has nicer fields"""
        required_fields = ("displayname", "name")
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")

        oauth2_rs_scope_map = [OAuth2RsScopeMap.from_entry(entry) for entry in self.attrs.get("oauth2_rs_scope_map", [])]
        oauth2_rs_sup_scope_map = [OAuth2RsScopeMap.from_entry(entry) for entry in self.attrs.get("oauth2_rs_sup_scope_map", [])]
        oauth2_rs_claim_map = [OAuth2RsClaimMap.from_entry(entry) for entry in self.attrs.get("oauth2_rs_claim_map", [])]

        origin = self.attrs.get("oauth2_rs_origin", [None])[0]
        if origin is None:
            origin = self.attrs.get("oauth2_rs_origin_landing", [None])[0]

        return OAuth2Rs(
            classes=self.attrs.get("class", []),
            displayname=self.attrs["displayname"][0],
            es256_private_key_der=self.attrs.get("es256_private_key_der", [None])[0],
            name=self.attrs["name"][0],
            oauth2_rs_basic_secret=self.attrs.get("oauth2_rs_basic_secret", [None])[0],
            oauth2_rs_origin=origin,
            oauth2_rs_token_key=self.attrs.get("oauth2_rs_token_key", [None])[0],
            oauth2_rs_scope_map=oauth2_rs_scope_map,
            oauth2_rs_sup_scope_map=oauth2_rs_sup_scope_map,
            oauth2_rs_claim_map=oauth2_rs_claim_map,
        )


Oauth2RsList = RootModel[List[RawOAuth2Rs]]
