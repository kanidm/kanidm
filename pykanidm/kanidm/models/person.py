# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import List
from uuid import UUID

from kanidm_openapi_client.models.entry import Entry as OpenApiEntry
from pydantic import BaseModel, ConfigDict, RootModel


class Person(BaseModel):
    classes: List[str]
    displayname: str
    memberof: List[str]
    name: str
    spn: str
    uuid: UUID


class RawPerson(OpenApiEntry):

    @property
    def as_person(self) -> Person:
        """return it as the Person object which has nicer fields"""
        required_fields = ("name", "uuid", "spn", "displayname")
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")
        return Person(
            classes=self.attrs["class"],
            displayname=self.attrs["displayname"][0],
            memberof=self.attrs.get("memberof", []),
            name=self.attrs["name"][0],
            spn=self.attrs["spn"][0],
            uuid=UUID(self.attrs["uuid"][0]),
        )


PersonList = RootModel[List[RawPerson]]


IPerson = OpenApiEntry


class PersonCredentialResetToken(BaseModel):
    token: str
    expiry_time: int
    model_config = ConfigDict(arbitrary_types_allowed=True)
