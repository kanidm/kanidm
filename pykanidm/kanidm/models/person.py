# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import Dict, List
from uuid import UUID

from pydantic import BaseModel, ConfigDict, RootModel


class Person(BaseModel):
    classes: List[str]
    displayname: str
    memberof: List[str]
    name: str
    spn: str
    uuid: UUID


class RawPerson(BaseModel):
    attrs: Dict[str, List[str]]
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_person(self) -> Person:
        """return it as the Person object which has nicer fields"""
        for field in "name", "uuid", "spn", "displayname":
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")

        return Person(
            classes=self.attrs["class"],
            displayname=self.attrs["displayname"][0],
            memberof=self.attrs.get("memberof", []),
            name=self.attrs["name"][0],
            spn=self.attrs["spn"][0],
            uuid=UUID(self.attrs["uuid"][0]),
        )

PersonList = RootModel[List[RawPerson]]
