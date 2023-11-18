# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import Dict, List, Optional
from uuid import UUID

from pydantic import ConfigDict, BaseModel, RootModel


class ServiceAccount(BaseModel):
    """nicer"""
    classes: List[str]
    displayname: str
    memberof: List[str]
    name: str
    spn: str
    uuid: UUID

class RawServiceAccount(BaseModel):
    """service account information as it comes back from the API"""

    attrs: Dict[str, List[str]]
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_service_account(self) -> ServiceAccount:
        """return it as the Person object which has nicer fields"""
        for field in "name", "uuid", "spn", "displayname":
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")

        return ServiceAccount(
            classes=self.attrs["class"],
            displayname=self.attrs["displayname"][0],
            memberof=self.attrs.get("memberof", []),
            name=self.attrs["name"][0],
            spn=self.attrs["spn"][0],
            uuid=UUID(self.attrs["uuid"][0]),
        )


ServiceAccountList = RootModel[List[RawServiceAccount]]
