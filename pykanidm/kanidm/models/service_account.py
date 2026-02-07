# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import List
from uuid import UUID

from kanidm_openapi_client.models.entry import Entry as OpenApiEntry
from pydantic import BaseModel, RootModel


class ServiceAccount(BaseModel):
    """nicer"""
    classes: List[str]
    displayname: str | None
    memberof: List[str]
    name: str
    spn: str
    uuid: UUID

class RawServiceAccount(OpenApiEntry):
    """Compatibility wrapper over OpenAPI-generated Entry for service accounts."""

    @property
    def as_service_account(self) -> ServiceAccount:
        """return it as the Person object which has nicer fields"""
        required_fields = ("uuid", "spn", "name")
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")

        displayname = self.attrs.get("displayname", [None])[0]

        return ServiceAccount(
            classes=self.attrs.get("class", []),
            displayname=displayname,
            memberof=self.attrs.get("memberof", []),
            name=self.attrs["name"][0],
            spn=self.attrs["spn"][0],
            uuid=UUID(self.attrs["uuid"][0]),
        )

ServiceAccountList = RootModel[List[RawServiceAccount]]


IServiceAccount = OpenApiEntry
