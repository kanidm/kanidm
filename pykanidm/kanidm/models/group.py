# pylint: disable=too-few-public-methods
# ^ disabling this because pydantic models don't have public methods

from typing import Dict, List, Optional, TypedDict

from pydantic import ConfigDict, BaseModel, RootModel


class Group(BaseModel):
    """nicer"""

    name: str
    dynmember: List[str]
    member: List[str]
    spn: str
    uuid: str
    # posix-enabled group
    gidnumber: Optional[int]

    def has_member(self, member: str) -> bool:
        """check if a member is in the group"""
        return member in self.member or member in self.dynmember


class RawGroup(BaseModel):
    """group information as it comes back from the API"""

    attrs: Dict[str, List[str]]
    model_config = ConfigDict(arbitrary_types_allowed=True)

    @property
    def as_group(self) -> Group:
        """return it as the GroupInfo object which has nicer fields"""
        required_fields = ("name", "uuid", "spn")
        for field in required_fields:
            if field not in self.attrs:
                raise ValueError(f"Missing field {field} in {self.attrs}")
            if len(self.attrs[field]) == 0:
                raise ValueError(f"Empty field {field} in {self.attrs}")

        # we want either the first element of gidnumber_field, or None
        gidnumber_field = self.attrs.get("gidnumber", [])
        gidnumber: Optional[int] = None
        if len(gidnumber_field) > 0:
            gidnumber = int(gidnumber_field[0])

        return Group(
            name=self.attrs["name"][0],
            uuid=self.attrs["uuid"][0],
            spn=self.attrs["spn"][0],
            member=self.attrs.get("member", []),
            dynmember=self.attrs.get("dynmember", []),
            gidnumber=gidnumber,
        )


GroupList = RootModel[List[RawGroup]]


class IGroup(TypedDict):
    attrs: Dict[str, List[str]]
