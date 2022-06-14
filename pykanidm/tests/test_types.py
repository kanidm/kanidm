""" tests types """

import pytest
import pydantic.error_wrappers

from kanidm.types import AuthInitResponse, KanidmClientConfig, RadiusGroup


def test_auth_init_response() -> None:
    """tests AuthInitResponse"""
    testobj = {
        "sessionid": "crabzrool",
        "state": {
            "choose": ["passwordmfa"],
        },
    }

    testval = AuthInitResponse.parse_obj(testobj)
    assert testval.sessionid == "crabzrool"


def test_radiusgroup_vlan_negative() -> None:
    """tests RadiusGroup's vlan validator"""
    with pytest.raises(pydantic.error_wrappers.ValidationError):
        RadiusGroup(vlan=-1)


def test_radiusgroup_vlan_zero() -> None:
    """tests RadiusGroup's vlan validator"""
    with pytest.raises(pydantic.error_wrappers.ValidationError):
        RadiusGroup(vlan=0)


def test_radiusgroup_vlan_4096() -> None:
    """tests RadiusGroup's vlan validator"""
    assert RadiusGroup(vlan=4096, name="crabzrool")


def test_radiusgroup_vlan_no_name() -> None:
    """tests RadiusGroup's vlan validator"""
    with pytest.raises(
        pydantic.error_wrappers.ValidationError, match="name\n.*field required"
    ):
        RadiusGroup(
            vlan=4096,
        )


def test_kanidmconfig_parse_toml() -> None:
    """tests KanidmClientConfig.parse_toml()"""

    config = KanidmClientConfig()
    config.parse_toml("uri = 'https://crabzrool.example.com'")
