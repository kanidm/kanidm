""" tests types """

import pytest
import pydantic.error_wrappers

from kanidm.types import AuthInitResponse, KanidmClientConfig, RadiusGroup, RadiusClient


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
        RadiusGroup(vlan=-1, spn="crabzrool@foo")


def test_radiusgroup_vlan_zero() -> None:
    """tests RadiusGroup's vlan validator"""
    with pytest.raises(pydantic.error_wrappers.ValidationError):
        RadiusGroup(vlan=0, spn="crabzrool@foo")


def test_radiusgroup_vlan_4096() -> None:
    """tests RadiusGroup's vlan validator"""
    assert RadiusGroup(vlan=4096, spn="crabzrool@foo")


def test_radiusgroup_vlan_no_name() -> None:
    """tests RadiusGroup's vlan validator"""
    with pytest.raises(
        pydantic.error_wrappers.ValidationError, match="spn\n.*field required"
    ):
        RadiusGroup(vlan=4096) # type: ignore[call-arg]

def test_kanidmconfig_parse_toml() -> None:
    """tests KanidmClientConfig.parse_toml()"""

    config = KanidmClientConfig()
    config.parse_toml("uri = 'https://crabzrool.example.com'")


@pytest.mark.network
def test_radius_client_bad_hostname() -> None:
    """tests with a bad hostname"""
    with pytest.raises(pydantic.error_wrappers.ValidationError):
        RadiusClient(
            name="test",
            ipaddr="thiscannotpossiblywork.kanidm.example.com",
            secret="nothing",
        )

    assert RadiusClient(name="test", ipaddr="kanidm.com", secret="nothing")
