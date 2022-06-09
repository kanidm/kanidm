""" tests the check_vlan function """

from calendar import c
from kanidmradius import check_vlan

from kanidm import KanidmClient
from kanidm.types import KanidmClientConfig

def test_check_vlan() -> None:
    """ test 1 """

    testconfig = KanidmClientConfig.parse_toml("""
radius_groups = [
    { name = "crabz", "vlan" = 1234 },
    { name = "hello world", "vlan" = 12345 },
]
""")

    print(f"{testconfig=}")

    kanidm_client = KanidmClient(uri='https://kanidm.example.com')
    kanidm_client.config = testconfig
    print(f"{kanidm_client.config=}")

    assert check_vlan(
        acc=12345678,
        group={'name' : 'crabz'},
        kanidm_client=kanidm_client
    ) == 1234

    assert check_vlan(
        acc=12345678,
        group={'name' : 'foo'},
        kanidm_client=kanidm_client
    ) == 12345678
