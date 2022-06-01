""" testing auth things """

from kanidm import KanidmClient

def test_auth_init() -> None:
    """ tests the auth init step """
    client = KanidmClient(config="~/.config/kanidm")

    client.authenticate()
