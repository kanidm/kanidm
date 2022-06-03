""" testing auth things """

import logging

from kanidm import KanidmClient

logging.basicConfig(level=logging.DEBUG)


def test_auth_init() -> None:
    """ tests the auth init step """
    client = KanidmClient(config="~/.config/kanidm")

    client.authenticate()
