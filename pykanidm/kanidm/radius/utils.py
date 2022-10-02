""" class utils """

from typing import Optional
import logging
import os

from .. import KanidmClient
from ..types import RadiusTokenGroup

def check_vlan(
    acc: int,
    group: RadiusTokenGroup,
    kanidm_client: Optional[KanidmClient] = None,
) -> int:
    """checks if a vlan is in the config,

    acc is the default vlan
    """
    logging.debug("acc=%s", acc)
    if kanidm_client is None:
        if "KANIDM_CONFIG_FILE" in os.environ:
            kanidm_client = KanidmClient(config_file=os.environ["KANIDM_CONFIG_FILE"])
        else:
            raise ValueError("Need to pass this a kanidm_client")

    for radius_group in kanidm_client.config.radius_groups:
        logging.debug(
            "Checking vlan group '%s' against user group %s", radius_group.spn, group.spn
        )
        if radius_group.spn == group.spn:
            logging.info("returning new vlan: %s", radius_group.vlan)
            return radius_group.vlan
    logging.debug("returning already set vlan: %s", acc)
    return acc
