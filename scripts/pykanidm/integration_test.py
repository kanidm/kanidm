import asyncio
import json
import logging
import os
import pathlib


import subprocess
import sys

# so we can load kanidm without building virtualenvs
sys.path.append("./pykanidm")

from kanidm import KanidmClient


def recover_account(username: str) -> str:
    """runs the kanidmd binary to recover creds"""
    recover_cmd = [
        "cargo",
        "run",
        "--bin",
        "kanidmd",
        "--",
        "recover-account",
        username,
        "--config",
        "../../examples/insecure_server.toml",
        "--output",
        "json",
    ]

    # Define the new working directory
    daemon_dir = os.path.abspath("./server/daemon/")
    # Run the command in the specified working directory
    result = subprocess.run(
        " ".join(recover_cmd), cwd=daemon_dir, shell=True, capture_output=True
    )

    stdout = result.stdout.decode("utf-8").strip().split("\n")[-1]

    try:
        password_response = json.loads(stdout)
    except json.decoder.JSONDecodeError:
        print(f"Failed to decode this as json: {stdout}")
        sys.exit(1)

    return password_response["password"]


async def main() -> None:
    """main loop"""

    # first reset the admin creds

    logger = logging.getLogger(__name__)
    admin_password = recover_account("admin")
    idm_admin_password = recover_account("idm_admin")

    host = "https://localhost:8443"

    # login time!
    admin_client = KanidmClient(uri=host, ca_path="/tmp/kanidm/ca.pem")
    logger.info("Attempting to login as admin with password")
    await admin_client.authenticate_password(
        "admin", admin_password, update_internal_auth_token=True
    )

    idm_admin_client = KanidmClient(uri=host, ca_path="/tmp/kanidm/ca.pem")
    logger.info("Attempting to login as idm_admin with password")
    await idm_admin_client.authenticate_password(
        "idm_admin", idm_admin_password, update_internal_auth_token=True
    )

    # create an oauth2 rs
    logger.info("Creating OAuth2 RS")
    res = await admin_client.oauth2_rs_basic_create(
        "basic_rs", "Basic AF RS", "https://basic.example.com"
    )
    logger.debug(f"Result: {res}")
    assert res.status_code == 200
    logger.info("Done!")

    logger.info("Getting basic secret for OAuth2 RS")
    res = await admin_client.oauth2_rs_get_basic_secret("basic_rs")
    assert res.status_code == 200
    assert res.data is not None

    # delete the oauth2 rs
    logger.info("Deleting OAuth2 RS")
    res = await admin_client.oauth2_rs_delete("basic_rs")
    logger.debug(f"Result: {res}")
    assert res.status_code == 200
    logger.info("Done!")
    print("Woooooooo")

    logger.info("Adding password 'cheese' to badlist")
    res = await admin_client.system_password_badlist_append(["cheese"])
    assert res.status_code == 200

    logger.info("Checking password 'cheese' is in badlist")
    res = await admin_client.system_password_badlist_get()
    assert res.status_code == 200
    assert "cheese" in res.data

    logger.info("Removing password 'cheese' from badlist")
    res = await admin_client.system_password_badlist_remove(["cheese"])
    assert res.status_code == 200

    test_user = "testuser"
    test_group = "testusers"

    logger.info("Adding user '%s' 'test_user'", test_user)
    res = await idm_admin_client.person_account_create(test_user, test_user.upper())
    assert res.status_code == 200

    logger.info("Adding group '%s'", test_group)
    res = await idm_admin_client.group_create(test_group)
    assert res.status_code == 200

    logger.info("Adding testuser to group '%s'", test_group)
    res = await idm_admin_client.group_add_members(test_group, ["testuser"])
    assert res.status_code == 200

    logger.info("Getting group %s", test_group)
    res = await idm_admin_client.group_get(test_group)
    assert res.status_code == 200
    logger.info("Got group %s", res.data)
    assert res.data.get("attrs", {}).get("member") == ["testuser@localhost"]

    logger.info("Deleting user '%s'", test_user)
    res = await idm_admin_client.person_account_delete(test_user)
    assert res.status_code == 200

    logger.info("Getting group %s", test_group)
    res = await idm_admin_client.group_get(test_group)
    assert res.status_code == 200
    logger.info("Got group %s", res.data)
    assert res.data.get("attrs", {}).get("member") is None

    logger.info("Deleting group '%s'", test_group)
    res = await idm_admin_client.group_delete(test_group)
    assert res.status_code == 200

    logger.info("Adding service account %s", test_user)
    res = await admin_client.service_account_create(test_user, test_user.upper())
    assert res.status_code == 200

    logger.info("Deleting service account %s", test_user)
    res = await admin_client.service_account_delete(test_user)
    assert res.status_code == 200


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

    if not pathlib.Path("scripts/pykanidm/integration_test.py").exists():
        logging.error("Please ensure this is running from the root of the repo!")
        sys.exit(1)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())

    print("##########################################")
    print("If you got this far, all the tests passed!")
    print("##########################################")
