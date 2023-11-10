import asyncio
import json
import logging
import os


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
    admin_password = recover_account("admin")
    idm_admin_password = recover_account("idm_admin")

    host = "https://localhost:8443"

    # login time!
    admin_client = KanidmClient(uri=host, ca_path="/tmp/kanidm/ca.pem")
    logging.info("Attempting to login as admin with password")
    await admin_client.authenticate_password(
        "admin", admin_password, update_internal_auth_token=True
    )

    idm_admin_client = KanidmClient(uri=host, ca_path="/tmp/kanidm/ca.pem")
    logging.info("Attempting to login as idm_admin with password")
    await idm_admin_client.authenticate_password(
        "idm_admin", idm_admin_password, update_internal_auth_token=True
    )

    # create an oauth2 rs
    logging.info("Creating oauth2 rs")
    res = await admin_client.oauth2_rs_basic_create(
        "basic_rs", "Basic AF RS", "https://basic.example.com"
    )
    logging.debug(f"Result: {res}")
    assert res.status_code == 200
    logging.info("Done!")

    # delete the oauth2 rs
    logging.info("Deleting oauth2 rs")
    res = await admin_client.oauth2_rs_delete("basic_rs")
    logging.debug(f"Result: {res}")
    assert res.status_code == 200
    logging.info("Done!")
    print("Woooooooo")


if __name__ == "__main__":
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
