import json
import logging
import os
from pathlib import Path

from kanidm import KanidmClient

import pytest


@pytest.fixture(scope="function")
async def client() -> KanidmClient:
    """sets up a client with a basic thing"""
    try:
        client = KanidmClient(
            config_file=Path(__file__).parent.parent.parent / "examples/config_localhost",
        )
    except FileNotFoundError as error:
        pytest.skip(f"File not found: {error}")  # type: ignore[call-non-callable]
    return client


@pytest.mark.network
@pytest.mark.asyncio
async def test_oauth2_rs_list(client: KanidmClient) -> None:
    """tests getting the list of oauth2 resource servers"""
    logging.basicConfig(level=logging.DEBUG)
    print(f"config: {client.config}")

    username = "idm_admin"
    # change this to be the password.
    password = os.getenv("KANIDM_PASSWORD")
    if password is None:
        print("No KANIDM_PASSWORD env var set for testing")
        pytest.skip("No KANIDM_PASSWORD env var set for testing")  # type: ignore[call-non-callable]

    auth_resp = await client.authenticate_password(username, password, update_internal_auth_token=True)
    if auth_resp.state is None:
        raise ValueError("Failed to authenticate, check the admin password is set right")
    if auth_resp.state.success is None:
        raise ValueError("Failed to authenticate, check the admin password is set right")

    resource_servers = await client.oauth2_rs_list()
    print("content:")

    if resource_servers:
        for oauth_rs in resource_servers:
            print(json.dumps(oauth_rs.model_dump(), indent=4, default=str))
            for mapping in oauth_rs.oauth2_rs_sup_scope_map:
                print(f"oauth2_rs_sup_scope_map: {mapping}")
