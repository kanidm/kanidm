import json
import logging
from pathlib import Path

from kanidm import KanidmClient

import pytest


@pytest.fixture(scope="function")
async def client() -> KanidmClient:
    """sets up a client with a basic thing"""

    return KanidmClient(
        config_file=Path(__file__).parent.parent.parent / "examples/config_localhost",
    )


@pytest.mark.network
@pytest.mark.asyncio
async def test_oauth2_rs_list(client: KanidmClient) -> None:
    """tests getting the list of oauth2 resource servers"""
    logging.basicConfig(level=logging.DEBUG)
    print(f"config: {client.config}")

    username = "admin"
    # change this to be your admin password.
    password = "Ek7A0fShLsCTXgK2xDqC9TNUgPYQdVFB6RMGKXLyNtGL5cER"

    auth_resp = await client.authenticate_password(
        username, password, update_internal_auth_token=True
    )
    assert auth_resp.state.success is not None

    resource_servers = await client.oauth2_rs_list()
    print("content:")
    print(json.dumps(resource_servers, indent=4))

    if resource_servers:
        for oauth_rs in resource_servers:
            for mapping in oauth_rs.oauth2_rs_sup_scope_map:
                print(f"oauth2_rs_sup_scope_map: {mapping}")
                user, scopes = mapping.split(":")
                scopes = scopes.replace("{", "[").replace("}", "]")
                scopes = json.loads(scopes)
                print(f"{user=} {scopes=}")
