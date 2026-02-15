"""testing get_radius_token"""

import json
import logging
import os
from pathlib import Path
from typing import AsyncIterator, Optional

import pytest
import toml
from kanidm_openapi_client.api.person_radius_api import PersonRadiusApi
from kanidm_openapi_client.exceptions import ApiException as OpenApiException

# pylint: disable=unused-import
from .testutils import client, KANIDM_IDM_ADMIN, openapi_ca_path, openapi_server_url, openapi_verify_tls
from kanidm import KanidmClient

logging.basicConfig(level=logging.DEBUG)

RADIUS_TEST_USER = os.getenv("KANIDM_RADIUS_TEST_USER")


@pytest.fixture(scope="function")
async def radius_token_client(
    tmp_path: Path,
    openapi_server_url: str,
    openapi_verify_tls: bool,
    openapi_ca_path: Optional[str],
) -> AsyncIterator[KanidmClient]:
    """Client fixture with a usable auth token for radius tests.

    Preference order:
    1. Existing valid auth_token from ~/.config/kanidm
    2. Generate a token from IDM_ADMIN_PASS and write a temporary config file
    """
    cleanup_clients: list[KanidmClient] = []
    local_config = Path("~/.config/kanidm").expanduser()

    if local_config.exists():
        local_client = KanidmClient(config_file=local_config)
        cleanup_clients.append(local_client)
        if local_client.config.auth_token is not None and await local_client.check_token_valid():
            try:
                yield local_client
            finally:
                for cleanup_client in cleanup_clients:
                    await cleanup_client.openapi_client.close()  # type: ignore[no-untyped-call]
            return

    admin_password = os.getenv("IDM_ADMIN_PASS")
    if not admin_password:
        pytest.skip("Need either a valid ~/.config/kanidm auth_token or IDM_ADMIN_PASS for radius token tests")  # type: ignore[call-non-callable]

    token_source_client = KanidmClient(
        uri=openapi_server_url,
        verify_hostnames=openapi_verify_tls,
        verify_certificate=openapi_verify_tls,
        verify_ca=openapi_verify_tls,
        ca_path=openapi_ca_path,
    )
    cleanup_clients.append(token_source_client)

    auth_resp = await token_source_client.authenticate_password(
        KANIDM_IDM_ADMIN,
        admin_password,
        update_internal_auth_token=True,
    )
    state = auth_resp.state
    if state is None:
        pytest.skip("Failed to generate IDM_ADMIN token for radius token test")  # type: ignore[call-non-callable]
        raise AssertionError("unreachable after pytest.skip")
    if state.success is None:
        pytest.skip("Failed to generate IDM_ADMIN token for radius token test")  # type: ignore[call-non-callable]
        raise AssertionError("unreachable after pytest.skip")
    auth_token = state.success

    config_data: dict[str, object] = {
        "uri": openapi_server_url,
        "verify_hostnames": openapi_verify_tls,
        "verify_certificate": openapi_verify_tls,
        "verify_ca": openapi_verify_tls,
        "username": KANIDM_IDM_ADMIN,
        "auth_token": auth_token,
    }
    if openapi_ca_path is not None:
        config_data["ca_path"] = openapi_ca_path

    generated_config = tmp_path / "kanidm.radius.token.toml"
    generated_config.write_text(toml.dumps(config_data), encoding="utf-8")

    token_client = KanidmClient(config_file=generated_config)
    cleanup_clients.append(token_client)

    try:
        yield token_client
    finally:
        for cleanup_client in cleanup_clients:
            await cleanup_client.openapi_client.close()  # type: ignore[no-untyped-call]


@pytest.mark.network
@pytest.mark.asyncio
async def test_radius_call(radius_token_client: KanidmClient) -> None:
    """tests the radius call step"""
    test_user = RADIUS_TEST_USER or radius_token_client.config.username or KANIDM_IDM_ADMIN
    provision_error: Optional[OpenApiException] = None

    try:
        await PersonRadiusApi(radius_token_client.openapi_client).person_id_radius_post_with_http_info(test_user)
    except OpenApiException as err:
        provision_error = err

    print(f"Doing radius token call using auth_token-backed config as {test_user}")
    result = await radius_token_client.get_radius_token(test_user)

    print(f"{result=}")
    print(json.dumps(result.model_dump_json(), indent=4, default=str))
    if result.status_code == 200:
        return

    if result.status_code == 500 and result.content is not None and '"missingattribute":"radius_secret"' in result.content:
        if provision_error is not None:
            pytest.skip(
                "Radius token test prerequisites not met: unable to provision radius_secret "
                f"for {test_user} ({provision_error.status})"
            )  # type: ignore[call-non-callable]
        pytest.skip(
            f"Radius token test prerequisites not met: account '{test_user}' is missing radius_secret"
        )  # type: ignore[call-non-callable]

    raise AssertionError(f"Unexpected radius token response status: {result.status_code}")
