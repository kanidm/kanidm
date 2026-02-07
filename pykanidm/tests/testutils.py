"""reusable widgets for testing"""

from logging import DEBUG, basicConfig, getLogger
from pathlib import Path
from typing import Any, AsyncIterator, Optional, Tuple
import os

import pytest
from kanidm import KanidmClient
from kanidm_openapi_client import ApiClient

KANIDM_IDM_ADMIN = "idm_admin"


@pytest.fixture(scope="function")
async def client() -> Optional[KanidmClient]:
    """sets up a client with a basic thing"""
    try:
        basicConfig(level=DEBUG)

        return KanidmClient(uri="https://idm.example.com")
    except FileNotFoundError:
        pytest.skip("Couldn't find config file...")  # type: ignore[call-non-callable]


@pytest.fixture(scope="function")
async def client_configfile() -> Optional[KanidmClient]:
    """sets up a client from a config file"""
    try:
        return KanidmClient(config_file=Path("~/.config/kanidm").expanduser())
    except FileNotFoundError:
        pytest.skip("Couldn't find config file...")  # type: ignore[call-non-callable]


@pytest.fixture(scope="session")
def openapi_server_url() -> str:
    return os.getenv("KANIDM_OPENAPI_URL", "https://localhost:8443")


@pytest.fixture(scope="session")
def openapi_ca_path() -> Optional[str]:
    env_path = os.getenv("KANIDM_CA_PATH")
    if env_path:
        return env_path
    default_path = "/tmp/kanidm/ca.pem"
    return default_path if Path(default_path).exists() else None


@pytest.fixture(scope="session")
def openapi_verify_tls(openapi_ca_path: Optional[str]) -> bool:
    insecure = os.getenv("KANIDM_INSECURE")
    if insecure and insecure.strip().lower() in {"1", "true", "yes", "on"}:
        return False
    return True


@pytest.fixture(scope="session")
def openapi_admin_credentials() -> Tuple[str, str]:
    username = KANIDM_IDM_ADMIN
    password = os.getenv("IDM_ADMIN_PASS")
    if not password:
        pytest.skip("No IDM_ADMIN_PASS env var set for openapi tests")  # type: ignore[call-non-callable]
    return username, password


@pytest.fixture(scope="function")
async def openapi_client(
    openapi_server_url: str,
    openapi_verify_tls: bool,
    openapi_ca_path: Optional[str],
) -> KanidmClient:
    return KanidmClient(
        uri=openapi_server_url,
        verify_hostnames=openapi_verify_tls,
        verify_certificate=openapi_verify_tls,
        verify_ca=openapi_verify_tls,
        ca_path=openapi_ca_path,
    )


@pytest.fixture(scope="function")
async def openapi_authed_client(
    openapi_client: KanidmClient,
    openapi_admin_credentials: Tuple[str, str],
) -> KanidmClient:
    username, password = openapi_admin_credentials
    auth_resp = await openapi_client.authenticate_password(username, password, update_internal_auth_token=True)
    if auth_resp.state is None or auth_resp.state.success is None:
        raise ValueError("Failed to authenticate with IDM_ADMIN_PASS")
    return openapi_client


@pytest.fixture(scope="function")
async def openapi_api_client(openapi_client: KanidmClient) -> AsyncIterator[ApiClient]:
    api_client = openapi_client.openapi_client
    try:
        yield api_client
    finally:
        await api_client.close()  # type: ignore[no-untyped-call]


@pytest.fixture(scope="function")
async def openapi_api_client_authed(openapi_authed_client: KanidmClient) -> AsyncIterator[ApiClient]:
    api_client = openapi_authed_client.openapi_client
    try:
        yield api_client
    finally:
        await api_client.close()  # type: ignore[no-untyped-call]


class MockResponse:
    """mock the things"""

    def __init__(self, text: str, status: int) -> None:
        self._text = text
        self.status = status

    async def text(self) -> str:
        """mock the things"""
        return self._text

    # pylint: disable=invalid-name
    async def __aexit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        """mock the things"""

    async def __aenter__(self) -> Any:
        """mock the things"""
        return self
