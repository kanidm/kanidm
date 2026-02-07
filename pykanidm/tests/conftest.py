"""Shared pytest fixtures for the pykanidm test suite."""

from pathlib import Path

import pytest
from kanidm.openapi_codegen import generate_openapi_client

from .testutils import (
    openapi_admin_credentials,
    openapi_authed_client,
    openapi_api_client,
    openapi_api_client_authed,
    openapi_ca_path,
    openapi_client,
    openapi_server_url,
    openapi_verify_tls,
)

PYKANIDM_DIR = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def openapi_codegen_once(
    openapi_server_url: str,
    openapi_verify_tls: bool,
    openapi_ca_path: str | None,
) -> None:
    """Ensure the generated OpenAPI client is refreshed once per openapi test run."""
    spec_url = f"{openapi_server_url.rstrip('/')}/docs/v1/openapi.json"
    generate_openapi_client(
        spec_url=spec_url,
        verify_tls=openapi_verify_tls,
        ca_file=Path(openapi_ca_path) if openapi_ca_path else None,
        output=PYKANIDM_DIR / "kanidm_openapi_client",
    )


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    """Auto-apply code generation fixture to tests marked openapi."""
    for item in items:
        if item.get_closest_marker("openapi") is None:
            continue
        if isinstance(item, pytest.Function) and "openapi_codegen_once" not in item.fixturenames:
            item.fixturenames.append("openapi_codegen_once")


__all__ = [
    "openapi_admin_credentials",
    "openapi_authed_client",
    "openapi_api_client",
    "openapi_api_client_authed",
    "openapi_ca_path",
    "openapi_client",
    "openapi_server_url",
    "openapi_verify_tls",
    "openapi_codegen_once",
]
