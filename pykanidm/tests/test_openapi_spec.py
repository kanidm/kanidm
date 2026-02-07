import json
import ssl
from typing import Any, Hashable, Mapping, cast
from urllib.request import urlopen

import pytest
from openapi_spec_validator import validate

from kanidm import KanidmClient
from .testutils import (
    openapi_authed_client,
    openapi_ca_path,
    openapi_client,
    openapi_server_url,
    openapi_verify_tls,
)


pytestmark = pytest.mark.openapi


@pytest.fixture(scope="session")
def openapi_spec(
    openapi_server_url: str,
    openapi_verify_tls: bool,
    openapi_ca_path: str | None,
) -> Mapping[Hashable, Any]:
    spec_url = f"{openapi_server_url.rstrip('/')}/docs/v1/openapi.json"
    if not openapi_verify_tls:
        context = ssl._create_unverified_context()
    elif openapi_ca_path:
        context = ssl.create_default_context(cafile=openapi_ca_path)
    else:
        context = None
    with urlopen(spec_url, context=context) as response:
        raw = json.loads(response.read().decode("utf-8"))
        return cast(Mapping[Hashable, Any], raw)


def test_openapi_spec_validates(openapi_spec: Mapping[Hashable, Any]) -> None:
    validate(openapi_spec)


async def test_openapi_status_endpoint(openapi_spec: Mapping[Hashable, Any], openapi_client: KanidmClient) -> None:
    assert "/status" in openapi_spec.get("paths", {})
    response = await openapi_client.call_get("/status")
    assert response.status_code == 200


async def test_openapi_group_list_endpoint(openapi_spec: Mapping[Hashable, Any], openapi_authed_client: KanidmClient) -> None:
    assert "/v1/group" in openapi_spec.get("paths", {})
    response = await openapi_authed_client.call_get("/v1/group")
    assert response.status_code == 200
    if response.data is not None:
        assert isinstance(response.data, list)
