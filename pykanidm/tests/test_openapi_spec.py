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


def _json_schema_for(
    openapi_spec: Mapping[Hashable, Any],
    path: str,
    method: str,
    status_code: str = "200",
) -> Mapping[str, Any]:
    paths = openapi_spec.get("paths", {})
    if not isinstance(paths, Mapping):
        raise AssertionError("OpenAPI paths is not a mapping")

    path_item = paths.get(path, {})
    if not isinstance(path_item, Mapping):
        raise AssertionError(f"OpenAPI path item for {path} is not a mapping")

    operation = path_item.get(method, {})
    if not isinstance(operation, Mapping):
        raise AssertionError(f"OpenAPI operation for {method.upper()} {path} is not a mapping")

    responses = operation.get("responses", {})
    if not isinstance(responses, Mapping):
        raise AssertionError(f"OpenAPI responses for {method.upper()} {path} is not a mapping")

    response = responses.get(status_code, {})
    if not isinstance(response, Mapping):
        raise AssertionError(f"OpenAPI response {status_code} for {method.upper()} {path} is not a mapping")

    content = response.get("content", {})
    if not isinstance(content, Mapping):
        raise AssertionError(f"OpenAPI content for {method.upper()} {path} {status_code} is not a mapping")

    app_json = content.get("application/json", {})
    if not isinstance(app_json, Mapping):
        raise AssertionError(f"OpenAPI application/json for {method.upper()} {path} {status_code} is not a mapping")

    schema = app_json.get("schema", {})
    if not isinstance(schema, Mapping):
        raise AssertionError(f"OpenAPI schema for {method.upper()} {path} {status_code} is not a mapping")

    return cast(Mapping[str, Any], schema)


def _schema_ref(schema: Mapping[str, Any]) -> str | None:
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return ref
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for item in all_of:
            if isinstance(item, Mapping):
                candidate = item.get("$ref")
                if isinstance(candidate, str):
                    return candidate
    return None


def test_openapi_status_schema_is_boolean(openapi_spec: Mapping[Hashable, Any]) -> None:
    schema = _json_schema_for(openapi_spec, "/status", "get")
    assert schema.get("type") == "boolean"


def test_openapi_scim_application_id_get_is_present(openapi_spec: Mapping[Hashable, Any]) -> None:
    paths = openapi_spec.get("paths", {})
    assert isinstance(paths, Mapping)
    scim_application_id = paths.get("/scim/v1/Application/{id}", {})
    assert isinstance(scim_application_id, Mapping)
    assert "get" in scim_application_id
    assert "delete" in scim_application_id
    get_operation = scim_application_id.get("get", {})
    assert isinstance(get_operation, Mapping)
    assert get_operation.get("operationId") == "scim_application_id_get"


def test_openapi_scim_list_endpoints_reference_scim_list_response(openapi_spec: Mapping[Hashable, Any]) -> None:
    list_paths = (
        "/scim/v1/Entry",
        "/scim/v1/Application",
        "/scim/v1/Class",
        "/scim/v1/Attribute",
        "/scim/v1/Message",
        "/scim/v1/Message/_ready",
    )
    for path in list_paths:
        schema = _json_schema_for(openapi_spec, path, "get")
        ref = _schema_ref(schema)
        assert isinstance(ref, str)
        assert ref.endswith("/ScimListResponse")


async def test_openapi_status_endpoint(openapi_spec: Mapping[Hashable, Any], openapi_client: KanidmClient) -> None:
    assert "/status" in openapi_spec.get("paths", {})
    status = await openapi_client.status()
    assert isinstance(status, bool)
    assert status is True


async def test_openapi_group_list_endpoint(openapi_spec: Mapping[Hashable, Any], openapi_authed_client: KanidmClient) -> None:
    assert "/v1/group" in openapi_spec.get("paths", {})
    response = await openapi_authed_client.group_list()
    assert isinstance(response, list)


async def test_openapi_scim_application_list_endpoint(
    openapi_spec: Mapping[Hashable, Any],
    openapi_authed_client: KanidmClient,
) -> None:
    assert "/scim/v1/Application" in openapi_spec.get("paths", {})
    response = await openapi_authed_client.scim_application_list()
    resources = getattr(response, "resources", None)
    assert isinstance(resources, list)
    total_results = getattr(response, "total_results", None)
    assert isinstance(total_results, int)


async def test_openapi_scim_application_id_get_endpoint_runtime(openapi_authed_client: KanidmClient) -> None:
    listing_response = await openapi_authed_client.scim_application_list()
    resources = getattr(listing_response, "resources", None)
    assert isinstance(resources, list)
    if not resources:
        pytest.skip("No SCIM applications available to test /scim/v1/Application/{id}")

    application_id = getattr(resources[0], "id", None)
    if not isinstance(application_id, str) or not application_id:
        pytest.skip("SCIM application resource is missing id")

    response = await openapi_authed_client.scim_application_get(application_id)
    assert getattr(response, "id", None) == application_id
