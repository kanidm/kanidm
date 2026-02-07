from typing import Any, Callable
from unittest.mock import AsyncMock

import pytest
from kanidm import KanidmClient


@pytest.mark.asyncio
async def test_status_wrapper_delegates_to_system_api(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    status_mock = mocker.patch(
        "kanidm_openapi_client.api.system_api.SystemApi.status",
        new=AsyncMock(return_value=True),
    )

    result = await client.status()

    assert result is True
    status_mock.assert_awaited_once()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("wrapper_name", "api_method_name"),
    [
        ("scim_application_list", "scim_application_get"),
        ("scim_entry_list", "scim_entry_get"),
        ("scim_class_list", "scim_schema_class_get"),
        ("scim_attribute_list", "scim_schema_attribute_get"),
        ("scim_message_list", "scim_message_get"),
        ("scim_message_ready_list", "scim_message_ready_get"),
    ],
)
async def test_scim_list_wrappers_delegate_to_scim_api(
    mocker: Any,
    wrapper_name: str,
    api_method_name: str,
) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    sentinel = object()
    method_mock = mocker.patch(
        f"kanidm_openapi_client.api.scim_api.ScimApi.{api_method_name}",
        new=AsyncMock(return_value=sentinel),
    )

    wrapper: Callable[[], Any] = getattr(client, wrapper_name)
    result = await wrapper()

    assert result is sentinel
    method_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_scim_application_get_wrapper_delegates_to_scim_api(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    sentinel = object()
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.scim_api.ScimApi.scim_application_id_get",
        new=AsyncMock(return_value=sentinel),
    )

    result = await client.scim_application_get("application-id")

    assert result is sentinel
    method_mock.assert_awaited_once_with("application-id")
