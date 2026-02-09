from typing import Any, Callable
from unittest.mock import AsyncMock

import pytest
from kanidm import KanidmClient
from kanidm_openapi_client.exceptions import ApiException
from kanidm.exceptions import AuthInitFailed


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


@pytest.mark.asyncio
async def test_check_token_valid_wrapper_delegates_to_auth_api(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_valid_with_http_info",
        new=AsyncMock(return_value=mocker.Mock(status_code=200)),
    )

    result = await client.check_token_valid()

    assert result is True
    method_mock.assert_awaited_once_with(_request_auth=None)


@pytest.mark.asyncio
async def test_check_token_valid_wrapper_uses_explicit_token(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_valid_with_http_info",
        new=AsyncMock(return_value=mocker.Mock(status_code=200)),
    )

    result = await client.check_token_valid("explicit-token")

    assert result is True
    method_mock.assert_awaited_once()
    kwargs = method_mock.await_args.kwargs
    assert kwargs["_request_auth"]["key"] == "Authorization"
    assert kwargs["_request_auth"]["value"] == "Bearer explicit-token"


@pytest.mark.asyncio
async def test_check_token_valid_wrapper_returns_false_on_auth_error(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_valid_with_http_info",
        new=AsyncMock(side_effect=ApiException(status=401, reason="Unauthorized")),
    )

    result = await client.check_token_valid()

    assert result is False
    method_mock.assert_awaited_once()


@pytest.mark.asyncio
async def test_check_token_valid_wrapper_syncs_openapi_token_for_default_token(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443", token="token-from-config")
    sync_mock = mocker.spy(client, "_sync_openapi_access_token")
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_valid_with_http_info",
        new=AsyncMock(return_value=mocker.Mock(status_code=200)),
    )

    result = await client.check_token_valid()

    assert result is True
    sync_mock.assert_called_once_with()
    method_mock.assert_awaited_once_with(_request_auth=None)


@pytest.mark.asyncio
async def test_auth_init_wrapper_delegates_to_auth_api(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    response = mocker.Mock(
        status_code=200,
        headers={},
        raw_data=b'{"sessionid":"session-id","state":{"choose":["password"]}}',
    )
    response.data = mocker.Mock(
        sessionid="session-id",
        to_dict=mocker.Mock(return_value={"sessionid": "session-id", "state": {"choose": ["password"]}}),
    )
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_post_with_http_info",
        new=AsyncMock(return_value=response),
    )

    result = await client.auth_init("idm_admin")

    assert result.sessionid == "session-id"
    assert result.state.choose == ["password"]
    assert client.config.auth_token == "session-id"
    method_mock.assert_awaited_once()
    args = method_mock.await_args.args
    assert len(args) == 1
    assert args[0].to_dict() == {"step": {"init": "idm_admin"}}


@pytest.mark.asyncio
async def test_auth_init_wrapper_raises_auth_init_failed_on_openapi_error(mocker: Any) -> None:
    client = KanidmClient(uri="https://localhost:8443")
    method_mock = mocker.patch(
        "kanidm_openapi_client.api.auth_api.AuthApi.auth_post_with_http_info",
        new=AsyncMock(side_effect=ApiException(status=401, reason="Unauthorized")),
    )

    with pytest.raises(AuthInitFailed):
        await client.auth_init("idm_admin")

    method_mock.assert_awaited_once()
