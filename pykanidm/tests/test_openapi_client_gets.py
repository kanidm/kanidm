import uuid

import pytest
from kanidm import KanidmClient


pytestmark = pytest.mark.openapi


def _unique_name(prefix: str) -> str:
    return f"{prefix}{uuid.uuid4().hex[:8]}"


async def test_kanidm_client_starts_with_openapi_client(openapi_client: KanidmClient) -> None:
    assert openapi_client.openapi_client is not None
    if openapi_client.config.uri is None:
        raise ValueError("openapi_client fixture returned a client without URI")
    assert openapi_client.openapi_client.configuration.host == openapi_client.config.uri.rstrip("/")


async def test_openapi_status_get(openapi_client: KanidmClient) -> None:
    status = await openapi_client.status()
    assert isinstance(status, bool)
    assert status is True


async def test_openapi_check_token_valid_for_authenticated_client(openapi_authed_client: KanidmClient) -> None:
    assert await openapi_authed_client.check_token_valid() is True


async def test_openapi_check_token_valid_for_invalid_explicit_token(openapi_authed_client: KanidmClient) -> None:
    assert await openapi_authed_client.check_token_valid("this-is-not-a-valid-token") is False


async def test_openapi_scim_application_list_get(openapi_authed_client: KanidmClient) -> None:
    response = await openapi_authed_client.scim_application_list()
    resources = getattr(response, "resources", None)
    assert isinstance(resources, list)
    assert isinstance(getattr(response, "total_results", None), int)


async def test_openapi_scim_application_id_get_roundtrip(openapi_authed_client: KanidmClient) -> None:
    listing = await openapi_authed_client.scim_application_list()
    resources = getattr(listing, "resources", None)
    assert isinstance(resources, list)
    if not resources:
        pytest.skip("No SCIM applications available to test /scim/v1/Application/{id}")

    raw_app_id = getattr(resources[0], "id", None)
    if not isinstance(raw_app_id, str) or not raw_app_id:
        pytest.skip("SCIM application resource is missing an id")
    app_id = str(raw_app_id)

    response = await openapi_authed_client.scim_application_get(app_id)
    assert getattr(response, "id", None) == app_id


async def test_openapi_group_list_get(openapi_authed_client: KanidmClient) -> None:
    groups = await openapi_authed_client.group_list()
    assert isinstance(groups, list)
    if groups:
        assert isinstance(groups[0].name, str)


async def test_openapi_group_get_by_id_roundtrip(openapi_authed_client: KanidmClient) -> None:
    name = _unique_name("openapitestgroup")
    create_response = await openapi_authed_client.group_create(name)
    assert create_response.status_code == 200
    try:
        group = await openapi_authed_client.group_get(name)
        assert group.name == name
    finally:
        await openapi_authed_client.group_delete(name)


async def test_openapi_person_list_get(openapi_authed_client: KanidmClient) -> None:
    persons = await openapi_authed_client.person_account_list()
    assert isinstance(persons, list)
    if persons:
        assert isinstance(persons[0].name, str)


async def test_openapi_person_get_by_id_roundtrip(openapi_authed_client: KanidmClient) -> None:
    name = _unique_name("openapitestperson")
    display = f"OpenAPI Test {name}"
    create_response = await openapi_authed_client.person_account_create(name=name, displayname=display)
    assert create_response.status_code == 200
    try:
        person = await openapi_authed_client.person_account_get(name)
        assert person.name == name
        assert person.displayname == display
    finally:
        await openapi_authed_client.person_account_delete(name)


async def test_openapi_oauth2_list_get(openapi_authed_client: KanidmClient) -> None:
    items = await openapi_authed_client.oauth2_rs_list()
    assert isinstance(items, list)
    if items:
        assert isinstance(items[0].name, str)


async def test_openapi_service_account_list_get(openapi_authed_client: KanidmClient) -> None:
    accounts = await openapi_authed_client.service_account_list()
    assert isinstance(accounts, list)
    if accounts:
        assert isinstance(accounts[0].name, str)


async def test_openapi_service_account_get_by_id_roundtrip(openapi_authed_client: KanidmClient) -> None:
    name = _unique_name("openapitestsa")
    display = f"OpenAPI Service {name}"
    create_response = await openapi_authed_client.service_account_create(name=name, displayname=display)
    assert create_response.status_code == 200
    try:
        account = await openapi_authed_client.service_account_get(name)
        assert account.name == name
        assert account.spn == f"{name}@localhost"
        if account.displayname is not None:
            assert account.displayname == display
    finally:
        await openapi_authed_client.service_account_delete(name)
