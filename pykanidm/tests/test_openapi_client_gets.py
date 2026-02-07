import uuid
from typing import Any

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


async def test_openapi_status_get(openapi_api_client: Any) -> None:
    from kanidm_openapi_client.api.system_api import SystemApi

    api = SystemApi(openapi_api_client)
    response = await api.status_with_http_info()
    assert response.status_code == 200
    assert isinstance(response.data, bool)
    assert response.data is True


async def test_openapi_scim_application_list_get(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.scim_api import ScimApi

    api = ScimApi(openapi_api_client_authed)
    response = await api.scim_application_get_with_http_info()
    assert response.status_code == 200
    assert response.data is not None
    assert isinstance(getattr(response.data, "resources", None), list)
    assert isinstance(getattr(response.data, "total_results", None), int)


async def test_openapi_scim_application_id_get_roundtrip(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.scim_api import ScimApi

    api = ScimApi(openapi_api_client_authed)
    listing = await api.scim_application_get()
    resources = getattr(listing, "resources", None)
    assert isinstance(resources, list)
    if not resources:
        pytest.skip("No SCIM applications available to test /scim/v1/Application/{id}")

    app_id = getattr(resources[0], "id", None)
    if not isinstance(app_id, str) or not app_id:
        pytest.skip("SCIM application resource is missing an id")

    response = await api.scim_application_id_get_with_http_info(app_id)
    assert response.status_code == 200
    assert response.data is not None
    assert getattr(response.data, "id", None) == app_id


async def test_openapi_group_list_get(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_group_api import V1GroupApi

    api = V1GroupApi(openapi_api_client_authed)
    groups = await api.group_get()
    assert isinstance(groups, list)
    if groups:
        assert hasattr(groups[0], "attrs")


async def test_openapi_group_get_by_id_roundtrip(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_group_api import V1GroupApi
    from kanidm_openapi_client.models.entry import Entry

    api = V1GroupApi(openapi_api_client_authed)
    name = _unique_name("openapitestgroup")
    await api.group_post(Entry(attrs={"name": [name]}))
    try:
        group = await api.group_id_get(name)
        assert group.attrs.get("name", [None])[0] == name
    finally:
        await api.group_id_delete(name)


async def test_openapi_person_list_get(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_person_api import V1PersonApi

    api = V1PersonApi(openapi_api_client_authed)
    persons = await api.person_get()
    assert isinstance(persons, list)
    if persons:
        assert hasattr(persons[0], "attrs")


async def test_openapi_person_get_by_id_roundtrip(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_person_api import V1PersonApi
    from kanidm_openapi_client.models.entry import Entry

    api = V1PersonApi(openapi_api_client_authed)
    name = _unique_name("openapitestperson")
    display = f"OpenAPI Test {name}"
    await api.person_post(Entry(attrs={"name": [name], "displayname": [display]}))
    try:
        person = await api.person_id_get(name)
        assert person.attrs.get("name", [None])[0] == name
        assert person.attrs.get("displayname", [None])[0] == display
    finally:
        await api.person_id_delete(name)


async def test_openapi_oauth2_list_get(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_oauth2_api import V1Oauth2Api

    api = V1Oauth2Api(openapi_api_client_authed)
    items = await api.oauth2_get()
    assert isinstance(items, list)


async def test_openapi_service_account_list_get(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_service_account_api import V1ServiceAccountApi

    api = V1ServiceAccountApi(openapi_api_client_authed)
    accounts = await api.service_account_get()
    assert isinstance(accounts, list)


async def test_openapi_service_account_get_by_id_roundtrip(openapi_api_client_authed: Any) -> None:
    from kanidm_openapi_client.api.v1_service_account_api import V1ServiceAccountApi
    from kanidm_openapi_client.models.entry import Entry

    api = V1ServiceAccountApi(openapi_api_client_authed)
    name = _unique_name("openapitestsa")
    display = f"OpenAPI Service {name}"
    await api.service_account_post(Entry(attrs={"name": [name], "displayname": [display]}))
    try:
        account = await api.service_account_id_get(name)
        assert account.attrs.get("name", [None])[0] == name
        if "displayname" in account.attrs:
            assert account.attrs.get("displayname", [None])[0] == display
    finally:
        await api.service_account_id_delete(name)
