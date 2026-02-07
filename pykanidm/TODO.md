# Pykanidm OpenAPI Plan

The OpenAPI alignment plan captured here has been completed.

Completed:
- Added user-facing `KanidmClient` wrappers for `status` and SCIM GET/list operations.
- Updated OpenAPI tests to use `KanidmClient` methods instead of direct `call_get` fallbacks.
- Reused generated OpenAPI `Entry` models in OAuth2 and service-account raw conversion paths.
- Reused generated OpenAPI `Entry` models in group and person raw conversion paths.
- Added unit tests that verify OpenAPI wrapper delegation in `KanidmClient` without requiring network state.
- Kept OpenAPI test/codegen flow passing under `uv` with strict typing checks.

Current verification commands:
- `uv run pytest -m openapi -vv`
- `uv run mypy --strict tests kanidm`
