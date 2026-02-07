"""Helpers for the OpenAPI-generated client."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from . import KanidmClient
from .types import KanidmClientConfig

try:
    from kanidm_openapi_client import ApiClient, Configuration
except ImportError as exc:  # pragma: no cover - packaged with project
    raise ImportError("kanidm_openapi_client is not available; re-run OpenAPI codegen") from exc


def openapi_configuration_from_client_config(config: KanidmClientConfig) -> Configuration:
    """Create an OpenAPI Configuration from a KanidmClientConfig."""
    if config.uri is None:
        raise ValueError("KanidmClientConfig.uri must be set")

    host = config.uri.rstrip("/")
    configuration = Configuration(host=host)

    verify_ssl = config.verify_certificate and config.verify_ca
    configuration.verify_ssl = verify_ssl
    if config.ca_path is not None:
        configuration.ssl_ca_cert = config.ca_path
    if config.auth_token is not None:
        configuration.access_token = config.auth_token

    return configuration


def openapi_client_from_client_config(config: KanidmClientConfig) -> ApiClient:
    """Create an OpenAPI ApiClient from a KanidmClientConfig."""
    return ApiClient(configuration=openapi_configuration_from_client_config(config))


def openapi_client_from_kanidm_client(client: "KanidmClient") -> ApiClient:
    """Create an OpenAPI ApiClient from a KanidmClient instance."""
    return openapi_client_from_client_config(client.config)


__all__ = [
    "ApiClient",
    "Configuration",
    "openapi_client_from_client_config",
    "openapi_client_from_kanidm_client",
    "openapi_configuration_from_client_config",
]
