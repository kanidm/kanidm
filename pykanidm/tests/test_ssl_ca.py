"""tests ssl validation and CA setting etc"""

import logging
from pathlib import Path
from ssl import SSLCertVerificationError

import aiohttp
import aiohttp.client_exceptions

import pytest


from kanidm import KanidmClient


async def _check_token_valid_with_cleanup(client: KanidmClient) -> bool:
    async with client.openapi_client:
        return await client.check_token_valid()


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_valid() -> None:
    """tests a valid connection"""

    url = "https://badssl.com"

    client = KanidmClient(
        uri=url,
    )

    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed() -> None:
    """tests with a self-signed cert"""

    url = "https://self-signed.badssl.com"

    logging.debug("testing self.?signed cert with defaults and expecting an error")
    client = KanidmClient(
        uri=url,
    )
    with pytest.raises(aiohttp.client_exceptions.ClientConnectorCertificateError):
        await _check_token_valid_with_cleanup(client)


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed_with_verify() -> None:
    """tests with a self-signed cert"""

    client = KanidmClient(
        uri="https://self-signed.badssl.com",
        verify_certificate=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed_no_verify_certificate() -> None:
    """tests with a self-signed cert"""

    client = KanidmClient(
        uri="https://self-signed.badssl.com",
        verify_certificate=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_throws_error() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    client = KanidmClient(uri="https://wrong.host.badssl.com/", verify_hostnames=True)
    with pytest.raises(
        aiohttp.client_exceptions.ClientConnectorCertificateError,
        match="Cannot connect to host wrong.host.badssl.com:443",
    ):
        await _check_token_valid_with_cleanup(client)


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_dont_verify_hostnames() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    client = KanidmClient(
        uri="https://wrong.host.badssl.com/",
        verify_hostnames=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_verify_certificate() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    client = KanidmClient(
        uri="https://wrong.host.badssl.com/",
        verify_hostnames=False,
        verify_certificate=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_revoked() -> None:
    """tests with a revoked certificate"""

    client = KanidmClient(
        uri="https://revoked.badssl.com/",
        verify_certificate=True,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False

    client = KanidmClient(
        uri="https://revoked.badssl.com/",
        verify_certificate=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_expired() -> None:
    """tests with an expired certificate"""

    client = KanidmClient(
        uri="https://expired.badssl.com/",
    )
    with pytest.raises(
        aiohttp.client_exceptions.ClientConnectorCertificateError,
        match="certificate verify failed: certificate has expired",
    ):
        await _check_token_valid_with_cleanup(client)


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_expired_ignore() -> None:
    """tests with an expired certificate"""

    client = KanidmClient(
        uri="https://expired.badssl.com/",
        verify_certificate=False,
    )
    result = await _check_token_valid_with_cleanup(client)
    assert result is False


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_untrusted_root_throws() -> None:
    """tests with an untrusted root, which should throw an error"""

    client = KanidmClient(
        uri="https://untrusted-root.badssl.com/",
    )
    with pytest.raises((SSLCertVerificationError, aiohttp.client_exceptions.ClientConnectorCertificateError)):
        await _check_token_valid_with_cleanup(client)


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_untrusted_root_configured() -> None:
    """tests with an untrusted root, which should throw an error"""

    testcert = Path("./tests/badssl_trusted_ca.pem").resolve()

    if not testcert.exists():
        pytest.skip(f"The trusted cert is missing from {testcert}")  # type: ignore[call-non-callable]

    client = KanidmClient(
        uri="https://untrusted-root.badssl.com/",
        ca_path=testcert.resolve().as_posix(),
    )
    with pytest.raises(
        aiohttp.client_exceptions.ClientConnectorCertificateError,
        match="certificate verify failed: self.?signed certificate in certificate chain",
    ):
        await _check_token_valid_with_cleanup(client)
