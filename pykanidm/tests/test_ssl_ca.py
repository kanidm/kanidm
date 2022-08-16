""" tests ssl validation and CA setting etc """

from pathlib import Path

import aiohttp
import aiohttp.client_exceptions

import pytest


from kanidm import KanidmClient


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_valid() -> None:
    """tests a valid connection"""

    url = "https://badssl.com"

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri=url,
            session=session,
        )

        result = await client.call_get("/")
        assert result.content
        print(f"{result.status_code=}")


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed() -> None:
    """tests with a self-signed cert"""

    url = "https://self-signed.badssl.com"

    async with aiohttp.ClientSession() as session:
        print("testing self signed cert with defaults and expecting an error")
        client = KanidmClient(
            uri=url,
            session=session,
        )
        with pytest.raises(aiohttp.client_exceptions.ClientConnectorCertificateError):
            await client.call_get("/")


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed_with_verify() -> None:
    """tests with a self-signed cert"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://self-signed.badssl.com",
            session=session,
            verify_certificate=False,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_self_signed_no_verify_certificate() -> None:
    """tests with a self-signed cert"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://self-signed.badssl.com",
            session=session,
            verify_certificate=False,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_throws_error() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://wrong.host.badssl.com/", session=session, verify_hostnames=True
        )
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError,
            match="Cannot connect to host wrong.host.badssl.com:443",
        ):
            result = await client.call_get("/")
            assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_dont_verify_hostnames() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://wrong.host.badssl.com/",
            session=session,
            verify_hostnames=False,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_wrong_hostname_verify_certificate() -> None:
    """tests with validate hostnames and wrong hostname in the cert"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://wrong.host.badssl.com/",
            session=session,
            verify_hostnames=False,
            verify_certificate=False,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_revoked() -> None:
    """tests with a revoked certificate, it'll pass but one day this should be a thing"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://revoked.badssl.com/",
            session=session,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_expired() -> None:
    """tests with an expired certificate"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://expired.badssl.com/",
            session=session,
        )
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError,
            match="certificate verify failed: certificate has expired",
        ):
            result = await client.call_get("/")
            assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_expired_ignore() -> None:
    """tests with an expired certificate"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://expired.badssl.com/",
            session=session,
            verify_certificate=False,
        )
        result = await client.call_get("/")
        assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_untrusted_root_throws() -> None:
    """tests with an untrusted root, which should throw an error"""

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://untrusted-root.badssl.com/",
            session=session,
        )
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError,
            match="certificate verify failed: self signed certificate in certificate chain",
        ):
            result = await client.call_get("/")
            assert result.content


@pytest.mark.network
@pytest.mark.asyncio
async def test_ssl_untrusted_root_configured() -> None:
    """tests with an untrusted root, which should throw an error"""

    testcert = Path("./tests/badssl_trusted_ca.pem").resolve()

    if not testcert.exists():
        pytest.skip(f"The trusted cert is missing from {testcert}")

    async with aiohttp.ClientSession() as session:
        client = KanidmClient(
            uri="https://untrusted-root.badssl.com/",
            session=session,
            ca_path=testcert.resolve().as_posix(),
        )
        with pytest.raises(
            aiohttp.client_exceptions.ClientConnectorCertificateError,
            match="certificate verify failed: self signed certificate in certificate chain",
        ):
            result = await client.call_get("/")
            assert result.content
