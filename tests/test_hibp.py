import hashlib

import httpx
import pytest
import respx

from pwscore.checks.hibp import HIBP_URL, check_hibp


def _sha1_parts(pw: str) -> tuple[str, str]:
    d = hashlib.sha1(pw.encode()).hexdigest().upper()
    return d[:5], d[5:]


@pytest.mark.asyncio
@respx.mock
async def test_pwned_password_is_detected() -> None:
    pw = "password"
    prefix, suffix = _sha1_parts(pw)
    body = f"{suffix}:847223\r\nOTHERSUFFIXX:1\r\n"
    respx.get(HIBP_URL.format(prefix=prefix)).respond(200, text=body)

    result = await check_hibp(pw)
    assert result.pwned is True
    assert result.count == 847223


@pytest.mark.asyncio
@respx.mock
async def test_unpwned_password_returns_zero() -> None:
    pw = "Xq7!mZ#p9kLwRt$2pL-7bNxyz"
    prefix, _ = _sha1_parts(pw)
    respx.get(HIBP_URL.format(prefix=prefix)).respond(
        200, text="UNRELATEDSUFFIX:12\r\nANOTHERONE:5\r\n"
    )

    result = await check_hibp(pw)
    assert result.pwned is False
    assert result.count == 0


@pytest.mark.asyncio
async def test_empty_skips_network() -> None:
    # Should never dial the API for an empty input.
    result = await check_hibp("")
    assert result.pwned is False
    assert result.count == 0


@pytest.mark.asyncio
@respx.mock
async def test_http_error_propagates() -> None:
    pw = "password"
    prefix, _ = _sha1_parts(pw)
    respx.get(HIBP_URL.format(prefix=prefix)).respond(503, text="upstream down")

    with pytest.raises(httpx.HTTPStatusError):
        await check_hibp(pw)
