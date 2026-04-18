"""HaveIBeenPwned Pwned-Passwords k-anonymity client.

The API (api.pwnedpasswords.com/range/{first_5_of_sha1}) accepts only the
first 5 hex characters of the password's SHA1 and returns every matching
suffix with its breach count. The password itself never leaves this process.

Docs: https://haveibeenpwned.com/API/v3#PwnedPasswords
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

import httpx

HIBP_URL = "https://api.pwnedpasswords.com/range/{prefix}"
DEFAULT_TIMEOUT_S = 5.0
USER_AGENT = "pwscore/0.1 (+https://github.com/ii-4ws/pwscore)"


@dataclass(frozen=True)
class HibpResult:
    pwned: bool
    count: int
    """Times this password has appeared across known breaches. 0 when not seen."""


def _sha1_hex(pw: str) -> str:
    return hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()


def _find_in_range(suffix: str, body: str) -> int:
    # Response body is lines of "SUFFIX:COUNT\r\n".
    for line in body.splitlines():
        if ":" not in line:
            continue
        s, _, c = line.partition(":")
        if s.strip().upper() == suffix:
            try:
                return int(c.strip())
            except ValueError:
                return 0
    return 0


async def check_hibp(
    pw: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> HibpResult:
    if not pw:
        return HibpResult(pwned=False, count=0)

    digest = _sha1_hex(pw)
    prefix, suffix = digest[:5], digest[5:]
    url = HIBP_URL.format(prefix=prefix)

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Add-Padding": "true"},
        )
    try:
        resp = await client.get(url)  # type: ignore[union-attr]
        resp.raise_for_status()
        count = _find_in_range(suffix, resp.text)
        return HibpResult(pwned=count > 0, count=count)
    finally:
        if owns_client:
            await client.aclose()  # type: ignore[union-attr]
