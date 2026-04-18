import pytest

from pwscore.analyzer import analyze, analyze_sync
from pwscore.models import Verdict

WEAK = [
    "password",
    "123456",
    "qwerty",
    "iloveyou",
    "letmein",
    "Password1!",
    "P@ssw0rd!",
    "qwerty123",
    "aaaaaaaa",
    "Summer2024!",
    "12345678",
    "admin",
    "dragon",
]

STRONG = [
    "correct horse battery staple",
    "Xq7!mZ#p9kLwRt$2pL-7bNx",
    "Tr0ub4dor&3xkcd#7aaW!",
    "8$vN!oQp#Rz@kXy^Gb3Fu",
]


@pytest.mark.asyncio
async def test_empty_is_weak() -> None:
    r = await analyze("", skip_hibp=True)
    assert r.verdict == Verdict.weak
    assert r.length == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("pw", WEAK)
async def test_weak_passwords_are_weak(pw: str) -> None:
    r = await analyze(pw, skip_hibp=True)
    assert r.verdict == Verdict.weak, (
        f"{pw!r} should be weak, got {r.verdict} | reasons={r.reasons}"
    )
    assert r.reasons, f"{pw!r} classified weak but no reasons given"


@pytest.mark.asyncio
@pytest.mark.parametrize("pw", STRONG)
async def test_strong_passwords_are_not_weak(pw: str) -> None:
    r = await analyze(pw, skip_hibp=True)
    # Fair or strong is fine; must not be weak.
    assert r.verdict != Verdict.weak, f"{pw!r} should not be weak. reasons={r.reasons}"


@pytest.mark.asyncio
async def test_worst_signal_wins() -> None:
    # "Password1!" looks strong by charset (~65 bits) and passes Markov,
    # but zxcvbn dictionary attack catches it fast AND a pattern catches
    # "password". Should still be weak.
    r = await analyze("Password1!", skip_hibp=True)
    assert r.verdict == Verdict.weak


def test_sync_wrapper_works() -> None:
    r = analyze_sync("password", skip_hibp=True)
    assert r.verdict == Verdict.weak
