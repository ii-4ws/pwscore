"""Pattern detectors that catch guessable structure entropy alone misses.

Each detector returns a reason string if the password matches, else None.
Callers (the analyzer) fold any match into the verdict as a weak-signal reason.
"""

from __future__ import annotations

import re

# US-keyboard rows and columns used for walk detection.
_KEYBOARD_SEQUENCES = [
    "1234567890",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "!@#$%^&*()",
    "1qaz2wsx3edc4rfv",
    "qazwsxedcrfv",
    "qwertyasdfgh",
]

_LEET_MAP = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "7": "t",
    "8": "b",
    "@": "a",
    "$": "s",
    "!": "i",
}

_COMMON_BASE_WORDS = {
    "password",
    "admin",
    "login",
    "welcome",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "hello",
    "iloveyou",
    "football",
    "secret",
    "sunshine",
    "princess",
    "starwars",
    "baseball",
}

_DATE_RE = re.compile(r"(?:19[5-9]\d|20[0-3]\d)")
_ALL_DIGITS_RE = re.compile(r"^\d+$")


def _has_repeats(pw: str, threshold: int = 4) -> str | None:
    run = 1
    prev = ""
    for c in pw:
        if c == prev:
            run += 1
            if run >= threshold:
                return f"contains a run of {run} or more identical characters"
        else:
            run = 1
            prev = c
    return None


def _has_sequence(pw: str, length: int = 4) -> str | None:
    low = pw.lower()
    for seq in _KEYBOARD_SEQUENCES:
        for i in range(len(seq) - length + 1):
            sub = seq[i : i + length]
            if sub in low or sub[::-1] in low:
                return f"contains keyboard or numeric sequence {sub!r}"
    # alphabet sequences
    alpha = "abcdefghijklmnopqrstuvwxyz"
    for i in range(len(alpha) - length + 1):
        sub = alpha[i : i + length]
        if sub in low or sub[::-1] in low:
            return f"contains alphabet sequence {sub!r}"
    return None


def _has_date(pw: str) -> str | None:
    m = _DATE_RE.search(pw)
    return f"contains a year-like token {m.group()!r}" if m else None


def _is_all_digits(pw: str) -> str | None:
    if _ALL_DIGITS_RE.match(pw):
        return "password is entirely digits"
    return None


def _leet_decode(pw: str) -> str:
    return "".join(_LEET_MAP.get(c, c) for c in pw.lower())


def _has_common_base_word(pw: str) -> str | None:
    decoded = _leet_decode(pw)
    for word in _COMMON_BASE_WORDS:
        if word in decoded:
            return f"contains common base word {word!r} (after leet-decoding)"
    return None


DETECTORS = [
    _has_repeats,
    _has_sequence,
    _has_date,
    _is_all_digits,
    _has_common_base_word,
]


def find_patterns(pw: str) -> list[str]:
    """Return every matching pattern reason for the password."""
    if not pw:
        return []
    reasons: list[str] = []
    for detector in DETECTORS:
        result = detector(pw)
        if result:
            reasons.append(result)
    return reasons
