"""Naive character-class entropy, kept as a baseline for comparison.

This is the textbook formula E = L * log2(N), where N is the charset size
implied by the classes present in the password. It assumes the password was
drawn uniformly at random from that charset. Real passwords are not drawn
uniformly at random, so this dramatically overestimates strength against a
real attacker. The benchmark suite quantifies exactly how badly.

Preserved here so the benchmark can compare every other scorer against the
same formula an undergraduate security course teaches.
"""

from __future__ import annotations

import math

_SYMBOL_CHARSET_SIZE = 32


def _has_lower(pw: str) -> bool:
    return any("a" <= c <= "z" for c in pw)


def _has_upper(pw: str) -> bool:
    return any("A" <= c <= "Z" for c in pw)


def _has_digit(pw: str) -> bool:
    return any("0" <= c <= "9" for c in pw)


def _has_symbol(pw: str) -> bool:
    return any(not c.isalnum() for c in pw)


def charset_size(pw: str) -> int:
    size = 0
    if _has_lower(pw):
        size += 26
    if _has_upper(pw):
        size += 26
    if _has_digit(pw):
        size += 10
    if _has_symbol(pw):
        size += _SYMBOL_CHARSET_SIZE
    return size


def naive_charset_entropy(pw: str) -> float:
    """Maximum theoretical entropy assuming uniform random draw from the
    inferred charset. Returns bits. Returns 0.0 for empty input."""
    if not pw:
        return 0.0
    n = charset_size(pw)
    if n == 0:
        return 0.0
    return len(pw) * math.log2(n)
