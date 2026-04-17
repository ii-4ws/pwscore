"""Shannon entropy over the observed character distribution.

H = -Σ p_i * log2(p_i), multiplied by length to report bits.

This is a better baseline than naive charset entropy because it responds to
actual character repetition ("aaaaaaaa" scores 0 bits/char, not 4.7). It
still overestimates attacker cost because it does not model the English
language, leet substitution, or dictionary structure.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_bits_per_char(pw: str) -> float:
    if not pw:
        return 0.0
    counts = Counter(pw)
    total = len(pw)
    h = 0.0
    for n in counts.values():
        p = n / total
        h -= p * math.log2(p)
    return h


def shannon_entropy(pw: str) -> float:
    """Total Shannon entropy in bits (H * length)."""
    return shannon_bits_per_char(pw) * len(pw)
