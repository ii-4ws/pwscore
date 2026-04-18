"""Bloom-filter-backed membership check against the RockYou top-10k.

The filter is built by benchmarks/build_bloom.py and shipped inside the
package. A positive result means the password is almost certainly in the
top-10k of the 2009 RockYou breach (false positive rate ~0.1%).
"""

from __future__ import annotations

from functools import cache
from importlib.resources import files

from pybloom_live import BloomFilter


@cache
def _bloom() -> BloomFilter:
    path = files("pwscore.data") / "rockyou_top10k.bloom"
    with path.open("rb") as fh:
        return BloomFilter.fromfile(fh)


def is_common(pw: str) -> bool:
    if not pw:
        return False
    return pw in _bloom()


def is_common_case_insensitive(pw: str) -> bool:
    """Check both as-is and lowercased. Captures trivial recapitalisations
    like 'Password' of 'password'."""
    if not pw:
        return False
    bf = _bloom()
    return pw in bf or pw.lower() in bf
