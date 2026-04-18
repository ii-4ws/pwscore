"""Thin wrapper over zxcvbn to normalize its output shape.

zxcvbn is the de-facto industry strength estimator (Dropbox, 1Password, etc.).
It runs dictionary/pattern/repeat/sequence/keyboard/date detectors and gives a
guess count, which we convert to log2 guesses for a bits-equivalent number.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from zxcvbn import zxcvbn


@dataclass(frozen=True)
class ZxcvbnResult:
    score: int  # 0..4
    guesses: float
    guesses_log2: float
    crack_time_offline_fast_hash_display: str
    warning: str
    suggestions: list[str]


def run_zxcvbn(pw: str) -> ZxcvbnResult:
    if not pw:
        return ZxcvbnResult(0, 0.0, 0.0, "instant", "Empty password.", [])
    r = zxcvbn(pw)
    guesses = float(r["guesses"])
    return ZxcvbnResult(
        score=int(r["score"]),
        guesses=guesses,
        guesses_log2=math.log2(guesses) if guesses > 0 else 0.0,
        crack_time_offline_fast_hash_display=str(
            r["crack_times_display"]["offline_fast_hashing_1e10_per_second"]
        ),
        warning=str(r["feedback"].get("warning") or ""),
        suggestions=list(r["feedback"].get("suggestions") or []),
    )
