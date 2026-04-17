"""Character-level Markov password entropy.

Loads an order-k transition table trained by benchmarks/train_markov.py and
scores a password as:

    bits = Σ -log2( P(c_i | c_{i-k}..c_{i-1}) )

Missing contexts and missing transitions fall back to the global fallback
probability stored in the trained file. Start/end symbols ^/$ pad every
input, so short passwords are still scored consistently.

This is the scorer that actually correlates with attacker cost — a 10-char
password made of English bigrams costs almost nothing vs a 10-char random
string, and the Markov scorer reflects that while the naive charset formula
does not.
"""

from __future__ import annotations

import json
import math
from functools import cache
from importlib.resources import files
from typing import Any

START = "^"
END = "$"


@cache
def _load_model() -> dict[str, Any]:
    path = files("pwscore.data") / "markov_rockyou.json"
    with path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def markov_entropy(pw: str) -> float:
    if not pw:
        return 0.0
    model = _load_model()
    order: int = model["order"]
    probs: dict[str, dict[str, float]] = model["probs"]
    fallback: float = model["fallback"]

    seq = START * order + pw + END
    total_bits = 0.0
    for i in range(len(seq) - order):
        ctx = seq[i : i + order]
        nxt = seq[i + order]
        ctx_probs = probs.get(ctx)
        if ctx_probs is None:
            p = fallback
        else:
            p = ctx_probs.get(nxt, fallback)
        total_bits += -math.log2(p)
    return total_bits


def markov_bits_per_char(pw: str) -> float:
    if not pw:
        return 0.0
    return markov_entropy(pw) / len(pw)
