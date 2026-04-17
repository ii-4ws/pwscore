"""Train a small character-level Markov model on a breach wordlist.

Output is a JSON file committed at src/pwscore/data/markov_rockyou.json, read
at runtime by pwscore.entropy.markov. The model is order-k by default, stored
as a flat mapping of (k-gram) -> {next_char: probability}. Start/end symbols
are encoded as "^" and "$" — any occurrence of these in an input password is
mapped to the highest-probability printable character before scoring, which is
an acceptable approximation for a scorer (this is not a generator).

Run:
    python benchmarks/train_markov.py \
        --input benchmarks/data/rockyou_top1m.txt \
        --output src/pwscore/data/markov_rockyou.json \
        --order 3
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter, defaultdict
from pathlib import Path

START = "^"
END = "$"


def train(path: Path, order: int) -> tuple[dict[str, dict[str, float]], dict[str, int]]:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    total: Counter[str] = Counter()
    lines = 0
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw or len(pw) < 1:
                continue
            seq = START * order + pw + END
            for i in range(len(seq) - order):
                ctx = seq[i : i + order]
                nxt = seq[i + order]
                counts[ctx][nxt] += 1
                total[ctx] += 1
            lines += 1
            if lines % 100_000 == 0:
                print(f"  {lines:>7} lines trained", file=sys.stderr)

    print(f"trained on {lines} passwords, {len(counts)} contexts", file=sys.stderr)

    # Smoothed probabilities: add-one over the alphabet of observed next chars
    # per context. A fully general add-one over all printable ASCII would bloat
    # the file; since we only need a lower bound on P(pw), observed-alphabet
    # smoothing is sufficient for our scorer.
    probs: dict[str, dict[str, float]] = {}
    for ctx, nxt_counts in counts.items():
        denom = total[ctx] + len(nxt_counts)
        probs[ctx] = {c: (n + 1) / denom for c, n in nxt_counts.items()}

    meta = {"order": order, "contexts": len(counts), "trained_on": lines}
    return probs, meta


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--order", type=int, default=3)
    p.add_argument(
        "--min-count",
        type=int,
        default=2,
        help="Drop context/next_char pairs with fewer than this many observations (shrinks the JSON).",
    )
    args = p.parse_args()

    if not args.input.exists():
        sys.exit(f"input not found: {args.input}")

    # Count first with the full alphabet so we can apply min-count after.
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    lines = 0
    with args.input.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if not pw:
                continue
            seq = START * args.order + pw + END
            for i in range(len(seq) - args.order):
                counts[seq[i : i + args.order]][seq[i + args.order]] += 1
            lines += 1
            if lines % 100_000 == 0:
                print(f"  {lines:>7} lines trained", file=sys.stderr)

    # Apply min-count pruning.
    pruned: dict[str, dict[str, int]] = {}
    total_after: dict[str, int] = {}
    for ctx, nxt in counts.items():
        filtered = {c: n for c, n in nxt.items() if n >= args.min_count}
        if filtered:
            pruned[ctx] = filtered
            total_after[ctx] = sum(filtered.values())

    # Smoothed probabilities.
    probs: dict[str, dict[str, float]] = {}
    for ctx, nxt in pruned.items():
        denom = total_after[ctx] + len(nxt)
        probs[ctx] = {c: (n + 1) / denom for c, n in nxt.items()}

    # Global fallback probability used when a context is absent at scoring
    # time. Chosen conservatively as log2 of a value small enough to make
    # unseen transitions expensive but not catastrophic.
    fallback = 1.0 / (sum(total_after.values()) or 1)

    out = {
        "order": args.order,
        "fallback": fallback,
        "fallback_bits": -math.log2(fallback),
        "contexts": len(probs),
        "trained_on": lines,
        "probs": probs,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as fh:
        json.dump(out, fh, separators=(",", ":"), ensure_ascii=False)
    size_kb = args.output.stat().st_size / 1024
    print(
        f"wrote {args.output} ({size_kb:.1f} KB, {len(probs)} contexts, "
        f"{lines} passwords)",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
