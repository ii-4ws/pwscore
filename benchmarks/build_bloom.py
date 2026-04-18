"""Build a bloom filter of the RockYou top-N for fast wordlist membership.

A 10k-entry bloom at 0.1% error is ~18 KB on disk. Loaded at startup, the
wordlist check is O(1) per query with no disk IO on the hot path.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from pybloom_live import BloomFilter


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--input", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.add_argument("--capacity", type=int, default=10_000)
    p.add_argument("--error-rate", type=float, default=0.001)
    args = p.parse_args()

    if not args.input.exists():
        sys.exit(f"input not found: {args.input}")

    bf = BloomFilter(capacity=args.capacity, error_rate=args.error_rate)
    count = 0
    with args.input.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            pw = line.rstrip("\n\r")
            if pw:
                bf.add(pw)
                count += 1
            if count >= args.capacity:
                break

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("wb") as fh:
        bf.tofile(fh)

    size_kb = args.output.stat().st_size / 1024
    print(
        f"wrote {args.output} ({size_kb:.1f} KB, {count} entries, "
        f"error rate {args.error_rate})",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
