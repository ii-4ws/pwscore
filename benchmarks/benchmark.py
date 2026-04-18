"""Benchmark every analyzer against the RockYou top-10k (the "attack set")
and against a handcrafted set of passwords a security-aware user might
pick (the "good set"). Produces benchmarks/results/report.md.

The point of the benchmark is to turn the claim "naive charset entropy is
broken" into a number. We measure false-strong rate — how often each
analyzer calls a known-breach password strong — and true-strong rate on the
good set.

The HIBP lookup is intentionally omitted from this offline benchmark so the
numbers reproduce without the network. The wordlist bloom filter naturally
catches the attack set by design; it is included to show the end-to-end
pwscore verdict.
"""

from __future__ import annotations

import argparse
import math
import random
import statistics
import sys
from dataclasses import dataclass, field
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from tqdm import tqdm  # noqa: E402

from pwscore.analyzer import analyze_sync
from pwscore.checks.patterns import find_patterns
from pwscore.checks.wordlist import is_common_case_insensitive
from pwscore.checks.zxcvbn_wrap import run_zxcvbn
from pwscore.entropy.charset import naive_charset_entropy
from pwscore.entropy.markov import markov_entropy
from pwscore.entropy.shannon import shannon_entropy

ROOT = Path(__file__).resolve().parent

# Thresholds for "is this analyzer calling the password strong?". The
# "csci262" threshold reproduces the exact rule the original undergraduate
# script used (charset entropy >= 30 bits). The "generous" threshold
# (60 bits) is what a better-informed user might pick if they still trusted
# charset entropy. Both are reported so the failure of the formula is
# visible at any reasonable threshold.
STRONG_CHARSET_CSCI262_BITS = 30.0
STRONG_CHARSET_GENEROUS_BITS = 60.0
STRONG_SHANNON_BITS = 40.0
STRONG_MARKOV_BITS = 60.0
STRONG_ZXCVBN_SCORE = 3

GOOD_SET = [
    "correct horse battery staple",
    "Xq7!mZ#p9kLwRt$2pL-7bNx",
    "Tr0ub4dor&3xkcd#7aaW!",
    "8$vN!oQp#Rz@kXy^Gb3Fu",
    "S3nd-Me-C0ffee-At-6am!",
    "jdk_v21.0.4+zulu-ubuntu-arm64",
    "cephalopod-ferrocene-narwhal-plethora",
    "unguent-hatrack-biome-pulchritude!7",
    "molten_kiwi.Orion$brass+Palladium",
    "9#tRk!fHm^uXi@zPw7%vLb3",
]


@dataclass
class BenchmarkRow:
    name: str
    strong_on_attack: int = 0
    strong_on_good: int = 0
    scores_attack: list[float] = field(default_factory=list)
    scores_good: list[float] = field(default_factory=list)


def _load_attack_set(path: Path, sample: int | None, seed: int) -> list[str]:
    lines = [ln.rstrip("\r\n") for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]
    if sample and sample < len(lines):
        rng = random.Random(seed)
        return rng.sample(lines, sample)
    return lines


def _pct(num: int, denom: int) -> str:
    return f"{100.0 * num / denom:.1f}%" if denom else "—"


def _summary(scores: list[float]) -> str:
    if not scores:
        return "—"
    return (
        f"mean={statistics.mean(scores):.1f} "
        f"median={statistics.median(scores):.1f} "
        f"p95={statistics.quantiles(scores, n=20)[-1]:.1f}"
    )


def _slug(name: str) -> str:
    return (
        name.lower()
        .replace(" ", "_")
        .replace("(", "")
        .replace(")", "")
        .replace(",", "")
    )


def _plot_distributions(rows: list[BenchmarkRow], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for row in rows:
        if not row.scores_attack or not row.scores_good:
            continue
        fig, ax = plt.subplots(figsize=(8, 4))
        ax.hist(row.scores_attack, bins=40, alpha=0.6, label="RockYou top-10k")
        ax.hist(row.scores_good, bins=10, alpha=0.6, label="good set")
        ax.set_xlabel(row.name)
        ax.set_ylabel("count")
        ax.set_title(f"score distribution: {row.name}")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / f"{_slug(row.name)}.png", dpi=120)
        plt.close(fig)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument(
        "--attack-set",
        type=Path,
        default=ROOT / "data" / "rockyou_top10k.txt",
        help="Newline-delimited attack wordlist (default: RockYou top-10k).",
    )
    p.add_argument("--sample", type=int, default=2000, help="Sample size from the attack set.")
    p.add_argument("--seed", type=int, default=1234)
    p.add_argument(
        "--output",
        type=Path,
        default=ROOT / "results" / "report.md",
    )
    p.add_argument(
        "--plots",
        type=Path,
        default=ROOT / "results" / "plots",
    )
    args = p.parse_args()

    if not args.attack_set.exists():
        sys.exit(f"attack set not found: {args.attack_set}")

    attack = _load_attack_set(args.attack_set, args.sample, args.seed)
    good = GOOD_SET

    rows = [
        BenchmarkRow("charset_bits (csci262 threshold, 30)"),
        BenchmarkRow("charset_bits (generous threshold, 60)"),
        BenchmarkRow("shannon_bits"),
        BenchmarkRow("markov_bits"),
        BenchmarkRow("zxcvbn_log2_guesses"),
        BenchmarkRow("pwscore_combined"),
    ]

    def _record(pw: str, on_good: bool) -> None:
        cs = naive_charset_entropy(pw)
        sh = shannon_entropy(pw)
        mk = markov_entropy(pw)
        zr = run_zxcvbn(pw)
        zl = zr.guesses_log2

        strong_cs_csci = cs >= STRONG_CHARSET_CSCI262_BITS
        strong_cs_gen = cs >= STRONG_CHARSET_GENEROUS_BITS
        strong_sh = sh >= STRONG_SHANNON_BITS
        strong_mk = mk >= STRONG_MARKOV_BITS
        strong_zx = zr.score >= STRONG_ZXCVBN_SCORE
        strong_pw = (
            not is_common_case_insensitive(pw)
            and not find_patterns(pw)
            and mk >= STRONG_MARKOV_BITS
            and zr.score >= STRONG_ZXCVBN_SCORE
        )

        for row, score, strong in [
            (rows[0], cs, strong_cs_csci),
            (rows[1], cs, strong_cs_gen),
            (rows[2], sh, strong_sh),
            (rows[3], mk, strong_mk),
            (rows[4], zl, strong_zx),
            (rows[5], float(zr.score), strong_pw),
        ]:
            (row.scores_good if on_good else row.scores_attack).append(score)
            if strong:
                if on_good:
                    row.strong_on_good += 1
                else:
                    row.strong_on_attack += 1

    print("scoring attack set ...", file=sys.stderr)
    for pw in tqdm(attack, unit="pw"):
        _record(pw, on_good=False)
    print("scoring good set ...", file=sys.stderr)
    for pw in tqdm(good, unit="pw"):
        _record(pw, on_good=True)

    _plot_distributions(rows, args.plots)

    n_attack = len(attack)
    n_good = len(good)

    lines: list[str] = []
    lines.append("# pwscore benchmark\n")
    lines.append(
        f"Attack set: RockYou top-10k, sample {n_attack} (seed {args.seed}). "
        f"Good set: {n_good} handcrafted strong passwords.\n"
    )
    lines.append(
        "A high _false-strong rate_ on the attack set means the analyzer is "
        "fooled by popular breached passwords. A high _true-strong rate_ on the "
        "good set means it correctly recognises well-chosen passwords.\n"
    )
    lines.append("## Headline\n")
    lines.append(
        "| analyzer | false-strong on RockYou top-10k | true-strong on good set | score distribution (attack set) |\n"
        "|---|---|---|---|\n"
    )
    for row in rows:
        lines.append(
            f"| `{row.name}` | {_pct(row.strong_on_attack, n_attack)} "
            f"({row.strong_on_attack}/{n_attack}) | "
            f"{_pct(row.strong_on_good, n_good)} ({row.strong_on_good}/{n_good}) | "
            f"{_summary(row.scores_attack)} |\n"
        )
    lines.append("\n## Thresholds used\n")
    lines.append(
        f"- `charset_bits @ csci262 threshold` strong iff ≥ {STRONG_CHARSET_CSCI262_BITS} "
        "(the exact rule the original CSCI262 script used)\n"
    )
    lines.append(
        f"- `charset_bits @ generous threshold` strong iff ≥ {STRONG_CHARSET_GENEROUS_BITS}\n"
    )
    lines.append(f"- `shannon_bits` strong iff ≥ {STRONG_SHANNON_BITS}\n")
    lines.append(f"- `markov_bits` strong iff ≥ {STRONG_MARKOV_BITS}\n")
    lines.append(f"- `zxcvbn` strong iff score ≥ {STRONG_ZXCVBN_SCORE}/4\n")
    lines.append(
        "- `pwscore_combined` strong iff **not** in top-10k bloom, **no** pattern match, "
        f"Markov ≥ {STRONG_MARKOV_BITS} bits, and zxcvbn ≥ {STRONG_ZXCVBN_SCORE}/4.\n"
    )

    # Worst offenders: leaked passwords the naive charset formula thinks are
    # strong at the CSCI262 threshold.
    charset_winners = [
        pw for pw in attack if naive_charset_entropy(pw) >= STRONG_CHARSET_CSCI262_BITS
    ][:15]
    if charset_winners:
        lines.append(
            "\n## Leaked passwords the original CSCI262 entropy rule calls 'strong'\n"
        )
        lines.append(
            "These are all in the RockYou top-10k and were nonetheless rated "
            f"≥{STRONG_CHARSET_CSCI262_BITS} bits by the textbook `L · log2(N)` formula:\n\n"
        )
        for pw in charset_winners:
            bits = naive_charset_entropy(pw)
            lines.append(f"- `{pw}` → {bits:.1f} bits\n")

    lines.append("\n## How to reproduce\n")
    lines.append(
        "```\n"
        "pip install -e \".[dev,bench]\"\n"
        "python benchmarks/train_markov.py --input benchmarks/data/rockyou_top1m.txt \\\n"
        "    --output src/pwscore/data/markov_rockyou.json --order 3 --min-count 25\n"
        "python benchmarks/build_bloom.py --input benchmarks/data/rockyou_top10k.txt \\\n"
        "    --output src/pwscore/data/rockyou_top10k.bloom\n"
        "python benchmarks/benchmark.py\n"
        "```\n"
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(lines), encoding="utf-8")
    print(f"wrote {args.output}", file=sys.stderr)

    # Echo the headline to stdout so CI / users see the numbers at a glance.
    print("\n" + "".join(lines[2:4 + len(rows) + 1]))


if __name__ == "__main__":
    main()
