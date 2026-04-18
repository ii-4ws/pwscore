"""Password analyzer that combines every signal into a single verdict.

Design rule: the **worst** signal decides. This is deliberate. Attackers try
every avenue — dictionary, pattern, leak lookup — so a password that passes
entropy but appears in a breach set is weak, not strong. Most lightweight
strength meters take the best signal and mislead users.

The network-based HIBP lookup is optional (see `skip_hibp`). When skipped,
the analyzer still produces a useful verdict from the offline signals.
"""

from __future__ import annotations

import httpx

from pwscore.checks.hibp import HibpResult, check_hibp
from pwscore.checks.patterns import find_patterns
from pwscore.checks.wordlist import is_common_case_insensitive
from pwscore.checks.zxcvbn_wrap import run_zxcvbn
from pwscore.entropy.charset import naive_charset_entropy
from pwscore.entropy.markov import markov_entropy
from pwscore.entropy.shannon import shannon_entropy
from pwscore.models import AnalysisResult, EntropyScores, Flags, Verdict

# Tunable thresholds. These are intentionally conservative. The benchmark
# harness reports false-strong rate against RockYou to let us tune if needed.
WEAK_MARKOV_BITS = 28.0
STRONG_MARKOV_BITS = 60.0
WEAK_ZXCVBN_SCORE = 2
STRONG_ZXCVBN_SCORE = 4


def _verdict(
    markov_bits: float,
    zxcvbn_score: int,
    flags: Flags,
) -> tuple[Verdict, list[str]]:
    reasons: list[str] = []

    if flags.hibp_pwned:
        reasons.append(f"found in the HaveIBeenPwned breach set ({flags.hibp_count:,} times)")
    if flags.in_common_wordlist:
        reasons.append("matches an entry in the RockYou top-10k wordlist")
    reasons.extend(flags.pattern_reasons)
    if markov_bits < WEAK_MARKOV_BITS:
        reasons.append(
            f"Markov-model entropy is only {markov_bits:.1f} bits "
            "(easy to guess given breach patterns)"
        )
    if zxcvbn_score < WEAK_ZXCVBN_SCORE:
        reasons.append(f"zxcvbn score is {zxcvbn_score}/4; {flags.zxcvbn_warning or 'weak'}")

    if reasons:
        return Verdict.weak, reasons

    if markov_bits >= STRONG_MARKOV_BITS and zxcvbn_score >= STRONG_ZXCVBN_SCORE:
        return Verdict.strong, []

    return Verdict.fair, []


async def analyze(
    pw: str,
    *,
    skip_hibp: bool = False,
    hibp_client: httpx.AsyncClient | None = None,
) -> AnalysisResult:
    charset = naive_charset_entropy(pw)
    shannon = shannon_entropy(pw)
    markov = markov_entropy(pw)
    zr = run_zxcvbn(pw)
    patterns = find_patterns(pw)
    common = is_common_case_insensitive(pw)

    if skip_hibp or not pw:
        hibp = HibpResult(pwned=False, count=0)
    else:
        hibp = await check_hibp(pw, client=hibp_client)

    flags = Flags(
        in_common_wordlist=common,
        hibp_pwned=hibp.pwned,
        hibp_count=hibp.count,
        pattern_reasons=patterns,
        zxcvbn_score=zr.score,
        zxcvbn_crack_time=zr.crack_time_offline_fast_hash_display,
        zxcvbn_warning=zr.warning,
        zxcvbn_suggestions=zr.suggestions,
    )
    verdict, reasons = _verdict(markov, zr.score, flags)

    return AnalysisResult(
        length=len(pw),
        verdict=verdict,
        reasons=reasons,
        entropy=EntropyScores(
            charset_bits=charset,
            shannon_bits=shannon,
            markov_bits=markov,
            zxcvbn_log2_guesses=zr.guesses_log2,
        ),
        flags=flags,
    )


def analyze_sync(pw: str, *, skip_hibp: bool = False) -> AnalysisResult:
    """Blocking wrapper for contexts where an event loop isn't available."""
    import asyncio

    return asyncio.run(analyze(pw, skip_hibp=skip_hibp))
