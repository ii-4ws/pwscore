from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    weak = "weak"
    fair = "fair"
    strong = "strong"


class EntropyScores(BaseModel):
    charset_bits: float = Field(description="Naive charset-based entropy (baseline).")
    shannon_bits: float = Field(description="Observed-distribution Shannon entropy.")
    markov_bits: float = Field(description="Order-3 Markov entropy on RockYou.")
    zxcvbn_log2_guesses: float = Field(description="log2(zxcvbn guesses) — bits-equivalent.")


class Flags(BaseModel):
    in_common_wordlist: bool
    hibp_pwned: bool
    hibp_count: int
    pattern_reasons: list[str]
    zxcvbn_score: int = Field(ge=0, le=4)
    zxcvbn_crack_time: str
    zxcvbn_warning: str
    zxcvbn_suggestions: list[str]


class AnalysisResult(BaseModel):
    length: int
    verdict: Verdict
    reasons: list[str] = Field(
        description=(
            "Human-readable reasons that drove the verdict. Every reason that "
            "weakened the score appears here — there can be more than one."
        )
    )
    entropy: EntropyScores
    flags: Flags

    @property
    def is_weak(self) -> bool:
        return self.verdict == Verdict.weak
