# pwscore

Password strength analyzer that combines Shannon entropy, Markov-model scoring, zxcvbn, pattern detection, a RockYou bloom-filter wordlist check, and the HaveIBeenPwned k-anonymity API. Ships as a CLI, a FastAPI service, and a Docker image. Benchmarked against the RockYou breach set.

The project started life as a naive `L · log2(N)` charset entropy script. The benchmark shows that rule rates **60% of the RockYou top-10k as "strong"**. pwscore gets that number to **0%** while still rating handcrafted strong passwords as strong.

## Headline benchmark

2000-sample from RockYou top-10k, 10 handcrafted strong passwords:

| analyzer | false-strong on RockYou top-10k | true-strong on good set |
|---|---|---|
| `charset_bits` @ csci262 threshold (30 bits) | **60.0%** (1200/2000) | 100% (10/10) |
| `charset_bits` @ generous threshold (60 bits) | 0.8% (16/2000) | 100% (10/10) |
| `shannon_bits` | 0.7% (13/2000) | 100% (10/10) |
| `markov_bits` | 9.2% (185/2000) | 100% (10/10) |
| `zxcvbn` | 2.4% (48/2000) | 100% (10/10) |
| **`pwscore_combined`** | **0.0%** (0/2000) | **100%** (10/10) |

Full report with score distributions and sample "leaked-but-called-strong" passwords at [`benchmarks/results/report.md`](benchmarks/results/report.md). Reproduce with `make bench`.

## Architecture

```
                      ┌─────────────────┐
CLI  ── pwscore ──►   │                 │──► charset entropy (baseline)
                      │    analyzer     │──► shannon entropy (observed)
HTTP ── FastAPI ──►   │  worst-signal   │──► markov entropy (rockyou)
                      │     wins        │──► zxcvbn score + crack-time
                      │                 │──► HIBP k-anonymity lookup
                      └─────────────────┘──► pattern detectors + rockyou bloom
```

One `analyze(password) → AnalysisResult` function; all surfaces call it. Verdict is decided by the **worst** signal, not the best — a password with high entropy that appears in a breach set is still weak.

## Install

```sh
pip install -e ".[dev,bench]"
```

## CLI

```sh
pwscore 'correct horse battery staple'
pwscore --offline 'Password1!'        # skip HIBP lookup
pwscore -i                            # interactive, password not echoed
pwscore --json 'hunter2'              # machine-readable
```

Exit code is `1` for `weak` and `0` for `fair` / `strong`, so it drops into scripts and pre-commit hooks.

## HTTP service

```sh
make run
curl -X POST http://127.0.0.1:8000/analyze \
  -H 'content-type: application/json' \
  -d '{"password":"Password1!","offline":true}'
```

- `GET /healthz` — liveness
- `GET /metrics` — Prometheus scrape endpoint
- `POST /analyze` — rate-limited to 20/min/IP (configurable via `slowapi`)

Passwords never appear in logs or metric labels; the request body uses Pydantic `SecretStr`.

## Docker

```sh
make docker
docker run -p 8000:8000 pwscore:dev
```

Multi-stage build (`python:3.12-slim` → wheel-only runtime), runs as non-root UID 10001, baked-in healthcheck against `/healthz`.

## What's inside

- **Markov entropy (`src/pwscore/entropy/markov.py`)** — order-3 character model trained on the Pwdb top-1M. Scores `-log2(P(pw))`. Handles missing contexts with a global fallback probability stored in the trained file.
- **Bloom wordlist (`src/pwscore/checks/wordlist.py`)** — 18 KB bloom filter of the RockYou top-10k loaded at startup. `O(1)` membership test, case-insensitive variant catches trivial recapitalisations.
- **Pattern detectors (`src/pwscore/checks/patterns.py`)** — keyboard walks, numeric/alphabet sequences, year tokens (1950–2039), repeat runs, leet-decode against a curated base-word list so `P@ssw0rd` collapses to `password`.
- **HIBP (`src/pwscore/checks/hibp.py`)** — SHA-1 k-anonymity client against `api.pwnedpasswords.com/range/{prefix}`. The password never leaves the process; only the first 5 hex of its SHA-1 goes out.
- **zxcvbn (`src/pwscore/checks/zxcvbn_wrap.py`)** — industry-standard guess estimator (Dropbox). Used as ground truth and folded into the verdict.

## References

- Wheeler, D. L. (2016). *zxcvbn: Low-Budget Password Strength Estimation*. USENIX Security.
- Weir, M., Aggarwal, S., de Medeiros, B., & Glodek, B. (2009). *Password Cracking Using Probabilistic Context-Free Grammars*. IEEE S&P.
- Castelluccia, C., Dürmuth, M., & Perito, D. (2012). *Adaptive Password-Strength Meters from Markov Models*. NDSS.
- NIST SP 800-63B *Digital Identity Guidelines — Authentication and Lifecycle Management* (§5.1.1.2 on password composition rules vs breach-corpus checks).
- *Have I Been Pwned — Pwned Passwords API v3*. https://haveibeenpwned.com/API/v3#PwnedPasswords

## License

MIT. See `LICENSE`.
