# pwscore

Password strength analyzer that combines Shannon entropy, Markov-model scoring, zxcvbn, and HaveIBeenPwned. Ships as a CLI, a FastAPI service, and a Docker image. Benchmarked against the RockYou breach set.

See `benchmarks/results/report.md` for the empirical comparison against naive charset entropy.

## Install

```
pip install -e ".[dev]"
```

## Quick start

```
pwscore 'Password1!'
```
