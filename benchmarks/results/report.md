# pwscore benchmark
Attack set: RockYou top-10k, sample 2000 (seed 1234). Good set: 10 handcrafted strong passwords.
A high _false-strong rate_ on the attack set means the analyzer is fooled by popular breached passwords. A high _true-strong rate_ on the good set means it correctly recognises well-chosen passwords.
## Headline
| analyzer | false-strong on RockYou top-10k | true-strong on good set | score distribution (attack set) |
|---|---|---|---|
| `charset_bits (csci262 threshold, 30)` | 60.0% (1200/2000) | 100.0% (10/10) | mean=33.6 median=32.9 p95=51.7 |
| `charset_bits (generous threshold, 60)` | 0.8% (16/2000) | 100.0% (10/10) | mean=33.6 median=32.9 p95=51.7 |
| `shannon_bits` | 0.7% (13/2000) | 100.0% (10/10) | mean=17.7 median=17.7 p95=31.2 |
| `markov_bits` | 9.2% (185/2000) | 100.0% (10/10) | mean=32.3 median=22.8 p95=84.6 |
| `zxcvbn_log2_guesses` | 2.4% (48/2000) | 100.0% (10/10) | mean=11.8 median=11.2 p95=19.9 |
| `pwscore_combined` | 0.0% (0/2000) | 100.0% (10/10) | mean=0.7 median=1.0 p95=1.0 |

## Thresholds used
- `charset_bits @ csci262 threshold` strong iff ≥ 30.0 (the exact rule the original CSCI262 script used)
- `charset_bits @ generous threshold` strong iff ≥ 60.0
- `shannon_bits` strong iff ≥ 40.0
- `markov_bits` strong iff ≥ 60.0
- `zxcvbn` strong iff score ≥ 3/4
- `pwscore_combined` strong iff **not** in top-10k bloom, **no** pattern match, Markov ≥ 60.0 bits, and zxcvbn ≥ 3/4.

## Leaked passwords the original CSCI262 entropy rule calls 'strong'
These are all in the RockYou top-10k and were nonetheless rated ≥30.0 bits by the textbook `L · log2(N)` formula:

- `pok29q6666` → 51.7 bits
- `steelers` → 37.6 bits
- `brooklyn1` → 46.5 bits
- `iloveyou1` → 46.5 bits
- `charley` → 32.9 bits
- `shearer` → 32.9 bits
- `forgotten` → 42.3 bits
- `ichliebedich` → 56.4 bits
- `john!20130605at1753` → 115.7 bits
- `slipknot` → 37.6 bits
- `123QWE` → 31.0 bits
- `Comply1!` → 52.4 bits
- `billy123` → 41.4 bits
- `marshall` → 37.6 bits
- `qwerty789` → 46.5 bits

## How to reproduce
```
pip install -e ".[dev,bench]"
python benchmarks/train_markov.py --input benchmarks/data/rockyou_top1m.txt \
    --output src/pwscore/data/markov_rockyou.json --order 3 --min-count 25
python benchmarks/build_bloom.py --input benchmarks/data/rockyou_top10k.txt \
    --output src/pwscore/data/rockyou_top10k.bloom
python benchmarks/benchmark.py
```
