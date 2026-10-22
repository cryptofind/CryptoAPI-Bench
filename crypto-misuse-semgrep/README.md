# Semgrep detectors for Java cryptographic API misuse

Sixteen Semgrep-based analysers, one per misuse category. They cover the 16 rules used by CryptoGuard and CryptoAPI-Bench: keys, passwords, hostname validation, certificate validation, SSL sockets, HTTP,
PRNGs, PRNGs' seeds, salts, ECB, IVs, PBE iterations, symmetric ciphers asymmetric ciphers, and hashes.

## Contents

| Path | What it is |
|---|---|
| `scripts/NN_<category>.py` | Analyser for category NN: runs the category's Semgrep rules, adds the inter-procedural layer, prints a report |
| `rules/NN_<category>.yaml` | Semgrep rules for category NN  |
| `cryptoscan/engine.py` | Shared engine: runs Semgrep, builds inter-procedural summaries, de-duplicates findings |
| `cryptoscan/cli.py` | Report and command line |
| `cryptoscan/categories.py` | category registry |
| `run_all.py` | Runs all 16 analysers and prints a summary table |
| `evaluate_cryptoapi_bench.py` | Scores the analysers against CryptoAPI-Bench's ground truth |
| `tools/build_rules.py` | Regenerates `rules/` and `scripts/` from shared fragments |
| `results/cryptoapi_bench_results.md` | Scores produced by the evaluator |

## Setup
Built and tested with Semgrep 1.182.1 (Community Edition) and Python 3.12.
```bash
python3 -m pip install -r requirements.txt 
```

## Usage
One directory per script:
```bash
python3 scripts/01_cryptographic_key.py  path/to/directory1
python3 scripts/14_symmetric_ciphers.py  path/to/directory14 --json dir14.json
```
Options: 
- `--no-interprocedural`: Plain Semgrep rules only
- `--json FILE`: Convert output to a JSON file
- `--pro`: passes `--pro` to Semgrep; needs Semgrep Pro
-  `--max-rounds N`:  
- `-v`: verbose

Exit statuses: 
- Nothing flagged: 0
- Misuse flagged: 1
- Error:2 

Each finding shows the file, line, code, rule and message. Inter-procedural findings also show how the constant reaches the crypto API, for example
`flow: constant -> argument #1 of Foo.go(...) -> crypto API at Foo.java:16`.

Run all categories at once:
```bash
    python3 run_all.py <path to parent directory of all categories> 
    python3 run_all.py --map 1=path/one --map 2=path/two ...
```

Run via `semgrep` command:
```bash
    semgrep scan --config rules/11_mode_of_operation.yaml <path to category 11 directory>
```

Reproduce the benchmark numbers:
```bash
    git clone https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git
    python3 evaluate_cryptoapi_bench.py CryptoAPI-Bench --compare
```

## Results on CryptoAPI-Bench
#### Plain Semgrep rules only (--no-interprocedural)
| # | Category | Cases | TP | FN | FP | TN | Precision | Recall | Time |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | Cryptographic Key | 9 | 2 | 5 | 1 | 1 | 66.7% | 28.6% | 19s |
| 2 | Password in PBE | 11 | 2 | 6 | 1 | 2 | 66.7% | 25.0% | 19s |
| 3 | Password in KeyStore | 10 | 2 | 5 | 1 | 2 | 66.7% | 28.6% | 19s |
| 4 | Hostname Verifier | 2 | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 19s |
| 5 | Certificate Validation | 3 | 3 | 0 | 0 | 0 | 100.0% | 100.0% | 19s |
| 6 | SSL Socket | 1 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 18s |
| 7 | HTTP Protocol | 9 | 1 | 5 | 1 | 2 | 50.0% | 16.7% | 19s |
| 8 | PRNG | 2 | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 19s |
| 9 | Seed in PRNG | 17 | 9 | 5 | 2 | 1 | 81.8% | 64.3% | 19s |
| 10 | Salt in PBE | 9 | 3 | 4 | 1 | 1 | 75.0% | 42.9% | 19s |
| 11 | Mode of Operation | 8 | 1 | 5 | 1 | 1 | 50.0% | 16.7% | 19s |
| 12 | Initialization Vector | 10 | 4 | 4 | 1 | 1 | 80.0% | 50.0% | 19s |
| 13 | Iteration in PBE | 9 | 2 | 5 | 1 | 1 | 66.7% | 28.6% | 19s |
| 14 | Symmetric Ciphers | 36 | 5 | 25 | 5 | 1 | 50.0% | 16.7% | 19s |
| 15 | Asymmetric Ciphers | 6 | 1 | 4 | 1 | 0 | 50.0% | 20.0% | 19s |
| 16 | Cryptographic Hash | 29 | 4 | 20 | 4 | 1 | 50.0% | 16.7% | 19s |
| | **Total** | 171 | 42 | 93 | 20 | 16 | **67.7%** | **31.1%** | |


| Case type | Insecure cases detected | Secure cases flagged |
|---|---:|---:|
| BB (basic) | 27/27 | 0/0 |
| ABI (inter-procedural) | 5/60 | 0/0 |
| ABS (field-sensitive) | 1/19 | 0/0 |
| ABMC (multiple classes) | 1/20 | 0/0 |
| ABH (HashMap / SecureRandom) | 8/9 | 0/2 |
| ABPS (path-sensitive) | 0/0 | 20/20 |
| Corrected (corrected) | 0/0 | 0/14 |

#### Semgrep rules + inter-procedural summary layer (default)
| # | Category | Cases | TP | FN | FP | TN | Precision | Recall | Time |
|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | Cryptographic Key | 9 | 7 | 0 | 1 | 1 | 87.5% | 100.0% | 119s |
| 2 | Password in PBE | 11 | 8 | 0 | 1 | 2 | 88.9% | 100.0% | 138s |
| 3 | Password in KeyStore | 10 | 7 | 0 | 1 | 2 | 87.5% | 100.0% | 119s |
| 4 | Hostname Verifier | 2 | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 19s |
| 5 | Certificate Validation | 3 | 3 | 0 | 0 | 0 | 100.0% | 100.0% | 19s |
| 6 | SSL Socket | 1 | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 19s |
| 7 | HTTP Protocol | 9 | 6 | 0 | 1 | 2 | 85.7% | 100.0% | 116s |
| 8 | PRNG | 2 | 1 | 0 | 0 | 1 | 100.0% | 100.0% | 19s |
| 9 | Seed in PRNG | 17 | 14 | 0 | 2 | 1 | 87.5% | 100.0% | 122s |
| 10 | Salt in PBE | 9 | 7 | 0 | 1 | 1 | 87.5% | 100.0% | 117s |
| 11 | Mode of Operation | 8 | 6 | 0 | 1 | 1 | 85.7% | 100.0% | 117s |
| 12 | Initialization Vector | 10 | 8 | 0 | 1 | 1 | 88.9% | 100.0% | 120s |
| 13 | Iteration in PBE | 9 | 7 | 0 | 1 | 1 | 87.5% | 100.0% | 68s |
| 14 | Symmetric Ciphers | 36 | 30 | 0 | 5 | 1 | 85.7% | 100.0% | 76s |
| 15 | Asymmetric Ciphers | 6 | 5 | 0 | 1 | 0 | 83.3% | 100.0% | 68s |
| 16 | Cryptographic Hash | 29 | 24 | 0 | 4 | 1 | 85.7% | 100.0% | 59s |
| | **Total** | 171 | 135 | 0 | 20 | 16 | **87.1%** | **100.0%** | |


| Case type | Insecure cases detected | Secure cases flagged |
|---|---:|---:|
| BB (basic) | 27/27 | 0/0 |
| ABI (inter-procedural) | 60/60 | 0/0 |
| ABS (field-sensitive) | 19/19 | 0/0 |
| ABMC (multiple classes) | 20/20 | 0/0 |
| ABH (HashMap / SecureRandom) | 9/9 | 0/2 |
| ABPS (path-sensitive) | 0/0 | 20/20 |
| Corrected (corrected) | 0/0 | 0/14 |

## Limitations
- **No full type resolution.** Calls through interfaces, overridden methods, reflection or lambdas are not followed. Fields are matched by class and name, and only the first six parameters of a method are summarised.
- **Socket hostname verification is checked per method.** Verification done in a helper method is not seen.
- **Unknown Files.** Files Semgrep cannot parse are skipped and counted as warnings in the report.