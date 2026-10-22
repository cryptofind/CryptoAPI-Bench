# Semgrep detectors for Java cryptographic API misuse

Sixteen Semgrep-based analysers, one per misuse category (directory). They cover the 16 rules used by
CryptoGuard and CryptoAPI-Bench: keys, passwords, hostname and certificate validation, SSL sockets, HTTP,
PRNGs and seeds, salts, ECB, IVs, PBE iterations, symmetric and asymmetric ciphers, and hashes.

## Contents

| Path | What it is |
|---|---|
| `scripts/NN_<category>.py` | Analyser for directory NN: runs the category's Semgrep rules, adds the inter-procedural layer, prints a report |
| `rules/NN_<category>.yaml` | Semgrep rules for directory NN (plain Semgrep, runnable on their own) |
| `cryptoscan/engine.py` | Shared engine: runs Semgrep, builds inter-procedural summaries, de-duplicates findings |
| `cryptoscan/cli.py`, `cryptoscan/categories.py` | Report and command line; category registry |
| `run_all.py` | Runs all 16 analysers and prints a summary table |
| `evaluate_cryptoapi_bench.py` | Scores the analysers against CryptoAPI-Bench's ground truth |
| `tools/build_rules.py` | Regenerates `rules/` and `scripts/` from shared fragments |
| `results/cryptoapi_bench_results.md` | Scores produced by the evaluator |

## Setup

    python3 -m pip install -r requirements.txt     # semgrep and PyYAML

Built and tested with Semgrep 1.182.1 (Community Edition) and Python 3.12.

## Usage

One directory per script:

    python3 scripts/01_cryptographic_key.py  path/to/directory1
    python3 scripts/14_symmetric_ciphers.py  path/to/directory14 --json dir14.json

Each finding shows the file, line, code, rule and message. Inter-procedural findings also show how the
constant reaches the crypto API, for example
`flow: constant -> argument #1 of Foo.go(...) -> crypto API at Foo.java:16`.
Exit status: 0 nothing flagged, 1 misuse flagged, 2 error.
Options: `--no-interprocedural` (plain Semgrep rules only), `--json FILE`, `--pro` (passes `--pro` to
Semgrep; needs Semgrep Pro), `--max-rounds N`, `-v`.

All directories at once:

    python3 run_all.py path/to/parent      # folders named 1..16, dir1, 01_xxx, a category name or the CryptoAPI-Bench name
    python3 run_all.py --map 1=path/a --map 2=path/b ...

Only the rules:

    semgrep scan --config rules/11_mode_of_operation.yaml path/to/directory11

Reproduce the benchmark numbers:

    git clone https://github.com/CryptoAPI-Bench/CryptoAPI-Bench.git
    python3 evaluate_cryptoapi_bench.py CryptoAPI-Bench --compare

## What each analyser flags

| Dir | Script | Flags |
|---:|---|---|
| 1 | `01_cryptographic_key.py` | Constant or predictable bytes (literals, literal arrays, element-wise constants, never-filled arrays) reaching `SecretKeySpec`, `DESKeySpec`, `DESedeKeySpec`, `PKCS8EncodedKeySpec`, `RSAPrivateKeySpec` |
| 2 | `02_pbe_password.py` | Constant passwords reaching `PBEKeySpec` |
| 3 | `03_keystore_password.py` | Constant passwords reaching `KeyStore.load/store/getKey/setKeyEntry`, `KeyManagerFactory.init`, `PasswordProtection` |
| 4 | `04_hostname_verifier.py` | `verify()` returning `true` with no `false` path, delegation or exception; `(h, s) -> true` lambdas; no-op or allow-all verifiers |
| 5 | `05_certificate_validation.py` | `checkServerTrusted`/`checkClientTrusted` that never throw or delegate; swallowed validation exceptions; `getAcceptedIssuers()` returning `null`; trust-all helpers |
| 6 | `06_ssl_socket.py` | `SSLSocketFactory.createSocket(...)` in a method that never calls `HostnameVerifier.verify` or `setEndpointIdentificationAlgorithm` |
| 7 | `07_http_protocol.py` | `http://` literals (not localhost) reaching `URL`, `URI`, Apache HttpClient, OkHttp, RestTemplate or Jsoup |
| 8 | `08_prng.py` | `java.util.Random`, `Math.random()`, `ThreadLocalRandom`, `SplittableRandom`, commons `RandomStringUtils`; ERROR when their output becomes a key, IV, salt, seed or password |
| 9 | `09_prng_seed.py` | Constant or time-based values reaching `new SecureRandom(seed)` or `setSeed` |
| 10 | `10_pbe_salt.py` | Constant or never-filled salts reaching `PBEParameterSpec` or `PBEKeySpec` |
| 11 | `11_mode_of_operation.py` | `Cipher.getInstance` with `/ECB/`, or with a bare block-cipher name (the JCE then defaults to ECB); RSA excluded |
| 12 | `12_initialization_vector.py` | Constant or never-filled IVs reaching `IvParameterSpec`, `GCMParameterSpec` or `ChaCha20ParameterSpec` |
| 13 | `13_pbe_iteration.py` | Iteration counts below 1000 (integers or numeric strings) reaching `PBEParameterSpec` or `PBEKeySpec` |
| 14 | `14_symmetric_ciphers.py` | DES, 3DES, RC2, RC4, Blowfish, IDEA and similar in `Cipher`, `KeyGenerator`, `SecretKeyFactory` or `SecretKeySpec`; `DESKeySpec` |
| 15 | `15_asymmetric_ciphers.py` | RSA/DSA/DH keys below 2048 bits, EC keys below 224 bits, weak named curves, RSA with `NoPadding` |
| 16 | `16_cryptographic_hash.py` | MD2, MD4, MD5 or SHA-1 in `MessageDigest`; MD5/SHA-1 signatures; commons-codec and Guava helpers |

## How it works

**Value misuses are taint rules.** Directories 1-3, 7 and 9-16 are about a value reaching an API: a
constant key, a short iteration count, an ECB transformation string. Each is a Semgrep taint rule whose
sinks are the sensitive argument (`$L`) of the relevant JCA calls.

**Literals count only in data positions.** Semgrep propagates taint from any argument of a call to its
result, so treating every literal as a source would flag `pw.getBytes("UTF-8")` or
`props.getProperty("key")`. Literals are therefore sources only where they are data: assignments and
declarations (including fields), `return`, the receiver of a call (`"secret".getBytes()`), concatenation,
`Map.put` values, and boxing, parsing and decoding calls. The algorithm-name categories (7, 11, 14, 16)
instead match any string literal against a regex such as `^(?:MD2|MD4|MD5|SHA|SHA-?1)$`.

**Sanitizers and propagators.** `nextBytes`, `read`, `readFully`, `ByteBuffer.get` and `System.arraycopy`
clean the array they fill. So `new byte[16]` followed by `SecureRandom.nextBytes` is fine, while a
never-filled `new byte[16]` IV, salt or key is flagged. Propagators for `Map.put`, `Collection.add` and
`StringBuilder.append` let constants survive a round trip through a `HashMap`.

**Structural misuses are pattern rules.** Directories 4, 5, 6 and 8 are about code shape: a verifier that
returns `true`, an empty `checkServerTrusted`, a socket without hostname verification. They use Semgrep
search rules with `pattern-not` and `pattern-not-inside` exclusions.

**Inter-procedural layer.** Semgrep Community Edition tracks taint only inside one method. For taint
rules marked `interprocedural: true`, the engine computes summaries with Semgrep itself:

1. It re-runs the rule's sinks with method parameters and field reads as sources. "Parameter *i* of
   `C.m` reaches a sink" makes argument *i* of every call to `C.m` a new sink. "Field `C.f` reaches a
   sink" makes every write to `C.f` a new sink. This repeats until nothing new appears.
2. Methods whose return value is constant turn their call sites into sources.
3. The rule's constant sources run against every derived sink.

Calls are linked by class, method name and argument position: unqualified or `this.` calls inside the
class, `C.m(...)`, receivers declared as `C`, `new C(...)`, and any receiver when the method name is
unique. This covers the benchmark's inter-procedural, field-sensitive and multi-class cases without
Semgrep Pro. With Semgrep Pro, `--pro` also turns on Pro's own inter-file analysis.

## Results on CryptoAPI-Bench

<!-- BEGIN RESULTS -->
Case-level scores on CryptoAPI-Bench with Semgrep 1.182.1.

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

Missed insecure cases (93): PredictableCryptographicKeyABICase1, PredictableCryptographicKeyABICase2, PredictableCryptographicKeyABICase3, PredictableCryptographicKeyABMCCase1, PredictableCryptographicKeyABSCase1, PredictablePBEPasswordABHCase2, PredictablePBEPasswordABICase1, PredictablePBEPasswordABICase2, PredictablePBEPasswordABICase3, PredictablePBEPasswordABMCCase1, PredictablePBEPasswordABSCase1, PredictableKeyStorePasswordABICase1, PredictableKeyStorePasswordABICase2, PredictableKeyStorePasswordABICase3, PredictableKeyStorePasswordABMCCase1, PredictableKeyStorePasswordABSCase1, HttpProtocolABICase1, HttpProtocolABICase2, HttpProtocolABICase3, HttpProtocolABMCCase1, HttpProtocolABSCase1, PredictableSeedsABICase1, PredictableSeedsABICase3, PredictableSeedsABICase5, PredictableSeedsABMCCase1, PredictableSeedsABSCase1, StaticSaltsABICase1, StaticSaltsABICase3, StaticSaltsABMCCase1, StaticSaltsABSCase1, EcbInSymmCryptoABICase1, EcbInSymmCryptoABICase2, EcbInSymmCryptoABICase3, EcbInSymmCryptoABMCCase1, EcbInSymmCryptoABSCase1, StaticInitializationVectorABICase1, StaticInitializationVectorABICase3, StaticInitializationVectorABMCCase1, StaticInitializationVectorABSCase1, LessThan1000IterationPBEABICase1, LessThan1000IterationPBEABICase2, LessThan1000IterationPBEABICase3, LessThan1000IterationPBEABMCCase1, LessThan1000IterationPBEABSCase1, BrokenCryptoABICase1, BrokenCryptoABICase10, BrokenCryptoABICase11, BrokenCryptoABICase12, BrokenCryptoABICase13, BrokenCryptoABICase14, BrokenCryptoABICase15, BrokenCryptoABICase2, BrokenCryptoABICase3, BrokenCryptoABICase4, BrokenCryptoABICase5, BrokenCryptoABICase6, BrokenCryptoABICase7, BrokenCryptoABICase8, BrokenCryptoABICase9, BrokenCryptoABMCCase1, BrokenCryptoABMCCase2, BrokenCryptoABMCCase3, BrokenCryptoABMCCase4, BrokenCryptoABMCCase5, BrokenCryptoABSCase1, BrokenCryptoABSCase2, BrokenCryptoABSCase3, BrokenCryptoABSCase4, BrokenCryptoABSCase5, InsecureAsymmetricCipherABICase1, InsecureAsymmetricCipherABICase2, InsecureAsymmetricCipherABICase3, InsecureAsymmetricCipherABMCCase1, BrokenHashABICase1, BrokenHashABICase10, BrokenHashABICase11, BrokenHashABICase12, BrokenHashABICase2, BrokenHashABICase3, BrokenHashABICase4, BrokenHashABICase5, BrokenHashABICase6, BrokenHashABICase7, BrokenHashABICase8, BrokenHashABICase9, BrokenHashABMCCase1, BrokenHashABMCCase2, BrokenHashABMCCase3, BrokenHashABMCCase4, BrokenHashABSCase1, BrokenHashABSCase2, BrokenHashABSCase3, BrokenHashABSCase4.

Secure cases flagged (20): PredictableCryptographicKeyABPSCase1, PredictablePBEPasswordABPSCase1, PredictableKeyStorePasswordABPSCase1, HttpProtocolABPSCase1, PredictableSeedsABPSCase1, PredictableSeedsABPSCase2, StaticSaltsABPSCase1, EcbInSymmCryptoABPSCase1, StaticInitializationVectorABPSCase1, LessThan1000IterationPBEABPSCase1, BrokenCryptoABPSCase1, BrokenCryptoABPSCase2, BrokenCryptoABPSCase3, BrokenCryptoABPSCase4, BrokenCryptoABPSCase5, InsecureAsymmetricCipherABPSCase1, BrokenHashABPSCase1, BrokenHashABPSCase2, BrokenHashABPSCase3, BrokenHashABPSCase4.

Wall-clock time: 38s.

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

Missed insecure cases (0): none.

Secure cases flagged (20): PredictableCryptographicKeyABPSCase1, PredictablePBEPasswordABPSCase1, PredictableKeyStorePasswordABPSCase1, HttpProtocolABPSCase1, PredictableSeedsABPSCase1, PredictableSeedsABPSCase2, StaticSaltsABPSCase1, EcbInSymmCryptoABPSCase1, StaticInitializationVectorABPSCase1, LessThan1000IterationPBEABPSCase1, BrokenCryptoABPSCase1, BrokenCryptoABPSCase2, BrokenCryptoABPSCase3, BrokenCryptoABPSCase4, BrokenCryptoABPSCase5, InsecureAsymmetricCipherABPSCase1, BrokenHashABPSCase1, BrokenHashABPSCase2, BrokenHashABPSCase3, BrokenHashABPSCase4.

Wall-clock time: 195s.
<!-- END RESULTS -->

## Limitations

- **Path-insensitive.** The path-sensitive (`ABPS`) cases are reported. They are secure only because `main`
  always passes `choice = 2`, so the insecure value is overwritten at run time. Proving that needs
  inter-procedural constant evaluation of branch conditions. The CryptoAPI-Bench paper reports the same
  false positives for CryptoGuard and the other tools it evaluated.
- **No full type resolution.** Calls through interfaces, overridden methods, reflection or lambdas are not
  followed. Fields are matched by class and name, and only the first six parameters of a method are
  summarised.
- **Socket hostname verification is checked per method.** Verification done in a helper method is not seen.
- **Thresholds.** Iterations below 1000 (CryptoGuard's rule; current OWASP guidance for PBKDF2 is far
  higher), RSA/DSA/DH below 2048 bits, EC below 224 bits. Change them in `tools/build_rules.py`
  (`below(...)`) or directly in the YAML (`metavariable-comparison`).
- Files Semgrep cannot parse are skipped and counted as warnings in the report.
