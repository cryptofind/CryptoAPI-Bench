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
