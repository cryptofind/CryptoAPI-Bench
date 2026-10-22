#!/usr/bin/env python3
"""Generate the 16 Semgrep rule files (rules/NN_*.yaml) and the per-directory scripts.

The YAML files are ordinary Semgrep rules and are the main deliverable.  This
script only keeps shared fragments (literal regexes, sanitizers, propagators,
sinks) identical across them.  After editing it, run:  python3 tools/build_rules.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from cryptoscan.categories import CATEGORIES  # noqa: E402

# ------------------------------------------------------------------ literals
STR = r'"(?:[^"\\]|\\.)+"'                              # non-empty string literal
CHR = r"'(?:[^'\\]|\\.)+'"                              # char literal
NUM = r"-?(?:0[xX][0-9a-fA-F]+|0[bB][01]+|\d+)[lL]?"   # integer literal
CAST = r"(?:\(\s*\w+\s*\)\s*)?"                          # optional cast such as (byte)
SCALAR = r"(?:" + CAST + r"(?:" + NUM + r"|" + CHR + r")|" + STR + r")"
ARRAY = r"\{\s*(?:" + SCALAR + r"\s*(?:,\s*" + SCALAR + r"\s*)*,?\s*)?\}"
NEW_ARRAY = r"new\s+\w+\s*(?:\[\s*\]\s*)+" + ARRAY
WRAPPED = r"(?:new\s+[\w.]+|[\w.]+\.valueOf)\s*\(\s*" + SCALAR + r"\s*\)"
#: a literal, a literal-only array, or a boxed literal such as new Byte((byte) 100)
SECRET_LITERAL = r"^\(?\s*(?:" + "|".join([SCALAR, ARRAY, NEW_ARRAY, WRAPPED]) + r")\s*\)?$"

# Positions where a literal is *data* rather than an option (charset name, map key,
# property name, algorithm name).  Only literals in these positions are constant
# sources, which avoids false positives like pw.getBytes("UTF-8") or getProperty("key").
DATA_CONTEXTS = [
    "$X = $L", "$T $X = $L;", "return $L;", "$L.$M(...)", "$L + $E", "$E + $L",
    "$MAP.put($K, $L)", "$COLL.add($L)",
    "String.valueOf($L, ...)", "String.copyValueOf($L, ...)", "new String($L, ...)",
    "new StringBuilder($L)", "new StringBuffer($L)", "$SB.append($L)", "$STR.concat($L)",
    "Arrays.copyOf($L, ...)", "Arrays.copyOfRange($L, ...)", "Arrays.asList(..., $L, ...)",
    "$DEC.decode($L)", "DatatypeConverter.parseBase64Binary($L)", "DatatypeConverter.parseHexBinary($L)",
    "Hex.decodeHex($L)", "Base64.decodeBase64($L)", "new BigInteger($L, ...)", "BigInteger.valueOf($L)",
    "new Byte($L)", "Byte.valueOf($L)", "new Short($L)", "Short.valueOf($L)", "new Integer($L)",
    "Integer.valueOf($L)", "new Long($L)", "Long.valueOf($L)", "new Character($L)", "Character.valueOf($L)",
    "Byte.parseByte($L, ...)", "Short.parseShort($L, ...)", "Integer.parseInt($L, ...)", "Long.parseLong($L, ...)",
]


def rx(regex, mv="$L"):
    return {"metavariable-regex": {"metavariable": mv, "regex": regex}}


def below(limit, mv="$L"):
    """Integer literals, or numeric strings such as "20", smaller than ``limit``."""
    return [[rx(r"^-?\d+$", mv), {"metavariable-comparison": {"metavariable": mv, "comparison": f"{mv} < {limit}"}}],
            [rx(r'^"\s*-?\d+\s*"$', mv),
             {"metavariable-comparison": {"metavariable": mv, "comparison": f"int({mv}) < {limit}"}}]]


SECRET = [[rx(SECRET_LITERAL)]]


def either(*patterns):
    return {"pattern-either": [{"pattern": p} for p in patterns]}


def sink(pattern, *conditions):
    """A sink specification; ``$L`` marks the security-sensitive argument."""
    return [*conditions, {"pattern": pattern}]


def sinks(specs):
    return [{"patterns": [*spec, {"focus-metavariable": "$L"}]} for spec in specs]


def literal_sources(alternatives, sink_specs=()):
    contexts = {"pattern-either": [{"pattern": c} for c in DATA_CONTEXTS]}
    out = [{"patterns": [contexts, *alt, {"focus-metavariable": "$L"}]} for alt in alternatives]
    # a literal written directly as the sensitive argument, e.g. sr.setSeed(12345L)
    out += [{"patterns": [*spec, *alt, {"focus-metavariable": "$L"}]} for spec in sink_specs for alt in alternatives]
    return out


def string_sources(content_regex):
    return [{"patterns": [{"pattern": '"$S"'}, rx(content_regex, "$S")]}]


FILL_SANITIZERS = [{"by-side-effect": True, "patterns": [
    either("$RND.nextBytes($FILLED)", "$IN.read($FILLED, ...)", "$IN.readFully($FILLED, ...)",
           "(ByteBuffer $BUF).get($FILLED, ...)", "System.arraycopy($SRC, $SRCPOS, $FILLED, ...)"),
    {"focus-metavariable": "$FILLED"}]}]

PROPAGATORS = [
    {"pattern": "$MAP.put($K, $V)", "from": "$V", "to": "$MAP"},
    {"pattern": "$COLL.add($V)", "from": "$V", "to": "$COLL"},
    {"pattern": "$SB.append($V)", "from": "$V", "to": "$SB"},
]

CWE321 = "CWE-321: Use of Hard-coded Cryptographic Key"
CWE259 = "CWE-259: Use of Hard-coded Password"
CWE297 = "CWE-297: Improper Validation of Certificate with Host Mismatch"
CWE295 = "CWE-295: Improper Certificate Validation"
CWE319 = "CWE-319: Cleartext Transmission of Sensitive Information"
CWE338 = "CWE-338: Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)"
CWE337 = "CWE-337: Predictable Seed in Pseudo-Random Number Generator (PRNG)"
CWE760 = "CWE-760: Use of a One-Way Hash with a Predictable Salt"
CWE327 = "CWE-327: Use of a Broken or Risky Cryptographic Algorithm"
CWE329 = "CWE-329: Generation of Predictable IV with CBC Mode"
CWE1204 = "CWE-1204: Generation of Weak Initialization Vector (IV)"
CWE916 = "CWE-916: Use of Password Hash With Insufficient Computational Effort"
CWE326 = "CWE-326: Inadequate Encryption Strength"
CWE780 = "CWE-780: Use of RSA Algorithm without OAEP"
CWE328 = "CWE-328: Use of Weak Hash"


def meta(cat, cwes, *, interprocedural=False, argument_literal=None):
    refs = [f"https://cwe.mitre.org/data/definitions/{c.split(':')[0].split('-')[1]}.html" for c in cwes]
    m = {"category": "security", "subcategory": ["vuln"], "cryptoapi-bench-category": cat, "cwe": cwes,
         "confidence": "MEDIUM", "likelihood": "MEDIUM", "impact": "HIGH", "references": refs}
    if interprocedural:
        m["interprocedural"] = True
    if argument_literal:
        m["argument-literal"] = json.loads(json.dumps(argument_literal).replace("$L", "$ARG"))
    return m


def taint(rule_id, severity, message, metadata, sources, sink_specs, *, sanitizers=None, propagators=PROPAGATORS):
    rule = {"id": rule_id, "mode": "taint", "languages": ["java"], "severity": severity, "message": message,
            "metadata": metadata, "pattern-sources": sources}
    if propagators:
        rule["pattern-propagators"] = propagators
    if sanitizers:
        rule["pattern-sanitizers"] = sanitizers
    rule["pattern-sinks"] = sinks(sink_specs)
    return rule


def search(rule_id, severity, message, metadata, **formula):
    return {"id": rule_id, "languages": ["java"], "severity": severity, "message": message,
            "metadata": metadata, **formula}


def constant_rule(cat, rule_id, message, cwes, sink_specs, *, alternatives=SECRET, zero_filled=False,
                  extra_sources=()):
    sources = literal_sources(alternatives, sink_specs) + list(extra_sources)
    if zero_filled:
        sources.append({"pattern": "new $T[$N]"})  # allocated but never filled: all zeros
    return taint(rule_id, "ERROR", message, meta(cat, cwes, interprocedural=True, argument_literal=alternatives),
                 sources, sink_specs, sanitizers=FILL_SANITIZERS)


def algorithm_rule(cat, rule_id, severity, message, cwes, content_regex, sink_specs):
    return taint(rule_id, severity, message, meta(cat, cwes, interprocedural=True),
                 string_sources(content_regex), sink_specs)


# --------------------------------------------------------------------- sinks
KEY_SINKS = [sink("new SecretKeySpec($L, ...)"), sink("new DESKeySpec($L, ...)"), sink("new DESedeKeySpec($L, ...)"),
             sink("new PKCS8EncodedKeySpec($L, ...)"), sink("new RSAPrivateKeySpec($MODULUS, $L)")]
PBE_PASSWORD_SINKS = [sink("new PBEKeySpec($L, ...)")]
KEYSTORE_SINKS = [sink("$KS.load($STREAM, $L)"), sink("(KeyStore $KS).store($STREAM, $L)"),
                  sink("$KS.getKey($ALIAS, $L)"), sink("$KS.setKeyEntry($ALIAS, $KEY, $L, $CHAIN)"),
                  sink("(KeyManagerFactory $KMF).init($KS, $L)"),
                  sink("new $PROTECTION($L, ...)", rx(r"^(?:KeyStore\.)?PasswordProtection$", "$PROTECTION"))]
SEED_SINKS = [sink("new SecureRandom($L)"), sink("$RND.setSeed($L)")]
SALT_SINKS = [sink("new PBEParameterSpec($L, ...)"), sink("new PBEKeySpec($PASSWORD, $L, ...)")]
IV_SINKS = [sink("new IvParameterSpec($L, ...)"), sink("new GCMParameterSpec($TAGLEN, $L, ...)"),
            sink("new ChaCha20ParameterSpec($L, $COUNTER)")]
ITERATION_SINKS = [sink("new PBEParameterSpec($SALT, $L, ...)"), sink("new PBEKeySpec($PASSWORD, $SALT, $L, ...)")]
HTTP_SINKS = [sink(p) for p in (
    "new URL($L, ...)", "URI.create($L)", "new URI($L)", "new HttpGet($L)", "new HttpPost($L)", "new HttpPut($L)",
    "new HttpDelete($L)", "new HttpPatch($L)", "new HttpHead($L)", "new HttpOptions($L)", "$REQUEST.url($L)",
    "Jsoup.connect($L)", "$REST.getForObject($L, ...)", "$REST.getForEntity($L, ...)",
    "$REST.postForObject($L, ...)", "$REST.postForEntity($L, ...)", "$REST.exchange($L, ...)")]
CIPHER_SINK = [sink("Cipher.getInstance($L, ...)")]
SYMMETRIC_SINKS = CIPHER_SINK + [sink("KeyGenerator.getInstance($L, ...)"), sink("SecretKeyFactory.getInstance($L, ...)"),
                                 sink("new SecretKeySpec($KEY, $L)"), sink("new SecretKeySpec($KEY, $OFFSET, $LEN, $L)")]
HASH_SINKS = [sink("MessageDigest.getInstance($L, ...)"), sink("DigestUtils.getDigest($L)"), sink("new DigestUtils($L)")]


def kpg_spec(algorithm_regex):
    """$L = key size passed to initialize() of a KeyPairGenerator created for a matching algorithm."""
    return [{"pattern-either": [
                {"pattern-inside": '$T $KPG = KeyPairGenerator.getInstance("$ALG", ...);\n...'},
                {"pattern-inside": '$KPG = KeyPairGenerator.getInstance("$ALG", ...);\n...'}]},
            rx(algorithm_regex, "$ALG"),
            {"pattern": "$KPG.initialize($L, ...)"}]


def ssl_exclusions():
    bodies = ["$HV.verify(...);", "if (<... $HV.verify(...) ...>) { ... }",
              "if (<... $HV.verify(...) ...>) throw $EXC;", "$VT $VB = <... $HV.verify(...) ...>;",
              "return <... $HV.verify(...) ...>;", "$SSLP.setEndpointIdentificationAlgorithm(...);"]
    return [{"pattern-not-inside": f"{head}(...) {{\n  ...\n  {body}\n  ...\n}}"}
            for head in ("$RT $M", "$M") for body in bodies]


HTTP_RX = r"(?i)^http://(?!(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\])(?:[:/]|$))(?!www\.w3\.org/).*$"
ECB_RX = (r"(?i)^(?:AES(?:_\d+)?|DES|DESede|TripleDES|3DES|Blowfish|RC2|RC5|IDEA|Camellia|SEED|ARIA|CAST5|CAST6"
          r"|Twofish|Serpent|SM4|GOST28147|Skipjack|XTEA|Rijndael)(?:/ECB(?:/[\w-]*)?)?$")
SYMMETRIC_RX = (r"(?i)^(?:(?:DES|DESede|TripleDES|3DES|DES3|RC2|RC4|ARCFOUR|ARC4|Blowfish|IDEA|RC5|CAST5|Skipjack"
                r"|GOST28147|XTEA|TEA)(?:/[\w-]+/[\w-]+)?|PBEWith\w*?And(?:DES|DESede|TripleDES|RC2_\d+|RC4_\d+))$")
HASH_RX = r"(?i)^(?:MD2|MD4|MD5|SHA|SHA-?0|SHA-?1)$"
SIGNATURE_RX = r"(?i)^(?:MD2|MD5|SHA1?|SHA-1)with\w+$"
RSA_NOPAD_RX = r"(?i)^RSA/(?:ECB|NONE)/NoPadding$"
WEAK_CURVE_RX = (r"(?i)^(?:secp(?:112|128|160|192)\w*|sect(?:113|131|163|193)\w*|prime192v\d"
                 r"|c2[pt]nb1(?:63|76|91)\w*|brainpoolP(?:160|192)[rt]1|P-192|nistp192)$")
RSA_LIKE_RX = r"(?i)^(?:RSA|RSASSA-PSS|DSA|DH|DiffieHellman|ElGamal)$"
EC_RX = r"(?i)^(?:EC|ECDSA|ECDH)$"
CHECK_TRUSTED = r"^check(?:Server|Client)Trusted$"
RSA_SINKS = [kpg_spec(RSA_LIKE_RX), sink("new RSAKeyGenParameterSpec($L, ...)"),
             sink("new DSAGenParameterSpec($L, ...)"), sink("new DHGenParameterSpec($L, ...)")]
PRNG = ("new java.util.Random(...)", "new Random(...)", "Math.random()", "ThreadLocalRandom.current()",
        "new SplittableRandom(...)")
TIME = ("System.currentTimeMillis()", "System.nanoTime()", "new Date().getTime()", "new java.util.Date().getTime()",
        "Instant.now().toEpochMilli()", "Calendar.getInstance().getTimeInMillis()")

# --------------------------------------------------------------------- rules
RULES = {
    1: [constant_rule(1, "cat01-hardcoded-crypto-key",
                      "Hard-coded or predictable key material is used to build a cryptographic key. Anyone who can "
                      "read the code or binary can recover the key; generate keys with KeyGenerator/KeyPairGenerator "
                      "or SecureRandom, or load them from a protected KeyStore.", [CWE321], KEY_SINKS, zero_filled=True)],
    2: [constant_rule(2, "cat02-constant-pbe-password",
                      "A constant password is used for password-based encryption (PBEKeySpec). The derived key is "
                      "only as secret as the source code; obtain the password from the user or a secret store at run "
                      "time.", [CWE259], PBE_PASSWORD_SINKS)],
    3: [constant_rule(3, "cat03-constant-keystore-password",
                      "A constant password protects a KeyStore or a key entry. Hard-coded keystore passwords such as "
                      "the default changeit let anyone open the keystore; read the password from protected "
                      "configuration or a secret manager instead.", [CWE259], KEYSTORE_SINKS)],
    4: [search("cat04-hostnameverifier-accepts-all", "ERROR",
               "This HostnameVerifier accepts every host because verify() returns true without checking the name. "
               "That disables TLS server-identity checks and enables man-in-the-middle attacks; use "
               "HttpsURLConnection.getDefaultHostnameVerifier() or compare the host with the certificate.",
               meta(4, [CWE297]),
               patterns=[{"pattern": "boolean verify(String $H, SSLSession $S) { ... return true; ... }"},
                         {"pattern-not": "boolean verify(String $H, SSLSession $S) { ... return false; ... }"},
                         {"pattern-not": "boolean verify(String $H, SSLSession $S) { ... return $V.verify(...); ... }"},
                         {"pattern-not": "boolean verify(String $H, SSLSession $S) { ... throw $E; ... }"}]),
        search("cat04-lambda-hostnameverifier-accepts-all", "ERROR",
               "A lambda HostnameVerifier accepts every host. That disables TLS server-identity checks; use the "
               "default verifier instead.", meta(4, [CWE297]),
               patterns=[either("($H, $S) -> true", "($H, $S) -> { return true; }"),
                         {"pattern-either": [{"pattern-inside": p} for p in (
                             "$X.setHostnameVerifier(...)", "HttpsURLConnection.setDefaultHostnameVerifier(...)",
                             "$X.hostnameVerifier(...)", "$X.setSSLHostnameVerifier(...)",
                             "new SSLConnectionSocketFactory(...)", "HostnameVerifier $V = ...;")]}]),
        search("cat04-allow-all-hostnameverifier", "ERROR",
               "A library allow-all HostnameVerifier is used. It accepts certificates issued for any host; use the "
               "default verifier instead.", meta(4, [CWE297]),
               **either("NoopHostnameVerifier.INSTANCE", "new NoopHostnameVerifier()", "new AllowAllHostnameVerifier()",
                        "SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER",
                        "SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER"))],
    5: [search("cat05-trustmanager-accepts-all", "ERROR",
               "X509TrustManager.$M() never rejects a certificate: it neither throws CertificateException nor "
               "delegates to a real TrustManager. Every certificate, including self-signed or attacker-issued ones, "
               "is trusted; delegate to the default TrustManagerFactory instead.", meta(5, [CWE295]),
               patterns=[{"pattern": "void $M(X509Certificate[] $CHAIN, ...) { ... }"}, rx(CHECK_TRUSTED, "$M"),
                         {"pattern-not": "void $M(...) { ... throw $E; ... }"},
                         {"pattern-not": "void $M(...) { ... $TM.$M(...); ... }"},
                         {"pattern-not": "void $M(...) { ... $CERT.checkValidity(...); ... }"},
                         {"pattern-not": "void $M(...) { ... $CERT.verify(...); ... }"}]),
        search("cat05-trustmanager-swallows-validation-error", "ERROR",
               "A certificate-validation exception is caught and ignored inside $M(). Validation failures are "
               "silently turned into success; let the CertificateException propagate.", meta(5, [CWE295]),
               patterns=[{"pattern-inside": "void $M(X509Certificate[] $CHAIN, ...) { ... }"}, rx(CHECK_TRUSTED, "$M"),
                         {"pattern": "try { ... } catch ($EX $E) { ... }"},
                         {"pattern-not": "try { ... } catch ($EX $E) { ... throw $T; ... }"}]),
        search("cat05-accepted-issuers-null", "WARNING",
               "getAcceptedIssuers() returns null, a hallmark of a trust-all TrustManager. Delegate to a real "
               "X509TrustManager or return an empty array.", meta(5, [CWE295]),
               pattern="X509Certificate[] getAcceptedIssuers() { return null; }"),
        search("cat05-trust-all-helper", "ERROR",
               "A library trust-all strategy or TrustManagerFactory disables certificate validation. Rely on the "
               "platform trust store or on explicit certificate pinning instead.", meta(5, [CWE295]),
               **either("TrustAllStrategy.INSTANCE", "new TrustAllStrategy()", "new TrustSelfSignedStrategy()",
                        "InsecureTrustManagerFactory.INSTANCE")),
        search("cat05-trust-all-lambda", "ERROR",
               "A TrustStrategy lambda accepts every certificate chain. Remove it and rely on normal validation.",
               meta(5, [CWE295]), pattern="$B.loadTrustMaterial($KS, ($C, $A) -> true)")],
    6: [search("cat06-sslsocket-without-hostname-verification", "ERROR",
               "An SSLSocket is created without verifying the server host name. SSLSocket does not check that the "
               "certificate matches the host, so any valid certificate is accepted; call HostnameVerifier.verify() "
               "on the session or set SSLParameters.setEndpointIdentificationAlgorithm(\"HTTPS\").",
               meta(6, [CWE297]),
               patterns=[either("(SSLSocketFactory $F).createSocket(...)", "((SSLSocketFactory) $X).createSocket(...)",
                                "SSLSocketFactory.getDefault().createSocket(...)",
                                "(SSLContext $CTX).getSocketFactory().createSocket(...)"),
                         *ssl_exclusions()])],
    7: [algorithm_rule(7, "cat07-cleartext-http-url", "WARNING",
                       "A plain http:// URL is used for a network request. Traffic, including any credentials or "
                       "tokens, can be read and modified in transit; use https://.", [CWE319], HTTP_RX, HTTP_SINKS),
        search("cat07-http-scheme-literal", "WARNING", "A URL is built with the plain http scheme. Use https instead.",
               meta(7, [CWE319]), patterns=[{"pattern": 'new URL("$PROTO", $HOST, ...)'}, rx(r"(?i)^http$", "$PROTO")])],
    8: [search("cat08-insecure-prng", "WARNING",
               "A non-cryptographic pseudo-random generator is used. java.util.Random, Math.random() and "
               "ThreadLocalRandom are predictable; use java.security.SecureRandom for keys, IVs, salts, tokens and "
               "passwords.", meta(8, [CWE338]),
               **{"pattern-either": [{"pattern": p} for p in PRNG] + [
                   {"patterns": [either("RandomStringUtils.$FN(...)", "RandomUtils.$FN(...)"),
                                 rx(r"^(?:random|next)", "$FN")]}]}),
        taint("cat08-insecure-prng-in-crypto", "ERROR",
              "Output of a non-cryptographic PRNG is used as key material, salt, IV, seed or password. An attacker who "
              "observes a few outputs can predict the rest; use SecureRandom.", meta(8, [CWE338]),
              [either(*PRNG)], KEY_SINKS + SALT_SINKS + IV_SINKS + SEED_SINKS + PBE_PASSWORD_SINKS,
              propagators=PROPAGATORS + [{"pattern": "$RND.nextBytes($OUT)", "from": "$RND", "to": "$OUT"}])],
    9: [constant_rule(9, "cat09-predictable-prng-seed",
                      "SecureRandom is seeded with a constant or time-based value. Seeding before first use can make "
                      "SHA1PRNG fully deterministic, so keys, nonces and tokens become predictable; let SecureRandom "
                      "seed itself.", [CWE337], SEED_SINKS, zero_filled=True, extra_sources=[either(*TIME)])],
    10: [constant_rule(10, "cat10-static-pbe-salt",
                       "A constant or never-filled (all-zero) salt is used for password-based key derivation. Static "
                       "salts allow pre-computed dictionary attacks across all users; generate a random salt per "
                       "password with SecureRandom.nextBytes().", [CWE760], SALT_SINKS, zero_filled=True)],
    11: [algorithm_rule(11, "cat11-ecb-mode", "ERROR",
                        "The cipher runs in ECB mode, either explicitly or because the transformation names no mode "
                        "(the JCE default for block ciphers is ECB). ECB encrypts equal blocks to equal ciphertext and "
                        "leaks plaintext structure; use an authenticated mode such as AES/GCM/NoPadding.",
                        [CWE327], ECB_RX, CIPHER_SINK)],
    12: [constant_rule(12, "cat12-static-iv",
                       "A constant or never-filled (all-zero) initialization vector is used. A predictable or reused "
                       "IV leaks information and is catastrophic for GCM and CTR; generate a fresh random IV for every "
                       "encryption.", [CWE329, CWE1204], IV_SINKS, zero_filled=True)],
    13: [constant_rule(13, "cat13-low-pbe-iteration-count",
                       "The PBE iteration count is below 1000. Few iterations make offline password guessing cheap; "
                       "use at least 1000 (CryptoGuard's threshold) and preferably the current OWASP recommendation, "
                       "which is in the hundreds of thousands for PBKDF2.", [CWE916], ITERATION_SINKS,
                       alternatives=below(1000))],
    14: [algorithm_rule(14, "cat14-broken-symmetric-cipher", "ERROR",
                        "A broken or weak symmetric cipher is used (DES, 3DES, RC2, RC4, Blowfish, IDEA or similar). "
                        "These have short keys, 64-bit blocks or biased keystreams; use AES (AES/GCM/NoPadding) or "
                        "ChaCha20-Poly1305.", [CWE327], SYMMETRIC_RX, SYMMETRIC_SINKS),
         search("cat14-des-keyspec", "WARNING",
                "DESKeySpec/DESedeKeySpec builds keys for a broken cipher. Migrate to AES keys.", meta(14, [CWE327]),
                **either("new DESKeySpec(...)", "new DESedeKeySpec(...)"))],
    15: [constant_rule(15, "cat15-weak-rsa-dsa-dh-key-size",
                       "An RSA, DSA or Diffie-Hellman key smaller than 2048 bits is generated. 1024-bit keys are "
                       "within reach of well-resourced attackers; use at least 2048 bits (3072 for long-term "
                       "secrets).", [CWE326], RSA_SINKS, alternatives=below(2048)),
         constant_rule(15, "cat15-weak-ec-key-size",
                       "An elliptic-curve key smaller than 224 bits is generated. Use a curve of at least 224 bits "
                       "such as P-256.", [CWE326], [kpg_spec(EC_RX)], alternatives=below(224)),
         algorithm_rule(15, "cat15-weak-ec-curve", "ERROR",
                        "A weak elliptic curve (smaller than 224 bits) is selected. Use secp256r1, secp384r1 or "
                        "X25519.", [CWE326], WEAK_CURVE_RX, [sink("new ECGenParameterSpec($L)")]),
         algorithm_rule(15, "cat15-rsa-without-padding", "WARNING",
                        "RSA is used without padding (textbook RSA). Unpadded RSA is deterministic and malleable; use "
                        "RSA/ECB/OAEPWithSHA-256AndMGF1Padding.", [CWE780], RSA_NOPAD_RX, CIPHER_SINK)],
    16: [algorithm_rule(16, "cat16-broken-hash", "ERROR",
                        "A broken hash function (MD2, MD4, MD5 or SHA-1) is used. Practical collision attacks exist "
                        "for all of them; use SHA-256 or stronger, and PBKDF2, bcrypt or Argon2 for passwords.",
                        [CWE328], HASH_RX, HASH_SINKS),
         algorithm_rule(16, "cat16-weak-signature-hash", "ERROR",
                        "A signature algorithm based on MD2, MD5 or SHA-1 is used. Use SHA256withRSA, SHA256withECDSA "
                        "or stronger.", [CWE328], SIGNATURE_RX, [sink("Signature.getInstance($L, ...)")]),
         search("cat16-broken-hash-helper", "ERROR",
                "A library helper computes an MD2, MD5 or SHA-1 digest. Use SHA-256 or stronger.", meta(16, [CWE328]),
                **{"pattern-either": [
                    {"patterns": [{"pattern": "DigestUtils.$FN(...)"},
                                  rx(r"^(?:md2|md5|sha1?|md2Hex|md5Hex|sha1Hex|shaHex|getMd2Digest|getMd5Digest"
                                     r"|getShaDigest|getSha1Digest)$", "$FN")]},
                    {"pattern": "Hashing.md5()"}, {"pattern": "Hashing.sha1()"}]})],
}

HEADER = """\
# Directory {n}: {title}
# Flags {summary}.
#
# Plain Semgrep rules; run them on their own with:
#     semgrep scan --config rules/{rules} <directory>
# scripts/{script} runs the same rules and adds the summary-based
# inter-procedural layer for taint rules marked `interprocedural: true`.
# Generated by tools/build_rules.py.

"""

SCRIPT = '''#!/usr/bin/env python3
"""Directory {n}: {title}.

Flags {summary}.
Semgrep rules: rules/{rules}

Usage:
    python3 scripts/{script} <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category={n}))
'''


class _Dumper(yaml.SafeDumper):
    def ignore_aliases(self, data):
        return True


def _represent_str(dumper, value):
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if "\n" in value else None)


_Dumper.add_representer(str, _represent_str)


def main():
    for number, cat in CATEGORIES.items():
        rules = RULES[number]
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids)), f"duplicate rule ids in category {number}"
        names = dict(n=number, title=cat.title, summary=cat.summary, rules=cat.rule_file.name, script=cat.script.name)
        body = yaml.dump({"rules": rules}, Dumper=_Dumper, sort_keys=False, width=4096, allow_unicode=True,
                         default_flow_style=False)
        cat.rule_file.parent.mkdir(parents=True, exist_ok=True)
        cat.rule_file.write_text(HEADER.format(**names) + body, encoding="utf-8")
        cat.script.parent.mkdir(parents=True, exist_ok=True)
        cat.script.write_text(SCRIPT.format(**names), encoding="utf-8")
        cat.script.chmod(0o755)
        print(f"wrote rules/{cat.rule_file.name} ({len(rules)} rule(s)) and scripts/{cat.script.name}")


if __name__ == "__main__":
    main()
