"""The 16 Java crypto-API misuse categories (rules 1-16 of CryptoGuard / CryptoAPI-Bench)."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_DIR = PROJECT_ROOT / "rules"
SCRIPTS_DIR = PROJECT_ROOT / "scripts"


@dataclass(frozen=True)
class Category:
    number: int
    slug: str
    title: str
    summary: str
    aliases: tuple  # normalised directory names; the first one is the CryptoAPI-Bench folder

    @property
    def rule_file(self) -> Path:
        return RULES_DIR / f"{self.number:02d}_{self.slug}.yaml"

    @property
    def script(self) -> Path:
        return SCRIPTS_DIR / f"{self.number:02d}_{self.slug}.py"

    @property
    def label(self) -> str:
        return f"Directory {self.number} - {self.title}"


_ALL = [
    Category(1, "cryptographic_key", "Cryptographic Key",
             "hard-coded or predictable key material passed to SecretKeySpec, DESKeySpec, PKCS8EncodedKeySpec, ...",
             ("predictablecryptographickey", "cryptographickey", "cryptokey", "key", "keys")),
    Category(2, "pbe_password", "Password in PBE", "constant passwords passed to PBEKeySpec",
             ("predictablepbepassword", "passwordinpbe", "pbepassword")),
    Category(3, "keystore_password", "Password in KeyStore",
             "constant passwords used to load, store or unlock a KeyStore or KeyManagerFactory",
             ("predictablekeystorepassword", "passwordinkeystore", "keystorepassword", "keystore")),
    Category(4, "hostname_verifier", "Hostname Verifier",
             "HostnameVerifier implementations or lambdas that accept every host",
             ("dummyhostnameverifier", "hostnameverifier")),
    Category(5, "certificate_validation", "Certificate Validation",
             "X509TrustManager implementations and helpers that accept every certificate",
             ("dummycertvalidation", "certificatevalidation", "certvalidation", "trustmanager")),
    Category(6, "ssl_socket", "SSL Socket", "SSLSocket creation without hostname verification",
             ("impropersslsocketfactory", "sslsocket", "sslsocketfactory")),
    Category(7, "http_protocol", "HTTP Protocol", "plain http:// URLs used for network requests",
             ("http", "httpprotocol")),
    Category(8, "prng", "PRNG", "non-cryptographic PRNGs (java.util.Random, Math.random, ThreadLocalRandom)",
             ("untrustedprng", "prng", "insecureprng", "random")),
    Category(9, "prng_seed", "Seed in PRNG", "constant or time-based seeds given to SecureRandom",
             ("predictableseeds", "seedinprng", "prngseed", "seed", "seeds")),
    Category(10, "pbe_salt", "Salt in PBE", "constant or all-zero salts for password-based encryption",
             ("staticsalts", "saltinpbe", "pbesalt", "salt", "salts")),
    Category(11, "mode_of_operation", "Mode of Operation",
             "ECB mode, explicit or implied by a transformation without a mode",
             ("ecbcrypto", "modeofoperation", "ecb")),
    Category(12, "initialization_vector", "Initialization Vector", "constant or all-zero initialization vectors",
             ("staticinitializationvector", "initializationvector", "iv")),
    Category(13, "pbe_iteration", "Iteration in PBE", "PBE iteration counts below 1000",
             ("pbeiteration", "iterationinpbe", "iteration", "iterations")),
    Category(14, "symmetric_ciphers", "Symmetric Ciphers",
             "broken symmetric ciphers (DES, 3DES, RC2, RC4, Blowfish, IDEA, ...)",
             ("brokencrypto", "symmetricciphers", "symmetriccipher")),
    Category(15, "asymmetric_ciphers", "Asymmetric Ciphers",
             "RSA/DSA/DH keys below 2048 bits, weak elliptic curves and unpadded RSA",
             ("insecureasymmetriccrypto", "asymmetricciphers", "asymmetriccipher")),
    Category(16, "cryptographic_hash", "Cryptographic Hash",
             "broken hashes (MD2, MD4, MD5, SHA-1) and MD5/SHA-1 based signatures",
             ("brokenhash", "cryptographichash", "hash")),
]
CATEGORIES = {c.number: c for c in _ALL}
