#!/usr/bin/env python3
"""Directory 1: Cryptographic Key.

Flags hard-coded or predictable key material passed to SecretKeySpec, DESKeySpec, PKCS8EncodedKeySpec, ....
Semgrep rules: rules/01_cryptographic_key.yaml

Usage:
    python3 scripts/01_cryptographic_key.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=1))
