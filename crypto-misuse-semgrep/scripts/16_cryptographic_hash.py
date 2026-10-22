#!/usr/bin/env python3
"""Directory 16: Cryptographic Hash.

Flags broken hashes (MD2, MD4, MD5, SHA-1) and MD5/SHA-1 based signatures.
Semgrep rules: rules/16_cryptographic_hash.yaml

Usage:
    python3 scripts/16_cryptographic_hash.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=16))
