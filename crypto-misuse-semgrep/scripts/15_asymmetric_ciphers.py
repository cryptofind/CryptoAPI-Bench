#!/usr/bin/env python3
"""Directory 15: Asymmetric Ciphers.

Flags RSA/DSA/DH keys below 2048 bits, weak elliptic curves and unpadded RSA.
Semgrep rules: rules/15_asymmetric_ciphers.yaml

Usage:
    python3 scripts/15_asymmetric_ciphers.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=15))
