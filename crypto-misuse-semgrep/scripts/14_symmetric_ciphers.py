#!/usr/bin/env python3
"""Directory 14: Symmetric Ciphers.

Flags broken symmetric ciphers (DES, 3DES, RC2, RC4, Blowfish, IDEA, ...).
Semgrep rules: rules/14_symmetric_ciphers.yaml

Usage:
    python3 scripts/14_symmetric_ciphers.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=14))
