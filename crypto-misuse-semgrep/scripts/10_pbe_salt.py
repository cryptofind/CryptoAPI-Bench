#!/usr/bin/env python3
"""Directory 10: Salt in PBE.

Flags constant or all-zero salts for password-based encryption.
Semgrep rules: rules/10_pbe_salt.yaml

Usage:
    python3 scripts/10_pbe_salt.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=10))
