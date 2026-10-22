#!/usr/bin/env python3
"""Directory 2: Password in PBE.

Flags constant passwords passed to PBEKeySpec.
Semgrep rules: rules/02_pbe_password.yaml

Usage:
    python3 scripts/02_pbe_password.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=2))
