#!/usr/bin/env python3
"""Directory 13: Iteration in PBE.

Flags PBE iteration counts below 1000.
Semgrep rules: rules/13_pbe_iteration.yaml

Usage:
    python3 scripts/13_pbe_iteration.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=13))
