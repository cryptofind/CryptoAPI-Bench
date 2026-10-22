#!/usr/bin/env python3
"""Directory 9: Seed in PRNG.

Flags constant or time-based seeds given to SecureRandom.
Semgrep rules: rules/09_prng_seed.yaml

Usage:
    python3 scripts/09_prng_seed.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=9))
