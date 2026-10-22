#!/usr/bin/env python3
"""Directory 12: Initialization Vector.

Flags constant or all-zero initialization vectors.
Semgrep rules: rules/12_initialization_vector.yaml

Usage:
    python3 scripts/12_initialization_vector.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=12))
