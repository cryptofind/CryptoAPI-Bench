#!/usr/bin/env python3
"""Directory 11: Mode of Operation.

Flags ECB mode, explicit or implied by a transformation without a mode.
Semgrep rules: rules/11_mode_of_operation.yaml

Usage:
    python3 scripts/11_mode_of_operation.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=11))
