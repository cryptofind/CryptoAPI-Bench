#!/usr/bin/env python3
"""Directory 4: Hostname Verifier.

Flags HostnameVerifier implementations or lambdas that accept every host.
Semgrep rules: rules/04_hostname_verifier.yaml

Usage:
    python3 scripts/04_hostname_verifier.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=4))
