#!/usr/bin/env python3
"""Directory 3: Password in KeyStore.

Flags constant passwords used to load, store or unlock a KeyStore or KeyManagerFactory.
Semgrep rules: rules/03_keystore_password.yaml

Usage:
    python3 scripts/03_keystore_password.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=3))
