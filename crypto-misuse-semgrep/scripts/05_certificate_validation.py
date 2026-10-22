#!/usr/bin/env python3
"""Directory 5: Certificate Validation.

Flags X509TrustManager implementations and helpers that accept every certificate.
Semgrep rules: rules/05_certificate_validation.yaml

Usage:
    python3 scripts/05_certificate_validation.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=5))
