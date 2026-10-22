#!/usr/bin/env python3
"""Directory 7: HTTP Protocol.

Flags plain http:// URLs used for network requests.
Semgrep rules: rules/07_http_protocol.yaml

Usage:
    python3 scripts/07_http_protocol.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=7))
