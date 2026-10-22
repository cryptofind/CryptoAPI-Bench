#!/usr/bin/env python3
"""Directory 6: SSL Socket.

Flags SSLSocket creation without hostname verification.
Semgrep rules: rules/06_ssl_socket.yaml

Usage:
    python3 scripts/06_ssl_socket.py <directory> [--json report.json] [--no-interprocedural] [--pro] [-v]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from cryptoscan.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main(category=6))
