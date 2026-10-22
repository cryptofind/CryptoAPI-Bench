"""Command-line front end shared by the 16 per-directory scripts."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

from .categories import CATEGORIES, PROJECT_ROOT
from .engine import DEFAULT_MAX_ROUNDS, SemgrepError, scan


def run_category(number, directory, *, interprocedural=True, pro=False, max_rounds=DEFAULT_MAX_ROUNDS,
                 verbose=False):
    cat = CATEGORIES[number]
    return scan(directory, cat.rule_file, interprocedural=interprocedural, max_rounds=max_rounds,
                semgrep_args=["--pro"] if pro else [], verbose=verbose)


def _rel(path, base):
    try:
        return str(Path(path).resolve().relative_to(Path(base).resolve()))
    except ValueError:
        return str(path)


def _first_sentence(text):
    idx = text.find(". ")
    return text if idx < 0 else text[: idx + 1]


def format_report(cat, result) -> str:
    base = result.target
    out = ["=" * 78, cat.label, f"Rules : {_rel(cat.rule_file, PROJECT_ROOT)}",
           f"Target: {base}  ({len(result.java_files)} Java file(s))", "=" * 78]
    by_file = defaultdict(list)
    for f in result.findings:
        by_file[f.path].append(f)
    for path in sorted(by_file):
        out += ["", _rel(path, base)]
        for f in by_file[path]:
            tag = "  [inter-procedural]" if f.kind == "inter" else ""
            out.append(f"  {f.severity:<7} line {f.line:<4} {f.rule_id}{tag}")
            if f.snippet:
                out.append(f"          {f.snippet}")
            out.append(f"          {_first_sentence(f.message)}")
            if f.kind == "inter":
                sink = f"{_rel(f.sink_path, base)}:{f.sink_line}" if f.sink_path else "?"
                out.append("          flow: " + " -> ".join(["constant", *f.trace, f"crypto API at {sink}"]))
    inter = sum(f.kind == "inter" for f in result.findings)
    out += ["", "-" * 78]
    if result.findings:
        out.append(f"{len(result.findings)} finding(s) in {len(by_file)} of {len(result.java_files)} Java file(s) "
                   f"[{len(result.findings) - inter} intra-procedural, {inter} inter-procedural]")
    else:
        out.append(f"No misuse found in {len(result.java_files)} Java file(s).")
    if result.warnings:
        out.append(f"Semgrep reported {len(result.warnings)} warning(s); run with --verbose to list them.")
    return "\n".join(out)


def _parser(cat):
    p = argparse.ArgumentParser(description=f"{cat.label}: flags {cat.summary}. Rules: rules/{cat.rule_file.name}")
    p.add_argument("directory", help="directory containing the Java files to analyse")
    p.add_argument("--json", metavar="FILE", help="also write the findings to FILE as JSON")
    p.add_argument("--no-interprocedural", action="store_true",
                   help="run the plain Semgrep rules only (skip the summary-based inter-procedural layer)")
    p.add_argument("--pro", action="store_true", help="pass --pro to Semgrep (requires Semgrep Pro / semgrep login)")
    p.add_argument("--max-rounds", type=int, default=DEFAULT_MAX_ROUNDS,
                   help=f"fixpoint rounds for the inter-procedural layer (default {DEFAULT_MAX_ROUNDS})")
    p.add_argument("-v", "--verbose", action="store_true", help="show Semgrep runs and warnings")
    return p


def main(category: int, argv=None) -> int:
    cat = CATEGORIES[category]
    args = _parser(cat).parse_args(argv)
    try:
        result = run_category(category, args.directory, interprocedural=not args.no_interprocedural,
                              pro=args.pro, max_rounds=args.max_rounds, verbose=args.verbose)
    except SemgrepError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(format_report(cat, result))
    if args.verbose:
        for warning in result.warnings:
            print(f"warning: {warning}", file=sys.stderr)
    if args.json:
        payload = {"category": cat.number, "title": cat.title, **result.to_dict()}
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return 1 if result.findings else 0
