#!/usr/bin/env python3
"""Run all 16 per-directory analysers and print a summary table.

    python3 run_all.py ROOT                     # discover the 16 directories under ROOT
    python3 run_all.py --map 1=path/to/dir1 --map 2=path/to/dir2 ...

Directories are matched by number (1, 01, dir1, directory_1, 01_xxx, ...), by
category name (cryptographic_key, hostname_verifier, ...) or by CryptoAPI-Bench
folder name (predictablecryptographickey, brokenhash, ...).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptoscan.categories import CATEGORIES  # noqa: E402
from cryptoscan.cli import format_report, run_category  # noqa: E402
from cryptoscan.engine import SemgrepError  # noqa: E402

_NUMBERED = re.compile(r"^(?:dir|directory|d|folder|cat|category|rule|case)?[\s_-]*0*(\d{1,2})(?:$|[\s_.-])", re.I)


def _norm(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())


def category_of(name):
    m = _NUMBERED.match(name)
    if m and 1 <= int(m.group(1)) <= 16:
        return int(m.group(1))
    key = _norm(name)
    for cat in CATEGORIES.values():
        if key in cat.aliases or key in (_norm(cat.slug), _norm(cat.title)):
            return cat.number
    return None


def discover(root, max_depth=6):
    root = Path(root).resolve()
    found = {}
    for path in sorted(root.rglob("*")):
        if not path.is_dir() or len(path.relative_to(root).parts) > max_depth:
            continue
        number = category_of(path.name)
        if number and number not in found and any(path.rglob("*.java")):
            found[number] = path
    return found


def main(argv=None):
    ap = argparse.ArgumentParser(description="Run the 16 crypto-misuse analysers.")
    ap.add_argument("root", nargs="?", help="folder that contains the 16 directories")
    ap.add_argument("--map", action="append", default=[], metavar="N=DIR", help="explicit directory for category N")
    ap.add_argument("--json", metavar="FILE", help="write all findings to FILE as JSON")
    ap.add_argument("--no-interprocedural", action="store_true", help="plain Semgrep rules only")
    ap.add_argument("--pro", action="store_true", help="pass --pro to Semgrep")
    ap.add_argument("--jobs", type=int, default=4, help="categories analysed in parallel (default 4)")
    ap.add_argument("--summary-only", action="store_true", help="print only the summary table")
    args = ap.parse_args(argv)
    dirs = discover(args.root) if args.root else {}
    for item in args.map:
        number, _, directory = item.partition("=")
        if not number.strip().isdigit() or int(number) not in CATEGORIES or not directory:
            ap.error(f"bad --map value {item!r}; expected N=DIR with N in 1..16")
        dirs[int(number)] = Path(directory).resolve()
    if not dirs:
        ap.error("no category directories found; pass ROOT or --map N=DIR")

    def work(number):
        try:
            return number, run_category(number, dirs[number], interprocedural=not args.no_interprocedural,
                                        pro=args.pro), None
        except SemgrepError as exc:
            return number, None, str(exc)

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        outcome = {n: (res, err) for n, res, err in pool.map(work, sorted(dirs))}
    rows, payload, status = [], [], 0
    for number in sorted(outcome):
        cat, (result, error) = CATEGORIES[number], outcome[number]
        if error:
            status = 2
            print(f"{cat.label}: ERROR {error}\n", file=sys.stderr)
            rows.append((number, cat.title, Path(dirs[number]).name, "-", "-", "error"))
            continue
        if not args.summary_only:
            print(format_report(cat, result) + "\n")
        inter = sum(f.kind == "inter" for f in result.findings)
        rows.append((number, cat.title, Path(result.target).name, len(result.java_files),
                     len({f.path for f in result.findings}),
                     f"{len(result.findings)} ({len(result.findings) - inter}+{inter})"))
        payload.append({"category": number, "title": cat.title, **result.to_dict()})
        if result.findings and status == 0:
            status = 1
    header = f"{'#':>2}  {'Category':<24} {'Directory':<30} {'Java':>5} {'Flagged':>8}  Findings (intra+inter)"
    print(header)
    print("-" * len(header))
    for number, title, name, files, flagged, findings in rows:
        print(f"{number:>2}  {title:<24} {name[:30]:<30} {files!s:>5} {flagged!s:>8}  {findings}")
    missing = [str(n) for n in CATEGORIES if n not in dirs]
    if missing:
        print(f"\nNo directory found for categories: {', '.join(missing)} (use --map N=DIR).")
    if args.json:
        Path(args.json).write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return status


if __name__ == "__main__":
    sys.exit(main())
