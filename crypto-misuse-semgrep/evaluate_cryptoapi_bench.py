#!/usr/bin/env python3
"""Score the 16 analysers against CryptoAPI-Bench's ground truth.

    python3 evaluate_cryptoapi_bench.py /path/to/CryptoAPI-Bench [--compare] [--markdown FILE]

Ground truth (CryptoAPI-Bench_details.xlsx), evaluated per test case:
  * every case is insecure except the *Corrected* files, the path-sensitive ABPS
    cases (the insecure value is overwritten on the only feasible path) and the two
    "advanced false-positive" cases PredictablePBEPasswordABHCase1 and
    PredictableKeyStorePasswordABHCase1;
  * a multi-class case (XABMCCaseN.java plus its helper XABMCN.java) is one case;
  * a case is detected when at least one finding is reported in one of its files.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from cryptoscan.categories import CATEGORIES  # noqa: E402
from cryptoscan.cli import run_category  # noqa: E402
from cryptoscan.engine import SemgrepError  # noqa: E402

SECURE_ABH = {"PredictablePBEPasswordABHCase1", "PredictableKeyStorePasswordABHCase1"}
KINDS = [("BB", "basic"), ("ABI", "inter-procedural"), ("ABS", "field-sensitive"), ("ABMC", "multiple classes"),
         ("ABH", "HashMap / SecureRandom"), ("ABPS", "path-sensitive"), ("Corrected", "corrected")]


@dataclass
class Case:
    name: str
    files: list
    kind: str
    insecure: bool
    detected: bool = False


def case_kind(stem):
    for key in ("Corrected", "ABPS", "ABMC", "ABH", "ABI", "ABS"):
        if key in stem:
            return key
    return "BB"


def load_cases(directory):
    stems = sorted(p.stem for p in Path(directory).glob("*.java"))
    helpers = {s for s in stems if re.search(r"ABMC\d+$", s)}
    cases = []
    for stem in stems:
        if stem in helpers:
            continue
        files = [stem]
        m = re.search(r"ABMCCase(\d+)$", stem)
        if m and f"{stem[:m.start()]}ABMC{m.group(1)}" in helpers:
            files.append(f"{stem[:m.start()]}ABMC{m.group(1)}")
        kind = case_kind(stem)
        cases.append(Case(stem, files, kind, kind not in ("Corrected", "ABPS") and stem not in SECURE_ABH))
    return cases


def find_bench(root):
    root = Path(root).resolve()
    for candidate in (root / "src" / "main" / "java" / "org" / "cryptoapi" / "bench", root):
        if (candidate / "brokencrypto").is_dir():
            return candidate
    sys.exit(f"error: CryptoAPI-Bench sources not found under {root}")


def evaluate(bench, interprocedural, jobs):
    def work(number):
        start = time.time()
        try:
            result = run_category(number, bench / CATEGORIES[number].aliases[0], interprocedural=interprocedural)
            return number, result, None, time.time() - start
        except SemgrepError as exc:
            return number, None, str(exc), time.time() - start

    with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        outcome = list(pool.map(work, sorted(CATEGORIES)))
    rows = {}
    for number, result, error, seconds in outcome:
        cases = load_cases(bench / CATEGORIES[number].aliases[0])
        flagged = {Path(f.path).stem for f in result.findings} if result else set()
        for case in cases:
            case.detected = any(name in flagged for name in case.files)
        rows[number] = (cases, result, error, seconds)
    return rows


def counts(cases):
    tp = sum(c.insecure and c.detected for c in cases)
    fn = sum(c.insecure and not c.detected for c in cases)
    fp = sum(not c.insecure and c.detected for c in cases)
    tn = sum(not c.insecure and not c.detected for c in cases)
    return tp, fn, fp, tn


def pct(num, den):
    return f"{100.0 * num / den:.1f}%" if den else "n/a"


def report(rows, title):
    out = [f"#### {title}", "", "| # | Category | Cases | TP | FN | FP | TN | Precision | Recall | Time |",
           "|---:|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    total, errors = [0, 0, 0, 0], []
    for number in sorted(rows):
        cases, _result, error, seconds = rows[number]
        tp, fn, fp, tn = counts(cases)
        if error:
            errors.append(f"{number}: {error.strip().splitlines()[0][:300]}")
        total = [a + b for a, b in zip(total, (tp, fn, fp, tn))]
        name = CATEGORIES[number].title + (" (error)" if error else "")
        out.append(f"| {number} | {name} | {len(cases)} | {tp} | {fn} | {fp} | {tn} | "
                   f"{pct(tp, tp + fp)} | {pct(tp, tp + fn)} | {seconds:.0f}s |")
    tp, fn, fp, tn = total
    out.append(f"| | **Total** | {tp + fn + fp + tn} | {tp} | {fn} | {fp} | {tn} | "
               f"**{pct(tp, tp + fp)}** | **{pct(tp, tp + fn)}** | |")
    all_cases = [c for number in sorted(rows) for c in rows[number][0]]
    out += ["", "| Case type | Insecure cases detected | Secure cases flagged |", "|---|---:|---:|"]
    for key, label in KINDS:
        insecure = [c for c in all_cases if c.kind == key and c.insecure]
        secure = [c for c in all_cases if c.kind == key and not c.insecure]
        out.append(f"| {key} ({label}) | {sum(c.detected for c in insecure)}/{len(insecure)} | "
                   f"{sum(c.detected for c in secure)}/{len(secure)} |")
    missed = [c.name for c in all_cases if c.insecure and not c.detected]
    flagged_secure = [c.name for c in all_cases if not c.insecure and c.detected]
    out += ["", f"Missed insecure cases ({len(missed)}): {', '.join(missed) or 'none'}.",
            "", f"Secure cases flagged ({len(flagged_secure)}): {', '.join(flagged_secure) or 'none'}."]
    if errors:
        out += ["", "Errors: " + "; ".join(errors)]
    return "\n".join(out)


def update_readme(path, text):
    readme = Path(path)
    content = readme.read_text(encoding="utf-8")
    start, end = "<!-- BEGIN RESULTS -->", "<!-- END RESULTS -->"
    if start in content and end in content:
        head, rest = content.split(start, 1)
        tail = rest.split(end, 1)[1]
        readme.write_text(f"{head}{start}\n{text}\n{end}{tail}", encoding="utf-8")


def semgrep_version():
    try:
        return subprocess.run(["semgrep", "--version"], capture_output=True, text=True).stdout.strip() or "?"
    except OSError:
        return "?"


def main(argv=None):
    ap = argparse.ArgumentParser(description="Score the analysers against CryptoAPI-Bench.")
    ap.add_argument("bench", help="path to a CryptoAPI-Bench checkout")
    ap.add_argument("--compare", action="store_true", help="also score the plain Semgrep rules")
    ap.add_argument("--no-interprocedural", action="store_true", help="score only the plain Semgrep rules")
    ap.add_argument("--jobs", type=int, default=4, help="categories analysed in parallel")
    ap.add_argument("--markdown", metavar="FILE", help="write the result tables to FILE")
    ap.add_argument("--update-readme", metavar="README", help="replace the results section of README")
    args = ap.parse_args(argv)
    bench = find_bench(args.bench)
    plain = (False, "Plain Semgrep rules only (--no-interprocedural)")
    full = (True, "Semgrep rules + inter-procedural summary layer (default)")
    modes = [plain] if args.no_interprocedural else ([plain, full] if args.compare else [full])
    sections = [f"Case-level scores on CryptoAPI-Bench with Semgrep {semgrep_version()}."]
    for interprocedural, title in modes:
        start = time.time()
        section = report(evaluate(bench, interprocedural, args.jobs), title)
        sections.append(f"{section}\n\nWall-clock time: {time.time() - start:.0f}s.")
        print(sections[-1] + "\n", flush=True)
    text = "\n\n".join(sections)
    if args.markdown:
        Path(args.markdown).parent.mkdir(parents=True, exist_ok=True)
        Path(args.markdown).write_text(text + "\n", encoding="utf-8")
    if args.update_readme:
        update_readme(args.update_readme, text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
