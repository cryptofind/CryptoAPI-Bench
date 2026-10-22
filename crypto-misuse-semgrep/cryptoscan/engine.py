"""Semgrep engine for one crypto-misuse category, plus an inter-procedural layer.

``scan()`` runs a category's rule file with Semgrep.  Semgrep Community Edition
tracks taint only inside one method, so for every taint rule whose metadata says
``interprocedural: true`` the engine adds summaries that are themselves computed
by Semgrep, using rules generated from that rule's own sources and sinks:

* Backward summaries: the sinks are re-run with method parameters and field
  reads as sources.  "Parameter i of C.m reaches a sink" makes argument i of
  every call to C.m a new sink; "field C.f reaches a sink" makes every write to
  C.f a new sink.  This repeats until no new sink appears (a fixpoint).
* Forward summaries: methods whose return value is constant (according to the
  rule's own sources) turn their call sites into sources.
* Final pass: the rule's constant sources are run against every derived sink.

Calls are linked by class + method name + argument position: unqualified or
``this.`` calls inside the class, ``Class.m(...)``, receivers whose declared
type is the class, ``new C(...)``, and any receiver when the method name is
unique in the scanned code.  Fields are linked by class + name.  It is a
deliberately simple over-approximation, not a full call graph.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from pathlib import Path

MAX_PARAMS = 6
DEFAULT_MAX_ROUNDS = 8
_IDENT = re.compile(r"^[A-Za-z_]\w*$")
# Never treated as "returns a constant" helpers: the names collide with JDK APIs.
_LIBRARY_NAMES = frozenset({
    "toString", "hashCode", "equals", "getBytes", "toCharArray", "valueOf", "get", "getInstance",
    "getProperty", "getenv", "trim", "substring", "name", "getName", "clone", "toLowerCase",
    "toUpperCase", "format", "parseInt", "decode", "encode", "copyOf", "next", "read", "readLine",
    "getValue", "apply", "call", "run", "build", "create",
})


class SemgrepError(RuntimeError):
    """Semgrep is missing, crashed, or rejected the rule set."""


def load_rule_file(path) -> list:
    text = Path(path).read_text(encoding="utf-8")
    try:
        import yaml
        data = yaml.safe_load(text)
    except ImportError:
        try:
            from ruamel.yaml import YAML
        except ImportError as exc:
            raise SemgrepError("PyYAML is needed to read the rule files: pip install pyyaml") from exc
        data = YAML(typ="safe", pure=True).load(text)
    return list((data or {}).get("rules", []))


def _short_id(check_id) -> str:
    return str(check_id).rsplit(".", 1)[-1]


@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    path: str
    line: int
    column: int
    end_line: int
    snippet: str = ""
    kind: str = "intra"              # "intra": plain Semgrep rule, "inter": summary layer
    trace: list = field(default_factory=list)
    sink_path: str | None = None
    sink_line: int | None = None
    cwe: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    rule_file: str
    findings: list
    java_files: list
    semgrep_runs: int
    warnings: list
    derived_sinks: int = 0

    def to_dict(self):
        return {"target": self.target, "rule_file": self.rule_file, "java_files": len(self.java_files),
                "semgrep_runs": self.semgrep_runs, "derived_sinks": self.derived_sinks,
                "findings": [f.to_dict() for f in self.findings], "warnings": self.warnings}


class _Runner:
    """Runs Semgrep on one target directory with generated rule sets."""

    def __init__(self, target, extra_args, timeout, verbose):
        exe = shutil.which("semgrep")
        if exe is None:
            raise SemgrepError("semgrep is not on PATH - install it with: pip install semgrep")
        self.exe, self.target, self.extra_args = exe, target, list(extra_args)
        self.timeout, self.verbose = timeout, verbose
        self.runs, self.warnings, self.dropped = 0, [], set()
        self._tmp = tempfile.TemporaryDirectory(prefix="cryptoscan-")
        # An empty .semgrepignore in the working directory replaces Semgrep's default
        # ignore list, which would otherwise skip folders such as test/ or build/.
        Path(self._tmp.name, ".semgrepignore").write_text("")

    def close(self):
        self._tmp.cleanup()

    def _invoke(self, rules):
        self.runs += 1
        cfg = Path(self._tmp.name, f"rules{self.runs}.yaml")
        cfg.write_text(json.dumps({"rules": rules}), encoding="utf-8")  # JSON is valid YAML
        cmd = [self.exe, "scan", "--config", str(cfg), "--json", "--metrics=off", "--disable-version-check",
               "--no-git-ignore", "--quiet", "--timeout", str(self.timeout), *self.extra_args, str(self.target)]
        if self.verbose:
            print(f"[cryptoscan] semgrep run #{self.runs}: {len(rules)} rule(s)", file=sys.stderr)
        proc = subprocess.run(cmd, capture_output=True, text=True, cwd=self._tmp.name)
        try:
            return json.loads(proc.stdout)
        except json.JSONDecodeError:
            detail = (proc.stderr or proc.stdout or "").strip()[-3000:]
            raise SemgrepError(f"Semgrep failed (exit code {proc.returncode}):\n{detail}") from None

    def run(self, rules) -> list:
        """Run ``rules``; a rule Semgrep cannot parse is dropped (with a warning) and the rest re-run."""
        rules = list(rules)
        while rules:
            data = self._invoke(rules)
            known = {r["id"] for r in rules}
            bad, fatal = set(), []
            for err in data.get("errors", []):
                kind = str(err.get("type", ""))
                text = str(err.get("message") or kind).strip()
                if not re.search(r"rule|pattern|invalid", kind, re.I):
                    self.warnings.append(text.splitlines()[0][:300] if text else kind)
                    continue
                rid = _short_id(err.get("rule_id") or "")
                if rid not in known:
                    rid = next((k for k in sorted(known, key=len, reverse=True)
                                if re.search(r"(?<![\w-])" + re.escape(k) + r"(?![\w-])", text)), None)
                if rid:
                    bad.add(rid)
                else:
                    fatal.append(f"{kind}: {text[:1500]}")
            if fatal:
                raise SemgrepError("Semgrep rejected the rule set:\n" + "\n".join(fatal))
            if not bad:
                return data.get("results", [])
            for rid in sorted(bad):
                self.dropped.add(rid)
                self.warnings.append(f"rule {rid} skipped: Semgrep could not parse it")
            rules = [r for r in rules if r["id"] not in bad]
        return []


class _Lines:
    def __init__(self):
        self._files = {}

    def get(self, path, line):
        if path not in self._files:
            try:
                self._files[path] = Path(path).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._files[path] = []
        text = self._files[path]
        return text[line - 1].strip() if 0 < line <= len(text) else ""


class _Declarations:
    """Method parameters and fields of the scanned code (collected with Semgrep)."""

    def __init__(self):
        self.params = defaultdict(lambda: defaultdict(set))  # (path, class, method) -> param -> {index}
        self.by_position = defaultdict(set)                  # (method, index) -> {class}
        self.by_name = defaultdict(set)                      # method -> {class}
        self.fields = set()

    def record(self, res):
        parts = res["extra"].get("message", "").split("|")
        if any("$" in p for p in parts[1:]):
            return
        if parts[0] == "DECL" and len(parts) == 5:
            _, cls, method, idx, param = parts
            self.params[(res["path"], cls, method)][param].add(int(idx))
            self.by_position[(method, int(idx))].add(cls)
            self.by_name[method].add(cls)
        elif parts[0] == "MDECL" and len(parts) == 3:
            self.by_name[parts[2]].add(parts[1])
        elif parts[0] == "FDECL" and len(parts) == 3:
            self.fields.add(parts[2])

    def param_indices(self, path, cls, method, param):
        exact = self.params.get((path, cls, method), {}).get(param)
        if exact:
            return sorted(exact)
        found = set()
        for (_, c, m), table in self.params.items():
            if c == cls and m == method and param in table:
                found |= table[param]
        return sorted(found)

    def unique(self, method, idx=None):
        owners = self.by_name.get(method, set()) if idx is None else self.by_position.get((method, idx), set())
        return len(owners) <= 1


# ----------------------------------------------------------- rule generators ---
_IN_CLASS = {"pattern-inside": "class $CLS { ... }"}


def _decl_rules():
    rules = []
    for i in range(MAX_PARAMS):
        before = "".join(f"$T{j} $X{j}, " for j in range(i))
        for tag, head in (("m", "$RT $M"), ("c", "$M")):
            rules.append({"id": f"cs-decl-{tag}{i}", "languages": ["java"], "severity": "INFO",
                          "message": f"DECL|$CLS|$M|{i}|$P",
                          "patterns": [_IN_CLASS, {"pattern": f"{head}({before}$PT $P, ...) {{ ... }}"}]})
    rules.append({"id": "cs-decl-method", "languages": ["java"], "severity": "INFO", "message": "MDECL|$CLS|$M",
                  "patterns": [_IN_CLASS, {"pattern": "$RT $M(...) { ... }"}]})
    rules.append({"id": "cs-decl-field", "languages": ["java"], "severity": "INFO", "message": "FDECL|$CLS|$FLD",
                  "patterns": [_IN_CLASS,
                               {"pattern-either": [{"pattern": "$FT $FLD;"}, {"pattern": "$FT $FLD = $FINIT;"}]},
                               {"pattern-not-inside": "$RT $M(...) { ... }"},
                               {"pattern-not-inside": "$M(...) { ... }"}]})
    return rules


def _local_exclusions(var):
    """Exclude identifiers that are parameters or locals of the enclosing method."""
    out = []
    for head in ("$XRT $XM", "$XM"):
        out.append({"pattern-not-inside": f"{head}(..., $XPT {var}, ...) {{ ... }}"})
        out.append({"pattern-not-inside": f"{head}(...) {{\n  ...\n  $XLT {var} = $XLI;\n  ...\n}}"})
        out.append({"pattern-not-inside": f"{head}(...) {{\n  ...\n  $XLT {var};\n  ...\n}}"})
    return out


_PARAM_SOURCES = [{"patterns": [
    _IN_CLASS,
    {"pattern-either": [{"pattern": "$RT $M(..., $PT $P, ...) { ... }"},
                        {"pattern": "$M(..., $PT $P, ...) { ... }"}]},
    {"focus-metavariable": "$P"}]}]

_RET_SINK = [{"patterns": [{"pattern-inside": "class $RCLS { ... }"},
                           {"pattern-inside": "$RRT $RM(...) { ... }"},
                           {"pattern": "return $RV;"},
                           {"focus-metavariable": "$RV"}]}]


def _names_regex(names):
    return "^(?:" + "|".join(re.escape(n) for n in sorted(names)) + ")$"


def _field_sources_own(names):
    rx = {"metavariable-regex": {"metavariable": "$FLD", "regex": _names_regex(names)}}
    return [{"patterns": [_IN_CLASS,
                          {"pattern-either": [{"pattern": "this.$FLD"},
                                              {"patterns": [{"pattern": "$FLD"}, *_local_exclusions("$FLD")]}]},
                          rx]}]


def _field_sources_ext(names):
    rx = {"metavariable-regex": {"metavariable": "$FLD", "regex": _names_regex(names)}}
    return [{"patterns": [{"pattern": "$OBJ.$FLD"}, {"pattern-not": "this.$FLD"}, rx]}]


def _field_sinks(cls, name):
    rx = {"metavariable-regex": {"metavariable": "$FLD", "regex": f"^{re.escape(name)}$"}}
    own = [{"pattern-either": [{"pattern": "this.$FLD = $VAL"},
                               {"patterns": [{"pattern": "$FLD = $VAL"}, *_local_exclusions("$FLD")]}]},
           rx, {"focus-metavariable": "$VAL"}]
    if cls != "*":
        own = [_IN_CLASS, {"metavariable-regex": {"metavariable": "$CLS", "regex": f"^{re.escape(cls)}$"}}] + own
    ext = [{"pattern": "$OBJ.$FLD = $VAL"}, {"pattern-not": "this.$FLD = $VAL"}, rx, {"focus-metavariable": "$VAL"}]
    return [{"patterns": own}, {"patterns": ext}]


def _callee_regex(method):
    return {"metavariable-regex": {"metavariable": "$CALLEE", "regex": f"^{re.escape(method)}(?:<.*>)?$"}}


def _call_alternatives(cls, method, args, unique):
    if method == cls:  # constructor
        return [{"pattern": f"new $CALLEE({args})"}]
    alts = [{"patterns": [{"pattern-inside": "class $CCLS { ... }"},
                          {"metavariable-regex": {"metavariable": "$CCLS", "regex": f"^{re.escape(cls)}$"}},
                          {"pattern-either": [{"pattern": f"$CALLEE({args})"},
                                              {"pattern": f"this.$CALLEE({args})"}]}]}]
    if _IDENT.match(cls):
        alts += [{"pattern": f"{cls}.$CALLEE({args})"}, {"pattern": f"({cls} $OBJ).$CALLEE({args})"}]
    if unique:
        alts.append({"pattern": f"$OBJ.$CALLEE({args})"})
    return alts


def _call_sink(cls, method, idx, unique):
    args = "".join(f"$A{j}, " for j in range(idx)) + "$ARG, ..."
    return {"patterns": [{"pattern-either": _call_alternatives(cls, method, args, unique)},
                         _callee_regex(method), {"focus-metavariable": "$ARG"}]}


def _ret_sources(returns, decls):
    return [{"patterns": [{"pattern-either": _call_alternatives(cls, m, "...", decls.unique(m))}, _callee_regex(m)]}
            for cls, m in sorted(returns)]


def _derived_sinks(key, decls):
    if key[0] == "P":
        _, cls, method, idx = key
        return [_call_sink(cls, method, idx, decls.unique(method, idx))]
    return _field_sinks(key[1], key[2])


def _arg_literal_sources(rule, key, decls):
    """A literal passed directly as the argument of a summarised call, e.g. go("secret")."""
    alts = (rule.get("metadata") or {}).get("argument-literal") or []
    if key[0] != "P" or not alts:
        return []
    _, cls, method, idx = key
    base = _call_sink(cls, method, idx, decls.unique(method, idx))["patterns"][:-1]
    return [{"patterns": [*base, *alt, {"focus-metavariable": "$ARG"}]} for alt in alts]


def _taint_rule(rule_id, message, sources, sinks, base):
    rule = {"id": rule_id, "mode": "taint", "languages": ["java"], "severity": "INFO", "message": message,
            "pattern-sources": sources, "pattern-sinks": sinks}
    for key in ("pattern-sanitizers", "pattern-propagators", "options"):
        if base.get(key):
            rule[key] = base[key]
    return rule


# ------------------------------------------------------- inter-procedural ---
@dataclass
class _State:
    rule: dict
    derived: dict = field(default_factory=dict)          # key -> (parent key or None, path, line)
    frontier: list = field(default_factory=lambda: [None])
    returns: set = field(default_factory=set)            # {(class, method)} returning a constant
    returns_changed: bool = True


def _keys_from(kind, parts, path, decls):
    if kind == "param" and len(parts) == 4:
        _, cls, method, param = parts
        if "$" in cls + method + param:
            return []
        return [("P", cls, method, i) for i in decls.param_indices(path, cls, method, param)]
    if kind == "field" and len(parts) == 3:
        _, cls, name = parts
        return [] if "$" in cls + name else [("F", cls, name)]
    return []


def _describe(key):
    if key[0] == "P":
        _, cls, method, idx = key
        target = f"new {cls}(...)" if method == cls else f"{cls}.{method}(...)"
        return f"argument #{idx + 1} of {target}"
    _, cls, name = key
    return f"field {name}" if cls == "*" else f"field {cls}.{name}"


def _trace(state, key, res):
    if key is None:
        return ["value returned by a helper method"], (res["path"], res["start"]["line"])
    steps, cur, seen, last = [], key, set(), (None, None)
    while cur is not None and cur not in seen:
        seen.add(cur)
        parent, path, line = state.derived[cur]
        steps.append(_describe(cur))
        last, cur = (path, line), parent
    return steps, last


def _const_sources(state, decls):
    return list(state.rule["pattern-sources"]) + (_ret_sources(state.returns, decls) if state.returns else [])


def _interprocedural(runner, ip_rules, decls, max_rounds, lines, verbose):
    states = [_State(rule=r) for r in ip_rules]
    own_fields = _field_sources_own(decls.fields) if decls.fields else None
    ext_fields = _field_sources_ext(decls.fields) if decls.fields else None
    for rnd in range(max_rounds):
        batch, meta = [], {}

        def add(rule_id, message, sources, sinks, si, kind, sink_key):
            batch.append(_taint_rule(rule_id, message, sources, sinks, states[si].rule))
            meta[rule_id] = (kind, si, sink_key)

        for si, st in enumerate(states):
            if st.returns_changed:
                add(f"cs-ret-{si}-{rnd}", "RET|$RCLS|$RM", _const_sources(st, decls), _RET_SINK, si, "ret", None)
            for fi, sink_key in enumerate(st.frontier):
                sinks = st.rule["pattern-sinks"] if sink_key is None else _derived_sinks(sink_key, decls)
                add(f"cs-par-{si}-{rnd}-{fi}", "PARAM|$CLS|$M|$P", _PARAM_SOURCES, sinks, si, "param", sink_key)
                if own_fields:
                    add(f"cs-fld-{si}-{rnd}-{fi}", "FIELD|$CLS|$FLD", own_fields, sinks, si, "field", sink_key)
                    add(f"cs-fldx-{si}-{rnd}-{fi}", "FIELD|*|$FLD", ext_fields, sinks, si, "field", sink_key)
        if not batch:
            break
        new_keys, new_returns = defaultdict(list), defaultdict(set)
        for res in runner.run(batch):
            kind, si, sink_key = meta[_short_id(res["check_id"])]
            st = states[si]
            parts = res["extra"].get("message", "").split("|")
            if kind == "ret":
                if len(parts) == 3 and "$" not in parts[1] + parts[2] and parts[2] not in _LIBRARY_NAMES:
                    if (parts[1], parts[2]) not in st.returns:
                        new_returns[si].add((parts[1], parts[2]))
                continue
            for key in _keys_from(kind, parts, res["path"], decls):
                if key == sink_key or key in st.derived:
                    continue
                st.derived[key] = (sink_key, res["path"], res["start"]["line"])
                new_keys[si].append(key)
        for si, st in enumerate(states):
            st.frontier = new_keys.get(si, [])
            st.returns |= new_returns.get(si, set())
            st.returns_changed = bool(new_returns.get(si))
        if verbose:
            print(f"[cryptoscan] round {rnd}: " + "; ".join(
                f"{st.rule['id']}: {len(st.derived)} derived sink(s), {len(st.returns)} constant-returning method(s)"
                for st in states), file=sys.stderr)
        if not any(st.frontier or st.returns_changed for st in states):
            break

    batch, meta = [], {}
    for si, st in enumerate(states):
        consts = _const_sources(st, decls)
        if st.returns:
            rid = f"cs-const-{si}-root"
            batch.append(_taint_rule(rid, "CONST", consts, st.rule["pattern-sinks"], st.rule))
            meta[rid] = (si, None)
        for ki, key in enumerate(st.derived):
            rid = f"cs-const-{si}-{ki}"
            batch.append(_taint_rule(rid, "CONST", consts + _arg_literal_sources(st.rule, key, decls),
                                     _derived_sinks(key, decls), st.rule))
            meta[rid] = (si, key)
    findings = []
    for res in runner.run(batch):
        si, key = meta[_short_id(res["check_id"])]
        finding = _finding(res, states[si].rule, lines, kind="inter")
        finding.trace, (finding.sink_path, finding.sink_line) = _trace(states[si], key, res)
        findings.append(finding)
    return findings, sum(len(st.derived) for st in states)


# ------------------------------------------------------------------- scan ---
def _finding(res, rule, lines, kind="intra"):
    meta = rule.get("metadata") or {}
    cwe = meta.get("cwe")
    if isinstance(cwe, list):
        cwe = cwe[0] if cwe else None
    if kind == "intra":
        severity = res["extra"].get("severity") or rule.get("severity", "WARNING")
        message = res["extra"].get("message") or rule.get("message", "")
    else:
        severity, message = rule.get("severity", "WARNING"), rule.get("message", "")
    path, line = res["path"], res["start"]["line"]
    return Finding(rule_id=rule["id"], severity=severity, message=" ".join(str(message).split()), path=path,
                   line=line, column=res["start"]["col"], end_line=res["end"]["line"],
                   snippet=lines.get(path, line), kind=kind, cwe=cwe)


def _dedupe(findings):
    intra_lines = {(f.rule_id, f.path, f.line) for f in findings if f.kind == "intra"}
    out, seen = [], set()
    for f in findings:
        if f.kind == "inter" and (f.rule_id, f.path, f.line) in intra_lines:
            continue
        key = (f.rule_id, f.path, f.line, f.column, f.kind)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return sorted(out, key=lambda f: (f.path, f.line, f.column, f.rule_id))


def scan(target, rule_file, *, interprocedural=True, max_rounds=DEFAULT_MAX_ROUNDS,
         semgrep_args=(), timeout=120, verbose=False) -> ScanResult:
    """Run one category's rules on ``target`` (a directory of Java files)."""
    target = Path(target).resolve()
    if not target.is_dir():
        raise SemgrepError(f"not a directory: {target}")
    rules = load_rule_file(rule_file)
    by_id = {r["id"]: r for r in rules}
    ip_rules = [r for r in rules if interprocedural and r.get("mode") == "taint"
                and (r.get("metadata") or {}).get("interprocedural")]
    runner = _Runner(target, semgrep_args, timeout, verbose)
    lines, decls, findings, derived = _Lines(), _Declarations(), [], 0
    try:
        for res in runner.run(rules + (_decl_rules() if ip_rules else [])):
            rid = _short_id(res["check_id"])
            if rid in by_id:
                findings.append(_finding(res, by_id[rid], lines))
            else:
                decls.record(res)
        ip_rules = [r for r in ip_rules if r["id"] not in runner.dropped]
        if ip_rules:
            extra, derived = _interprocedural(runner, ip_rules, decls, max_rounds, lines, verbose)
            findings += extra
    finally:
        runner.close()
    java = sorted(str(p) for p in target.rglob("*.java"))
    return ScanResult(str(target), str(rule_file), _dedupe(findings), java, runner.runs, runner.warnings, derived)
