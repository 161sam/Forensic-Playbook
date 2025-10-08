#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IoC_Scan.py — npm/yarn/pnpm supply-chain scanner mit Heuristiken & Registry-Härtung

Was es macht:
- Findet Repos via package.json (node_modules & Co. ignoriert)
- Parst Lockfiles: package-lock.json, npm-shrinkwrap.json, yarn.lock (Classic & Berry),
  pnpm-lock.yaml
- Prüft package.json-Lifecycle-Hooks (pre/install/prepare/postinstall)
- Grept Source nach Red Flags:
    * child_process.(exec|spawn|execSync|spawnSync)        [+3]
    * eval(…) oder new Function(…)                         [+2]
    * Buffer.from(…, "base64") oder atob(…)                [+2]
    * Netz-IO (curl|wget|Invoke-WebRequest|https?://)      [+4]
  Hooks selbst geben +3 (nur wenn nicht whitelisted, s. --whitelist)
- Registry-Härtung: scannt .npmrc, publishConfig.registry, .yarnrc.yml (npmRegistryServer)
  und NPM_CONFIG_REGISTRY; warnt, wenn ≠ https://registry.npmjs.org
- Optionales IoC-Matching (Packages oder Domains)
- Ausgaben: JSON (detailliert), CSV (Summary) und SARIF 2.1.0
- Performance: Multiprocessing + optional ripgrep-Beschleunigung

Beispiele:
  python3 IoC_Scan.py /path/to/root1 /path/to/root2 \
    --json out.json --csv out.csv --sarif out.sarif --workers 8

  python3 IoC_Scan.py /home/user/Projects --ioc-file iocs.txt --no-rg

IoC-Datei (einfach, newline-delimited):
  # package IoCs
  left-pad@1.3.0
  @scope/badpkg@2.0.0
  # domains / URLs
  websocket-api2.publicvm.com
  https://npmjs.help
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import dataclasses
import fnmatch
import io
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple, Set

# --------------------------- Defaults ---------------------------

DEFAULT_EXCLUDES = [
    "**/node_modules/**",
    "**/.git/**",
    "**/.hg/**",
    "**/.svn/**",
    "**/.cache/**",
    "**/.venv/**",
    "**/.venvs/**",
    "**/.next/**",
    "**/dist/**",
    "**/build/**",
    "**/out/**",
    "**/__tests__/**",
    "**/tests/**",
    "**/test/**",
    "**/spec/**",
    "**/examples/**",
    "**/example/**",
    "**/docs/**",
]

DEFAULT_EXTS = [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json"]

WHITELIST_DEFAULT = [
    # Whitelist greift NUR auf Hook-Kommandos (substring, case-insensitive)
    "husky", "prisma", "node-gyp", "opencollective", "esbuild",
    "sharp", "cypress", "electron", "nx", "vite"
]

REGISTRY_SAFE = "https://registry.npmjs.org"

# Heuristik-Gewichte
WEIGHTS = {
    "hook": 3,
    "child_process": 3,
    "eval_function": 2,
    "base64_decode": 2,
    "net_io": 4,
    "registry_warn": 1,
    "ioc_match": 5,
}

# ripgrep-Patterns
RG_PATTERNS = {
    "child_process": r"child_process\.(exec|spawn|execSync|spawnSync)",
    "eval_function": r"\beval\s*\(|\bnew\s+Function\s*\(",
    "base64_decode": r"Buffer\.from\([^,]+,\s*['\"]base64['\"]\)|\batob\s*\(",
    "net_io": r"\bcurl\s+https?://|\bwget\s+https?://|\bInvoke-WebRequest\b|\bPowerShell\s+-|https?://|wss?://|tcp://|udp://",
}

RE_NPMRC_REG = re.compile(r"^\s*(?:@[^:]+:)?registry\s*=\s*(\S+)\s*$", re.I)
RE_YARNRC_REG = re.compile(r"^\s*npmRegistryServer\s*:\s*(\S+)\s*$", re.I)
RE_ENV_ASSIGN = re.compile(r"\bNPM_CONFIG_REGISTRY\s*=\s*([^\s\"']+)", re.I)

RE_YARN_RESOLVED = re.compile(r'^\s*resolved\s+"([^"]+)"')         # Classic
RE_YARN_RESOLUTION = re.compile(r'^\s*resolution\s*:\s*"([^"]+)"')  # Berry
RE_URL = re.compile(r"https?://[^\s\"')]+")

RE_PNPM_TARBALL = re.compile(r"\btarball\s*:\s*(https?://\S+)")
RE_PNPM_NAME = re.compile(r"^\s*name\s*:\s*(.+)$")

RE_HOST = re.compile(r"^(?:https?://)?([^/]+)")

# --------------------------- Data ---------------------------

@dataclasses.dataclass
class RuleHit:
    rule: str
    file: str
    line: int
    snippet: str

@dataclasses.dataclass
class HookHit:
    file: str
    hook: str
    command: str
    whitelisted: bool

@dataclasses.dataclass
class RegistryFinding:
    file: str
    kind: str  # npmrc | publishConfig | yarnrc | env
    value: str
    ok: bool

@dataclasses.dataclass
class LockFinding:
    file: str
    package: Optional[str]
    resolved: Optional[str]
    extra: Dict[str, str] = dataclasses.field(default_factory=dict)

@dataclasses.dataclass
class RepoReport:
    repo_path: str
    score: int
    rule_counts: Dict[str, int]
    hooks: List[HookHit]
    rule_hits: List[RuleHit]
    registries: List[RegistryFinding]
    lockfindings: List[LockFinding]
    ioc_matches: List[str]
    notes: List[str]

# --------------------------- Utils ---------------------------

def which(cmd: str) -> Optional[str]:
    return shutil.which(cmd)

def read_text(path: Path, max_bytes: int = 8 * 1024 * 1024) -> Optional[str]:
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes + 1)
        if len(data) > max_bytes:
            data = data[:max_bytes]
        return data.decode("utf-8", errors="replace")
    except Exception:
        return None

def is_excluded(path: Path, exclude_globs: List[str]) -> bool:
    s = str(path)
    for pat in exclude_globs:
        if fnmatch.fnmatch(s, pat):
            return True
    return False

def find_repos(roots: List[Path], exclude_globs: List[str]) -> List[Path]:
    repo_roots: Set[Path] = set()
    for root in roots:
        root = root.resolve()
        if root.is_file():
            continue
        for p in root.rglob("package.json"):
            if "node_modules" in p.parts:
                continue
            if any(fnmatch.fnmatch(str(p), g) for g in exclude_globs):
                continue
            repo_roots.add(p.parent.resolve())
    return sorted(repo_roots)

def load_json_safely(p: Path) -> Optional[dict]:
    try:
        return json.loads(read_text(p) or "")
    except Exception:
        return None

def iter_files(repo: Path, exts: List[str], exclude_globs: List[str]) -> Iterable[Path]:
    for p in repo.rglob("*"):
        if p.is_file():
            if exts and p.suffix.lower() not in exts:
                continue
            if is_excluded(p, exclude_globs):
                continue
            yield p

# --------------------------- ripgrep ---------------------------

def rg_search(repo: Path, pattern: str, exts: List[str], exclude_globs: List[str], max_filesize: int) -> List[RuleHit]:
    rg = which("rg")
    if not rg:
        return []
    cmd = [rg, "-n", "-i", "--no-heading", f"--max-filesize={max_filesize}M"]
    for g in exclude_globs:
        cmd += ["-g", f"!{g}"]
    if exts:
        for ext in set(exts):
            cmd += ["-g", f"**/*{ext}"]
    cmd += ["-e", pattern, str(repo)]
    try:
        out = subprocess.run(cmd, check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True).stdout
    except Exception:
        return []
    hits: List[RuleHit] = []
    for line in out.splitlines():
        try:
            file_part, lineno, snippet = line.split(":", 2)
            hits.append(RuleHit(rule="", file=file_part, line=int(lineno), snippet=snippet.strip()))
        except ValueError:
            continue
    return hits

def py_grep(repo: Path, pattern: str, exts: List[str], exclude_globs: List[str], max_bytes_per_file: int = 4 * 1024 * 1024) -> List[RuleHit]:
    rx = re.compile(pattern, re.I)
    hits: List[RuleHit] = []
    for f in iter_files(repo, exts, exclude_globs):
        txt = read_text(f, max_bytes=max_bytes_per_file)
        if not txt:
            continue
        for i, ln in enumerate(txt.splitlines(), 1):
            if rx.search(ln):
                hits.append(RuleHit(rule="", file=str(f), line=i, snippet=ln.strip()))
    return hits

# --------------------------- Lockfiles ---------------------------

def parse_package_lock(p: Path) -> List[LockFinding]:
    data = load_json_safely(p) or {}
    findings: List[LockFinding] = []
    if "packages" in data:  # npm v7+
        for k, v in data.get("packages", {}).items():
            resolved = (v or {}).get("resolved")
            name = (v or {}).get("name")
            if resolved or name:
                findings.append(LockFinding(file=str(p), package=name, resolved=resolved))
    elif "dependencies" in data:
        def walk_deps(d):
            for name, info in d.items():
                resolved = (info or {}).get("resolved")
                version = (info or {}).get("version")
                pkg = f"{name}@{version}" if version else name
                findings.append(LockFinding(file=str(p), package=pkg, resolved=resolved))
                if "dependencies" in (info or {}):
                    walk_deps(info["dependencies"])
        walk_deps(data["dependencies"])
    return findings

def parse_yarn_lock(p: Path) -> List[LockFinding]:
    findings: List[LockFinding] = []
    txt = read_text(p) or ""
    pkg_current: Optional[str] = None
    for raw in txt.splitlines():
        line = raw.rstrip()
        m_resolved = RE_YARN_RESOLVED.match(line)  # Classic
        if m_resolved:
            findings.append(LockFinding(file=str(p), package=pkg_current, resolved=m_resolved.group(1)))
            continue
        if line and not line.startswith((" ", "#")) and line.endswith(":"):
            pkg_current = line.strip().rstrip(":").strip('"')
        m_resolution = RE_YARN_RESOLUTION.match(line)  # Berry
        if m_resolution:
            findings.append(LockFinding(file=str(p), package=m_resolution.group(1), resolved=None, extra={"resolution": m_resolution.group(1)}))
            continue
        for u in RE_URL.findall(line):
            findings.append(LockFinding(file=str(p), package=pkg_current, resolved=u))
    return findings

def parse_pnpm_lock(p: Path) -> List[LockFinding]:
    findings: List[LockFinding] = []
    txt = read_text(p) or ""
    current_name: Optional[str] = None
    for line in txt.splitlines():
        m_name = RE_PNPM_NAME.match(line)
        if m_name:
            current_name = m_name.group(1).strip().strip('"')
        for m in RE_PNPM_TARBALL.finditer(line):
            findings.append(LockFinding(file=str(p), package=current_name, resolved=m.group(1)))
        for u in RE_URL.findall(line):
            if u.endswith(".tgz"):
                findings.append(LockFinding(file=str(p), package=current_name, resolved=u))
    return findings

def parse_lockfiles(repo: Path) -> List[LockFinding]:
    findings: List[LockFinding] = []
    for name in ("package-lock.json", "npm-shrinkwrap.json"):
        p = repo / name
        if p.exists():
            findings.extend(parse_package_lock(p))
    yl = repo / "yarn.lock"
    if yl.exists():
        findings.extend(parse_yarn_lock(yl))
    pl = repo / "pnpm-lock.yaml"
    if pl.exists():
        findings.extend(parse_pnpm_lock(pl))
    return findings

# --------------------------- IoCs ---------------------------

@dataclasses.dataclass
class IoCSet:
    packages: Set[str]
    domains: Set[str]
    raw: Set[str]

def load_iocs(path: Optional[Path]) -> IoCSet:
    pkgs: Set[str] = set()
    doms: Set[str] = set()
    raw: Set[str] = set()
    if path and path.exists():
        content = read_text(path) or ""
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            raw.add(line)
            if "://" in line:
                m = RE_HOST.match(line.replace("\\", "/"))
                if m:
                    doms.add(m.group(1).lower())
            elif "/" in line and "." in line and " " not in line:
                doms.add(line.lower())
            elif "@" in line:
                pkgs.add(line)
            else:
                pkgs.add(line + "@*")
    return IoCSet(pkgs, doms, raw)

def ioc_match_lock(lockfindings: List[LockFinding], iocs: IoCSet) -> List[str]:
    matches: Set[str] = set()
    for lf in lockfindings:
        if lf.package:
            pkg = lf.package
            if "@npm:" in pkg:  # Yarn Berry normalize
                pkg = pkg.replace("@npm:", "@")
            if pkg in iocs.packages:
                matches.add(pkg)
            if "@" in pkg:
                name = pkg.split("@", 1)[0]
                if f"{name}@*" in iocs.packages:
                    matches.add(pkg)
        if lf.resolved:
            m = RE_HOST.match(lf.resolved)
            if m and m.group(1).lower() in iocs.domains:
                matches.add(m.group(1).lower())
    return sorted(matches)

# --------------------------- Registry-Härtung ---------------------------

def scan_registries(repo: Path) -> List[RegistryFinding]:
    findings: List[RegistryFinding] = []

    # .npmrc
    for p in repo.rglob(".npmrc"):
        if is_excluded(p, DEFAULT_EXCLUDES):
            continue
        txt = read_text(p) or ""
        for ln in txt.splitlines():
            m = RE_NPMRC_REG.search(ln)
            if m:
                val = m.group(1).strip()
                ok = val.startswith(REGISTRY_SAFE)
                findings.append(RegistryFinding(file=str(p), kind="npmrc", value=val, ok=ok))

    # publishConfig.registry
    for p in repo.rglob("package.json"):
        if "node_modules" in p.parts or is_excluded(p, DEFAULT_EXCLUDES):
            continue
        data = load_json_safely(p) or {}
        pc = (data or {}).get("publishConfig") or {}
        reg = pc.get("registry")
        if isinstance(reg, str):
            ok = reg.startswith(REGISTRY_SAFE)
            findings.append(RegistryFinding(file=str(p), kind="publishConfig", value=reg, ok=ok))

    # .yarnrc.yml
    for p in repo.rglob(".yarnrc.yml"):
        if is_excluded(p, DEFAULT_EXCLUDES):
            continue
        txt = read_text(p) or ""
        for ln in txt.splitlines():
            m = RE_YARNRC_REG.search(ln)
            if m:
                val = m.group(1).strip()
                ok = val.startswith(REGISTRY_SAFE)
                findings.append(RegistryFinding(file=str(p), kind="yarnrc", value=val, ok=ok))

    # NPM_CONFIG_REGISTRY in env-/shell-Dateien
    cand_globs = ["*.env", ".env", ".env.*", "*rc", "*.sh", "*.bash", "*.zsh", "*.fish"]
    for g in cand_globs:
        for p in repo.rglob(g):
            if is_excluded(p, DEFAULT_EXCLUDES):
                continue
            txt = read_text(p) or ""
            for m in RE_ENV_ASSIGN.finditer(txt):
                val = m.group(1).strip()
                ok = val.startswith(REGISTRY_SAFE)
                findings.append(RegistryFinding(file=str(p), kind="env", value=val, ok=ok))

    return findings

# --------------------------- Hooks ---------------------------

def scan_hooks(repo: Path, whitelist: List[str]) -> List[HookHit]:
    hits: List[HookHit] = []
    wl = [w.lower() for w in whitelist]
    for p in repo.rglob("package.json"):
        if "node_modules" in p.parts or is_excluded(p, DEFAULT_EXCLUDES):
            continue
        data = load_json_safely(p) or {}
        scripts = (data or {}).get("scripts") or {}
        for hook in ("preinstall", "install", "prepare", "postinstall"):
            cmd = scripts.get(hook)
            if not isinstance(cmd, str):
                continue
            lower = cmd.lower()
            whitelisted = any(w in lower for w in wl)
            hits.append(HookHit(file=str(p), hook=hook, command=cmd, whitelisted=whitelisted))
    return hits

# --------------------------- Code-Grep ---------------------------

def scan_code(repo: Path, use_rg: bool, exts: List[str], exclude_globs: List[str], max_filesize_mb: int, max_hits_per_rule: int) -> Tuple[Dict[str, int], List[RuleHit]]:
    counts: Dict[str, int] = defaultdict(int)
    all_hits: List[RuleHit] = []
    for rule, pattern in RG_PATTERNS.items():
        if use_rg and which("rg"):
            hits = rg_search(repo, pattern, exts, exclude_globs, max_filesize=max_filesize_mb)
        else:
            hits = py_grep(repo, pattern, exts, exclude_globs)
        for h in hits[:max_hits_per_rule] if max_hits_per_rule > 0 else hits:
            h.rule = rule
            all_hits.append(h)
        counts[rule] += len(hits)
    return counts, all_hits

# --------------------------- Scoring ---------------------------

def compute_score(hooks: List[HookHit], rule_counts: Dict[str, int], registries: List[RegistryFinding], ioc_matches: List[str]) -> int:
    score = 0
    for h in hooks:
        if not h.whitelisted:
            score += WEIGHTS["hook"]
    for k, c in rule_counts.items():
        score += WEIGHTS.get(k, 0) * c
    for r in registries:
        if not r.ok:
            score += WEIGHTS["registry_warn"]
    if ioc_matches:
        score += WEIGHTS["ioc_match"] * len(ioc_matches)
    return score

# --------------------------- Repo-Verarbeitung ---------------------------

def process_repo(repo: Path, args, iocs) -> RepoReport:
    notes: List[str] = []
    hooks = scan_hooks(repo, args.whitelist)
    rule_counts, rule_hits = scan_code(
        repo=repo,
        use_rg=not args.no_rg,
        exts=args.exts,
        exclude_globs=args.exclude,
        max_filesize_mb=args.max_filesize,
        max_hits_per_rule=args.max_hits
    )
    lockfindings = parse_lockfiles(repo)
    registries = scan_registries(repo)
    ioc_matches = ioc_match_lock(lockfindings, iocs) if iocs.raw else []
    score = compute_score(hooks, rule_counts, registries, ioc_matches)
    return RepoReport(
        repo_path=str(repo),
        score=score,
        rule_counts=dict(rule_counts),
        hooks=hooks,
        rule_hits=rule_hits,
        registries=registries,
        lockfindings=lockfindings,
        ioc_matches=ioc_matches,
        notes=notes,
    )

# --------------------------- Output ---------------------------

def to_json(reports: List[RepoReport]) -> str:
    def _enc(o):
        if dataclasses.is_dataclass(o):
            return dataclasses.asdict(o)
        if isinstance(o, Path):
            return str(o)
        raise TypeError
    return json.dumps(reports, default=_enc, indent=2, ensure_ascii=False)

def to_csv(reports: List[RepoReport]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "repo_path", "score",
        "hooks", "child_process", "eval_function", "base64_decode", "net_io",
        "registry_warn_count", "ioc_matches"
    ])
    for r in reports:
        reg_warns = sum(1 for x in r.registries if not x.ok)
        writer.writerow([
            r.repo_path, r.score,
            sum(1 for h in r.hooks if not h.whitelisted),
            r.rule_counts.get("child_process", 0),
            r.rule_counts.get("eval_function", 0),
            r.rule_counts.get("base64_decode", 0),
            r.rule_counts.get("net_io", 0),
            reg_warns,
            ";".join(r.ioc_matches),
        ])
    return buf.getvalue()

def to_sarif(reports: List[RepoReport]) -> dict:
    rules = {
        "HOOK":  {"id":"HOOK","name":"Lifecycle hook","shortDescription":{"text":"Suspicious lifecycle hook"},"help":{"text":"Install-Skripte können Code ausführen."}},
        "CHILD": {"id":"CHILD","name":"child_process usage","shortDescription":{"text":"Spawns shell/commands"},"help":{"text":"Kann beliebigen Code ausführen."}},
        "EVAL":  {"id":"EVAL","name":"eval/new Function","shortDescription":{"text":"Dynamic code evaluation"},"help":{"text":"Häufige Obfuskation."}},
        "B64":   {"id":"B64","name":"base64 decoding","shortDescription":{"text":"Buffer.from(..., 'base64')/atob"},"help":{"text":"Payload-Dekodierung."}},
        "NET":   {"id":"NET","name":"network IO","shortDescription":{"text":"Network access strings"},"help":{"text":"Downloads/Beaconing."}},
        "REG":   {"id":"REG","name":"registry override","shortDescription":{"text":"Non-standard npm registry"},"help":{"text":"Sollte registry.npmjs.org sein."}},
    }
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {"name": "IoC_Scan.py", "informationUri": "https://example.local/ioc-scan","rules": list(rules.values())}},
            "results": []
        }]
    }
    results = sarif["runs"][0]["results"]
    for r in reports:
        for h in r.hooks:
            if h.whitelisted:
                continue
            results.append({
                "ruleId": "HOOK",
                "message": {"text": f"{h.hook} -> {h.command}"},
                "locations": [{"physicalLocation":{"artifactLocation":{"uri": h.file},"region":{"startLine":1}}}],
                "properties": {"repo": r.repo_path}
            })
        mapping = {"child_process":"CHILD","eval_function":"EVAL","base64_decode":"B64","net_io":"NET"}
        for hit in r.rule_hits:
            results.append({
                "ruleId": mapping.get(hit.rule, "NET"),
                "message": {"text": hit.snippet[:500]},
                "locations": [{"physicalLocation":{"artifactLocation":{"uri": hit.file},"region":{"startLine": hit.line}}}],
                "properties": {"repo": r.repo_path}
            })
        for reg in r.registries:
            if reg.ok:
                continue
            results.append({
                "ruleId": "REG",
                "message": {"text": f"{reg.kind}: {reg.value}"},
                "locations": [{"physicalLocation":{"artifactLocation":{"uri": reg.file},"region":{"startLine":1}}}],
                "properties": {"repo": r.repo_path}
            })
    return sarif

# --------------------------- Args ---------------------------

def parse_args(argv: List[str]) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="Scan npm/yarn/pnpm Repos nach IoCs, riskanten Patterns und Registry-Overrides.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument("paths", nargs="+", help="Directories zum Scannen (es wird nach package.json gesucht).")
    ap.add_argument("--ioc-file", type=str, default=None, help="Pfad zu IoC-Liste (Packages/Domains).")
    ap.add_argument("--json", type=str, default=None, help="Schreibe detailliertes JSON hierhin. (Default: stdout)")
    ap.add_argument("--csv", type=str, default=None, help="Schreibe Summary-CSV hierhin.")
    ap.add_argument("--sarif", type=str, default=None, help="Schreibe SARIF v2.1.0 hierhin.")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Parallelität.")
    ap.add_argument("--no-rg", action="store_true", help="ripgrep-Beschleunigung deaktivieren.")
    ap.add_argument("--max-hits", type=int, default=50, help="Max. gespeicherte Hits je Rule/Repo (0 = unlimited).")
    ap.add_argument("--max-filesize", type=int, default=4, help="Max. Filesize (MB) für Code-Scan.")
    ap.add_argument("--exts", type=str, default=",".join(DEFAULT_EXTS), help="Dateiendungen (comma-separated).")
    ap.add_argument("--exclude", type=str, default=",".join(DEFAULT_EXCLUDES), help="Glob-Excludes (comma-separated).")
    ap.add_argument("--whitelist", type=str, default=",".join(WHITELIST_DEFAULT), help="Whitelist-Substrings für Hook-Kommandos.")
    return ap.parse_args(argv)

# --------------------------- Main ---------------------------

def main(argv: List[str]) -> int:
    args = parse_args(argv)
    roots = [Path(p) for p in args.paths]
    args.exts = [e.strip() for e in (args.exts.split(",") if isinstance(args.exts, str) else args.exts) if e.strip()]
    args.exclude = [g.strip() for g in (args.exclude.split(",") if isinstance(args.exclude, str) else args.exclude) if g.strip()]
    args.whitelist = [w.strip() for w in (args.whitelist.split(",") if isinstance(args.whitelist, str) else args.whitelist) if w.strip()]

    repos = find_repos(roots, args.exclude)
    if not repos:
        print("Keine Repos gefunden (keine package.json).", file=sys.stderr)
        return 2

    iocs = load_iocs(Path(args.ioc_file)) if args.ioc_file else IoCSet(set(), set(), set())
    print(f"[+] {len(repos)} Repos gefunden. ripgrep: {'ja' if (not args.no_rg and which('rg')) else 'nein'}", file=sys.stderr)

    reports: List[RepoReport] = []
    t0 = time.time()
    with cf.ProcessPoolExecutor(max_workers=args.workers) as exe:
        futs = [exe.submit(process_repo, repo, args, iocs) for repo in repos]
        for i, fut in enumerate(cf.as_completed(futs), 1):
            try:
                reports.append(fut.result())
            except Exception as e:
                print(f"[!] Fehler im Repo: {e}", file=sys.stderr)
            if i % 20 == 0:
                print(f"  .. {i}/{len(repos)} Repos verarbeitet", file=sys.stderr)
    elapsed = time.time() - t0
    print(f"[+] Fertig. {len(reports)} Repos in {elapsed:.1f}s verarbeitet", file=sys.stderr)

    reports.sort(key=lambda r: r.score, reverse=True)

    if args.json:
        Path(args.json).write_text(to_json(reports), encoding="utf-8")
        print(f"[+] JSON: {args.json}", file=sys.stderr)
    else:
        print(to_json(reports))

    if args.csv:
        Path(args.csv).write_text(to_csv(reports), encoding="utf-8")
        print(f"[+] CSV: {args.csv}", file=sys.stderr)

    if args.sarif:
        Path(args.sarif).write_text(json.dumps(to_sarif(reports), indent=2), encoding="utf-8")
        print(f"[+] SARIF: {args.sarif}", file=sys.stderr)

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

