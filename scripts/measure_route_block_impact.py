#!/usr/bin/env python3
"""What does reading route declarations inside block statements change on real code?

WHY THIS EXISTS AS A SCRIPT IN THE REPOSITORY. The change it measures says four
rules now read a route declared inside a module-level `if:`/`try:`/`with:`/`for:`.
Two claims follow from that, and neither is worth making without a number:

  1. unchanged repositories will see NEW findings after the next engine bump --
     the cache is keyed by engine version, so a smarter engine re-runs and the
     customer's report changes with no edit on their side;
  2. a conditional import (`try: from fastapi import APIRouter`) still establishes
     no provenance, which is a deliberate rule in `auth_read._scope_bindings`.

Claim 1 is measured by scanning the SAME bytes with two engine revisions and
diffing the findings. Claim 2 is measured by counting where provenance-bearing
imports are written -- a question no shipped function answers, so the counter
here walks the AST itself, and it reuses `app.scan.scope_statements` so that
"inside a block" cannot come to mean two different things in the counter and in
the rules.

THE DETECTOR IS NOT REIMPLEMENTED. The differential runs the shipped
`run_static_scan` in a subprocess rooted at each revision, exactly as the product
runs it. Only the shape counter is local, and its docstring says so.

NO LIVE CONTACT. The only network calls fetch public repository zipballs. Nothing
here executes uploaded code: every scanner parses source.

SAMPLING, STATED BECAUSE IT IS NOT RANDOM. Twelve public FastAPI projects, taken
from GitHub's star ranking for "fastapi template", pinned by commit. Templates are
not the population of customer repositories, and they over-represent application
factories and startup-time route registration -- precisely the shapes under
measurement. This non-random sample cannot establish a prevalence bound for
application code; an occurrence demonstrates a shape, not its frequency.

Usage:
    python scripts/measure_route_block_impact.py fetch
    python scripts/measure_route_block_impact.py shapes --root ~/shipit
    python scripts/measure_route_block_impact.py scan --root /tmp/engine-baseline --out /tmp/base.json
    python scripts/measure_route_block_impact.py scan --root ~/shipit --out /tmp/cand.json
    python scripts/measure_route_block_impact.py diff /tmp/base.json /tmp/cand.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

CORPUS: tuple[tuple[str, str], ...] = (
    ("s3rius/FastAPI-template", "f7ed808be8d239b5a8511b146c46ee0ec7e31e06"),
    ("wassim249/fastapi-langgraph-agent-production-ready-template", "36c7e2b87bc2e60ee230348e857e6c9d9570a46e"),
    ("zhanymkanov/fastapi_production_template", "8e82353ff3430c77fb77ead7de0d680f0229a667"),
    ("Aeternalis-Ingenium/FastAPI-Backend-Template", "d2e931b9639aa5fbca2a85c1711e47c8ee39b254"),
    ("rafsaf/minimal-fastapi-postgres-template", "b384f05abc2fb1d06dc39fb1f6855f6c083f5026"),
    ("NicholasGoh/fastapi-mcp-langgraph-template", "2bd004a51e5d741e8eaf5bb01716b6a673684a53"),
    ("JiayuXu0/FastAPI-Template", "f8f7f11bcbed38c82fe00fbaf014d55fae3f3f2f"),
    ("rochacbruno/fastapi-project-template", "26320c200e90ac05ebd0d84d6b6b9356e3a77d9e"),
    ("AtticusZeller/fastapi_supabase_template", "1acfbe345e31310683575bfe1ffda6a9b02e98b1"),
    ("Kuzyashin/FastAPI_Tortoise_template", "48e1d30cb41398109853d3ec4d9939dd0a3c42e9"),
    ("seapagan/fastapi-template", "23fe83f2fe1ed934032737a301583fd47ec7d1e3"),
    ("luchog01/minimalistic-fastapi-template", "f96e1dd35f94ffd5746f98745dbec8e763a2e0c7"),
)

CACHE = Path(os.environ.get("CACHE", "/tmp/route-block-corpus"))

# Names whose provenance the route rules rely on. An import of one of these written
# inside a block is what claim 2 is about.
_PROVENANCE_MODULES = ("fastapi", "httpx", "requests", "aiohttp")
_PROVENANCE_NAMES = {"APIRouter", "FastAPI", "Depends", "Security"}

# The scanning half, run inside the target revision's own tree.
_SCAN_SNIPPET = r"""
import io, json, sys, zipfile
from pathlib import Path

out = Path(sys.argv[1])
zips = [Path(p) for p in sys.argv[2:]]
from app.scan.static import run_static_scan

report = {}
for path in zips:
    key = path.name
    try:
        findings = run_static_scan(io.BytesIO(path.read_bytes()))["findings"]
    except Exception as exc:
        report[key] = {"error": f"{type(exc).__name__}: {exc}"}
        continue
    report[key] = [
        {"rule_id": f.get("rule_id"), "file": f.get("file"), "line": f.get("line")}
        for f in findings
    ]
out.write_text(json.dumps(report, indent=2, sort_keys=True))
print(f"scanned {len(zips)} archives -> {out}")
"""


def _zip_path(slug: str) -> Path:
    return CACHE / (slug.replace("/", "__") + ".zip")


def fetch() -> int:
    CACHE.mkdir(parents=True, exist_ok=True)
    manifest = []
    for slug, sha in CORPUS:
        target = _zip_path(slug)
        if not target.exists():
            url = f"https://codeload.github.com/{slug}/zip/{sha}"
            print(f"fetch {slug} @ {sha[:8]}", flush=True)
            with urllib.request.urlopen(url, timeout=120) as response:
                target.write_bytes(response.read())
        digest = hashlib.sha256(target.read_bytes()).hexdigest()
        manifest.append({"slug": slug, "commit": sha, "bytes": target.stat().st_size, "sha256": digest})
        print(f"  {target.name}  {target.stat().st_size:>9} bytes  {digest[:16]}")
    (CACHE / "manifest.json").write_text(json.dumps(
        {"archives": manifest,
         "manifest_sha256": hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()},
        indent=2))
    print(f"\nmanifest: {CACHE / 'manifest.json'}")
    return 0


def shapes(root: str) -> int:
    """Where provenance-bearing imports are written, and where routes are declared.

    Local AST pass, on purpose (see the module docstring). It imports
    `scope_statements` from `root`, so "inside a block" means the shipped thing in
    the counter and in the rules alike.

    What it does NOT claim: which files an engine revision can or cannot read.
    That is what `diff` of two `scan` runs measures, on the shipped stage, rather
    than a second implementation of the discovery rules here.
    """
    sys.path.insert(0, root)
    import ast  # noqa: PLC0415

    from app.scan.auth_read import _METHODS  # noqa: PLC0415
    from app.scan.scope_statements import scope_statements  # noqa: PLC0415

    files = routes_anywhere = block_imports = 0
    block_route_files: list[tuple[str, str]] = []
    block_import_rows: list[tuple[str, str, str]] = []
    for slug, _sha in CORPUS:
        archive = _zip_path(slug)
        if not archive.exists():
            print(f"missing {archive} -- run `fetch` first")
            return 2
        with zipfile.ZipFile(archive) as zf:
            for info in zf.infolist():
                if info.is_dir() or not info.filename.endswith(".py"):
                    continue
                try:
                    tree = ast.parse(zf.read(info).decode("utf-8"))
                except (SyntaxError, UnicodeError, ValueError, RecursionError):
                    continue
                files += 1
                every = list(scope_statements(tree))
                block_statements = [node for node in every if node not in tree.body]

                def is_route(node):
                    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or len(node.decorator_list) != 1:
                        return False
                    dec = node.decorator_list[0]
                    return (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                            and dec.func.attr in _METHODS)

                if any(is_route(node) for node in ast.walk(tree)):
                    routes_anywhere += 1
                if any(is_route(node) for node in block_statements):
                    block_route_files.append((slug, info.filename))

                for node in block_statements:
                    if isinstance(node, (ast.Import, ast.ImportFrom)):
                        names = {alias.asname or alias.name.split(".")[0] for alias in node.names}
                        module = getattr(node, "module", None) or ""
                        if module.split(".")[0] in _PROVENANCE_MODULES or names & _PROVENANCE_NAMES:
                            block_imports += 1
                            block_import_rows.append((slug, info.filename, ast.unparse(node)))
                            break

    print(f"python files parsed:                          {files}")
    print(f"files declaring a route anywhere:             {routes_anywhere}")
    print(f"files declaring a route inside a block:       {len(block_route_files)}")
    print(f"files with a provenance import inside a block: {block_imports}")
    print("\nfiles declaring a route inside a block:")
    for slug, name in block_route_files:
        print(f"  {slug}: {name}")
    print("\nprovenance imports written inside a block:")
    for slug, name, text in block_import_rows:
        print(f"  {slug}: {name}: {text}")
    return 0


def scan(root: str, out: Path) -> int:
    archives = [_zip_path(slug) for slug, _ in CORPUS]
    missing = [p for p in archives if not p.exists()]
    if missing:
        print(f"missing {len(missing)} archives -- run `fetch` first")
        return 2
    env = dict(os.environ, PYTHONPATH=os.path.abspath(root))
    return subprocess.run([sys.executable, "-c", _SCAN_SNIPPET, str(out), *map(str, archives)],
                          env=env, check=False).returncode


def diff(baseline: Path, candidate: Path) -> int:
    base = json.loads(baseline.read_text())
    cand = json.loads(candidate.read_text())
    added_total = removed_total = 0
    for key in sorted(set(base) | set(cand)):
        b, c = base.get(key, []), cand.get(key, [])
        if isinstance(b, dict) or isinstance(c, dict):
            print(f"!! {key}: {b or c}")
            continue
        key_of = lambda f: (f["rule_id"], f["file"], f["line"])  # noqa: E731
        added = [f for f in c if key_of(f) not in {key_of(x) for x in b}]
        removed = [f for f in b if key_of(f) not in {key_of(x) for x in c}]
        added_total += len(added)
        removed_total += len(removed)
        if added or removed:
            print(f"{key}: +{len(added)} -{len(removed)}")
            for f in added:
                print(f"   + {f['rule_id']} {f['file']}:{f['line']}")
            for f in removed:
                print(f"   - {f['rule_id']} {f['file']}:{f['line']}")
    print(f"\nTOTAL added={added_total} removed={removed_total}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("fetch")
    shapes_p = sub.add_parser("shapes")
    shapes_p.add_argument("--root", default=".")
    scan_p = sub.add_parser("scan")
    scan_p.add_argument("--root", required=True)
    scan_p.add_argument("--out", required=True)
    diff_p = sub.add_parser("diff")
    diff_p.add_argument("baseline")
    diff_p.add_argument("candidate")
    args = ap.parse_args()

    if args.command == "fetch":
        return fetch()
    if args.command == "shapes":
        return shapes(args.root)
    if args.command == "scan":
        return scan(args.root, Path(args.out))
    return diff(Path(args.baseline), Path(args.candidate))


if __name__ == "__main__":
    raise SystemExit(main())
