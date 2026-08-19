"""How often does a vibe-coded server route hold the key that ignores RLS?

WHY THIS EXISTS. app/scan/service_role.py was written because a paying
customer's re-audit found the pattern on 21 of 29 routes and nothing static
was looking for it. One repository is an anecdote. This turns it into a rate,
and — more importantly — it is the only way to see the rule's FALSE POSITIVES
before a customer does, because every hit here is a file we can open and read.

IT MEASURES TWO THINGS, and the second is the one that decides whether the
rule ships:

  1. YIELD. Of repositories that use Supabase AND have server-side request
     handlers at all, how many have at least one handler reading a
     service-role key? Repos with no handlers are excluded from the
     denominator rather than counted as clean: a Vite SPA has no server, so
     "no finding" there is not evidence about this rule.

  2. WHAT THE HITS ACTUALLY ARE. Every flagged file is written out with the
     matched line, so the hits can be read rather than trusted. A rate is
     worthless if a tenth of it is `route.ts` files that mention the key in a
     comment, and the only way to know is to look.

THE CLASSIFICATION IS PRODUCTION'S. `is_request_handler` and
`service_role_env_reads` are imported from app/scan/service_role.py, not
reimplemented — the same rule that produced the number is the one a customer
gets. This project has already paid once for two readers of the same thing
(see app/scan/sql_schema.py).

NO LIVE CONTACT. The only network calls are git fetches of public
repositories. Nothing here queries a Supabase project.

SAMPLING, STATED BECAUSE IT IS NOT RANDOM. The same three candidate lists as
scripts/measure_rls_blind_spot.py — captured GitHub code-search results for
`lovable-tagger`, `.bolt/`, and the Supabase dependency, fetched 2026-08-18.
The strata are reported separately for the same reason as there: two are drawn
on a generator marker and one on the dependency itself, so pooling them would
average populations built by different criteria. For THIS question the strata
also differ structurally — Lovable and bolt emit Vite SPAs with no server at
all — which is itself a finding rather than a nuisance.

Usage:
    python scripts/measure_service_role_routes.py
    LIMIT=20 python scripts/measure_service_role_routes.py     # a quick pass
    WORKERS=4 python scripts/measure_service_role_routes.py

Writes batch_reports/service_role_routes.json — one record per repository,
pinned to the SHA that was read, with every flagged path and line, so a
disputed hit can be opened at the exact commit this run saw.
"""

from __future__ import annotations

import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.service_role import (  # noqa: E402
    is_request_handler,
    service_role_env_reads,
)

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "data"
OUT = ROOT / "batch_reports" / "service_role_routes.json"

SUPABASE_DEP = "@supabase/supabase-js"
LOVABLE_MARKERS = ("lovable-tagger", "lovable.dev")
BOLT_DIR = ".bolt/"
V0_MARKERS = ("v0.dev", "v0-user-next.config")

STRATA = (
    ("lovable", "Lovable (`lovable-tagger`)", "lovable_candidates.txt"),
    ("bolt", "bolt (`.bolt/` scaffolding)", "bolt_candidates.txt"),
    ("handwritten", "no generator marker (control)", "handwritten_candidates.txt"),
)

_CLONE_TIMEOUT_S = 120
_SHOW_TIMEOUT_S = 60

# A monorepo can carry hundreds of handlers. Reading them all costs a blob
# fetch each and adds nothing: the question is whether the pattern is present,
# and the customer-facing scanner reads the archive it already has in memory.
_MAX_HANDLERS_READ = 60


@dataclass
class Repo:
    slug: str
    stratum: str = ""
    sha: str = ""
    reachable: bool = False
    error: str = ""

    is_lovable: bool = False
    is_bolt: bool = False
    is_v0: bool = False
    has_supabase_dep: bool = False

    handlers: list[str] = field(default_factory=list)
    # "path:line env_var" per flagged handler, so a disputed hit can be opened
    # at the pinned SHA without re-running anything.
    hits: list[str] = field(default_factory=list)
    # Files that name a service-role variable but are NOT handlers — seed
    # scripts, edge functions, admin tooling. Counted to show what the handler
    # filter is buying: without it these would all be findings.
    non_handler_files: list[str] = field(default_factory=list)

    @property
    def has_handlers(self) -> bool:
        return bool(self.handlers)

    @property
    def flagged(self) -> bool:
        return bool(self.hits)

    def belongs_to(self, key: str) -> bool:
        if key == "lovable":
            return self.is_lovable
        if key == "bolt":
            return self.is_bolt
        return not (self.is_lovable or self.is_bolt or self.is_v0)


def _git(args: list[str], cwd: str | None = None,
         timeout: int = _SHOW_TIMEOUT_S) -> subprocess.CompletedProcess:
    """Decoded here with errors replaced, matching what the shipped scanner
    does to the same bytes. See the note in measure_rls_blind_spot.py: a
    strict decode inside a worker killed a 199-repo run at repo ~120."""
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True,
        timeout=timeout, check=False,
    )
    return subprocess.CompletedProcess(
        proc.args, proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def inspect(slug: str, workdir: Path) -> Repo:
    """One repository, and never more than one — a survey of strangers' code
    keeps meeting inputs nobody predicted, and each belongs in a record with a
    reason rather than ending the run."""
    try:
        return _inspect(slug, workdir)
    except Exception as exc:                                   # noqa: BLE001
        return Repo(slug=slug, error=f"{type(exc).__name__}: {exc}"[:200])


def _inspect(slug: str, workdir: Path) -> Repo:
    repo = Repo(slug=slug)
    dest = workdir / slug.replace("/", "__")
    proc = _git([
        "clone", "--filter=blob:none", "--no-checkout", "--depth", "1",
        f"https://github.com/{slug}", str(dest),
    ], timeout=_CLONE_TIMEOUT_S)
    if proc.returncode != 0:
        repo.error = (proc.stderr or "clone failed").strip().splitlines()[-1][:200]
        return repo

    head = _git(["rev-parse", "HEAD"], cwd=str(dest))
    if head.returncode != 0:
        repo.error = "no HEAD"
        return repo
    repo.sha = head.stdout.strip()
    repo.reachable = True

    listing = _git(["ls-tree", "-r", "HEAD", "--name-only"], cwd=str(dest))
    if listing.returncode != 0:
        repo.reachable = False
        repo.error = "ls-tree failed"
        return repo
    paths = [p for p in listing.stdout.splitlines() if p]

    manifests = [p for p in paths if p.rsplit("/", 1)[-1].startswith("package.json")]
    for manifest in manifests[:12]:
        shown = _git(["show", f"HEAD:{manifest}"], cwd=str(dest))
        if shown.returncode != 0:
            continue
        lowered = shown.stdout.lower()
        if any(m in lowered for m in LOVABLE_MARKERS):
            repo.is_lovable = True
        if any(m in lowered for m in V0_MARKERS):
            repo.is_v0 = True
        if SUPABASE_DEP in shown.stdout and manifest.rsplit("/", 1)[-1] == "package.json":
            repo.has_supabase_dep = True
    repo.is_bolt = any(p.startswith(BOLT_DIR) for p in paths)

    repo.handlers = [p for p in paths if is_request_handler(p)]
    _read_handlers(repo, dest)
    _count_non_handlers(repo, dest, paths)
    return repo


def _read_handlers(repo: Repo, dest: Path) -> None:
    for path in repo.handlers[:_MAX_HANDLERS_READ]:
        shown = _git(["show", f"HEAD:{path}"], cwd=str(dest))
        if shown.returncode != 0:
            continue
        for name, line in service_role_env_reads(shown.stdout):
            repo.hits.append(f"{path}:{line} {name}")


# Where a service-role key legitimately lives. Counted so the handler filter's
# value is visible: these are the files a rule without it would report, and
# every one of them would be a false positive.
_LEGITIMATE_HINTS = ("supabase/functions/", "scripts/", "seed", "migrate",
                     "/admin/", "tools/", "cli")


def _count_non_handlers(repo: Repo, dest: Path, paths: list[str]) -> None:
    """Non-handler files that read a service-role key.

    Sampled rather than exhaustive — a blob fetch each, and the point is the
    ORDER OF MAGNITUDE of what the handler filter excludes, not a census.
    """
    candidates = [
        p for p in paths
        if p.lower().endswith((".ts", ".tsx", ".js", ".mjs", ".py"))
        and not is_request_handler(p)
        and any(h in p.lower() for h in _LEGITIMATE_HINTS)
    ]
    for path in candidates[:20]:
        shown = _git(["show", f"HEAD:{path}"], cwd=str(dest))
        if shown.returncode == 0 and service_role_env_reads(shown.stdout):
            repo.non_handler_files.append(path)


def _wilson(hits: int, total: int) -> tuple[float, float]:
    """95% interval. A rate over 30 repositories quoted as a point estimate is
    the 3-of-7 mistake this project already made once."""
    if total == 0:
        return (0.0, 0.0)
    z = 1.96
    p = hits / total
    d = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / d
    half = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def _pct(hits: int, total: int) -> str:
    if total == 0:
        return "n/a (0 repos)"
    low, high = _wilson(hits, total)
    return f"{hits}/{total} = {100 * hits / total:.0f}% [95% CI {100 * low:.0f}-{100 * high:.0f}%]"


def main() -> int:
    limit = int(os.environ.get("LIMIT", "0"))
    workers = int(os.environ.get("WORKERS", "8"))

    slugs: dict[str, str] = {}
    for key, _label, filename in STRATA:
        for line in (DATA / filename).read_text().splitlines():
            slug = line.strip()
            if slug and not slug.startswith("#"):
                slugs.setdefault(slug, key)
    ordered = list(slugs.items())
    if limit:
        ordered = ordered[:limit]
    print(f"inspecting {len(ordered)} repositories with {workers} workers\n")

    workdir = Path(tempfile.mkdtemp(prefix="svcrole-"))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            repos = list(pool.map(lambda pair: _tag(inspect(pair[0], workdir), pair[1]),
                                  ordered))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    reachable = [r for r in repos if r.reachable]
    if reachable and all(r.error for r in repos):
        print("every repository failed identically — that is OUR bug, not a rate")
        return 2

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps([asdict(r) for r in repos], indent=2))

    print(f"reachable: {len(reachable)}/{len(repos)}\n")
    for key, label, _f in STRATA:
        members = [r for r in reachable if r.stratum == key and r.belongs_to(key)]
        supa = [r for r in members if r.has_supabase_dep]
        served = [r for r in supa if r.has_handlers]
        flagged = [r for r in served if r.flagged]
        print(f"{label}")
        print(f"  in stratum ............... {len(members)}")
        print(f"  uses @supabase/supabase-js {len(supa)}")
        print(f"  has server request handlers {_pct(len(served), len(supa))}")
        print(f"  >> handler reads service-role key {_pct(len(flagged), len(served))}")
        if flagged:
            routes = sum(len(r.hits) for r in flagged)
            handlers = sum(len(r.handlers) for r in flagged)
            print(f"     across flagged repos: {routes} of {handlers} handlers")
        print()

    excluded = sum(len(r.non_handler_files) for r in reachable)
    print(f"non-handler files reading a service-role key (excluded by the "
          f"handler filter): {excluded}")
    print("  these are seed scripts, edge functions and admin tooling — every")
    print("  one would be a false positive without is_request_handler()\n")

    print("EVERY HIT, for reading by hand:")
    for r in sorted(reachable, key=lambda r: r.slug):
        for hit in r.hits:
            print(f"  https://github.com/{r.slug}/blob/{r.sha}/{hit.split(':')[0]}"
                  f"   ({hit})")
    print(f"\nwrote {OUT}")
    return 0


def _tag(repo: Repo, stratum: str) -> Repo:
    repo.stratum = stratum
    return repo


if __name__ == "__main__":
    raise SystemExit(main())
