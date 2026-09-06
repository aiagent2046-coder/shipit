"""How often does a vibe-coded app ship the RLS-bypassing key in its browser bundle?

WHY THIS EXISTS. app/scan/secrets.py already flags a service_role JWT committed
in REPOSITORY SOURCE. This measures a DIFFERENT population: the key built into
the published client bundle (`dist/`, `.next/static/`, `assets/`) and served to
every visitor's browser. The two disagree on purpose —

  * a key imported only in a server module is tree-shaken out of the bundle:
    secrets fires, the bundle does not (a false positive secrets would ship);
  * a key injected at build time from a `VITE_`/`NEXT_PUBLIC_`-prefixed env var
    never appears in source but lands in the bundle: secrets is silent, the
    bundle carries it (the miss that matters — the prefix is exactly what
    publishes it).

This is Part A of SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md. Nothing gets built
before the number exists.

WHAT IT MEASURES, and the second number is the one that decides the class:

  1. YIELD. Of repositories that use Supabase AND commit a readable build
     directory, how many ship a NON-DEMO service_role JWT in it? Repos with no
     committed bundle are excluded from the denominator and counted as a BLIND
     SPOT — not clean. A repo that emits source and builds on a CI we cannot see
     tells us nothing about this rule, exactly as a Vite SPA tells the route
     rule nothing.

  2. HOW BIG THE BLIND SPOT IS. If almost no repository commits a bundle — the
     likely case, since generators emit source — then the corpus-wide committed-
     bundle rate is uninformative and the real signal is entirely in the live-
     fetch path (Parts B/C, owned/consented only). That is a valid GO/NO-GO
     answer ("this class is invisible to static analysis on this market"), not a
     failure, and it is printed as a blind-spot statement rather than dressed up
     as coverage.

THE ORACLE IS PRODUCTION'S. `_is_demo_jwt` and `_jwt_severity` are imported from
app/scan/secrets.py, not reimplemented. A service_role token signed with the
public demo secret is not a credential — anyone can mint it — and every local
Supabase stack ships one. Re-deriving that check here is the two-readers failure
this project has already paid for (see app/scan/sql_schema.py); the demo carve-
out MUST be the same code the customer-facing scanner runs.

NO LIVE CONTACT. The only network calls are git fetches of public repositories.
Nothing here queries a Supabase project or fetches a deployment's served assets
— that is Parts B/C, and it is gated on ownership/consent.

SAMPLING, STATED BECAUSE IT IS NOT RANDOM. The same three candidate lists as
scripts/measure_service_role_routes.py and measure_rls_blind_spot.py — captured
GitHub code-search results for `lovable-tagger`, `.bolt/`, and the Supabase
dependency. The strata are reported separately for the same reason as there: two
are drawn on a generator marker and one on the dependency itself, so pooling
them averages populations built by different criteria.

Usage:
    python scripts/measure_service_role_bundle_yield.py
    LIMIT=20 python scripts/measure_service_role_bundle_yield.py   # quick pass
    WORKERS=4 python scripts/measure_service_role_bundle_yield.py

Writes batch_reports/service_role_bundle.json — one record per repository,
pinned to the SHA that was read, with every bundle file and decoded ref, so a
disputed hit can be opened at the exact commit this run saw.
"""

from __future__ import annotations

import base64
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scan.secrets import _is_demo_jwt, _jwt_severity  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "scripts" / "data"
OUT = ROOT / "batch_reports" / "service_role_bundle.json"

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

# The same JWT shape the shipped secrets scanner matches (app/scan/secrets.py
# `jwt-in-code`). Kept identical on purpose — a bundle token this misses is one
# the customer's own report would also miss, and a looser pattern here would
# manufacture a disagreement between the two readers that is ours, not real.
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b")

# Directories a client build lands in. A file is "bundle" if any path segment
# is one of these — `dist/assets/index-abc.js`, `.next/static/chunks/…`,
# `build/…`. NOT source: `src/`, `app/`, `pages/` are where the secrets scanner
# already looks, and a key there is that finding, not this one.
_BUNDLE_DIR_PARTS = (
    "dist/", "build/", "out/", "assets/",
    ".next/static/", ".output/public/", ".svelte-kit/output/",
)

# Bundled JS extensions. `.map` deliberately excluded: a source map can carry
# the key too, but it is a different artifact (usually not served in prod) and
# folding it in would inflate the rate with files a browser never downloads.
_BUNDLE_SUFFIXES = (".js", ".mjs", ".cjs")

# A committed bundle can be large. We only need to know whether the key is
# present, and reading every chunk of a monorepo's build costs a blob fetch
# each for no extra signal.
_MAX_BUNDLE_FILES_READ = 80

# Path hints that a "bundle-looking" dir is actually vendored source, not build
# output. `node_modules/` is the obvious one; a key found inside a dependency's
# shipped code is that dependency's problem, not the app's.
_NOT_APP_BUNDLE = ("node_modules/",)


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

    bundle_files: list[str] = field(default_factory=list)
    # "path role ref" per service_role token found in the bundle, so a disputed
    # hit can be opened at the pinned SHA. `ref` is the Supabase project the
    # token belongs to (the `ref` claim), printed so a human can sanity-check
    # that it is a real project and not a fixture.
    hits: list[str] = field(default_factory=list)
    # Demo-signed service_role tokens in the bundle: local scaffolding served
    # by accident. Counted, never a hit — this is the carve-out that keeps the
    # rate honest, and its size shows how much noise the demo check removes.
    demo_hits: list[str] = field(default_factory=list)
    # Non-service tokens in the bundle (anon keys, other JWTs). Counted only to
    # confirm the bundle really was parsed — an anon key in the bundle is
    # public by design and is NOT a finding.
    other_jwt_count: int = 0

    @property
    def has_bundle(self) -> bool:
        return bool(self.bundle_files)

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
    """Decoded with errors replaced, matching what the shipped scanner does to
    the same bytes. Minified bundles are full of non-UTF-8 sequences; a strict
    decode inside a worker killed a 199-repo run at repo ~120 (see
    measure_rls_blind_spot.py)."""
    proc = subprocess.run(
        ["git", *args], cwd=cwd, capture_output=True,
        timeout=timeout, check=False,
    )
    return subprocess.CompletedProcess(
        proc.args, proc.returncode,
        proc.stdout.decode("utf-8", errors="replace"),
        proc.stderr.decode("utf-8", errors="replace"),
    )


def is_bundle_file(path: str) -> bool:
    lowered = path.lower()
    if any(part in lowered for part in _NOT_APP_BUNDLE):
        return False
    if not lowered.endswith(_BUNDLE_SUFFIXES):
        return False
    return any(part in lowered for part in _BUNDLE_DIR_PARTS)


def _decode_role_and_ref(token: str) -> tuple[str, str]:
    """Return (role, ref) from a Supabase JWT payload, ('', '') if undecodable.

    Same payload decode as app/scan/secrets._jwt_severity, kept local only to
    also pull `ref` (which _jwt_severity has no reason to expose). The ROLE
    decision that matters — service_role vs anon vs demo — is delegated to the
    production functions below, not made here.
    """
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        data = json.loads(base64.urlsafe_b64decode(payload))
        return str(data.get("role", "")), str(data.get("ref", ""))
    except Exception:                                          # noqa: BLE001
        return "", ""


def _classify_bundle_token(repo: Repo, path: str, token: str) -> None:
    """Sort one bundled JWT into hit / demo / other, using PRODUCTION's oracle.

    The demo check comes first and outranks the role, exactly as
    _jwt_severity documents: a service_role token signed with the public secret
    is a fixture that happens to say service_role, not a credential.
    """
    role, ref = _decode_role_and_ref(token)
    if role != "service_role":
        if role:  # anon or some other JWT — parsed fine, just not the finding
            repo.other_jwt_count += 1
        return
    if _is_demo_jwt(token):
        repo.demo_hits.append(f"{path} demo ref={ref or '?'}")
        return
    # Real service_role in the served bundle. Confirm severity through the
    # production function so this run and a customer's report agree on the word.
    severity, _conf, _msg = _jwt_severity(token)
    repo.hits.append(f"{path} role=service_role ref={ref or '?'} sev={severity}")


def inspect(slug: str, workdir: Path) -> Repo:
    """One repository, and never more than one — a survey of strangers' builds
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

    repo.bundle_files = [p for p in paths if is_bundle_file(p)]
    _read_bundle(repo, dest)
    return repo


def _read_bundle(repo: Repo, dest: Path) -> None:
    for path in repo.bundle_files[:_MAX_BUNDLE_FILES_READ]:
        shown = _git(["show", f"HEAD:{path}"], cwd=str(dest))
        if shown.returncode != 0:
            continue
        for token in _JWT.findall(shown.stdout):
            _classify_bundle_token(repo, path, token)


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


def _tag(repo: Repo, stratum: str) -> Repo:
    repo.stratum = stratum
    return repo


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

    workdir = Path(tempfile.mkdtemp(prefix="svcbundle-"))
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            repos = list(pool.map(
                lambda pair: _tag(inspect(pair[0], workdir), pair[1]),
                ordered))
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    reachable = [r for r in repos if r.reachable]
    if repos and all(r.error for r in repos):
        print("every repository failed identically — that is OUR bug, not a rate")
        return 2

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps([asdict(r) for r in repos], indent=2))

    print(f"reachable: {len(reachable)}/{len(repos)}\n")

    total_supa = 0
    total_blind = 0
    for key, label, _f in STRATA:
        members = [r for r in reachable if r.stratum == key and r.belongs_to(key)]
        supa = [r for r in members if r.has_supabase_dep]
        with_bundle = [r for r in supa if r.has_bundle]
        blind = [r for r in supa if not r.has_bundle]
        flagged = [r for r in with_bundle if r.flagged]
        total_supa += len(supa)
        total_blind += len(blind)
        print(f"{label}")
        print(f"  in stratum ................. {len(members)}")
        print(f"  uses @supabase/supabase-js . {len(supa)}")
        print(f"  commits a readable bundle .. {_pct(len(with_bundle), len(supa))}"
              f"   <- the measurable denominator")
        print(f"  no committed bundle (blind). {_pct(len(blind), len(supa))}"
              f"   <- undetermined, NOT clean")
        print(f"  >> bundle ships service_role {_pct(len(flagged), len(with_bundle))}")
        print()

    # The headline this run exists to produce. If the committed-bundle
    # denominator is tiny, say so LOUD — the static method structurally cannot
    # see this class on most of the market, and that is the finding, not a
    # rate hidden behind a small n.
    print("=" * 60)
    if total_supa:
        seen = total_supa - total_blind
        print(f"BLIND SPOT: {_pct(total_blind, total_supa)} of Supabase repos "
              f"commit NO bundle.")
        if seen < 10:
            print(f"  Only {seen} Supabase repos commit a readable bundle across the")
            print("  whole corpus. The corpus-wide committed-bundle RATE is not")
            print("  informative at this n — the signal for this class lives in the")
            print("  live-fetch path (Parts B/C, owned/consented only). This is a")
            print("  BLIND-SPOT result, not a coverage result. Report it as such.")
    print("=" * 60)
    print()

    demo = sum(len(r.demo_hits) for r in reachable)
    others = sum(r.other_jwt_count for r in reachable)
    print(f"demo service_role tokens in bundles (carved out, NOT counted): {demo}")
    print("  local-stack keys served by accident — informational, forgeable\n")
    print(f"other bundled JWTs seen (anon etc., parsed but not the finding): {others}\n")

    print("EVERY HIT, for reading by hand:")
    any_hit = False
    for r in sorted(reachable, key=lambda r: r.slug):
        for hit in r.hits:
            any_hit = True
            path = hit.split(" ", 1)[0]
            print(f"  https://github.com/{r.slug}/blob/{r.sha}/{path}   ({hit})")
    if not any_hit:
        print("  (none)")
    print(f"\nwrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
