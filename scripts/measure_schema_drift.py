"""How often do a repository's migrations fail to describe the tables it names?

WHY THIS EXISTS AS A SCRIPT IN THE REPOSITORY, and not as a notebook on
somebody's laptop. app/scan/schema_drift.py claims 50% [41-59]. A number in a
docstring that nobody can reproduce is a number nobody can dispute, and the
detector's whole argument is that it is careful about what it asserts.

IT RUNS THE SHIPPED DETECTOR. Not a copy of the matcher, not a
reimplementation of the rule: it fetches a zipball and hands the bytes to
`scan_schema_drift` exactly as `run_static_scan` does. That is the difference
from the ad-hoc pass this replaces, which carried its own name filter and
therefore measured a slightly different question than the code answers -- the
failure SUPABASE_RLS_YIELD_PLAN.md already recorded once, in its own words:
"The script carried its own copy of the matcher and drifted from production
within the hour."

THE PREVIOUS PASS UNDERCOUNTED, and by a knowable amount. It dropped
bucket-shaped names (`documents`, `files`, `media`) BY NAME; production drops
them BY CALL SITE, keeping `supabase.from('documents')` and discarding only
`supabase.storage.from('documents')`. Those are ordinary table names, so the
shipped detector sees a superset. This run measures that superset directly,
which is why all three strata are re-measured rather than only the missing
one: a control measured with one rule and two strata measured with another do
not belong in the same table.

SAMPLING, STATED BECAUSE IT IS NOT RANDOM. Three candidate lists captured
2026-08-18 from GitHub code search: `lovable-tagger` in package.json, `.bolt/`
scaffolding, and a control with neither marker. Search ranking is not a
uniform sample and no way to draw one exists; what can be said is that nothing
in the ranking is plausibly correlated with whether a repository commits
migrations, which is the quantity at stake. Membership is re-decided by
reading the fetched tree, so a stale search hit drops out rather than counting.

NO LIVE CONTACT. Nothing here queries a Supabase project. The only network
calls are fetches of public repositories.

Usage:
    python scripts/measure_schema_drift.py
    LIMIT=20 python scripts/measure_schema_drift.py     # a quick pass
    WORKERS=6 python scripts/measure_schema_drift.py

Writes batch_reports/schema_drift.json -- one record per repository, pinned to
the SHA that was read, so the run can be reproduced or disputed.
"""

from __future__ import annotations

import io
import json
import math
import os
import sys
import time
import urllib.error
import urllib.request
import zipfile
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scan.rls import read_committed_sql  # noqa: E402
from app.scan.schema_drift import scan_schema_drift  # noqa: E402
from app.scan.sql_schema import parse_schema  # noqa: E402
from app.scan.table_names import read_named_tables  # noqa: E402

DATA = ROOT / "scripts" / "data"
OUT = ROOT / "batch_reports" / "schema_drift.json"

LIMIT = int(os.environ.get("LIMIT") or 0)
WORKERS = int(os.environ.get("WORKERS") or 4)

SUPABASE_DEP = "@supabase/supabase-js"
_HTTP_TIMEOUT_S = 90

STRATA = (
    ("lovable", "Lovable (`lovable-tagger`)", "lovable_candidates.txt"),
    ("bolt", "bolt (`.bolt/` scaffolding)", "bolt_candidates.txt"),
    ("handwritten", "no generator marker (control)", "handwritten_candidates.txt"),
)


@dataclass
class Repo:
    slug: str
    stratum: str = ""
    ref: str = ""
    reachable: bool = False
    error: str = ""

    has_supabase_dep: bool = False
    commits_schema: bool = False
    declared: int = 0
    # The detector's own verdict, which is the point of the run.
    fires: bool = False
    drifted: list[str] = field(default_factory=list)
    from_types: int = 0
    has_dynamic_from: bool = False


def _fetch(slug: str) -> tuple[bytes, str]:
    """The zipball, and the SHA recovered from its root directory name."""
    last = ""
    for attempt in range(3):
        try:
            req = urllib.request.Request(
                f"https://codeload.github.com/{slug}/zip/HEAD",
                headers={"User-Agent": "drift-measure"})
            with urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT_S) as resp:
                raw = resp.read()
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                names = zf.namelist()
            root = names[0].split("/", 1)[0] if names else ""
            return raw, (root.rsplit("-", 1)[-1] if "-" in root else "")
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 404, 451):
                raise RuntimeError(f"HTTP {exc.code}") from exc
            last = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001
            last = type(exc).__name__
        # MEASURED on this network: about 1.4% of TLS handshakes stall for
        # 15-22s, so a single probe is not evidence a repository is gone.
        time.sleep(2 * (attempt + 1))
    raise RuntimeError(last or "failed")


def inspect(slug: str, stratum: str) -> Repo:
    """ONE REPOSITORY MUST NOT BE ABLE TO END THE RUN."""
    repo = Repo(slug=slug, stratum=stratum)
    try:
        raw, repo.ref = _fetch(slug)
    except Exception as exc:  # noqa: BLE001
        repo.error = f"{type(exc).__name__}: {exc}"[:160]
        return repo

    repo.reachable = True
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            for info in zf.infolist():
                rel = info.filename.split("/", 1)[-1]
                if rel != "package.json" or info.file_size > 512 * 1024:
                    continue
                if SUPABASE_DEP in zf.read(info).decode("utf-8", "replace"):
                    repo.has_supabase_dep = True
                break
        if not repo.has_supabase_dep:
            return repo

        buf = io.BytesIO(raw)
        sql, _ = read_committed_sql(buf)
        declared = {t.name.lower() for t in parse_schema(sql).values()
                    if t.schema in ("public", "")} if sql.strip() else set()
        repo.commits_schema = bool(declared)
        repo.declared = len(declared)

        named = read_named_tables(buf)
        repo.has_dynamic_from = named.has_dynamic_from
        repo.from_types = len(named.from_types)

        # THE MEASUREMENT: the shipped scanner, on the same bytes, by the same
        # entry point run_static_scan uses.
        findings = scan_schema_drift(buf)
        repo.fires = bool(findings)
        if findings:
            repo.drifted = sorted(
                (named.from_code | named.from_types) - declared)[:200]
    except Exception as exc:  # noqa: BLE001
        repo.error = f"read: {type(exc).__name__}: {exc}"[:160]
    return repo


def wilson(k: int, n: int) -> tuple[float, float, float]:
    if n == 0:
        return (0.0, 0.0, 0.0)
    p, z = k / n, 1.96
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / d
    return (round(100 * p, 1), round(100 * max(0.0, centre - half), 1),
            round(100 * min(1.0, centre + half), 1))


def _median(xs: list[int]) -> float:
    if not xs:
        return 0.0
    ordered = sorted(xs)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[mid])
    return (ordered[mid - 1] + ordered[mid]) / 2


def main() -> int:
    record: dict = {"strata": {}, "repos": []}
    for key, label, filename in STRATA:
        listing = DATA / filename
        if not listing.exists():
            print(f"missing {listing}", file=sys.stderr)
            return 2
        slugs = [ln.strip() for ln in listing.read_text().splitlines()
                 if ln.strip() and not ln.startswith("#")]
        if LIMIT:
            slugs = slugs[:LIMIT]

        print(f"\n{label}: {len(slugs)} candidates", flush=True)
        repos: list[Repo] = []
        with ThreadPoolExecutor(max_workers=WORKERS) as pool:
            for i, repo in enumerate(
                    pool.map(lambda s: inspect(s, key), slugs), 1):
                repos.append(repo)
                if i % 10 == 0:
                    ok = sum(1 for r in repos if r.reachable)
                    print(f"  {i}/{len(slugs)} (read {ok})", flush=True)

        members = [r for r in repos if r.reachable]
        supa = [r for r in members if r.has_supabase_dep]
        schema = [r for r in supa if r.commits_schema]
        fired = [r for r in schema if r.fires]
        record["strata"][key] = {
            "label": label,
            "candidates": len(slugs),
            "unreachable": len(repos) - len(members),
            "uses_supabase": len(supa),
            "commits_schema": len(schema),
            "detector_fires": len(fired),
            "fire_rate": wilson(len(fired), len(schema)),
            "median_drifted": _median([len(r.drifted) for r in fired]),
            "max_drifted": max((len(r.drifted) for r in fired), default=0),
            "carry_generated_types": sum(1 for r in schema if r.from_types),
            "dynamic_from": sum(1 for r in supa if r.has_dynamic_from),
        }
        record["repos"].extend(asdict(r) for r in repos)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(record, indent=2))

    schema_all = [r for r in record["repos"]
                  if r["reachable"] and r["has_supabase_dep"]
                  and r["commits_schema"]]
    fired_all = [r for r in schema_all if r["fires"]]
    print("\n" + "=" * 60)
    for key, stats in record["strata"].items():
        print(f"{key:12} {stats['detector_fires']:3}/{stats['commits_schema']:3}"
              f"  {stats['fire_rate']}")
    print(f"{'POOLED':12} {len(fired_all):3}/{len(schema_all):3}"
          f"  {wilson(len(fired_all), len(schema_all))}")
    print(f"\nwritten to {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
