"""How often can the runtime CORS probe actually say anything? (P2 measurement)

The one number standing between `PROOF_RUNTIME_CORS=1` and honest external
claims. app/proof/runtime_cors.py refuses to boot unless three things hold, and
each refusal is invisible from inside the code: how many real repositories
carry an open-CORS pattern at all, how many of those are self-buildable, and
how many of THOSE actually come up. This walks a fixed corpus and counts.

    repos
      └─ static cors_open fired?          ← the production trigger
           └─ root Dockerfile present?    ← else `skipped`
                └─ container answered 200? ← else `error`
                     └─ oracle verdict     ← success / failure

Every stage but the last is a reason the feature says nothing, and a feature
that says nothing on most repositories is not a feature we may describe as one.
The last stage matters differently: a static hit that the running app does NOT
reproduce is the disagreement app/proof/stage.py deliberately keeps both halves
of, and its frequency here says which half deserves the reader's weight.

COSTS NO LLM MONEY. It runs the static template and docker only — the expense
is host CPU and minutes, roughly two builds per qualifying repo.

Usage on a host with the runner (from /opt/shipit):
    set -a; . ./.env; set +a
    .venv/bin/python scripts/measure_runtime_cors_yield.py

    LIMIT=3 .venv/bin/python scripts/measure_runtime_cors_yield.py   # first 3

Writes batch_reports/runtime_cors_yield.json alongside the printed table.
"""

from __future__ import annotations

import io
import json
import os
import sys
import time
import urllib.request
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import sandbox_client  # noqa: E402
from app.proof.registry import get_template  # noqa: E402
from app.proof.runtime_cors import has_root_dockerfile  # noqa: E402

# Pinned, resolved 2026-08-17. Head-of-branch would make the measurement
# unrepeatable the moment any of these repos moved — the same lesson
# scripts/batch_audit.py learned the expensive way.
CORPUS: tuple[tuple[str, str], ...] = (
    ("PramodDutta/qaskills", "287bbfb352a6384e95db04996d4d92cbe40669f0"),
    ("Avisafety-1/blank-slate", "5e82a79a2b5381bd544d7bbc21722ee7a5d1a4d6"),
    ("dalebooth9-ui/servexaapp", "fc66eccb7f48252cdc5301b168b9d323e16a8775"),
    ("aliganey2016000-del/Minhaaj.com",
     "40a795583193f374318776ee0070da21764bf841"),
    ("5streams/peri-track-insights-quiz",
     "66e6bdcfa8ac844648eefa007d9e54a3f31f5d77"),
    ("dzianisv/VibeBrowserProductPage",
     "d767bc1246c38d32045ffe51407278b6658155ed"),
    ("SahonSrabon/zombiecodersmarteditor",
     "a787a111ede8c17ad23cd38a46eaa0f39b543aa0"),
    ("tscircuit/tscircuit.com", "0b90e089be74e88e3464377a14ae6b20f22d0720"),
    ("aiagent2046-coder/ai-co-founder-matching",
     "c15be34f488521123a0ff77a30a7f885c3f1fdc6"),
)

OUT = Path(__file__).resolve().parent.parent / "batch_reports"
BASE_PORT = 31200


@dataclass
class RepoResult:
    slug: str
    sha: str
    static_hit: bool = False
    static_files: list[str] = field(default_factory=list)
    dockerfile: bool = False
    probe_status: str = "not_attempted"
    probe_reason: str = ""
    probe_detail: str = ""
    boot_detail: str = ""
    seconds: float = 0.0
    error: str = ""


def fetch_repack(slug: str, sha: str) -> bytes:
    """GitHub nests everything under <repo>-<sha>/; strip it so the archive
    looks like a user export, exactly as the audit pipeline receives one."""
    url = f"https://codeload.github.com/{slug}/zip/{sha}"
    raw = urllib.request.urlopen(url, timeout=180).read()
    src = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for zi in src.infolist():
            parts = zi.filename.split("/", 1)
            if len(parts) < 2 or not parts[1] or zi.is_dir():
                continue
            dst.writestr(parts[1], src.read(zi))
    return out.getvalue()


def measure_one(slug: str, sha: str, port: int) -> RepoResult:
    result = RepoResult(slug=slug, sha=sha)
    started = time.time()
    try:
        data = fetch_repack(slug, sha)
    except Exception as exc:  # noqa: BLE001
        result.error = f"fetch failed: {type(exc).__name__}"
        result.seconds = round(time.time() - started, 1)
        return result

    # Stage 1 — the production trigger. No static hit, no runtime probe, ever.
    attempt = get_template("cors_open")(data)
    result.static_hit = bool(attempt.success)
    result.static_files = [
        str(s.get("file")) for s in (attempt.evidence or {}).get("samples", [])
        if isinstance(s, dict)
    ][:5]
    if not result.static_hit:
        result.probe_status = "no_static_hit"
        result.seconds = round(time.time() - started, 1)
        return result

    # Stage 2 — self-buildable, or we would be measuring our own generated
    # Dockerfile rather than the customer's application.
    result.dockerfile = has_root_dockerfile(data)
    if not result.dockerfile:
        result.probe_status = "skipped_no_dockerfile"
        result.seconds = round(time.time() - started, 1)
        return result

    # Stage 3+4 — boot and ask. One workspace: this measures the population,
    # not a before/after pair, so there is no patched half to build.
    try:
        probe = sandbox_client.run_cors_probe(
            data, host_port=port, container_port=8000,
        )
    except Exception as exc:  # noqa: BLE001 — a runner outage is not a verdict
        result.probe_status = "runner_unavailable"
        result.error = f"{type(exc).__name__}: {exc}"[:200]
        result.seconds = round(time.time() - started, 1)
        return result

    result.probe_status = probe.status
    result.probe_detail = probe.detail[:200]
    result.probe_reason = str((probe.evidence or {}).get("reason", ""))
    result.boot_detail = str((probe.evidence or {}).get("boot_detail", ""))[:120]
    result.seconds = round(time.time() - started, 1)
    return result


def main() -> int:
    limit = int(os.environ.get("LIMIT", "0")) or len(CORPUS)
    corpus = CORPUS[:limit]
    OUT.mkdir(exist_ok=True)

    results: list[RepoResult] = []
    for i, (slug, sha) in enumerate(corpus):
        print(f"[{i + 1}/{len(corpus)}] {slug}", flush=True)
        r = measure_one(slug, sha, BASE_PORT + i)
        results.append(r)
        print(f"    static_hit={r.static_hit} dockerfile={r.dockerfile} "
              f"probe={r.probe_status} {r.probe_reason} ({r.seconds}s)",
              flush=True)
        if r.error:
            print(f"    error: {r.error}", flush=True)

    total = len(results)
    hits = [r for r in results if r.static_hit]
    buildable = [r for r in hits if r.dockerfile]
    booted = [r for r in buildable
              if r.probe_status in ("success", "failure")]
    reproduced = [r for r in booted if r.probe_status == "success"]

    print("\n=== RUNTIME CORS YIELD ===")
    print(f"{'repo':45s} {'static':7s} {'docker':7s} {'probe':22s} reason")
    for r in results:
        print(f"{r.slug:45.45s} {str(r.static_hit):7s} {str(r.dockerfile):7s} "
              f"{r.probe_status:22.22s} {r.probe_reason}")

    print()
    print(f"repos in corpus                 : {total}")
    print(f"  static cors_open fired        : {len(hits)}"
          f"  {_pct(len(hits), total)}")
    print(f"    ...and self-buildable       : {len(buildable)}"
          f"  {_pct(len(buildable), len(hits))} of hits")
    print(f"      ...and actually booted    : {len(booted)}"
          f"  {_pct(len(booted), len(buildable))} of buildable")
    print(f"        ...runtime reproduced   : {len(reproduced)}"
          f"  {_pct(len(reproduced), len(booted))} of booted")
    print()
    print(f"END-TO-END YIELD: {len(reproduced)}/{total} "
          f"{_pct(len(reproduced), total)} of the corpus produced a runtime "
          f"proof; {len(booted) - len(reproduced)} booted and did NOT "
          f"reproduce the static finding.")
    print()
    print("Read the last line before quoting anything externally. A booted "
          "app that does not reproduce is the case app/proof/stage.py keeps "
          "both halves of, and its share decides which half a reader should "
          "weigh.")

    payload = {
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus_size": total,
        "static_hits": len(hits),
        "buildable": len(buildable),
        "booted": len(booted),
        "reproduced": len(reproduced),
        "results": [asdict(r) for r in results],
    }
    path = OUT / "runtime_cors_yield.json"
    path.write_text(json.dumps(payload, indent=1))
    print(f"\nwrote {path}")
    return 0


def _pct(part: int, whole: int) -> str:
    return f"({part / whole:.0%})" if whole else "(n/a)"


if __name__ == "__main__":
    raise SystemExit(main())
