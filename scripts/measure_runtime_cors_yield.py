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

DETECTOR=1 asks the other half of the question. It drops the static-hit gate
and probes every buildable repository in the BACKENDS corpus, because the
static template can only match LITERAL configuration and real backends do not
write it that way — they use `cors(getCorsOptions())`, `app.use(cors())`, an
env-driven allowlist. On those, `static_hit=False` means "cannot be determined
statically", not "safe", and gating the probe behind it means the only method
that could answer never runs. Detector mode measures whether the probe can
REACH such applications at all; it is an experiment, not the shipped
behaviour (app/proof/runtime_cors.py still requires the static hit).

Usage on a host with the runner (from /opt/shipit):
    set -a; . ./.env; set +a
    .venv/bin/python scripts/measure_runtime_cors_yield.py

    LIMIT=3 .venv/bin/python scripts/measure_runtime_cors_yield.py   # first 3
    DETECTOR=1 .venv/bin/python scripts/measure_runtime_cors_yield.py

Detector mode builds real application images — node monorepos, a Postgres-
backed API — so budget tens of minutes and disk for the layers, and run it
with LIMIT first.

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

# DETECTOR=1 corpus: server-side applications that ship a root Dockerfile,
# chosen by structure and never by their CORS configuration. Seven of the ten
# candidates screened on 2026-08-17; the other three (chainlit, chatbot-ui,
# formbricks) have no root Dockerfile and cannot be booted.
#
# NONE of these produced a static hit, which is the whole point of running
# them: they configure CORS through function calls and env-driven allowlists
# (Flowise `cors(getCorsOptions())`, LibreChat `app.use(cors())`, documenso's
# own OriginFn helper) that no regex over source can read. On such a
# repository the static template says nothing because it CAN say nothing —
# not because the application is safe. Only a booted app can answer.
BACKENDS: tuple[tuple[str, str], ...] = (
    ("tiangolo/full-stack-fastapi-template",
     "162344da111e833b30892728372ab95331f06873"),
    ("danny-avila/LibreChat",
     "57ea1137f66dcde298e2bb6b634dd4d72d6c297d"),
    ("FlowiseAI/Flowise",
     "9291856d1ea4a4ceea9f8fef8ce14f4f6c81e8eb"),
    ("reworkd/AgentGPT",
     "18b073ab05b2902e1d052c3d2799786d8623b5e5"),
    ("zylon-ai/private-gpt",
     "4a030776a31a901ad80b1bf4d7faa2c1a367efbb"),
    ("documenso/documenso",
     "779de01fe8fb8c242da867b6c1fa38c70e448c3a"),
    ("langfuse/langfuse",
     "da0e8c5eb08819d59268101b7f86a4b4c8089984"),
)

OUT = Path(__file__).resolve().parent.parent / "batch_reports"
BASE_PORT = 31200

# Real applications do not all serve on 8000: LibreChat is 3080, Flowise and
# documenso 3000, private-gpt 8001. Guessing one number would measure "we
# picked the wrong port" and report it as "the app did not boot" — the
# error/failure distinction this whole feature is built around, undone by a
# constant. The Dockerfile already declares it.
DEFAULT_CONTAINER_PORT = 8000


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
    container_port: int = 0
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


def exposed_port(zip_bytes: bytes) -> int:
    """The port the image declares, from the Dockerfile's first EXPOSE.

    Guessing one constant would report "we picked the wrong port" as "the app
    did not boot" — collapsing exactly the error/failure distinction this
    feature is built on. Falls back to 8000 when nothing is declared, which is
    a guess and is recorded as one in the result row.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            for name in zf.namelist():
                parts = name.replace("\\", "/").split("/")
                if parts and parts[-1] == "Dockerfile" and len(parts) <= 2:
                    text = zf.read(name).decode("utf-8", errors="replace")
                    for line in text.splitlines():
                        stripped = line.strip()
                        if stripped.upper().startswith("EXPOSE"):
                            token = stripped.split()[1].split("/")[0]
                            return int(token)
    except Exception:  # noqa: BLE001 — an unreadable Dockerfile is a guess too
        pass
    return DEFAULT_CONTAINER_PORT


def measure_one(slug: str, sha: str, port: int,
                detector: bool = False) -> RepoResult:
    result = RepoResult(slug=slug, sha=sha)
    started = time.time()
    try:
        data = fetch_repack(slug, sha)
    except Exception as exc:  # noqa: BLE001
        result.error = f"fetch failed: {type(exc).__name__}"
        result.seconds = round(time.time() - started, 1)
        return result

    # Stage 1 — the production trigger. No static hit, no runtime probe, ever.
    #
    # DETECTOR mode suspends that rule on purpose. The static template can only
    # match literal configuration, and real backends do not write it that way,
    # so gating on it means the one method that could judge them never runs.
    # The hit is still recorded, because the comparison IS the experiment.
    attempt = get_template("cors_open")(data)
    result.static_hit = bool(attempt.success)
    result.static_files = [
        str(s.get("file")) for s in (attempt.evidence or {}).get("samples", [])
        if isinstance(s, dict)
    ][:5]
    if not result.static_hit and not detector:
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
    container_port = exposed_port(data)
    result.container_port = container_port
    try:
        probe = sandbox_client.run_cors_probe(
            data, host_port=port, container_port=container_port,
            # These are real applications, not the two-file e2e fixture: a
            # node monorepo image takes far longer than the 300s default, and
            # a timeout would be recorded as "did not boot".
            build_timeout_s=1800, boot_timeout_s=120,
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
    detector = (os.environ.get("DETECTOR") or "").strip().lower() in (
        "1", "true", "yes", "on")
    source = BACKENDS if detector else CORPUS
    limit = int(os.environ.get("LIMIT", "0")) or len(source)
    corpus = source[:limit]
    OUT.mkdir(exist_ok=True)

    if detector:
        print("DETECTOR MODE: probing every buildable repo regardless of a "
              "static hit.\nThis measures whether the probe can REACH these "
              "applications at all — not\nwhether they are vulnerable. Expect "
              "`failure` (no open CORS) as the healthy\nanswer for mature "
              "projects; `error` means the stand did not come up.\n",
              flush=True)

    results: list[RepoResult] = []
    for i, (slug, sha) in enumerate(corpus):
        print(f"[{i + 1}/{len(corpus)}] {slug}", flush=True)
        r = measure_one(slug, sha, BASE_PORT + i, detector=detector)
        results.append(r)
        print(f"    static_hit={r.static_hit} dockerfile={r.dockerfile} "
              f"port={r.container_port or '-'} probe={r.probe_status} "
              f"{r.probe_reason} ({r.seconds}s)", flush=True)
        if r.error:
            print(f"    error: {r.error}", flush=True)

    total = len(results)
    hits = [r for r in results if r.static_hit]
    buildable = [r for r in (results if detector else hits) if r.dockerfile]
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

    if detector:
        print()
        print("DETECTOR READING: `booted` is the applicability number — how "
              "often the probe\ncan speak at all about a repository the static "
              "template cannot read. A\n`failure` among those is a real "
              "answer ('no open CORS'), not a silence.")

    payload = {
        "mode": "detector" if detector else "trigger",
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
