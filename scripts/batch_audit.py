"""Batch reproducibility run: real vibe-coded repos through the full
audit pipeline (static + LLM), N runs each, variance report.

Usage (on the VPS, from /opt/shipit, with .env exported):
    set -a; . ./.env; set +a
    .venv/bin/python batch_audit.py            # RUNS=2 by default
    RUNS=3 .venv/bin/python batch_audit.py     # more runs, more cost

Cost note: each run = up to 2 rubric prompts of up to ~90-100K tokens.
10 repos x 2 runs is a realistic ~$10-30 through AITunnel. Start with 2.

Writes: /tmp/batch_reports/<repo>__run<N>.json and a summary table.
"""
from __future__ import annotations

import io
import json
import os
import statistics
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest.stack_detect import detect_stack  # noqa: E402
from app.ingest.validators import validate_zip  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.scan.pipeline import run_scan  # noqa: E402

REPOS = [
    # (owner/repo, branch) -- selected 2026-07-12 from live GitHub search
    # for Lovable/Bolt/v0 export markers; mixed stacks, sizes, hygiene.
    ("PramodDutta/qaskills", "main"),                       # nextjs, static 0.0 -- known FP case (blog code samples)
    ("Avisafety-1/blank-slate", "main"),                    # vite, 48 static findings
    ("dalebooth9-ui/servexaapp", "main"),                   # vite, 714 files
    ("aliganey2016000-del/Minhaaj.com", "main"),            # vite, static 5.3
    ("5streams/peri-track-insights-quiz", "main"),          # vite, mid
    ("furkanyildirim4409-beep/blossom-db-forge", "main"),   # vite, 14 findings
    ("tiagosvalerio/rexisdata-landing", "main"),            # vite, clean 9.8 -- control
    ("dzianisv/VibeBrowserProductPage", "main"),            # nextjs, 9.2
    ("SahonSrabon/zombiecodersmarteditor", "main"),         # nextjs, small
    ("tscircuit/tscircuit.com", "main"),                    # vite, mature OSS -- maturity control
]

RUNS = int(os.environ.get("RUNS", "2"))
OUT = Path("/tmp/batch_reports")
OUT.mkdir(exist_ok=True)


def fetch_repack(slug: str, branch: str) -> bytes:
    """GitHub zip nests everything under repo-branch/; strip it so the
    archive looks like a user export (files at root)."""
    url = f"https://codeload.github.com/{slug}/zip/refs/heads/{branch}"
    raw = urllib.request.urlopen(url, timeout=120).read()
    src = zipfile.ZipFile(io.BytesIO(raw))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for zi in src.infolist():
            parts = zi.filename.split("/", 1)
            if len(parts) < 2 or not parts[1] or zi.is_dir():
                continue
            dst.writestr(parts[1], src.read(zi))
    return out.getvalue()


def main() -> int:
    client = LLMClient()
    if not client.providers:
        print("no LLM providers configured -- export .env first", file=sys.stderr)
        return 2

    rows = []
    for slug, branch in REPOS:
        safe = slug.replace("/", "__")
        try:
            data = fetch_repack(slug, branch)
            validate_zip(io.BytesIO(data), size_bytes=len(data))
            stack = detect_stack(io.BytesIO(data)).value
        except Exception as exc:  # noqa: BLE001 -- batch must continue
            rows.append((slug, "SKIP", str(exc)[:60], []))
            continue

        totals, llm_verified = [], []
        for i in range(1, RUNS + 1):
            t0 = time.time()
            scan = run_scan(data, client)
            dt = time.time() - t0
            totals.append(scan["score"]["total"])
            llm = scan["llm"]
            llm_verified.append(llm.get("verified") if isinstance(llm, dict) else llm)
            (OUT / f"{safe}__run{i}.json").write_text(json.dumps(scan, indent=1))
            print(f"  {slug} run {i}/{RUNS}: score {scan['score']['total']}, "
                  f"llm={llm if isinstance(llm, str) else llm}, {dt:.0f}s", flush=True)
        rows.append((slug, stack, totals, llm_verified))

    print("\n=== REPRODUCIBILITY SUMMARY ===")
    print(f"{'repo':45s} {'stack':10s} {'scores':22s} {'spread':7s} llm_verified")
    for slug, stack, totals, llm_v in rows:
        if stack == "SKIP":
            print(f"{slug:45s} SKIP       {totals}")
            continue
        spread = round(max(totals) - min(totals), 2)
        med = statistics.median(totals)
        print(f"{slug:45s} {stack:10s} {str(totals):22s} {spread:<7} {llm_v}  (median {med})")
    print(f"\nreports: {OUT}/  (RUNS={RUNS})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
