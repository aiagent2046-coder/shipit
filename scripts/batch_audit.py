"""Reproducibility series: fixed repos through the full audit pipeline
(static + LLM), N runs each, variance and reproduction report.

This used to be a breadth survey -- ten repos x 2 runs, asking whether the
score moves at all. It does (tasks #32-#34 hold the measurements), so the
question changed: not WHETHER but BY HOW MUCH, and that is answered by depth
on fixed revisions, not by more repos. The series below continue measurements
that already exist, which is why every entry is pinned to the revision those
measurements were made on.

What each series is for:
  ai-co-founder-matching  #34 -- the production pair (5.5 and 5.1, a third of
                          the findings list changed) proved the variance;
                          runs on the current engine give it a band and
                          per-severity reproduction rates. ALSO #33: audit
                          fb00b177 -- the 22-finding, hand-verified 20/22 run
                          behind the stuck-flag severity rule -- was of THIS
                          repository (audits.repo_url for fb00b177-55b2, same
                          content hash), a fact this file spent a day not
                          knowing while planning a separate series around a
                          customer archive nobody could find. The stuck-flag
                          findings should hold at medium/low across runs while
                          the SSRF stays high+; and since precision here is
                          hand-verified, this series measures reproduction of
                          KNOWN-TRUE findings, not findings in general.
  blank-slate             #34 second profile; #32 recall -- the union of these
                          runs plus the existing Haiku run, hand-verified, is
                          the denominator a single run's recall is measured
                          against.
  zombiecodersmarteditor  clean control (9.6/9.7 on 2026-08-17): does a clean
                          repo stay clean across runs? Decides whether
                          monitoring can alert on any new critical/high or
                          only on reproducing classes. Third holder of the
                          role: rexisdata-landing (9.8) went private or
                          deleted, and VibeBrowserProductPage -- picked as its
                          replacement on its July score of 9.2 -- scored
                          6.3/6.4 with ~10 LLM findings when the survey re-ran
                          it on today's engine, which disqualifies it as a
                          control and is itself a datum: engine drift moved a
                          repo three points in a month.

Usage (on the VPS, from /opt/shipit, with .env exported):
    set -a; . ./.env; set +a
    .venv/bin/python scripts/batch_audit.py

Runs are cumulative: existing <name>__run*.json files in batch_reports/ are
counted, new runs are numbered after them, and the summary reads them all.
Re-running the script therefore extends every series instead of redoing it.
To add runs beyond the defaults, raise the entry's `runs` (it is a target
TOTAL, not an increment): a series that already holds that many files runs
nothing new and only re-prints the summary.

Cost note: blank-slate is the expensive one (~1.46M input tokens/run
measured); the whole default set is roughly $25-45 through AITunnel.

Writes: batch_reports/<name>__run<N>.json and a summary. batch_reports/ is
gitignored -- the JSONs hold customer code paths and belong on the host.
"""
from __future__ import annotations

import io
import json
import statistics
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest.stack_detect import detect_stack  # noqa: E402
from app.ingest.validators import validate_zip  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.scan.pipeline import run_scan  # noqa: E402


@dataclass(frozen=True)
class Series:
    name: str          # report filename stem; keep stable, runs accumulate under it
    runs: int          # target TOTAL runs on disk, existing files included
    slug: str          # owner/repo on GitHub
    sha: str           # full commit SHA -- a branch head would silently fork the series
    # Byte size of the LLM prompt on the runs this series extends. A pinned
    # SHA proves the INPUT matched only for GitHub sources; the local-archive
    # series has no SHA, and blank-slate's prior three audits recorded prompt
    # chars but not the revision, so this is the splice check: a run whose
    # prompt_chars differ is measuring a different input and the summary must
    # say so rather than average it in.
    expect_prompt_chars: int = 0


SERIES = [
    Series(name="aiagent2046-coder__ai-co-founder-matching", runs=4,
           slug="aiagent2046-coder/ai-co-founder-matching",
           sha="c15be34f488521123a0ff77a30a7f885c3f1fdc6"),
    # runs=4, the sum of two merged plans (3 for #34's band + a series for
    # #33's stuck-flag rule, which turned out to be this same repository).
    # The three production runs (fb00b177 and the 5.5/5.1 pair, engine
    # 2026-08-14-5) are not on disk here and are not spliced in: the engine
    # moved since. They are quoted alongside as the prior engine's numbers.
    Series(name="Avisafety-1__blank-slate", runs=4,
           slug="Avisafety-1/blank-slate",
           sha="5e82a79a2b5381bd544d7bbc21722ee7a5d1a4d6",
           # Measured on the two 2026-08-17 survey runs at this SHA, which
           # matched each other byte for byte. NOT the 4,161,116 the three
           # July audits recorded: same repo, but the engine's prompt assembly
           # changed in between (truncation fixes among others), so those
           # three are a closed series on a prior engine -- the July totals
           # (4.1/4.0/4.1) are quoted next to today's, never averaged in.
           expect_prompt_chars=4_162_085),
    Series(name="SahonSrabon__zombiecodersmarteditor", runs=3,
           slug="SahonSrabon/zombiecodersmarteditor",
           sha="a787a111ede8c17ad23cd38a46eaa0f39b543aa0",
           expect_prompt_chars=932_766),
]

OUT = Path(__file__).resolve().parent.parent / "batch_reports"
OUT.mkdir(exist_ok=True)

_SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def fetch_repack(slug: str, sha: str) -> bytes:
    """GitHub zip nests everything under <repo>-<sha>/; strip it so the
    archive looks like a user export (files at root)."""
    url = f"https://codeload.github.com/{slug}/zip/{sha}"
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


def existing_runs(name: str) -> list[Path]:
    return sorted(OUT.glob(f"{name}__run*.json"),
                  key=lambda p: int(p.stem.rsplit("run", 1)[1]))


def _key(f: dict) -> tuple[str, str]:
    # Same identity monitoring uses (app/monitor/diff.py): (rule_id, file),
    # line excluded. The alert-threshold question this series answers is asked
    # about exactly this key, so measuring reproduction under any tighter key
    # would answer a question nobody acts on.
    return (f.get("rule_id") or "", f.get("file") or "")


def summarize(name: str, scans: list[dict]) -> None:
    n = len(scans)
    totals = [s["score"]["total"] for s in scans]
    print(f"\n--- {name}  ({n} run{'s' * (n > 1)}) ---")
    print(f"total: {totals}  band {min(totals)}..{max(totals)}"
          f"  median {statistics.median(totals)}")

    cats: dict[str, list[float]] = {}
    for s in scans:
        for c, v in s["score"]["categories"].items():
            cats.setdefault(c, []).append(v)
    for c, vals in sorted(cats.items()):
        spread = round(max(vals) - min(vals), 2)
        print(f"  {c:14s} {str(vals):30s} swing {spread}")

    prompt_chars = {(s.get("llm") or {}).get("prompt_chars")
                    for s in scans if isinstance(s.get("llm"), dict)}
    if len(prompt_chars) > 1:
        print(f"  !! prompt_chars differ across runs: {sorted(prompt_chars)}"
              " -- these runs did not read the same input; the band above"
              " mixes measurements and must not be quoted")

    if n < 2:
        return

    # LLM findings only: the static stage is deterministic and would report
    # 100% reproduction of itself, drowning the number that moves.
    per_run_keys: list[set] = []
    sev_by_key: dict[tuple, dict[int, str]] = {}
    for i, s in enumerate(scans):
        llm = [f for f in s["findings"]
               if (f.get("rule_id") or "").startswith("llm-")]
        per_run_keys.append({_key(f) for f in llm})
        for f in llm:
            best = sev_by_key.setdefault(_key(f), {})
            sev = f.get("severity", "?")
            # (rule_id, file) can hold several findings in one run; keep the
            # worst, which is the one an alert would fire on.
            if _SEV_ORDER.get(sev, 0) >= _SEV_ORDER.get(best.get(i, ""), 0):
                best[i] = sev

    union = set().union(*per_run_keys)
    by_sev: dict[str, list[float]] = {}
    print(f"  llm finding keys: union {len(union)}, "
          f"per-run {[len(k) for k in per_run_keys]}")
    rows = []
    for k in union:
        seen = sum(k in run for run in per_run_keys)
        sevs = [sev_by_key[k].get(i, "-") for i in range(n)]
        worst = max((s for s in sevs if s in _SEV_ORDER),
                    key=lambda s: _SEV_ORDER[s], default="?")
        by_sev.setdefault(worst, []).append(seen / n)
        rows.append((-_SEV_ORDER.get(worst, 0), k[1], k[0], seen, sevs))
    print("  reproduction by severity (share of runs a key appears in,"
          " averaged over keys of that worst-severity):")
    for sev in ("critical", "high", "medium", "low"):
        if sev in by_sev:
            rates = by_sev[sev]
            print(f"    {sev:8s} {sum(rates) / len(rates):>4.0%}"
                  f"  ({len(rates)} keys)")
    print("  per-key severities across runs ('-' = absent that run):")
    for _, file, rule, seen, sevs in sorted(rows):
        flag = "" if len(set(sevs)) == 1 else "  <- moves"
        print(f"    {seen}/{n} {file:44.44s} {rule:20.20s} {sevs}{flag}")


def main() -> int:
    client = LLMClient()
    if not client.providers:
        print("no LLM providers configured -- export .env first", file=sys.stderr)
        return 2

    for s in SERIES:
        have = existing_runs(s.name)
        todo = s.runs - len(have)
        print(f"\n=== {s.name}: {len(have)} on disk, {max(todo, 0)} to run ===",
              flush=True)
        if todo > 0:
            try:
                data = fetch_repack(s.slug, s.sha)
                validate_zip(io.BytesIO(data), size_bytes=len(data))
                detect_stack(io.BytesIO(data))
            except Exception as exc:  # noqa: BLE001 -- batch must continue,
                # and runs already on disk still deserve their summary below
                print(f"  SKIP: {exc}", flush=True)
                todo = 0
        if todo > 0:
            for i in range(len(have) + 1, s.runs + 1):
                t0 = time.time()
                scan = run_scan(data, client)
                dt = time.time() - t0
                (OUT / f"{s.name}__run{i}.json").write_text(
                    json.dumps(scan, indent=1))
                llm = scan["llm"]
                chars = llm.get("prompt_chars") if isinstance(llm, dict) else "?"
                print(f"  run {i}/{s.runs}: total {scan['score']['total']},"
                      f" prompt_chars {chars}, {dt:.0f}s", flush=True)
                if (s.expect_prompt_chars and isinstance(llm, dict)
                        and llm.get("prompt_chars") != s.expect_prompt_chars):
                    print(f"  !! prompt_chars {llm.get('prompt_chars')} !="
                          f" {s.expect_prompt_chars} recorded on the prior"
                          f" audits -- the input moved; this run starts a NEW"
                          f" series and must not be spliced with the old one",
                          flush=True)

        scans = [json.loads(p.read_text()) for p in existing_runs(s.name)]
        if scans:
            summarize(s.name, scans)

    print(f"\nreports: {OUT}/")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
