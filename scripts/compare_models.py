#!/usr/bin/env python3
"""Run the same repositories through two models and compare what they report.

    scripts/compare_models.py                       # the batch_audit sample
    scripts/compare_models.py --models a b c        # any models in PRICE_TABLE
    scripts/compare_models.py --repos owner/x owner/y
    scripts/compare_models.py --dry-run             # cost estimate, no calls

WHAT THIS MEASURES, AND WHAT IT DOES NOT.

It measures agreement, cost and shape: how many findings each model reports,
where they overlap, what each one alone saw, and how much the run cost. Those
are facts and it can settle them.

It does NOT measure whether the findings are true. Two models agreeing can
both be wrong; a finding only one of them made can be the best finding in the
run. A model that reports one issue three times looks more thorough than one
that reports it once, on every count this prints.

So the output is the INPUT to a judgement, not the judgement. The
`--json` file exists to be read by a human afterwards, and the summary ends
by naming how many findings would have to be checked by hand to say anything
about precision. This warning is here because the last cost estimate on this
project was confidently wrong for two cancelling reasons and would have driven
a real decision if nobody had measured.

Both models see the SAME BYTES: each repository is fetched once and the
archive reused. Fetching per model would let the default branch move between
runs and quietly compare two different repositories.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import time
import urllib.request
import zipfile
from collections import defaultdict
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.llm.client import LLMClient  # noqa: E402
from app.llm.pricing import PRICE_TABLE, cost_usd  # noqa: E402
from app.scan.pipeline import run_scan  # noqa: E402

# The sample from scripts/batch_audit.py, imported rather than copied: it was
# selected once, deliberately, for stack/size/hygiene spread with a clean
# control and a mature-OSS control. A second list here would drift from it and
# nobody would notice which run used which.
from scripts.batch_audit import REPOS  # noqa: E402

# Per-audit averages for the --dry-run estimate only; real cost comes from
# each run's own usage block.
#
# These are the MEASURED means over the batch sample, and they replace numbers
# taken from a single small repository. The first estimate this script printed
# was $12.30 against an actual $31.11 -- 2.5x low -- because Sonnet's figure
# came from kristina_agent_center alone and was applied to a sample chosen for
# size spread, where a 2447-file repository fills the whole per-rubric budget
# and costs four times as much.
#
# Cost per audit is dominated by repository size, so any single number here is
# an average over a specific sample and not a per-repo prediction. The spread
# behind these means is wide: Sonnet ran $1.03 to $4.63.
_ROUGH_COST_PER_AUDIT = {"claude-sonnet-4.6": 3.50, "claude-sonnet-4-6": 3.50,
                         "claude-sonnet-5": 4.55,   # +30% tokenizer, measured
                         "claude-haiku-4.5": 0.39, "claude-haiku-4-5": 0.39}

# How far apart two findings may sit and still be "the same place". Models
# disagree about which line of a handler to point at. Three, because that is
# the window app/scan/cross_rubric_dedup.py already uses -- it additionally
# requires the titles to be similar, which is right when merging two findings
# into one report and wrong here, where two MODELS naming the same bug
# differently is the interesting case rather than a reason to call them
# different findings.
_SAME_PLACE_LINES = 3


def fetch(slug: str, branch: str) -> bytes:
    url = f"https://codeload.github.com/{slug}/zip/refs/heads/{branch}"
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def key(f: dict) -> tuple[str, int]:
    return (str(f.get("file") or ""), int(f.get("line") or 0))


def same_place(a: tuple[str, int], b: tuple[str, int]) -> bool:
    return a[0] == b[0] and abs(a[1] - b[1]) <= _SAME_PLACE_LINES


def overlap(left: list[dict], right: list[dict]) -> tuple[int, int, int]:
    """(in both, only left, only right), matched by location."""
    lk = [key(f) for f in left]
    rk = [key(f) for f in right]
    matched_r: set[int] = set()
    both = 0
    for a in lk:
        for i, b in enumerate(rk):
            if i not in matched_r and same_place(a, b):
                matched_r.add(i)
                both += 1
                break
    return both, len(lk) - both, len(rk) - len(matched_r)


def repeats(findings: list[dict]) -> int:
    """How many findings restate one already reported in the same file.

    The "three command injections at lines 64, 78 and 90 where the other model
    saw one at 67" question, which is the first thing to look at when one model
    reports far more than another.

    Keyed on (file, rule, title) rather than on line proximity. The first
    version of this counted findings sitting within _SAME_PLACE_LINES of each
    other and would have returned ZERO for exactly that case -- 64, 78 and 90
    are twelve and fourteen lines apart, far outside a window meant for line
    drift between models. It measured nothing and would have printed a
    reassuring 0 next to the run it existed to question.

    A repeat is not proof of duplication: three handlers in one file can each
    be genuinely injectable, and then three findings are correct. It says
    where to look, not what is true.
    """
    seen: set[tuple[str, str, str]] = set()
    n = 0
    for f in findings:
        k = (str(f.get("file") or ""), str(f.get("rule_id") or ""),
             " ".join(str(f.get("title") or "").lower().split()))
        if k in seen:
            n += 1
        seen.add(k)
    return n


def severities(findings: list[dict]) -> str:
    c = defaultdict(int)
    for f in findings:
        c[str(f.get("severity"))] += 1
    return "/".join(str(c[s]) for s in ("critical", "high", "medium", "low"))


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--models", nargs="+",
                    default=["claude-sonnet-4.6", "claude-haiku-4.5"])
    ap.add_argument("--repos", nargs="+", default=None,
                    help="owner/repo[@branch]; defaults to the batch sample")
    ap.add_argument("--json", default="/tmp/model_comparison.json")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    repos = ([(r.split("@")[0], (r.split("@") + ["main"])[1]) for r in args.repos]
             if args.repos else list(REPOS))

    unpriced = [m for m in args.models if m not in PRICE_TABLE]
    if unpriced:
        print(f"not in app/llm/pricing.py: {', '.join(unpriced)}. Their cost "
              "would be estimated at DEFAULT_PRICE (the dearest known row), so "
              "the totals below would be fiction. Add a row first.",
              file=sys.stderr)
        return 2

    estimate = sum(_ROUGH_COST_PER_AUDIT.get(m, 1.0) for m in args.models) * len(repos)
    print(f"{len(repos)} repositories x {len(args.models)} models "
          f"= {len(repos) * len(args.models)} audits, roughly ${estimate:.2f}.")
    if args.dry_run:
        print("--dry-run: nothing called.")
        return 0

    base = LLMClient()
    if not base.providers:
        print("no LLM providers configured -- export .env first "
              "(set -a; . ./.env; set +a)", file=sys.stderr)
        return 2

    results: dict[str, dict[str, dict]] = {}
    spent = Decimal(0)
    for slug, branch in repos:
        try:
            raw = fetch(slug, branch)          # ONCE, shared by every model
        except Exception as exc:               # noqa: BLE001 - report and carry on
            print(f"\n{slug}: fetch failed ({exc}) -- skipped", file=sys.stderr)
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(raw)) as zf:
                files = sum(1 for i in zf.infolist() if not i.is_dir())
        except zipfile.BadZipFile:
            print(f"\n{slug}: not a zip -- skipped", file=sys.stderr)
            continue

        print(f"\n{slug}@{branch}  {files} files  {len(raw)/1e6:.1f} MB")
        results[slug] = {}
        for model in args.models:
            t0 = time.time()
            scan = run_scan(raw, base.with_model(model))
            elapsed = time.time() - t0
            usage = scan.get("llm_usage") or {}
            served = usage.get("model") or model
            cost = cost_usd(served, usage.get("input_tokens") or 0,
                            usage.get("output_tokens") or 0)
            spent += cost
            findings = scan["findings"]
            # The whole usage block, not just the money. The first run of
            # this script recorded cost alone, and then could not answer the
            # question the numbers raised: Sonnet cost NINE times Haiku where
            # the price table says three, so one of them read far less of the
            # same repository -- and the tokens that would say which were the
            # one thing not written down.
            results[slug][model] = {
                "served_model": served, "cost_usd": float(cost),
                "input_tokens": usage.get("input_tokens"),
                "output_tokens": usage.get("output_tokens"),
                "prompts": usage.get("prompts"),
                "calls": usage.get("calls"),
                "cost_cap_exceeded": usage.get("cost_cap_exceeded"),
                "seconds": round(elapsed, 1),
                "basis": scan["score"].get("basis"),
                "total": scan["score"]["total"],
                "categories": scan["score"]["categories"],
                "llm": scan["llm"] if isinstance(scan["llm"], str) else None,
                "findings": [
                    {k: f.get(k) for k in
                     ("rule_id", "severity", "confidence", "category",
                      "file", "line", "title", "origin_category")}
                    for f in findings],
            }
            note = ""
            if isinstance(scan["llm"], str):        # "failed: ..."
                note = "  <- LLM STAGE FAILED, static-only"
            if usage.get("cost_cap_exceeded"):
                note += "  <- JOB_COST_CAP_USD hit, scan cut short"
            print(f"    {model:20s} {scan['score']['total']:>5}  "
                  f"{len(findings):>3} findings  {severities(findings):>12}  "
                  f"{(usage.get('input_tokens') or 0)/1000:>7.0f}K in  "
                  f"${float(cost):.3f}  {elapsed:.0f}s{note}")

    if len(args.models) == 2 and results:
        a, b = args.models
        print(f"\n{'repo':34s}{'both':>6}{'only ' + a[:9]:>16}"
              f"{'only ' + b[:9]:>16}{'repeats':>12}")
        for slug, per in results.items():
            if a not in per or b not in per:
                continue
            fa, fb = per[a]["findings"], per[b]["findings"]
            both, only_a, only_b = overlap(fa, fb)
            print(f"{slug[:33]:34s}{both:>6}{only_a:>16}{only_b:>16}"
                  f"{repeats(fa):>6}/{repeats(fb):<5}")

    Path(args.json).write_text(json.dumps(results, indent=2, sort_keys=True))
    to_check = sum(len(m["findings"]) for per in results.values()
                   for m in per.values())
    print(f"\nspent ${float(spent):.2f}  ->  {args.json}")
    print(f"{to_check} findings recorded. None of them is verified: this run "
          "compared the models to each other, not to the code. Precision needs "
          "a human reading the flagged lines, and the disagreements are where "
          "to start.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
