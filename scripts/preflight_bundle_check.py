#!/usr/bin/env python3
"""Rehearse a bundle check without spending a request from the daily budget.

WHY THIS EXISTS, and it is a specific failure rather than a general nicety. On
2026-09-01 the whole day's allowance — five requests — went to a hostname whose
Caddy block had not been deployed. Every run came back
`status: error, ConnectError` and `rotation: no_baseline`, three times, and then
429. Nothing was learned, and the next attempt had to wait a day.

The endpoint's limit is not the problem: it bounds requests we make to a third
party on a caller's say-so, and five a day is a deliberate number. The problem
was spending them to discover something a plain fetch answers for free.

WHAT IT SHARES WITH THE REAL THING. Everything except the ledger: the same
fetch_served_bundle, so the same SSRF vetting, the same https-only rule, the
same IP-pinned transport, the same transitive crawl, the same registry and the
same redaction. If this says `checked` with a finding, the endpoint will too.

WHAT IT DOES NOT COVER, so nobody reads a green rehearsal as a finished result:
persistence, the consent ledger row, and the rotation verdict as the SERVER
computes it. Those are what the real runs are for and why they are worth the
budget. `--baseline` computes the verdict locally from a previous result file,
which rehearses the comparison but not the row it will be stored against.

    python scripts/preflight_bundle_check.py https://host/
    python scripts/preflight_bundle_check.py https://host/ --baseline /root/rot-1.json

API_KEY_PEPPER must be the one production uses, or fingerprints come back empty
and the rotation rehearsal compares two blanks.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.rotation import compare_findings  # noqa: E402
from app.proof.served_bundle import fetch_served_bundle  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("url", help="the deployment to read, https only")
    ap.add_argument("--baseline", type=Path, default=None,
                    help="a previous result JSON, to rehearse the rotation "
                         "verdict this run would produce against it")
    args = ap.parse_args()

    if not os.environ.get("API_KEY_PEPPER", "").strip():
        print("API_KEY_PEPPER is not set — fingerprints will be empty and the "
              "rotation rehearsal would compare two blanks", file=sys.stderr)
        return 78

    # ownership="consented" is what app/routes/bundle_check.py passes, and this
    # is a rehearsal of that call rather than a more permissive one.
    result = fetch_served_bundle(url=args.url, consent=True,
                                 ownership="consented")

    findings = [bf.evidence() for bf in result.findings]
    print(f"status    : {result.status}")
    print(f"detail    : {result.detail}")
    print(f"leaked    : {result.leaked}")
    print(f"findings  : {len(findings)}")
    for f in findings:
        print(f"    {f.get('pattern')}  {f.get('redacted')}  "
              f"fp {str(f.get('fingerprint'))[:12]}  at {f.get('location')}")
    print(f"publishable: {len(result.publishable)}")
    print(f"assets_read: {json.dumps(result.assets_read, ensure_ascii=False)}")
    print(f"evidence  : {json.dumps(result.evidence, ensure_ascii=False)}")

    if args.baseline is not None:
        prior = json.loads(args.baseline.read_text())
        # The same shape the endpoint stores, so a rehearsal reads a real
        # previous result file rather than a hand-built one.
        previous = prior.get("findings")
        if not isinstance(previous, list):
            print(f"\n{args.baseline}: no `findings` list — cannot rehearse a "
                  "verdict against it", file=sys.stderr)
            return 1
        verdict = compare_findings(previous, findings, had_baseline=True)
        print(f"\nrotation would be: {verdict.verdict}")
        print(f"  {verdict.detail}")
        print(f"  still_shipped: {list(verdict.still_shipped)}")

    if result.status != "checked":
        print("\nNOT `checked` — spending a real request on this URL would "
              "burn one of five for the day and learn the same thing.",
              file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
