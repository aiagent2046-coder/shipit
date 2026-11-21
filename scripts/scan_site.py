"""Scan a site's STRUCTURE for exposed files and misconfiguration.

Part of the consented-request family (RLS check → served-bundle check →
this). The kernel is app/proof/web_scan.py; this is the operator edge.

CONSENT IS NOT A FLAG. `SITE_SCAN_CONSENT` must be set to the exact string
`i-own-this-project` — the same typed phrase the RLS probe and the bundle
check use. A boolean would get set once and stay set; a sentence someone has
to type is a sentence they have to mean. The kernel also refuses without
`consent=True`: this is the second lock, on the operator rather than the
caller.

WHAT THIS SENDS: read-only GET requests to a FIXED probe list (16 files,
8 directories), with an honest User-Agent and a delay between requests. No
payloads, no auth attempts, no exploitation. Everything it reports is an
observable configuration fact.

    export SITE_SCAN_CONSENT=i-own-this-project
    python scripts/scan_site.py https://example.com [--json] [--fail-on high]
    python scripts/scan_site.py http://127.0.0.1:8000 --allow-loopback   # local stand

Exit codes follow drydock-local: 0 — ran, nothing at/above --fail-on;
1 — findings at/above --fail-on; 2 — refused or failed before any probe.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.web_scan import (  # noqa: E402
    SEVERITY_ORDER,
    render_text,
    run_web_structure_scan,
)
from app.routes.rls_check import CONSENT_PHRASE  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan a site's structure (fixed, read-only probes).")
    parser.add_argument("url", help="https://site to scan (http:// only for --allow-loopback)")
    parser.add_argument("--json", action="store_true", help="complete machine-readable report")
    parser.add_argument("--fail-on", choices=SEVERITY_ORDER, default="none",
                        help="exit 1 when a finding reaches this severity")
    parser.add_argument("--allow-loopback", action="store_true",
                        help="local stand only: allow http:// on a loopback host")
    parser.add_argument("--delay", type=float, default=0.2,
                        help="seconds between requests (default 0.2)")
    args = parser.parse_args(argv)

    if (os.environ.get("SITE_SCAN_CONSENT") or "").strip() != CONSENT_PHRASE:
        print(f"refusing: set SITE_SCAN_CONSENT={CONSENT_PHRASE} to confirm "
              "this site is yours to scan", file=sys.stderr)
        return 2

    result = run_web_structure_scan(
        url=args.url, consent=True, allow_loopback=args.allow_loopback, delay_s=args.delay)

    if args.json:
        print(json.dumps(result.to_json(), ensure_ascii=False), flush=True)
    else:
        print(render_text(result), flush=True)

    if result.status != "checked":
        # A refusal or a failed target is not a finding, and must not exit
        # like one: 2 is "did not run", 1 is reserved for the finding gate.
        return 2
    if args.fail_on != "none":
        threshold = SEVERITY_ORDER.index(args.fail_on)
        if any(SEVERITY_ORDER.index(f.severity) >= threshold for f in result.findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())