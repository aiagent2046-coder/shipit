#!/usr/bin/env python3
"""Metamorphic probe: measure detector stability without any model.

For every golden-corpus case and every applicable invariant transform:

  control  -- the untouched case must reproduce its expected.json (a case
             that fails its control is invalid input, not a detector gap);
  variant  -- the transformed case must reproduce the SAME expected.json.

Positives that lose their finding are ESCAPES. Negatives that start firing
are NOISE. A variant whose rewrite stops parsing is UNPARSEABLE (a bug in
the generator, never a detector verdict).

Usage:
    .venv/bin/python scripts/metamorphic_probe.py                # whole corpus
    .venv/bin/python scripts/metamorphic_probe.py --rules insecure-session-cookie-attributes
    .venv/bin/python scripts/metamorphic_probe.py --json /tmp/metamorphic.json

Output: a rule x transform table plus an optional JSON report with the
individual escape/noise cases for triage.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.scan.static import run_static_scan  # noqa: E402
from tests.detector_samples import expand_samples  # noqa: E402
from tests.detectors.conftest import discover_cases, load_expected  # noqa: E402
from tests.detectors.test_golden_corpus import assert_case  # noqa: E402
from tests.metamorphic_variants import TRANSFORMS, variant_entries  # noqa: E402


def case_entries(case_dir: Path) -> dict[str, str]:
    entries: dict[str, str] = {}
    for path in sorted(case_dir.rglob("*")):
        if path.is_file() and path.name != "expected.json":
            name = path.relative_to(case_dir).as_posix().removesuffix(".fixture")
            entries[name] = expand_samples(path.read_text())
    return entries


def scan_entries(entries: dict[str, str]) -> list[dict]:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return run_static_scan(buf)["findings"]


def verdict_holds(rule_id: str, polarity: str, expected: dict, findings: list) -> bool:
    try:
        assert_case(rule_id, polarity, expected, findings)
    except AssertionError:
        return False
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rules", help="comma-separated rule ids (default: all)")
    parser.add_argument("--json", dest="json_out", help="write a JSON report here")
    args = parser.parse_args()

    wanted = set(args.rules.split(",")) if args.rules else None
    cases = [
        case for case in discover_cases()
        if wanted is None or case[0] in wanted
    ]

    # table[(rule, transform)][polarity] -> [survived, broken]
    table: dict[tuple[str, str], dict[str, list[int]]] = defaultdict(
        lambda: {"positive": [0, 0], "negative": [0, 0]}
    )
    incidents: list[dict] = []
    skipped_unparseable: list[dict] = []
    invalid_controls: list[str] = []
    n_applied = 0

    for rule_id, polarity, case_dir in cases:
        expected = load_expected(case_dir)
        entries = case_entries(case_dir)
        findings = scan_entries(entries)
        if not verdict_holds(rule_id, polarity, expected, findings):
            # Control first: the untouched case must pass its own contract.
            invalid_controls.append(f"{rule_id}/{polarity}/{case_dir.name}")
            continue
        for transform in TRANSFORMS:
            variant = variant_entries(entries, transform)
            if variant.status == "not-applicable":
                continue
            if variant.status == "unparseable":
                skipped_unparseable.append({
                    "case": f"{rule_id}/{polarity}/{case_dir.name}",
                    "transform": f"{transform.lang}:{transform.id}",
                    "file": variant.changed_files[0],
                })
                continue
            n_applied += 1
            cell = table[(rule_id, f"{transform.lang}:{transform.id}")][polarity]
            if verdict_holds(rule_id, polarity, expected, scan_entries(variant.entries)):
                cell[0] += 1
            else:
                cell[1] += 1
                incidents.append({
                    "case": f"{rule_id}/{polarity}/{case_dir.name}",
                    "polarity": polarity,
                    "transform": f"{transform.lang}:{transform.id}",
                    "kind": "escape" if polarity == "positive" else "noise",
                })

    print(f"cases={len(cases)} applied_variants={n_applied} "
          f"invalid_controls={len(invalid_controls)} unparseable={len(skipped_unparseable)}")
    if invalid_controls:
        print("INVALID CONTROLS (case fails its own expected.json untouched):")
        for name in invalid_controls:
            print(f"  {name}")
    if skipped_unparseable:
        print("UNPARSEABLE (generator bugs, not detector verdicts):")
        for item in skipped_unparseable:
            print(f"  {item['case']} x {item['transform']}: {item['file']}")

    print(f"\n{'rule':44s} {'transform':18s} {'pos ok/esc':>10s} {'neg ok/noise':>13s}")
    for (rule_id, transform), cells in sorted(table.items()):
        pos, neg = cells["positive"], cells["negative"]
        print(f"{rule_id:44s} {transform:18s} "
              f"{pos[0]:>4d}/{pos[1]:<5d} {neg[0]:>6d}/{neg[1]:<6d}")

    escaped = [i for i in incidents if i["kind"] == "escape"]
    noisy = [i for i in incidents if i["kind"] == "noise"]
    print(f"\nESCAPES: {len(escaped)}   NOISE: {len(noisy)}")
    for item in incidents:
        print(f"  [{item['kind']}] {item['case']} x {item['transform']}")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps({
            "applied_variants": n_applied,
            "invalid_controls": invalid_controls,
            "unparseable": skipped_unparseable,
            "incidents": incidents,
            "table": {f"{r}|{t}": cells for (r, t), cells in table.items()},
        }, indent=2))
        print(f"\nreport: {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
