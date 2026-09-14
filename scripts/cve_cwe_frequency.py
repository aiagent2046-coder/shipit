#!/usr/bin/env python3
"""Count CWE class frequencies across a CVEProject/cvelistV5 checkout.

Deterministic analysis, no network and no LLM. Point --source at a clean
clone of https://github.com/CVEProject/cvelistV5 (a depth-1 clone is
enough; see docs/browser-cve-learning.md for the cloning procedure).
Package identity for the npm/PyPI cut uses the same
``app.scan.cve_catalog._identity`` logic as the knowledge compiler, so
"npm/PyPI records" means exactly the records the browser catalog can
index. Records whose containers store a list (e.g. `adp`) are handled
the same way the compiler handles them.

Output: total counts, the top-N CWE classes overall, and the top-N CWE
classes among npm/PyPI records, with three example CVE ids each.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from app.scan.cve_catalog import _identity  # noqa: E402


def _container_entries(record: dict, name: str):
    entry = record.get("containers", {}).get(name, {})
    if isinstance(entry, dict):
        yield entry
    elif isinstance(entry, list):
        yield from (item for item in entry if isinstance(item, dict))


def cwe_ids(record: dict) -> set[str]:
    found = set()
    for container in ("cna", "adp"):
        for entries in _container_entries(record, container):
            for group in entries.get("problemTypes", []):
                for item in group.get("descriptions", []):
                    cwe = item.get("cweId") or ""
                    if cwe.startswith("CWE-"):
                        found.add(cwe)
    return found


def npm_pypi(record: dict) -> bool:
    for container in ("cna", "adp"):
        for entries in _container_entries(record, container):
            for affected in entries.get("affected", []):
                if not isinstance(affected, dict):
                    continue
                try:
                    if _identity(affected) is not None:
                        return True
                except Exception:
                    continue
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, help="path to a cvelistV5 checkout")
    parser.add_argument("--top", type=int, default=35, help="rows per table")
    args = parser.parse_args()

    source = Path(args.source)
    overall: Counter[str] = Counter()
    eco: Counter[str] = Counter()
    examples: dict[str, list[str]] = {}
    records = no_cwe = eco_records = 0

    for path in source.rglob("cves/*/*/*.json"):
        try:
            record = json.loads(path.read_text())
        except (ValueError, UnicodeError):
            continue
        records += 1
        cwes = cwe_ids(record)
        if not cwes:
            no_cwe += 1
        if npm_pypi(record):
            eco_records += 1
        cve_id = record.get("cveMetadata", {}).get("cveId", path.stem)
        for cwe in cwes:
            overall[cwe] += 1
            if npm_pypi(record):
                eco[cwe] += 1
                examples.setdefault(cwe, [])
                if len(examples[cwe]) < 3:
                    examples[cwe].append(cve_id)

    print(f"records={records}  with_cwe={records - no_cwe}  no_cwe={no_cwe}  npm_pypi={eco_records}")
    print(f"\n=== TOP {args.top} CWE overall:")
    for cwe, count in overall.most_common(args.top):
        print(f"  {cwe:10} {count:6}  ({100 * count // max(1, records)}%)")
    print(f"\n=== TOP {args.top} CWE among npm/PyPI records:")
    for cwe, count in eco.most_common(args.top):
        ids = ", ".join(examples.get(cwe, []))
        print(f"  {cwe:10} {count:5}  ({100 * count // max(1, eco_records)}%)  e.g. {ids}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
