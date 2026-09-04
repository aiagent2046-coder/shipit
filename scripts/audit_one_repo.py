#!/usr/bin/env python3
"""Run one public repo through the full audit pipeline and print the findings.

    set -a; . ./.env; set +a
    .venv/bin/python scripts/audit_one_repo.py owner/repo [branch]

batch_audit.py answers "is the score reproducible across ten repos". This
answers a different question that came up three times in two days and was
each time served by a hand-assembled shell block: "what does the engine say
about THIS repo, finding by finding, so I can grade it against a key I wrote
first". Assembling that block by hand is how a `read -rs` once swallowed the
next line of the script and read it as an API key.

Prints file:line for every finding because that is the only form a finding can
be graded in. A run that reports "5 findings" without locations cannot be
checked against a clone, and an unverifiable measurement is worse than none --
it looks like evidence.
"""
from __future__ import annotations

import io
import json
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest.stack_detect import detect_stack  # noqa: E402
from app.ingest.validators import validate_zip  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.scan.llm_scan import RUBRICS  # noqa: E402
from app.scan.pipeline import run_scan  # noqa: E402

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def fetch_repack(slug: str, branch: str) -> bytes:
    """GitHub's zip nests everything under repo-branch/; strip that prefix so
    the archive looks like the user export the pipeline expects."""
    url = f"https://codeload.github.com/{slug}/zip/refs/heads/{branch}"
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


def _reclassified_marker(finding: dict) -> str:
    """" <- llm-security" when a finding did not keep its rubric's category.

    LLMScanStats counts these as `recategorised`, and the first real run
    returned 2 -- which answered half a question. The other half, whether the
    model moved them the RIGHT way, could not be answered from this output at
    all: it printed the category and not the rule id, so the two findings that
    had moved were indistinguishable from the thirteen that had not.

    A count says the feature is alive. Naming the findings is what lets
    someone judge them, and judging is the whole reason the field exists: a
    model reclassifying wrongly is worse than one not reclassifying at all.
    """
    rule_id = str(finding.get("rule_id") or "")
    if not rule_id.startswith("llm-"):
        return ""
    rubric = RUBRICS.get(rule_id[len("llm-"):])
    if rubric is None:
        return ""
    declared = str(finding.get("category") or "")
    if declared and declared != rubric["category"]:
        return f" (moved from {rubric['category']})"
    return ""


def pack_directory(root: Path) -> bytes:
    """Zip a clone that is already on disk, minus .git.

    Grading a run means reading the flagged lines in a working tree, so the
    tree is usually already there; re-downloading it from GitHub would only
    add a way for the audited bytes and the graded bytes to differ.
    """
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as dst:
        for path in sorted(root.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            dst.write(path, path.relative_to(root).as_posix())
    return out.getvalue()


def main(argv: list[str]) -> int:
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    slug = argv[0]
    branch = argv[1] if len(argv) > 1 else "main"
    local = Path(slug).expanduser()

    client = LLMClient()
    if not client.providers:
        # Not fatal: the static half still runs, and saying so beats a scan
        # that silently reports static-only numbers as if the LLM had spoken.
        print("WARNING: no LLM providers configured -- static-only run "
              "(export .env for the full audit)", file=sys.stderr)

    if local.is_dir():
        data = pack_directory(local)
        origin = f"{local} (local clone)"
    else:
        data = fetch_repack(slug, branch)
        origin = f"{slug}@{branch}"
    validate_zip(io.BytesIO(data), size_bytes=len(data))
    stack = detect_stack(io.BytesIO(data)).value
    print(f"{origin}  stack={stack}  {len(data) / 1e6:.1f} MB")

    t0 = time.time()
    scan = run_scan(data, client)
    elapsed = time.time() - t0

    score = scan["score"]
    print(f"\nscore {score['total']}  basis={score.get('basis')}  {elapsed:.0f}s")
    for name, value in sorted((score.get("categories") or {}).items()):
        mark = " (unexamined)" if name in (score.get("unexamined") or []) else ""
        print(f"    {name:16s} {value}{mark}")

    # Printed beside the categories because it is what makes the Frontend
    # number readable. `Frontend 10.0` means two different things -- a mounted
    # app with a boundary above its routes, and a repository with no frontend
    # at all -- and grading a run against a key written first requires knowing
    # which. The engine has persisted this in score_json since 2026-09-04; a
    # grading tool that did not print it left the reader to guess.
    scan_context = score.get("frontend_scan") or {}
    if scan_context:
        print(f"    {'(frontend scan)':16s} mount={scan_context.get('mount')} "
              f"coverage={scan_context.get('coverage')}")

    llm = scan["llm"]
    print(f"\nllm: {llm if isinstance(llm, str) else json.dumps(llm, sort_keys=True)}")
    print(f"usage: {json.dumps(scan['llm_usage'], sort_keys=True)}")

    findings = sorted(
        scan["findings"],
        key=lambda f: (SEVERITY_ORDER.get(str(f.get("severity")).lower(), 9),
                       str(f.get("file")), f.get("line") or 0),
    )
    print(f"\n=== {len(findings)} findings")
    for f in findings:
        print(f"  [{str(f.get('severity')).upper():8s}] {f.get('category')}"
              f"{_reclassified_marker(f)}  {f.get('rule_id')}  "
              f"conf={f.get('confidence')}")
        print(f"      {f.get('file')}:{f.get('line')}  {f.get('title')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
