"""Run a full audit on a local ZIP:

  python -m app.audit_cli app.zip [report.html]

Static scan always runs; LLM scan runs only if providers are configured
in the environment (.env). Prints the report as JSON to stdout.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from app.ingest.stack_detect import detect_stack
from app.ingest.validators import ArchiveValidationError, validate_zip
from app.llm.client import LLMClient
from app.scan.llm_scan import run_llm_scan
from app.scan.scoring import compute_scores
from app.scan.static import run_static_scan


def main() -> int:
    if len(sys.argv) not in (2, 3):
        print("usage: python -m app.audit_cli <archive.zip> [report.html]",
              file=sys.stderr)
        return 2

    raw = Path(sys.argv[1]).read_bytes()
    buf = io.BytesIO(raw)

    try:
        validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        print(json.dumps({"error": exc.reason, "detail": exc.detail}))
        return 1

    buf.seek(0)
    stack = detect_stack(buf)

    buf.seek(0)
    static = run_static_scan(buf)
    findings = static["findings"]

    llm_stats = None
    client = LLMClient()
    if client.providers:
        buf.seek(0)
        llm_findings, stats = run_llm_scan(buf, client)
        findings += [vars(f) for f in llm_findings]
        llm_stats = vars(stats)

    from app.scan.scoring import ScoredFinding
    score = compute_scores([ScoredFinding(**f) for f in findings])

    report = {
        "stack": stack.value,
        "score": score,
        "findings": findings,
        "llm": llm_stats or "skipped (no providers in env)",
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if len(sys.argv) == 3:
        from app.report.html import render_report
        out = Path(sys.argv[2])
        out.write_text(render_report(report, project_name=Path(sys.argv[1]).stem))
        print(f"html report: {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
