"""Run a full audit on a local ZIP:

  python -m app.audit_cli app.zip [report.html]

Static scan always runs; LLM scan runs only if providers are configured
in the environment (.env). Prints the report as JSON to stdout. Shares
the scan pipeline with the API (app/scan/pipeline.py) — same findings,
same scoring, same honest "skipped"/"failed" states for the LLM stage.
"""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

from app.logging_config import configure_logging
from app.ingest.stack_detect import detect_stack
from app.ingest.validators import ArchiveValidationError, validate_zip
from app.sca.stage import sca_client_for
from app.llm.client import LLMClient
from app.scan.pipeline import run_scan


def main() -> int:
    # Every `python -m` entry point configures logging through here, and the
    # rule is one rule because the exception is what bites: without it records
    # ride the root logger's lastResort handler, which applies no
    # RedactionFilter. Nothing has leaked from this CLI only because
    # lastResort also drops anything under WARNING -- one WARNING carrying a
    # token is all that stands between "safe by accident" and the journal.
    configure_logging()
    # `--sca` is an explicit opt-in, and deliberately not the default: this
    # tool audits a repository that is usually someone else's, and the
    # dependency check is the one part of a scan that sends anything to a
    # third party. The operator decides that per run; the service decides it
    # per entitlement (see app/sca/stage.py:sca_client_for).
    #
    # `--sarif <path>` writes the same findings in the format GitHub's code
    # scanning and VS Code consume. It changes nothing about the audit.
    argv = sys.argv[1:]
    with_sca = "--sca" in argv
    argv = [a for a in argv if a != "--sca"]
    sarif_path: str | None = None
    if "--sarif" in argv:
        index = argv.index("--sarif")
        if index + 1 >= len(argv):
            print("--sarif needs a path to write", file=sys.stderr)
            return 2
        sarif_path = argv[index + 1]
        argv = argv[:index] + argv[index + 2:]
    if len(argv) not in (1, 2):
        print("usage: python -m app.audit_cli <archive.zip> [report.html] "
              "[--sca] [--sarif out.sarif]", file=sys.stderr)
        return 2

    raw = Path(argv[0]).read_bytes()
    buf = io.BytesIO(raw)

    try:
        validate_zip(buf, size_bytes=len(raw))
    except ArchiveValidationError as exc:
        print(json.dumps({"error": exc.reason, "detail": exc.detail}))
        return 1

    buf.seek(0)
    stack = detect_stack(buf)

    scan = run_scan(raw, LLMClient(),
                    sca_client=sca_client_for(paid=True, requested=with_sca))

    report = {
        "stack": stack.value,
        "score": scan["score"],
        "findings": scan["findings"],
        "llm": scan["llm"],
        "sca": scan.get("sca"),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))

    if len(argv) == 2:
        from app.report.html import render_report
        out = Path(argv[1])
        out.write_text(render_report(report, project_name=Path(argv[0]).stem))
        print(f"html report: {out}", file=sys.stderr)

    if sarif_path:
        from app.report.sarif import render_sarif
        destination = Path(sarif_path)
        destination.write_text(render_sarif(
            scan["findings"], engine_version=scan["score"]["scan_manifest"]["engine_version"],
            score=scan["score"], project_name=Path(argv[0]).stem))
        print(f"sarif: {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
