"""Run a full audit on a local ZIP:

  python -m app.audit_cli app.zip [report.html]
  python -m app.audit_cli app.zip --sarif out.sarif --sarif-root export-folder

Static scan always runs; LLM scan runs only if providers are configured
in the environment (.env). Prints the report as JSON to stdout. Shares
the scan pipeline with the API (app/scan/pipeline.py) — same findings,
same scoring, same honest "skipped"/"failed" states for the LLM stage.
"""

from __future__ import annotations

import io
import json
import os
import re
import sys
import zipfile
from pathlib import Path

from app.logging_config import configure_logging
from app.ingest.stack_detect import detect_stack
from app.ingest.validators import ArchiveValidationError, validate_zip
from app.sca.stage import sca_client_for
from app.llm.client import LLMClient
from app.scan.pipeline import run_scan


def _github_archive_prefix(raw: bytes) -> str | None:
    """Recognize a common GitHub commit-export folder from all ZIP entries.

    Never strip an arbitrary common directory such as `src/`. Other export
    wrappers need `--sarif-root`; passing `.` explicitly keeps archive paths.
    """
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        names = [entry.filename.removeprefix("./") for entry in archive.infolist()]
    files = [name for name in names if name and not name.endswith("/")]
    if not files:
        return None
    prefix = files[0].partition("/")[0]
    if not re.fullmatch(r"[A-Za-z0-9_.-]+-[0-9a-fA-F]{7,40}", prefix):
        return None
    if not all(name.startswith(prefix + "/") for name in names):
        return None
    return prefix


def _write_artifact(path: Path, text: str) -> None:
    """Write an audit artifact only its owner can read.

    The report carries credential-shaped material in masked form, and this tool
    writes it wherever the operator points -- which is often /tmp on a shared
    machine. The default umask gives 0644, so the audit of someone else's
    repository would be readable by every account on the box; 0600 is the whole
    difference, and it is deliberate rather than incidental.

    CodeQL flags both writes here as clear-text storage of sensitive data, and
    it is right about the class: an operator tool that dumps an audit to a file
    does exactly that, and the same alert is open on main for this file and for
    scripts/batch_audit.py. The permissions are what this side can honestly fix;
    anything more would mean not writing the artifact at all.
    """
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        # The mode above applies only when the file is CREATED. Overwriting a
        # file an earlier run left world-readable would keep its old mode, so
        # the permission is set on the descriptor, every time.
        os.fchmod(handle.fileno(), 0o600)
        handle.write(text)


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
    # dependency check sends package names and versions to OSV. The operator
    # decides that per run; the service decides it
    # per entitlement (see app/sca/stage.py:sca_client_for).
    #
    # `--sarif <path>` writes the same findings in the format GitHub's code
    # scanning and VS Code consume. It changes nothing about the audit.
    argv = sys.argv[1:]
    with_sca = "--sca" in argv
    argv = [a for a in argv if a != "--sca"]
    sarif_options: dict[str, str] = {}
    for option in ("--sarif", "--sarif-root"):
        if option in argv:
            index = argv.index(option)
            if index + 1 >= len(argv) or argv[index + 1].startswith("--"):
                print(f"{option} needs a path", file=sys.stderr)
                return 2
            sarif_options[option] = argv[index + 1]
            argv = argv[:index] + argv[index + 2:]
    sarif_path = sarif_options.get("--sarif")
    if "--sarif-root" in sarif_options and not sarif_path:
        print("--sarif-root requires --sarif", file=sys.stderr)
        return 2
    if len(argv) not in (1, 2):
        print("usage: python -m app.audit_cli <archive.zip> [report.html] "
              "[--sca] [--sarif out.sarif] [--sarif-root archive/folder]", file=sys.stderr)
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
        _write_artifact(out, render_report(report, project_name=Path(argv[0]).stem))
        print(f"html report: {out}", file=sys.stderr)

    if sarif_path:
        from app.report.sarif import render_sarif
        destination = Path(sarif_path)
        archive_root = sarif_options.get("--sarif-root")
        if archive_root is None:
            archive_root = _github_archive_prefix(raw)
        _write_artifact(destination, render_sarif(
            scan["findings"], engine_version=scan["score"]["scan_manifest"]["engine_version"],
            score=scan["score"], project_name=Path(argv[0]).stem,
            archive_root=archive_root))
        print(f"sarif: {destination}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
