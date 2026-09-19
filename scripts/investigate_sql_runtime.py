"""Investigate an archive with the non-LLM agent and its trusted SQL capability.

Run from the installed repository with an explicit disposable PostgreSQL DSN.
The archive is only read by static collectors; the executor receives no archive,
project code, SQL or expectations. The ordinary offline package stays offline.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.ingest.validators import MAX_ARCHIVE_BYTES, ArchiveValidationError  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.proof.sql_runtime_executor import SyntheticSqlExecutor  # noqa: E402
from app.scan.pipeline import BASIS_PREVIEW, run_scan  # noqa: E402


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, help="New JSON report; existing files are never overwritten")
    args = parser.parse_args(argv)
    output = args.output.open("x", encoding="utf-8") if args.output else None
    try:
        with args.archive.open("rb") as source:
            raw = source.read(MAX_ARCHIVE_BYTES + 1)
        result = run_scan(raw, LLMClient(providers=[]), depth=BASIS_PREVIEW,
                          synthetic_sql_executor=SyntheticSqlExecutor())
        encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
        if output:
            output.write(encoded)
        print(encoded, end="")
        agent = result["score"]["scan_manifest"]["security_agent"]
        contracts = [item["synthetic_contract"] for item in agent["observations"] if "synthetic_contract" in item]
        # Exit 0 describes a completed synthetic investigation, never a clean project.
        if any(item["status"] == "failed" for item in contracts):
            return 1
        return 0 if contracts and agent["status"] == "completed" and all(
            item["status"] == "passed" for item in contracts) else 2
    except ArchiveValidationError as exc:
        print(json.dumps({"error": exc.reason}), file=sys.stderr)
        return 2
    finally:
        if output:
            output.close()


if __name__ == "__main__":
    raise SystemExit(main())
