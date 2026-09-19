"""Import a bounded, pinned operator runtime receipt into a non-LLM scan.

No project code or receipt-provided commands are executed. A passed import
means evidence consistency within one scenario, not independent attestation.
"""

from __future__ import annotations
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
# Direct script execution needs the repository root before application imports.
from app.ingest.validators import MAX_ARCHIVE_BYTES, ArchiveValidationError  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.scan.pipeline import BASIS_PREVIEW, run_scan  # noqa: E402

MAX_EVIDENCE_BYTES = 64 * 1024


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate_evidence_key")
        out[key] = value
    return out


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--evidence", type=Path, required=True, help="Raw scenario.json, not verdict.json")
    parser.add_argument("--run-id", required=True, help="Expected ID from the controlled run-id.txt")
    parser.add_argument(
        "--output", type=Path, required=True, help="New report JSON; existing files are not overwritten"
    )
    args = parser.parse_args(argv)
    created_output = False
    complete_output = False
    try:
        # Reserve output before expensive work, without overwriting earlier evidence.
        with args.output.open("x", encoding="utf-8") as output:
            created_output = True
            with args.archive.open("rb") as f:
                raw = f.read(MAX_ARCHIVE_BYTES + 1)
            with args.evidence.open("rb") as f:
                payload = f.read(MAX_EVIDENCE_BYTES + 1)
            if len(payload) > MAX_EVIDENCE_BYTES:
                raise ValueError("evidence_too_large")
            evidence = json.loads(
                payload,
                object_pairs_hook=unique_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid_json_number")),
            )
            result = run_scan(
                raw,
                LLMClient(providers=[]),
                depth=BASIS_PREVIEW,
                client_runtime_evidence=evidence,
                client_runtime_run_id=args.run_id,
            )
            json.dump(result, output, ensure_ascii=False, indent=2, allow_nan=False)
            output.write("\n")
        complete_output = True
        agent = result["score"]["scan_manifest"]["security_agent"]
        accepted = agent.get("client_runtime_status") == "accepted"
        print(
            json.dumps(
                {
                    "status": "accepted" if accepted else "rejected",
                    "scope": "operator_evidence_consistency",
                    "model_calls": result["score"]["scan_manifest"]["model_calls"],
                    "customer_project_verified": False,
                    "automatic_patch": False,
                }
            )
        )
        return 0 if accepted else 1
    except (OSError, ValueError, ArchiveValidationError, RecursionError):
        if created_output and not complete_output:
            args.output.unlink(missing_ok=True)
        print(json.dumps({"status": "unavailable", "reason": "invalid_or_unavailable_input"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
