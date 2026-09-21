"""Reuse the released bounded validator for successful experiment variants."""

import json
from pathlib import Path

from app.scan.client_runtime_record import (
    ARCHIVE_SHA256 as ARCHIVE,
    SCENARIO_ID,
    validate_client_runtime_evidence,
)


SCENARIO = SCENARIO_ID


def verify(directory):
    directory = Path(directory)
    path = directory / "scenario.json"
    if path.stat().st_size > 64 * 1024:
        raise ValueError("Evidence too large")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result

    report = json.loads(path.read_text(), object_pairs_hook=unique)
    record = validate_client_runtime_evidence(
        report,
        archive_sha256=ARCHIVE,
        run_id=(directory / "run-id.txt").read_text().strip(),
    )
    if record is None:
        raise ValueError("Successful variant observations failed the runtime contract")
    return record
