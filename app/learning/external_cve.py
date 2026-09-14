"""Report a compiled CVE knowledge snapshot without claiming model training."""

from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

DATA_DIRECTORY = Path(__file__).resolve().parents[1] / "data"


@lru_cache(maxsize=4)
def external_cve_status(data_directory: Path = DATA_DIRECTORY) -> dict:
    """Validate the deployed snapshot once per process; never contact a source.

    A release replaces these files together. Missing or corrupt evidence must
    not appear as a successful training run or a healthy empty knowledge base.
    """
    base = {"kind": "knowledge_compilation", "classifier_trained": False,
            "customer_outcomes_added": 0}
    try:
        summary = json.loads((data_directory / "cve-learning.json").read_text())
        digest = hashlib.sha256((data_directory / "cve-catalog.json").read_bytes()).hexdigest()
        if (summary.get("schema") != 1 or summary.get("catalog_sha256") != digest
                or not isinstance(summary.get("source"), dict)
                or not isinstance(summary.get("stats"), dict)):
            return {**base, "status": "invalid"}
        sources = summary.get("sources", {"cvelist": summary["source"]})
        if not isinstance(sources, dict):
            return {**base, "status": "invalid"}
        return {**base, "status": "compiled", "source": summary["source"],
                "sources": sources, "stats": summary["stats"],
                "catalog_sha256": digest, "coverage": summary.get("coverage", {})}
    except FileNotFoundError:
        return {**base, "status": "unavailable"}
    except (OSError, ValueError, TypeError, AttributeError):
        return {**base, "status": "invalid"}
