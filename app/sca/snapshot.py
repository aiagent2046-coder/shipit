"""Server-side use of the bundled offline catalog; never contacts a service."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from app.local_store import MAX_CATALOG_BYTES, decode_catalog
from app.scan.cve_evidence import empty_cve_summary
from app.scan.cve_match import RULE_ID, match_archive

CATALOG_PATH = Path(__file__).resolve().parents[1] / "data/cve-catalog.json"
CHECKSUM_PATH = CATALOG_PATH.with_suffix(".json.sha256")


def _inputs() -> tuple[bytes, bytes, str | None, str]:
    """Bound both reads; fingerprint failed attempts as well as valid catalogs.

    Hashing the receipt alone would cache corrupted data after its repair.
    Paths and exception messages never become public scan metadata.
    """
    parts = []
    failure = None
    digest = hashlib.sha256(b"drydock-bundled-catalog-v1\0")
    for path, limit in ((CATALOG_PATH, MAX_CATALOG_BYTES), (CHECKSUM_PATH, 1024)):
        try:
            with path.open("rb") as handle:
                raw = handle.read(limit + 1)
            state = b"oversized" if len(raw) > limit else b"read"
            if len(raw) > limit:
                failure = "cve_catalog_invalid"
        except OSError:
            raw, state = b"", b"unavailable"
            failure = "cve_catalog_unavailable"
        digest.update(state + b"\0" + len(raw).to_bytes(8, "big") + raw)
        parts.append(raw)
    return parts[0], parts[1], failure, digest.hexdigest()


def snapshot_is_current(score: dict) -> bool:
    metadata = (score.get("scan_manifest") or {}).get("dependency_snapshot")
    return (isinstance(metadata, dict) and metadata.get("version") == 1
            and metadata.get("mode") == "bundled"
            and metadata.get("fingerprint") == _inputs()[3])


def baseline_is_current(score: dict) -> bool:
    baseline = score.get("free_baseline")
    return (isinstance(baseline, dict) and isinstance(baseline.get("score"), dict)
            and snapshot_is_current(baseline["score"]))


def run_snapshot_stage(data: bytes) -> tuple[list[dict], dict]:
    raw, receipt, failure, fingerprint = _inputs()
    metadata = {"version": 1, "mode": "bundled", "fingerprint": fingerprint,
                "catalog_sha256": None, "checked_at": None}
    findings = []
    if failure is None:
        try:
            tokens = receipt.decode("ascii").split()
            catalog, digest = decode_catalog(raw, tokens[0] if tokens else "")
            result = match_archive(data, catalog)
            findings, coverage = result["findings"], result["coverage"]
            metadata.update(catalog_sha256=digest, checked_at=datetime.now(timezone.utc).isoformat())
        except Exception:  # noqa: BLE001 -- isolate catalog failure from static/model work
            failure = "cve_catalog_invalid"
    if failure:
        coverage = {"status": "unavailable", "limitations": [failure]}
    # These fields describe the REMOTE stage only. Matching a bundled file is
    # not an OSV query, even when its source advisories use the OSV format.
    stats = {"checks_run": [], "asked_at": None, "skipped_reason": "no_client",
             "dependencies": 0, "dependencies_found": 0, "findings": 0,
             "advisories": 0, "unreadable_advisories": 0, "truncated": 0,
             "coverage_incomplete": False, "incomplete_lockfiles": {},
             "below_severity_floor": 0, "cve": empty_cve_summary("not_run"),
             "dependency_cve": coverage, "dependency_snapshot": metadata}
    return findings, stats


def refresh_snapshot(score: dict, findings: list[dict], raw: bytes) -> dict:
    """Replace only snapshot evidence, preserving already purchased analysis."""
    # Delayed import: refresh uses pipeline scoring, which imports this stage.
    from app.sca.refresh import refreshed_score

    current, stats = run_snapshot_stage(raw)
    kept = [f for f in findings if f.get("rule_id") != RULE_ID]
    coverage = stats["dependency_cve"]
    incomplete = (coverage["status"] == "unavailable"
                  or any(coverage.get(key) for key in
                         ("inventory_truncated", "evaluations_truncated", "findings_truncated"))
                  or bool((coverage.get("status_counts") or {}).get("unknown")))

    def identity(finding):
        evidence = finding.get("claim_evidence") or {}
        return tuple(evidence.get(key) for key in
                     ("ecosystem", "package", "installed_version", "advisory_id"))

    identities = {identity(f) for f in current}
    retained = [f for f in findings if f.get("rule_id") == RULE_ID
                and identity(f) not in identities
                and (incomplete or f.get("file") in (coverage.get("incomplete_manifests") or {}))]
    current += retained
    if retained:
        stats["dependency_snapshot"]["retained_findings"] = len(retained)
    findings = kept + current
    return {"score": refreshed_score(score, findings, stats), "findings": findings,
            "llm": {}, "llm_usage": {"calls": 0}, "sca": stats}
