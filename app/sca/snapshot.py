"""Server-side use of the bundled offline catalog; never contacts a service."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
from pathlib import Path

from app.local_store import MAX_CATALOG_BYTES, decode_catalog
from app.scan.cve_evidence import empty_cve_summary
from app.scan.cve_match import RULE_ID, match_archive
from app.sca.lockfiles import normalize_pypi
from app.scan.remediation_catalog import CATALOG_VERSION as REMEDIATION_CATALOG_VERSION

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
    digest.update(REMEDIATION_CATALOG_VERSION.encode("ascii") + b"\0")
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


def run_snapshot_stage(data: bytes, *, assessment_observer=None) -> tuple[list[dict], dict]:
    raw, receipt, failure, fingerprint = _inputs()
    metadata = {"version": 1, "mode": "bundled", "fingerprint": fingerprint,
                "catalog_sha256": None, "checked_at": None}
    findings = []
    if failure is None:
        try:
            tokens = receipt.decode("ascii").split()
            catalog, digest = decode_catalog(raw, tokens[0] if tokens else "")
            result = match_archive(data, catalog, assessment_observer=assessment_observer)
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

    kept = [f for f in findings if f.get("rule_id") != RULE_ID]
    previous = [f for f in findings if f.get("rule_id") == RULE_ID]

    def identity(finding):
        evidence = finding.get("claim_evidence") or {}
        return tuple(evidence.get(key) for key in
                     ("ecosystem", "package", "installed_version"))

    def advisory_ids(finding):
        evidence = finding.get("claim_evidence") or {}
        return {value for value in (evidence.get("advisory_id"),
                                   *(evidence.get("advisory_ids") or []))
                if isinstance(value, str) and value}

    previous_by_dependency = {}
    for index, finding in enumerate(previous):
        previous_by_dependency.setdefault(identity(finding), []).append((index, advisory_ids(finding)))
    # An omitted inventory entry or an interrupted check cannot retire evidence.
    # Only this exact dependency/advisory's completed assessment can do so.
    pending = set(range(len(previous)))

    def observe(dep, assessments, identities_complete):
        name = normalize_pypi(dep.name) if dep.ecosystem == "PyPI" else dep.name
        for index, ids in previous_by_dependency.get((dep.ecosystem, name, dep.version), ()):
            if not ids:
                continue
            matched = [assessment for assessment in assessments
                       if ids & assessment["advisory_ids"]]
            if ((matched and all(assessment["status"] == "unaffected" or assessment["reported"]
                                 for assessment in matched))
                    or (not matched and identities_complete)):
                pending.discard(index)

    current, stats = run_snapshot_stage(raw, assessment_observer=observe)
    if stats["dependency_cve"]["status"] == "unavailable":
        pending = set(range(len(previous)))
    current_ids = {}
    for finding in current:
        current_ids.setdefault(identity(finding), set()).update(advisory_ids(finding))
    retained = [
        {**finding,
         **({"fix_hint": "The current check could not reconfirm this dependency match. "
                         "Repeat the advisory check before choosing an upgrade; previously recorded "
                         "upgrade candidates have not been reconfirmed."}
            if (finding.get("claim_evidence") or {}).get("remediation") is not None else {}),
         "claim_evidence": {
            **(finding.get("claim_evidence") or {}),
            "snapshot_check_status": "retained_not_reconfirmed",
        }}
        for index, finding in enumerate(previous)
        if index in pending and not advisory_ids(finding) & current_ids.get(identity(finding), set())
    ]
    current += retained
    if retained:
        stats["dependency_snapshot"]["retained_findings"] = len(retained)
    findings = kept + current
    return {"score": refreshed_score(score, findings, stats), "findings": findings,
            "llm": {}, "llm_usage": {"calls": 0}, "sca": stats}
