"""Public, bounded project-check evidence; never a finding or readiness score."""

from __future__ import annotations

import re

from app.report.threat_context import threat_context_record, threat_context_rows

SOURCE_REPOSITORIES = {
    "cvelist": "https://github.com/CVEProject/cvelistV5",
    "github-reviewed": "https://github.com/github/advisory-database",
}
STATUSES = {"completed", "partial", "unavailable", "not_run", "not_applicable"}
SCOPE = (
    "Missing or incomplete checks are not clean results. Ghidra evidence is operator-supplied; "
    "hash consistency does not authenticate tool execution. Symbols do not establish a CVE match. "
    "Runtime behaviour is not verified and binary evidence does not authorize automatic patches."
)


def _text(value: object, limit: int = 1024) -> str | None:
    return value if isinstance(value, str) and len(value) <= limit and not any(ord(c) < 32 for c in value) else None


def _hash(value: object, length: int = 64) -> bool:
    return isinstance(value, str) and re.fullmatch(f"[0-9a-f]{{{length}}}", value) is not None


def _count(value: object) -> bool:
    return type(value) is int and 0 <= value <= 9_007_199_254_740_991


def _stage(value: object) -> bool:
    return isinstance(value, dict) and isinstance(value.get("status"), str) and value["status"] in STATUSES


def project_checks_record(value: object) -> dict | None:
    """Drop unknown/raw facts and fail visibly for malformed saved evidence."""
    if value is None:
        return None
    invalid = {
        "schema": 1,
        "status": "unavailable",
        "reason": "invalid_project_check_record",
        "runtime_verified": False,
    }
    if (
        not isinstance(value, dict)
        or type(value.get("schema")) is not int
        or value["schema"] != 1
        or not _hash(value.get("archive_sha256"))
        or value.get("runtime_verified") is not False
    ):
        return invalid
    source, dependencies, binary = (value.get(key) for key in ("source", "dependencies", "binary_static"))
    if (
        not all(_stage(stage) for stage in (source, dependencies, binary))
        or not all(_count(source.get(key)) for key in ("checks_run", "checks_not_run", "findings"))
        or _text(source.get("agent_status"), 80) is None
        or not _count(dependencies.get("findings"))
        or dependencies.get("mode") not in ("offline_catalog", "live_osv", "not_run")
        or (dependencies.get("catalog_sha256") is not None and not _hash(dependencies["catalog_sha256"]))
        or type(binary.get("schema")) is not int
        or binary["schema"] != 1
        or binary.get("provenance") != "operator_supplied"
        or binary.get("runtime_verified") is not False
        or binary.get("automatic_patch") is not False
        or not _count(binary.get("artifacts_omitted"))
        or binary.get("archive_sha256") != value["archive_sha256"]
    ):
        return invalid
    if source["status"] == "completed" and (source["checks_not_run"] or not source["checks_run"]):
        return invalid
    sources = dependencies.get("sources")
    if not isinstance(sources, dict) or len(sources) > 8:
        return invalid
    clean_sources = {}
    for name, item in sources.items():
        if (
            name not in SOURCE_REPOSITORIES
            or not isinstance(item, dict)
            or item.get("repository") != SOURCE_REPOSITORIES[name]
            or not _hash(item.get("commit"), 40)
            or _text(item.get("generated_at"), 64) is None
        ):
            return invalid
        clean = {}
        for key in ("repository", "commit", "generated_at"):
            if key in item:
                if _text(item[key]) is None or (key == "commit" and not _hash(item[key], 40)):
                    return invalid
                clean[key] = item[key]
        clean_sources[name] = clean
    artifacts = binary.get("artifacts")
    limitations = binary.get("limitations")
    if (
        not isinstance(artifacts, list)
        or len(artifacts) > 32
        or not isinstance(limitations, list)
        or len(limitations) > 32
        or any(_text(item) is None for item in limitations)
    ):
        return invalid
    clean_artifacts = []
    for artifact in artifacts:
        if (
            not _stage(artifact)
            or not {"sha256", "bytes"} <= artifact.keys()
            or _text(artifact.get("path"), 4096) is None
            or (artifact.get("sha256") is not None and not _hash(artifact["sha256"]))
            or (artifact.get("bytes") is not None and not _count(artifact["bytes"]))
            or (
                artifact["status"] in {"completed", "partial"}
                and (artifact.get("sha256") is None or artifact.get("bytes") is None)
            )
        ):
            return invalid
        provider, facts = artifact.get("provider"), artifact.get("facts")
        if (
            artifact.get("runtime_verified") is True
            or artifact.get("automatic_patch") is True
            or (artifact.get("provenance") not in (None, "operator_supplied"))
            or (
                artifact["status"] in {"completed", "partial"}
                and (
                    not isinstance(provider, dict)
                    or provider.get("name") != "ghidra"
                    or _text(provider.get("version"), 160) is None
                    or not isinstance(facts, dict)
                    or any(
                        not isinstance(facts.get(key), list) or len(facts[key]) > 1000
                        for key in ("functions", "imports")
                    )
                )
            )
        ):
            return invalid
        clean = {key: artifact[key] for key in ("path", "sha256", "bytes", "status")}
        if artifact.get("reason") is not None:
            if _text(artifact["reason"]) is None:
                return invalid
            clean["reason"] = artifact["reason"]
        provider = artifact.get("provider")
        if isinstance(provider, dict):
            clean["provider"] = {
                key: provider[key] for key in ("name", "version") if _text(provider.get(key), 160) is not None
            }
            for key in ("distribution_sha256", "exporter_sha256"):
                if _hash(provider.get(key)):
                    clean["provider"][key] = provider[key]
        elif _text(provider, 160) is not None:
            clean["provider"] = provider
        facts = artifact.get("facts")
        if isinstance(facts, dict):
            clean["fact_counts"] = {
                key: len(facts[key])
                for key in ("functions", "imports")
                if isinstance(facts.get(key), list) and len(facts[key]) <= 1000
            }
        clean_artifacts.append(clean)
    if (
        (
            binary["status"] == "completed"
            and (
                not clean_artifacts
                or binary["artifacts_omitted"]
                or any(item["status"] != "completed" for item in clean_artifacts)
            )
        )
        or (binary["status"] == "not_applicable" and (clean_artifacts or binary["artifacts_omitted"]))
        or (binary["status"] == "not_run" and any(item["status"] != "not_run" for item in clean_artifacts))
    ):
        return invalid
    reason = dependencies.get("reason")
    if reason is not None and _text(reason) is None:
        return invalid
    return {
        "schema": 1,
        "archive_sha256": value["archive_sha256"],
        "runtime_verified": False,
        **({"threat_context": threat_context_record(value["threat_context"])} if "threat_context" in value else {}),
        "source": {key: source[key] for key in ("status", "checks_run", "checks_not_run", "findings", "agent_status")},
        "dependencies": {
            "status": dependencies["status"],
            "mode": dependencies["mode"],
            "findings": dependencies["findings"],
            "catalog_sha256": dependencies.get("catalog_sha256"),
            "sources": clean_sources,
            "reason": reason,
        },
        "binary_static": {
            "schema": 1,
            "provenance": "operator_supplied",
            "runtime_verified": False,
            "automatic_patch": False,
            "artifacts_omitted": binary["artifacts_omitted"],
            "status": binary["status"],
            "archive_sha256": binary["archive_sha256"],
            "artifacts": clean_artifacts,
            "limitations": limitations[:],
        },
    }


def project_checks_rows(value: object) -> list[tuple[str, str]]:
    record = project_checks_record(value)
    if record is None:
        return []
    if record.get("status") == "unavailable":
        return [
            (
                "Project checks",
                "Unavailable: invalid or incompatible recorded evidence; no complete result established.",
            )
        ]
    source, dependencies, binary = (record[key] for key in ("source", "dependencies", "binary_static"))

    def label(status):
        return status.replace("_", " ")

    rows = [
        (
            "Source",
            f"{label(source['status'])}; checks run: {source['checks_run']}; "
            f"not run: {source['checks_not_run']}; findings: {source['findings']}; "
            f"pattern review: {label(source['agent_status'])}.",
        ),
        (
            "Vulnerability databases",
            f"{label(dependencies['status'])}; mode: {label(dependencies['mode'])}; "
            f"findings: {dependencies['findings']}.",
        ),
        (
            "Ghidra / binary static",
            f"{label(binary['status'])}; artifacts: {len(binary['artifacts'])}; "
            f"omitted: {binary['artifacts_omitted']}. Operator-supplied evidence; execution not authenticated.",
        ),
        ("Project archive SHA-256", record["archive_sha256"]),
    ]
    if dependencies["reason"]:
        rows.append(("Dependency check scope", dependencies["reason"]))
    rows.append(("Catalog SHA-256", dependencies["catalog_sha256"] or "Not recorded"))
    for name, provenance in dependencies["sources"].items():
        rows.append(
            (
                f"Advisory source: {name}",
                "; ".join(f"{key}: {item}" for key, item in provenance.items()) or "Provenance not recorded",
            )
        )
    for index, artifact in enumerate(binary["artifacts"], 1):
        detail = (
            f"{artifact['path']}; {label(artifact['status'])}; "
            f"SHA-256: {artifact['sha256'] or 'Not recorded'}; "
            f"bytes: {artifact['bytes'] if artifact['bytes'] is not None else 'Not recorded'}."
        )
        if artifact.get("reason"):
            detail += " " + artifact["reason"]
        for key, count in artifact.get("fact_counts", {}).items():
            detail += f" {key}: {count}."
        provider = artifact.get("provider")
        if isinstance(provider, dict):
            detail += " Provider: " + "; ".join(f"{key}: {item}" for key, item in provider.items()) + "."
        elif provider:
            detail += " Provider: " + provider + "."
        rows.append((f"Binary artifact {index}", detail))
    rows.extend((f"Binary limitation {i}", item) for i, item in enumerate(binary["limitations"], 1))
    if "threat_context" in record:
        threat_rows = threat_context_rows(record["threat_context"])
        rows.insert(3, threat_rows[0])
        rows.extend(threat_rows[1:])
    return rows
