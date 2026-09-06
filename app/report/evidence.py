"""Presentation of evidence, including older audits without provenance.

Neither the current static scanners nor the model independently verifies a
finding's consequence. Keep that limit visible regardless of confidence,
severity, tier, or how many model passes repeated the same claim.
"""

from app.scan.secrets import NON_PRODUCTION_CONTEXTS, is_non_production_path
from app.scan.scoring import CATEGORIES, LLM_ONLY_CATEGORIES


def is_non_production(finding: dict) -> bool:
    context = finding.get("context")
    return (context in NON_PRODUCTION_CONTEXTS if context
            else is_non_production_path(str(finding.get("file", ""))))


def finding_counts(findings: list[dict]) -> tuple[int, int]:
    source = examples = 0
    for finding in findings:
        # Display-only RLS groups retain one title for each stored observation.
        count = len(finding.get("occurrence_titles") or []) or 1
        if is_non_production(finding):
            examples += count
        else:
            source += count
    return source, examples


def evidence_label(finding: dict) -> str:
    source = finding.get("source")
    if source == "llm" or str(finding.get("rule_id", "")).startswith("llm-"):
        return "Model hypothesis — unverified"
    if source == "static":
        return "Static signal — unverified"
    return "Legacy finding — verification not recorded"


def coverage_rows(score: dict, findings: list[dict]) -> list[tuple[str, str]]:
    basis = score.get("basis")
    recorded = "unexamined" in score or basis in ("static_only", "static+preview")
    skipped = set(score.get("unexamined", LLM_ONLY_CATEGORIES if recorded else ()))
    names = dict.fromkeys((*CATEGORIES, *score.get("categories", {})))
    rows = []
    for name in names:
        count, examples = finding_counts([f for f in findings if f.get("category") == name])
        if not recorded:
            label = "Coverage not recorded"
        elif name in skipped:
            label = "Not surveyed — see findings" if count else "Not checked"
        else:
            label = "Partly checked"
        if name == "Auth" and "auth_read_consistency" in (
                score.get("scan_manifest", {}).get("static_checks", [])):
            label = "Partly checked — local Python route comparison"
        elsewhere = (score.get("reported_elsewhere") or {}).get(name)
        if elsewhere:
            label += " — findings reported under " + ", ".join(elsewhere)
        if count:
            label += f" · {count} unverified finding{'s' if count != 1 else ''}"
        if examples:
            label += f" · {examples} test/example observations"
        rows.append((name, label))
    return rows


def manifest_rows(score: dict) -> list[tuple[str, str]]:
    manifest = score.get("scan_manifest")
    if not isinstance(manifest, dict):
        return [("Scan record", "Not recorded for this older audit")]
    rows = [
        ("Archive SHA-256", manifest.get("archive_sha256") or "Not recorded"),
        ("Git commit", manifest.get("commit_sha") or "Not recorded for this archive"),
        ("Scan engine", manifest.get("engine_version") or "Not recorded"),
        ("Files in archive", str(manifest.get("archive_files", "Not recorded"))),
        ("Static checks run", ", ".join(manifest.get("static_checks", [])) or "Not recorded"),
        ("Last responding model", manifest.get("model") or "No model response recorded"),
        ("Model responses", str(manifest.get("model_calls", 0))),
        ("Review areas applied", ", ".join(manifest.get("rubrics_completed", [])) or "None"),
    ]
    for key, label in (("llm_candidate_files", "Files eligible for model review"),
                       ("llm_submitted_files", "Unique files submitted to model"),
                       ("llm_files_not_submitted", "Eligible files not submitted")):
        value = manifest.get(key)
        rows.append((label, str(value) if value is not None else "Not recorded"))
    limitations = manifest.get("limitations", [])
    rows.append(("Model limits / skip reasons", ", ".join(limitations) or "None recorded"))
    for check, status in manifest.get("static_limits", {}).items():
        rows.append((f"Static scope: {check}", str(status)))
    for kind, paths in manifest.get("inventory", {}).items():
        shown = ", ".join(paths[:5])
        if len(paths) > 5:
            shown += f" (+{len(paths) - 5} more)"
        rows.append((kind, f"{len(paths)} found" + (f": {shown}" if shown else "")))
    return rows
