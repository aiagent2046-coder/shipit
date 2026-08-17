"""Proof artifacts: log + ASCII storyboard for PR body and proof_json.

MVP is dependency-free. Real GIF / object-storage upload is gated on
``PROOF_ARTIFACT_STORE`` (off by default) and left as a follow-up that
reuses the same ``ProofArtifact`` shape.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any, Literal

from app.proof.types import ProofReport

ArtifactKind = Literal["log", "storyboard"]


@dataclass(frozen=True)
class ProofArtifact:
    kind: ArtifactKind
    template_id: str
    content: str
    content_sha256: str
    bytes_len: int

    def to_json(self, *, include_content: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "template_id": self.template_id,
            "content_sha256": self.content_sha256,
            "bytes_len": self.bytes_len,
        }
        if include_content:
            payload["content"] = self.content
        return payload


def build_artifacts(report: ProofReport) -> list[ProofArtifact]:
    """Build log + storyboard for one proof report. Never raises."""
    try:
        log = _build_log(report)
        board = _build_storyboard(report)
        return [
            _artifact("log", report.template_id, log),
            _artifact("storyboard", report.template_id, board),
        ]
    except Exception:  # noqa: BLE001 — artifacts must never break delivery
        return []


def render_artifacts_markdown(artifacts: list[ProofArtifact]) -> str:
    """Collapsible PR blocks. Empty string when nothing to show."""
    if not artifacts:
        return ""
    parts: list[str] = []
    for art in artifacts:
        if art.kind == "storyboard":
            parts.append("**Storyboard**")
            parts.append("")
            parts.append("```")
            parts.append(art.content.rstrip())
            parts.append("```")
        elif art.kind == "log":
            parts.append("<details>")
            parts.append(
                f"<summary>Proof log — <code>{art.template_id}</code></summary>"
            )
            parts.append("")
            parts.append("```")
            parts.append(art.content.rstrip())
            parts.append("```")
            parts.append("")
            parts.append("</details>")
    return "\n".join(parts)


def artifacts_to_json(
    artifacts: list[ProofArtifact],
    *,
    max_content_chars: int = 8_000,
) -> list[dict[str, Any]]:
    """Serialize for jsonb. Truncate oversized content; hash stays full."""
    out: list[dict[str, Any]] = []
    for art in artifacts:
        content = art.content
        truncated = False
        if len(content) > max_content_chars:
            content = content[:max_content_chars] + "\n… [truncated]"
            truncated = True
        row = art.to_json(include_content=True)
        row["content"] = content
        row["truncated"] = truncated
        out.append(row)
    return out


def _artifact(kind: ArtifactKind, template_id: str, content: str) -> ProofArtifact:
    raw = content.encode("utf-8")
    return ProofArtifact(
        kind=kind,
        template_id=template_id,
        content=content,
        content_sha256=hashlib.sha256(raw).hexdigest(),
        bytes_len=len(raw),
    )


def _build_log(report: ProofReport) -> str:
    lines = [
        "Drydock before/after check log",
        f"template: {report.template_id}",
        f"verified: {report.verified}",
        f"detail:   {report.detail}",
        "",
        "=== BEFORE (original workspace) ===",
        f"status:  {report.before.status}",
        f"success: {report.before.success}",
        f"detail:  {report.before.detail}",
        f"duration_ms: {report.before.duration_ms}",
    ]
    lines.extend(_evidence_log_lines(report.before.evidence))
    lines += [
        "",
        "=== AFTER (patched workspace) ===",
        f"status:  {report.after.status}",
        f"success: {report.after.success}",
        f"detail:  {report.after.detail}",
        f"duration_ms: {report.after.duration_ms}",
    ]
    lines.extend(_evidence_log_lines(report.after.evidence))
    lines += [
        "",
        "=== VERDICT ===",
        (
            "PASS — vulnerable pattern present before, absent after"
            if report.verified
            else "FAIL — pattern still present after the patch (see detail)"
        ),
        "method: static scan of the workspace before and after the patch;"
        " no attack is executed",
    ]
    return "\n".join(lines) + "\n"


def _evidence_log_lines(evidence: dict[str, Any] | None) -> list[str]:
    if not evidence:
        return ["evidence: (none)"]
    lines = [f"finding_count: {evidence.get('finding_count', 0)}"]
    samples = evidence.get("samples") or []
    if not isinstance(samples, list):
        return lines
    for i, sample in enumerate(samples[:8], start=1):
        if not isinstance(sample, dict):
            continue
        path = sample.get("file", "?")
        line = sample.get("line", "?")
        rule = sample.get("rule_id", "?")
        extra = sample.get("masked") or sample.get("snippet") or ""
        extra = _one_line(str(extra), 80)
        if extra:
            lines.append(f"  [{i}] {path}:{line}  {rule}  {extra}")
        else:
            lines.append(f"  [{i}] {path}:{line}  {rule}")
    return lines


def _build_storyboard(report: ProofReport) -> str:
    """Two-panel ASCII film strip — works in any monospace PR view.

    Panels say what the scanner saw, not what an attacker achieved: these
    templates are static (see app/proof/render.py's _METHOD_NOTE). "EXPLOIT
    OK" over a regex hit was a claim the code cannot support.
    """
    before = "VULN FOUND" if report.before.success else "NOT FOUND"
    after = "VULN FOUND" if report.after.success else "CLEARED"
    verdict = "VERIFIED" if report.verified else "NOT VERIFIED"
    tid = report.template_id[:18]
    return "\n".join([
        "+----------------------+----------------------+",
        "| BEFORE               | AFTER                |",
        f"| template: {tid:<12} | template: {tid:<12} |",
        f"| {before:^20} | {after:^20} |",
        "+----------------------+----------------------+",
        f"| verdict: {verdict:<35} |",
        "+---------------------------------------------+",
    ])


def _one_line(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[: limit - 1] + "…"
