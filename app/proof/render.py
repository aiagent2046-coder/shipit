"""PR-body markdown for Proof-of-Exploit reports.

The section always documents what was tried. When the report is not
informational (gate mode soft/hard) the footer note is omitted so we do
not contradict a soft warning or a hard block that the processor applied.
"""

from __future__ import annotations

from app.proof.types import ProofReport


def render_proof_markdown(report: ProofReport) -> str:
    """Render one ProofReport as a PR section. Empty string if skipped."""
    if report.before.status == "skipped" and report.after.status == "skipped":
        return ""

    before_cell = _cell(report.before.success, report.before.status)
    after_cell = _cell(report.after.success, report.after.status)

    if report.verified:
        verdict = (
            "**верифицирован** — атака сработала до патча и не сработала после"
        )
    elif report.before.status in ("error",) or report.after.status in ("error",):
        verdict = "не завершён (ошибка инфраструктуры)"
    elif not report.before.success:
        verdict = (
            "не воспроизведён на исходном коде "
            "(статический finding без runtime-доказательства)"
        )
    else:
        verdict = "не подтверждён — атака всё ещё срабатывает после патча"

    lines = [
        "## Proof-of-Exploit → Proof-of-Fix",
        "",
        f"**Шаблон:** `{report.template_id}`",
        f"**Вердикт:** {verdict}",
        "",
        "| | До патча | После патча |",
        "|---|---|---|",
        f"| Эксплуатация | {before_cell} | {after_cell} |",
        "",
        f"_{report.detail}_",
    ]

    evidence_bits = _evidence_lines(report)
    if evidence_bits:
        lines.append("")
        lines.append("**Детали:**")
        lines.extend(f"- {bit}" for bit in evidence_bits)

    if report.informational:
        lines.append("")
        lines.append(
            "> Informational only: этот отчёт не блокирует доставку PR."
        )
    elif (
        not report.verified
        and report.before.success
        and report.before.status == "success"
        and report.after.status not in ("error", "skipped")
    ):
        # Soft-gate case: still delivered, but the report must not look
        # like a clean pass. Hard-gate jobs never reach PR rendering.
        lines.append("")
        lines.append(
            "> ⚠️ Soft gate: эксплойт всё ещё срабатывает после предложенного "
            "патча. PR доставлен для ручного разбора — не мержите, пока "
            "причина не устранена."
        )

    return "\n".join(lines)


def _cell(success: bool, status: str) -> str:
    if status == "skipped":
        return "пропущено"
    if status == "error":
        return "ошибка"
    return "✅ успех" if success else "❌ нет"


def _evidence_lines(report: ProofReport) -> list[str]:
    bits: list[str] = []
    for label, attempt in (("до", report.before), ("после", report.after)):
        evidence = attempt.evidence or {}
        count = evidence.get("finding_count")
        if isinstance(count, int):
            bits.append(f"{label}: найдено секретов (high+): {count}")
        samples = evidence.get("samples")
        if isinstance(samples, list) and samples:
            for sample in samples[:3]:
                if not isinstance(sample, dict):
                    continue
                path = sample.get("file", "?")
                line = sample.get("line", "?")
                masked = sample.get("masked", "?")
                rule = sample.get("rule_id", "?")
                bits.append(
                    f"{label}: `{path}:{line}` — {rule} (`{masked}`)"
                )
    return bits
