"""PR-body markdown for Proof-of-Exploit reports.

The section always documents what was tried. When the report is not
informational (gate mode soft/hard) the footer note is omitted so we do
not contradict a soft warning or a hard block that the processor applied.
"""

from __future__ import annotations

from app.proof.artifacts import ProofArtifact, render_artifacts_markdown
from app.proof.types import ProofReport

# Printed under every proof section, and load-bearing rather than decorative.
#
# All three templates are static scanners: secrets_leak re-runs
# app.scan.secrets, sqli and cors_open match regexes over the workspace zip.
# Nothing in app/proof/ opens a socket, starts a container, or executes the
# target — `success` means "the pattern is present", not "the attack ran".
#
# The wording here used to say "атака сработала до патча и не сработала
# после". On a leaked key that is nearly true; on a regex hit for sqli or
# cors_open it is a claim the code cannot support, and a false positive would
# have told a customer their app was exploited. This project has removed the
# same overstatement three times (#22, #27, #35) — a report about proof is the
# last place to reintroduce it. What survives the correction is still the
# thing competitors do not do: a checkable before/after inside the PR.
_METHOD_NOTE = (
    "_Проверка статическая: сканер ищет уязвимую конструкцию в коде до и "
    "после патча. Атака не выполняется — «найдено» означает наличие "
    "конструкции, а не подтверждённую эксплуатацию._"
)


def render_proof_markdown(report: ProofReport | object) -> str:
    """Render one ProofReport as a PR section. Empty string if skipped.

    Also accepts a ``ProofStageResult`` and renders all of its reports
    plus artifacts.
    """
    if hasattr(report, "reports") and hasattr(report, "primary"):
        arts = list(getattr(report, "artifacts", None) or [])
        return render_proof_with_artifacts(
            list(getattr(report, "reports") or []),
            arts,
        )

    if not isinstance(report, ProofReport):
        return ""

    if report.before.status == "skipped" and report.after.status == "skipped":
        return ""

    before_cell = _cell(report.before.success, report.before.status)
    after_cell = _cell(report.after.success, report.after.status)

    if report.verified:
        verdict = (
            "**подтверждён** — уязвимая конструкция найдена до патча "
            "и отсутствует после"
        )
    elif report.before.status in ("error",) or report.after.status in ("error",):
        verdict = "не завершён (ошибка инфраструктуры)"
    elif not report.before.success:
        verdict = "не найден на исходном коде — сравнивать нечего"
    else:
        verdict = "не подтверждён — конструкция на месте и после патча"

    lines = [
        "## Проверка «до / после»",
        "",
        f"**Шаблон:** `{report.template_id}`",
        f"**Вердикт:** {verdict}",
        "",
        "| | До патча | После патча |",
        "|---|---|---|",
        f"| Уязвимая конструкция | {before_cell} | {after_cell} |",
        "",
        f"_{report.detail}_",
        "",
        _METHOD_NOTE,
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
        lines.append("")
        lines.append(
            "> ⚠️ Soft gate: уязвимая конструкция осталась на месте и после "
            "предложенного патча. PR доставлен для ручного разбора — не "
            "мержите, пока причина не устранена."
        )

    return "\n".join(lines)


def _cell(success: bool, status: str) -> str:
    if status == "skipped":
        return "пропущено"
    if status == "error":
        return "ошибка"
    # "найдена"/"не найдена", not "успех"/"нет": the column reports what the
    # scanner saw in the code, and a ✅ next to "успех" read as a successful
    # attack.
    return "⚠️ найдена" if success else "✅ не найдена"


def _evidence_lines(report: ProofReport) -> list[str]:
    bits: list[str] = []
    for label, attempt in (("до", report.before), ("после", report.after)):
        evidence = attempt.evidence or {}
        count = evidence.get("finding_count")
        if isinstance(count, int):
            bits.append(f"{label}: найдено (high+): {count}")
        samples = evidence.get("samples")
        if isinstance(samples, list) and samples:
            for sample in samples[:3]:
                if not isinstance(sample, dict):
                    continue
                path = sample.get("file", "?")
                line = sample.get("line", "?")
                rule = sample.get("rule_id", "?")
                masked = sample.get("masked")
                snippet = sample.get("snippet")
                extra = masked or snippet or ""
                if extra:
                    bits.append(
                        f"{label}: `{path}:{line}` — {rule} (`{extra}`)"
                    )
                else:
                    bits.append(f"{label}: `{path}:{line}` — {rule}")
    return bits


def render_proof_sections(reports: list[ProofReport]) -> str:
    """Join multiple proof sections with horizontal rules. Empty if none."""
    parts = [render_proof_markdown(r) for r in reports]
    parts = [p for p in parts if p]
    return "\n\n---\n\n".join(parts)


def render_proof_with_artifacts(
    reports: list[ProofReport],
    artifacts: list[ProofArtifact] | None = None,
) -> str:
    """Reports sections plus optional artifact blocks."""
    body = render_proof_sections(reports)
    art = render_artifacts_markdown(list(artifacts or []))
    if body and art:
        return body + "\n\n" + art
    return body or art
