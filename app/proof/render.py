"""PR-body markdown for Proof-of-Exploit reports.

The section always documents what was tried. When the report is not
informational (gate mode soft/hard) the footer note is omitted so we do
not contradict a soft warning or a hard block that the processor applied.
"""

from __future__ import annotations

from app.proof.artifacts import ProofArtifact, render_artifacts_markdown
from app.proof.types import ProofReport

# Printed under a STATIC proof section, and load-bearing rather than
# decorative.
#
# The three routed templates are static scanners: secrets_leak re-runs
# app.scan.secrets, sqli and cors_open match regexes over the workspace zip.
# None of them opens a socket, starts a container, or executes the target —
# `success` means "the pattern is present", not "the attack ran". (Since P1
# there is also cors_open_runtime, which does boot the app; it carries
# _RUNTIME_METHOD_NOTE below instead, and nothing routes to it yet.)
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

# The runtime counterpart. A report from app/proof/cors_probe.py earned a
# stronger sentence than the static note above: the application was actually
# built, started and asked. Printing the static disclaimer over it would
# understate the evidence just as badly as the old wording overstated it —
# the note has to describe the method that ran, not the method most templates
# use.
_RUNTIME_METHOD_NOTE = (
    "_Проверка динамическая: приложение собрано и запущено в изолированной "
    "песочнице, запрос с постороннего Origin выполнен реально, вердикт "
    "вынесен по ответным заголовкам._"
)

# Which note belongs to which template. A template absent from this map falls
# back to the static note, which is the safe direction: understating a static
# check costs nothing, overstating one is the defect this map exists to avoid.
_METHOD_NOTES: dict[str, str] = {
    "cors_open_runtime": _RUNTIME_METHOD_NOTE,
}

# Templates whose report describes a booted application rather than a scan.
# Kept beside the notes so a future runtime template cannot pick up the
# stronger verdict wording while still printing the static disclaimer.
_RUNTIME_TEMPLATES = frozenset({"cors_open_runtime"})


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

    runtime = str(report.template_id) in _RUNTIME_TEMPLATES
    before_cell = _cell(report.before.success, report.before.status, runtime)
    after_cell = _cell(report.after.success, report.after.status, runtime)
    row_label = "Кросс-доменный запрос" if runtime else "Уязвимая конструкция"

    if report.verified:
        # The runtime wording is stronger BECAUSE the evidence is: the app was
        # built, started, and answered. Saying "конструкция найдена" over a
        # real request would undersell it exactly as badly as the old static
        # wording oversold a regex.
        verdict = (
            "**подтверждён** — запрос с постороннего origin получил доступ "
            "до патча и не получает после"
            if runtime else
            "**подтверждён** — уязвимая конструкция найдена до патча "
            "и отсутствует после"
        )
    elif report.before.status in ("error",) or report.after.status in ("error",):
        verdict = (
            "не завершён — приложение не удалось собрать или запросить"
            if runtime else
            "не завершён (ошибка инфраструктуры)"
        )
    elif not report.before.success:
        verdict = (
            "запущенное приложение не подтвердило доступ — сравнивать нечего"
            if runtime else
            "не найден на исходном коде — сравнивать нечего"
        )
    else:
        verdict = (
            "не подтверждён — доступ выдаётся и после патча"
            if runtime else
            "не подтверждён — конструкция на месте и после патча"
        )

    lines = [
        "## Проверка «до / после»",
        "",
        f"**Шаблон:** `{report.template_id}`",
        f"**Вердикт:** {verdict}",
        "",
        "| | До патча | После патча |",
        "|---|---|---|",
        f"| {row_label} | {before_cell} | {after_cell} |",
        "",
        f"_{report.detail}_",
        "",
        _METHOD_NOTES.get(str(report.template_id), _METHOD_NOTE),
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


def _cell(success: bool, status: str, runtime: bool = False) -> str:
    if status == "skipped":
        return "пропущено"
    if status == "error":
        return "не проверено"
    # The static column reports what the scanner saw in the code; the runtime
    # column reports what the running application did. Neither says "успех",
    # which read as a successful attack whichever half produced it.
    if runtime:
        return "⚠️ доступ разрешён" if success else "✅ отклонён"
    return "⚠️ найдена" if success else "✅ не найдена"


def _evidence_lines(report: ProofReport) -> list[str]:
    bits: list[str] = []
    for label, attempt in (("до", report.before), ("после", report.after)):
        evidence = attempt.evidence or {}

        # Runtime evidence is the transcript, and it is the whole point of
        # having booted the app: the reader sees the headers the server
        # actually sent, not our summary of them.
        if "allow_origin" in evidence or "allow_credentials" in evidence:
            origin = evidence.get("allow_origin")
            creds = evidence.get("allow_credentials")
            bits.append(
                f"{label}: `Access-Control-Allow-Origin: "
                f"{origin if origin else '(отсутствует)'}`"
            )
            bits.append(
                f"{label}: `Access-Control-Allow-Credentials: "
                f"{creds if creds else '(отсутствует)'}`"
            )
            continue

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
