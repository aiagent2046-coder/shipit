"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape

from app.report.evidence import coverage_rows, evidence_label, finding_counts, is_non_production, manifest_rows
from app.report.grouping import group_for_display
from app.report.plain_language import plain_fields, tier

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_COLOR = {
    "critical": "#e5484d", "high": "#f76b15",
    "medium": "#f5d90a", "low": "#8b8d98",
}


def _category_label(f: dict) -> str:
    """Name the finding's category and its producer's original category."""
    cat = escape(str(f.get("category") or ""))
    if not cat:
        return ""
    origin = escape(str(f.get("origin_category") or ""))
    return f"{cat} (moved from {origin})" if origin and origin != cat else cat


def _finding_row(f: dict) -> str:
    sev = str(f.get("severity", "low"))
    color = _SEVERITY_COLOR.get(sev, "#8b8d98")
    loc = escape(str(f.get("file", "")))
    if f.get("line"):
        loc += f":{int(f['line'])}"
    what, risk, fix = plain_fields(f)
    emoji, _ = tier(sev)
    tier_label = f"Potential {sev} impact"
    risk_html = f'<div class="risk">{escape(risk)}</div>' if risk else ""
    fix_html = f'<div class="fix">→ {escape(fix)}</div>' if fix else ""
    tech_bits = " · ".join(x for x in (
        _category_label(f),
        escape(str(f.get("title", ""))), loc,
        escape(str(f.get("masked", "")))) if x)
    return (
        '<tr>'
        f'<td class="tiercell"><span class="sev" style="background:{color}">'
        f'{emoji} {escape(tier_label)}</span></td>'
        f'<td class="title"><div class="what">{escape(what)}</div>'
        f'<div class="tech">{escape(evidence_label(f))}</div>'
        f'{risk_html}{fix_html}'
        f'<div class="tech">{tech_bits}</div></td>'
        '</tr>'
    )


# Path classification is a heuristic; it does not establish deployment scope.
NON_PRODUCTION_HEADING = "In tests, examples and scaffolding"
NON_PRODUCTION_NOTE = (
    "These paths or contexts suggest tests, examples or scaffolding; deployment "
    "has not been checked. Confirm whether a credential is synthetic. A real "
    "secret still requires action even when it is committed in a test."
)


_is_non_production = is_non_production

def _findings_table(findings: list[dict]) -> str:
    rows = "".join(_finding_row(f) for f in findings)
    return (
        '<table><thead><tr><th></th><th>Finding</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )


def render_report(result: dict, project_name: str = "your app") -> str:
    score = result["score"]
    raw_findings = result.get("findings", [])
    findings = sorted(
        group_for_display(raw_findings),
        key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity")), 9),
                       -float(f.get("confidence", 0))),
    )
    # The legacy numeric fields remain in storage for API compatibility.
    # No tier currently has a validated measure of production readiness.
    heading = f"Project audit — {escape(project_name)}"
    og_title = f"Project audit — {project_name}"
    source_count, example_count = finding_counts(raw_findings)
    header_left = (
        f'<div class="noring">{source_count}'
        f'<small>source observations'
        '</small></div>'
    )
    header_left += f'<p>{example_count} test/example observations, listed separately.</p>'
    cats = "".join(
        f'<div class="cat"><span class="cat-name">{escape(name)}</span>'
        f'<span class="cat-skip">{escape(label)}</span></div>'
        for name, label in coverage_rows(score, raw_findings)
    )
    basis = str(score.get("basis") or "unknown")
    tier_note = (
        '<section><p class="secnote">No readiness score out of 10. '
        'Severity describes the claimed consequence, not how well it is '
        'proven. Static signals and model hypotheses need verification. '
        'A repeated model claim is not independent evidence.</p>'
        f'<p class="secnote">Scan basis: {escape(basis)}. '
        'The scope below describes source review, not runtime verification '
        'or a check of your live deployment.</p></section>'
    )
    # Split, don't hide. A secret in a test fixture and a secret in a running
    # handler need different reactions -- one is "check the fixture is fake",
    # the other is "revoke the key now" -- and one undifferentiated table asks
    # the reader to tell them apart from the file path. Readers don't; they
    # either treat every row as urgent or, after the first false alarm, none
    # of them.
    production = [f for f in findings if not _is_non_production(f)]
    non_production = [f for f in findings if _is_non_production(f)]

    if production:
        body = _findings_table(production)
    elif non_production:
        body = ('<p class="clean">No findings outside the test and example '
                'section. This does not establish safety.</p>')
    else:
        body = '<p class="clean">No issues found by the current checks.</p>'

    if non_production:
        body += (
            f'<h2 class="sechead">{NON_PRODUCTION_HEADING}</h2>'
            f'<p class="secnote">{NON_PRODUCTION_NOTE}</p>'
            + _findings_table(non_production)
        )

    record = "".join(
        f"<dt>{escape(label)}</dt><dd>{escape(value)}</dd>"
        for label, value in manifest_rows(score)
    )
    body += (
        '<section><h2 class="sechead">Scan record</h2><dl style="overflow-wrap:anywhere">'
        + record + '</dl><p class="secnote">File presence is not a deployment check. '
        'Submitted files may be excerpted; submission does not prove full review. '
        'Model cost is not recorded in this report.</p></section>'
    )
    coverage_note = (
        '<section><h2 class="sechead">Limits of this audit</h2>'
        '<p class="secnote">No finding is independently confirmed by this '
        'source scan. Absence of a finding does not establish safety. '
        'Runtime behaviour, payment replay and crash recovery, user isolation, '
        'and live deployment configuration have not been verified here. '
        'Check the cited code and reproduce the claimed consequence in an '
        'isolated test environment before applying a suggested fix.</p></section>'
    )

    counts = {}
    for f in raw_findings:
        if is_non_production(f):
            continue
        counts[f.get("severity")] = counts.get(f.get("severity"), 0) + 1
    summary = " · ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
        if s in counts
    ) or "No findings from the checks that ran"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Drydock audit — {escape(project_name)}</title>
<meta property="og:title" content="{escape(og_title)}">
<meta property="og:description" content="{escape(summary)} — Drydock audit of {escape(project_name)}">
<style>
 body{{margin:0;background:#111113;color:#ededef;
      font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}}
 .wrap{{max-width:860px;margin:0 auto;padding:40px 20px}}
 header{{display:flex;align-items:center;gap:28px;margin-bottom:32px}}
 .noring{{width:110px;height:110px;border-radius:50%;display:flex;
       flex-direction:column;align-items:center;justify-content:center;
       flex-shrink:0;border:6px solid #4a4b52;font-size:30px;
       font-weight:700}}
 .noring small{{font-size:11px;font-weight:400;color:#8b8d98}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#8b8d98;font-size:13px}}
 .cat{{display:flex;align-items:center;gap:10px;margin:6px 0}}
 .cat-name{{width:110px;color:#8b8d98;font-size:13px}}
 .cat-val{{width:34px;text-align:right;font-variant-numeric:tabular-nums}}
 table{{width:100%;border-collapse:collapse;margin-top:24px;font-size:14px}}
 th{{text-align:left;color:#8b8d98;font-weight:500;font-size:12px;
    padding:6px 10px;border-bottom:1px solid #26262a}}
 td{{padding:8px 10px;border-bottom:1px solid #1c1c1f;vertical-align:top}}
 .what{{font-weight:600;margin-bottom:4px}}
.risk{{color:#b4b4bc;margin-bottom:4px}}
.fix{{color:#0a7d33;margin-bottom:4px}}
.tech{{color:#8b8d98;font-size:12px;font-family:monospace}}
.tiercell{{white-space:nowrap;vertical-align:top}}
.sev{{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;
      color:#111113;text-transform:uppercase}}
 .loc{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#8b8d98}}
 .clean{{color:#30a46c}}
 .sechead{{font-size:15px;margin:32px 0 4px;padding-top:24px;
          border-top:1px solid #26262a}}
 .secnote{{color:#8b8d98;font-size:13px;margin:0}}
.cat-skip{{color:#8b8d98;font-size:12px;width:auto;white-space:nowrap}}
 footer{{margin-top:36px;color:#5a5c66;font-size:12px}}
</style></head><body><div class="wrap">
<header>
  {header_left}
  <div>
    <h1>{heading}</h1>
    <div class="sub">stack: {escape(str(result.get("stack", "?")))} · {escape(summary)}</div>
  </div>
</header>
{tier_note}
<section>{cats}</section>
{body}
{coverage_note}
<footer>Generated by Drydock — source audit with verification limits.</footer>
</div></body></html>"""
