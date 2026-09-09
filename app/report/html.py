"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape
from app.scan.claim_evidence import partial_contradicted, syntax_contradicted, unsupported_transport

from app.report.evidence import (
    is_informational, coverage_rows, evidence_label, finding_counts, is_non_production, manifest_rows,
    model_status_notice, source_severity_counts, claim_evidence_rows, observation_summary, review_contribution_rows,
    model_acceptance_notice,
)
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


def _finding_row(f: dict, *, historical: bool = False, included: bool = False) -> str:
    sev = str(f.get("severity", "low"))
    color = _SEVERITY_COLOR.get(sev, "#8b8d98")
    loc = escape(str(f.get("file", "")))
    if f.get("line"):
        loc += f":{int(f['line'])}"
    what, risk, fix = plain_fields(f)
    emoji, _ = tier(sev)
    tier_label = f"Potential {sev} impact"
    contradicted = syntax_contradicted(f.get("claim_evidence"))
    partial = partial_contradicted(f.get("claim_evidence")) and not historical
    unsupported = unsupported_transport(f.get("claim_evidence")) and not historical
    if contradicted:
        emoji, tier_label, color = "", "Syntax premise contradicted", "#8b8d98"
    elif partial:
        emoji, tier_label, color = "", "Assessment needs review", "#8b8d98"
    elif unsupported:
        emoji, tier_label, color = "", "Needs exposure evidence", "#8b8d98"
    if is_informational(f):
        emoji, tier_label, color = "", "Informational", "#8b8d98"
    if historical:
        emoji, color = "", "#8b8d98"
        tier_label = ("Free audit observation — included in this audit" if included
                      else "Previous preview — not reassessed")
        if is_non_production(f):
            tier_label += " · Test/example context"
    risk_html = f'<div class="risk">{escape(risk)}</div>' if risk else ""
    fix_html = f'<div class="fix">→ {escape(fix)}</div>' if fix else ""
    model = f.get("source") == "llm" or str(f.get("rule_id", "")).startswith("llm-")
    if model:
        if risk:
            risk_html = ('<div class="risk"><strong>Possible consequence — unverified:</strong> '
                         + escape(risk) + '</div>')
        if fix:
            fix_html = '<div class="fix"><strong>Suggested verification / fix:</strong> ' + escape(fix) + '</div>'
    if contradicted:
        fix_html = ('<details><summary>Original model suggestion — premise contradicted</summary>'
                    + escape(fix) + '</details>') if fix else ""
    if historical:
        fix_html = ('<details><summary>'
                    + ('Free audit suggestion — unverified' if included
                       else 'Original preview suggestion — not reassessed')
                    + '</summary>'
                    + escape(fix) + '</details>') if fix else ""
    if partial:
        original = ('<details><summary>Original model claim and suggestion — contains a contradicted premise</summary>'
                    + '<p>' + escape(what) + '</p>'
                    + ('<p>' + escape(risk) + '</p>' if risk else '')
                    + ('<p>' + escape(fix) + '</p>' if fix else '') + '</details>')
        what = "Source checks contradict part of this finding"
        risk_html = ('<div class="risk">Other claims remain unverified. Review the counterevidence below; '
                     'the original model severity is retained in the score pending review.</div>')
        fix_html = original
    if unsupported:
        original = ('<details><summary>Original model claim and suggestion — exposure not established</summary>'
                    + '<p>' + escape(what) + '</p>'
                    + ('<p>' + escape(risk) + '</p>' if risk else '')
                    + ('<p>' + escape(fix) + '</p>' if fix else '') + '</details>')
        what = "Credential transport — exposure not established"
        risk_html = ('<div class="risk">This transport-only hypothesis is excluded from the score. '
                     'Runtime routing, logging and credential exposure remain unverified.</div>')
        fix_html = original
    evidence = '<dl style="white-space:pre-line">' + "".join(
        f'<dt>{escape(label)}</dt><dd>{escape(value)}</dd>' for label, value in claim_evidence_rows(f, historical)
    ) + '</dl>'
    if not model:
        evidence = '<details><summary>Evidence and conditions</summary>' + evidence + '</details>'
    tech_bits = " · ".join(x for x in (
        _category_label(f),
        ("" if partial or unsupported else escape(str(f.get("title", "")))), loc,
        escape(str(f.get("masked", "")))) if x)
    return (
        '<tr>'
        f'<td class="tiercell"><span class="sev" style="background:{color}">'
        f'{emoji} {escape(tier_label)}</span></td>'
        f'<td class="title"><div class="what">{escape(what)}</div>'
        f'<div class="tech">{escape(evidence_label(f, historical))}</div>'
        f'{risk_html}{evidence}{fix_html}'
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

def _findings_table(findings: list[dict], *, historical: bool = False, included: bool = False) -> str:
    rows = "".join(_finding_row(f, historical=historical, included=included) for f in findings)
    return (
        '<table><thead><tr><th></th><th>Finding</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )


def _preview_history(score: dict) -> str:
    history = score.get("preview_history") or {}
    if history.get("version") != 1:
        return ""
    retained = history.get("retained_findings") or []
    source = escape(str(history.get("preview_audit_id", "")))
    engine = escape(str(history.get("engine_version", "")))
    model = escape(str(history.get("model") or "not recorded"))
    reused = ('<p>The model analysis was reused from an existing audit; adding this '
              'history made no new LLM calls.</p>' if score.get("analysis_reused_from") else "")
    return (
        '<section aria-label="Free audit history"><h2 class="sechead">Free audit history</h2>'
        f'<p>Preview {source} · engine {engine} · model {model}.</p>'
        '<p>Matched by identical archive content and audit engine. '
        f'{int(history.get("matched_count", 0))} unchanged observations already appear in this scan; '
        f'{len(retained)} other preview observations are retained below.</p>'
        '<p>Not repeated does not mean fixed, disproved or confirmed. These are original '
        'preview records, not reassessed findings. They are excluded from current scan '
        'counts, scores and automatic fixes. Repetition is not independent evidence.</p>'
        + reused + (_findings_table(retained, historical=True) if retained else "") + '</section>'
    )


def _free_baseline(score: dict) -> str:
    baseline = score.get("free_baseline") or {}
    if baseline.get("version") != 1:
        return ""
    status = escape(str(baseline.get("status", "unavailable")))
    origin = "Reused same-archive free audit" if baseline.get("origin") == "reused" else "Included in this paid audit"
    result = ('<section aria-label="Included free audit"><h2 class="sechead">Included free audit</h2>'
              f'<p>{origin}. Status: {status}.</p>'
              '<p>The complete baseline is preserved below, including observations repeated in the paid review. '
              'It includes static observations and any model hypotheses; repeated observations are not '
              'independent confirmation or additional current-scan findings.</p>')
    prior = baseline.get("score")
    if not prior:
        return (result + '<p>Free audit unavailable: '
                + escape(str(baseline.get("reason", "not recorded"))) + '.</p></section>')
    acceptance = model_acceptance_notice(prior)
    if acceptance:
        result += ('<aside aria-label="Free audit observation acceptance"><strong>'
                   + escape(acceptance[0]) + '</strong><p>' + escape(acceptance[1]) + '</p></aside>')
    findings = baseline.get("findings") or []
    rows = coverage_rows(prior, findings) + manifest_rows(prior)
    record = ''.join(f'<dt>{escape(label)}</dt><dd>{escape(value)}</dd>' for label, value in rows)
    return (result + '<details><summary>Full baseline findings and scope</summary>'
            + _findings_table(findings, historical=True, included=baseline.get("origin") == "included")
            + '<dl style="overflow-wrap:anywhere">'
            + record + '</dl></details></section>')


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
    source_count, _ = finding_counts(raw_findings)
    header_left = (
        f'<div class="noring">{source_count}'
        f'<small>source observations'
        '</small></div>'
    )
    header_left += f'<p>{escape(observation_summary(raw_findings))}</p>'
    if (score.get("preview_history") or {}).get("version") == 1:
        count = len(score["preview_history"].get("retained_findings") or [])
        header_left += f'<p>{count} additional preview observations retained in Free audit history.</p>'
    cats = "".join(
        f'<div class="cat"><span class="cat-name">{escape(name)}</span>'
        f'<span class="cat-skip">{escape(label)}</span></div>'
        for name, label in coverage_rows(score, raw_findings)
    )
    basis = str(score.get("basis") or "unknown")
    notice = model_status_notice(score)
    status_note = (
        '<aside aria-label="Model review status" style="border:1px solid #d9a441;padding:16px;margin:16px 0">'
        f'<strong>{escape(notice[0])}</strong><p>{escape(notice[1])}</p></aside>'
        if notice else ""
    )
    acceptance = model_acceptance_notice(score)
    acceptance_note = (
        '<aside aria-label="Model observation acceptance" style="border:1px solid #d9a441;padding:16px;margin:16px 0">'
        f'<strong>{escape(acceptance[0])}</strong><p>{escape(acceptance[1])}</p></aside>'
        if acceptance else ""
    )
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
    contradicted = [f for f in findings if syntax_contradicted(f.get("claim_evidence"))]
    unsupported = [f for f in findings if not syntax_contradicted(f.get("claim_evidence"))
                   and not is_informational(f) and unsupported_transport(f.get("claim_evidence"))]
    unresolved = [f for f in findings if not syntax_contradicted(f.get("claim_evidence"))
                  and not unsupported_transport(f.get("claim_evidence"))]
    informational = [f for f in unresolved if is_informational(f)]
    unresolved = [f for f in unresolved if not is_informational(f)]
    production = [f for f in unresolved if not _is_non_production(f)]
    non_production = [f for f in unresolved if _is_non_production(f)]

    if production:
        body = _findings_table(production)
    elif non_production:
        body = ('<p class="clean">No findings outside the test and example '
                'section. This does not establish safety.</p>')
    elif unsupported:
        body = ('<p class="clean">The transport observations below need evidence of credential exposure. '
                'Their unresolved deployment conditions do not establish safety.</p>')
    else:
        body = '<p class="clean">No issues found by the current checks.</p>'

    if non_production:
        body += (
            f'<h2 class="sechead">{NON_PRODUCTION_HEADING}</h2>'
            f'<p class="secnote">{NON_PRODUCTION_NOTE}</p>'
            + _findings_table(non_production)
        )
    if informational:
        body += '<h2 class="sechead">Deployment inventory</h2>' + _findings_table(informational)
    if unsupported:
        body += ('<h2 class="sechead">Credential transport requiring exposure evidence</h2>'
                 '<p class="secnote">These observations remain available for review. '
                 'Transport alone does not establish a leak; actual exposure paths require evidence.</p>'
                 + _findings_table(unsupported))

    if contradicted:
        body += ('<h2 class="sechead">Contradicted syntax premises</h2>'
                 '<p class="secnote">These model claims contradict the bounded syntax check. '
                 'They are retained for traceability and excluded from unresolved finding counts '
                 'and score penalties. This does not establish that the surrounding code is safe.</p>'
                 + _findings_table(contradicted))

    contribution = review_contribution_rows(score)
    if contribution:
        rows = "".join(f'<tr><th scope="row">{escape(label)}</th><td>{escape(free)}</td>'
                       f'<td>{escape(paid)}</td></tr>' for label, free, paid in contribution)
        body = ('<section aria-label="Model review contribution"><h2 class="sechead">Model review contribution</h2>'
                '<table><thead><tr><th scope="col">Recorded work</th><th scope="col">Free audit</th>'
                '<th scope="col">Paid review</th></tr></thead><tbody>' + rows + '</tbody></table>'
                '<p>Model hypotheses may repeat the free audit; these are not counts of new or confirmed problems. '
                'Zero retained hypotheses does not establish safety. Submitted files may be excerpted.</p>'
                + ('<p>Paid analysis was reused; these counts describe the stored review.</p>'
                   if score.get("analysis_reused_from") else '') + '</section>') + body

    history_html = _free_baseline(score) + _preview_history(score)
    if history_html:
        body = history_html + '<h2 class="sechead">Current scan observations</h2>' + body

    record = "".join(
        f'<dt>{escape(label)}</dt><dd translate="no">{escape(value)}</dd>'
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

    counts = source_severity_counts(raw_findings)
    summary = " · ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
        if counts[s]
    ) or "No source observations recorded"

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
{status_note}
{acceptance_note}
<section>{cats}</section>
{body}
{coverage_note}
<footer>Generated by Drydock — source audit with verification limits.</footer>
</div></body></html>"""
