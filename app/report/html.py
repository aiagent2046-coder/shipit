"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape
from app.scan.claim_evidence import (
    narrative_review_checks, partial_contradicted, syntax_contradicted, unsupported_transport,
)
from app.scan.claim_narrative import narrative_projection

from app.report.evidence import (
    is_informational, coverage_rows, evidence_label, finding_counts, is_non_production, manifest_rows,
    model_status_notice, non_model_status_notices, source_severity_counts, claim_evidence_rows,
    observation_summary, review_contribution_rows,
    model_acceptance_notice,
)
from app.report.grouping import GROUPABLE, group_for_display, related_finding_groups
from app.report.owner_roadmap import build_owner_roadmap
from app.report.owner_report import build_owner_report, owner_report_context
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


def _finding_row(f: dict, *, historical: bool = False, included: bool = False,
                 refreshed: bool = False, owner_card: dict | None = None,
                 roadmap_indices: list[int] | None = None) -> str:
    sev = str(f.get("severity", "low"))
    color = _SEVERITY_COLOR.get(sev, "#8b8d98")
    loc = escape(str(f.get("file", "")))
    if f.get("line"):
        loc += f":{int(f['line'])}"
    what, risk, fix = plain_fields(f)
    projection = narrative_projection(f)
    emoji, _ = tier(sev)
    tier_label = f"Potential {sev} impact"
    contradicted = syntax_contradicted(f.get("claim_evidence"))
    partial = partial_contradicted(f.get("claim_evidence")) and not historical
    unsupported = unsupported_transport(f.get("claim_evidence")) and not historical
    review = bool(narrative_review_checks(f.get("claim_evidence"))) and not historical
    snapshot_match = (f.get("rule_id") == "dependency-cve-match" and f.get("source") == "dependency"
                      and f.get("verification_method") == "package_version_match")
    retained_match = (f.get("claim_evidence") or {}).get("snapshot_check_status") == "retained_not_reconfirmed"
    if contradicted:
        emoji, tier_label, color = "", "Syntax premise contradicted", "#8b8d98"
    elif partial:
        emoji, tier_label, color = "", "Assessment needs review", "#8b8d98"
    elif unsupported:
        emoji, tier_label, color = "", "Needs exposure evidence", "#8b8d98"
    elif review:
        emoji, tier_label, color = "", "Outcome needs review", "#8b8d98"
    if is_informational(f):
        emoji, tier_label, color = "", "Informational", "#8b8d98"
    if historical:
        emoji, color = "", "#8b8d98"
        tier_label = ("Free audit observation — included in this audit" if included
                      else "Previous preview — not reassessed")
        if refreshed:
            tier_label = ("Earlier dependency finding — not reconfirmed" if retained_match else
                          "Dependency match — checked with refreshed snapshot") if snapshot_match else (
                              "Reused free audit observation — not reassessed")
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
        guidance = ('Recorded verification guidance — not reassessed' if projection else
                    'Free audit suggestion — unverified' if included else
                    'Original preview suggestion — not reassessed')
        if refreshed and not projection:
            guidance = ("Earlier advisory guidance — not reconfirmed" if retained_match else
                        "Snapshot advisory guidance — reachability unverified") if snapshot_match else (
                            "Reused free audit suggestion — not reassessed")
        fix_html = ('<details><summary>'
                    + guidance
                    + '</summary>'
                    + escape(fix) + '</details>') if fix else ""
    if partial and not projection:
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
    elif review and not partial and not contradicted and not projection:
        fix_html = ('<details><summary>Original model claim and suggestion — outcome not established</summary>'
                    + '<p>' + escape(what) + '</p>'
                    + ('<p>' + escape(risk) + '</p>' if risk else '')
                    + ('<p>' + escape(fix) + '</p>' if fix else '') + '</details>')
        what = "Source checks leave this outcome unresolved"
        risk_html = ('<div class="risk">Review the source conditions below before acting. '
                     'The original model severity remains in the score pending review; '
                     'the claimed outcome and project safety have not been verified.</div>')
    if projection:
        original = projection["original"]
        fix_html += ('<details><summary>Superseded model wording — source premise corrected</summary>'
                     + ''.join('<p>' + escape(str(original[key])) + '</p>'
                               for key in ('title', 'explanation', 'fix_hint', 'observation') if original.get(key))
                     + '</details>')
    evidence = '<dl style="white-space:pre-line">' + "".join(
        f'<dt>{escape(label)}</dt><dd>{escape(value)}</dd>' for label, value in claim_evidence_rows(f, historical)
    ) + '</dl>'
    if not model:
        evidence = '<details><summary>Evidence and conditions</summary>' + evidence + '</details>'
    tech_bits = " · ".join(x for x in (
        _category_label(f),
        ("" if (partial or unsupported or review) and not projection else escape(str(f.get("title", "")))), loc,
        escape(str(f.get("masked", "")))) if x)
    if owner_card is not None and not historical:
        source_details = ''.join(
            '<p class="tech">Source: ' + escape(ref["file"]) + ':' + str(ref["line"])
            + ' · SHA-256: ' + escape(ref["sha256"])
            + ' · call span: ' + escape(str(ref["sink_span"]))
            + ' · acquisition version: ' + str(ref["acquisition_version"]) + '</p>'
            for ref in owner_card["source_refs"]
        )
        developer_details = (
            '<details class="owner-developer"><summary>Details for a developer</summary>'
            f'<p>{escape(what)}</p>{risk_html}{evidence}{fix_html}'
            f'<div class="tech">{tech_bits}</div>{source_details}</details>'
        )
        what = owner_card["title"]
        risk_html = f'<div class="risk">{escape(owner_card["impact"])}</div>'
        evidence = '<dl class="owner-evidence">' + ''.join(
            '<dt>' + label + '</dt><dd><ul>'
            + ''.join('<li>' + escape(item) + '</li>' for item in owner_card[key])
            + '</ul></dd>' for label, key in (("What we know", "known"), ("What needs checking", "unknown"))
        ) + ('<dt>What to do next</dt><dd>' + escape(owner_card["next_action"])
             + '</dd><dt>This step is complete when</dt><dd>' + escape(owner_card["done_when"]) + '</dd></dl>')
        fix_html = developer_details
        tech_bits = loc
    roadmap_anchors = ''.join(
        f'<span class="roadmap-anchor" id="roadmap-finding-{index}" tabindex="-1"></span>'
        for index in (roadmap_indices or []) if not historical
    )
    return (
        (f'<tr id="owner-finding-{owner_card["finding_index"]}" tabindex="-1">'
         if owner_card is not None and not historical else '<tr>')
        + f'<td class="tiercell"><span class="sev" style="background:{color}">'
        f'{emoji} {escape(tier_label)}</span></td>'
        f'<td class="title">{roadmap_anchors}<div class="what">{escape(what)}</div>'
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

def _findings_table(findings: list[dict], *, historical: bool = False, included: bool = False,
                    refreshed: bool = False, owner_cards: dict[int, dict] | None = None,
                    roadmap_indices: dict[int, list[int]] | None = None) -> str:
    rows = ""
    for group in related_finding_groups(findings):
        rows += '<tbody>'
        if len(group) > 1:
            rows += ('<tr><th colspan="2" scope="rowgroup">'
                     f'Pickle file loading · {len(group)} locations</th></tr>')
        rows += "".join(_finding_row(f, historical=historical, included=included, refreshed=refreshed,
                                    owner_card=(owner_cards or {}).get(id(f)),
                                    roadmap_indices=(roadmap_indices or {}).pop(id(f), []))
                        for f in group)
        rows += '</tbody>'
    return (
        '<table><thead><tr><th></th><th>Finding</th></tr></thead>'
        f'{rows}</table>'
    )


def _roadmap_finding_indices(raw_findings: list[dict], displayed: list[dict]) -> dict[int, list[int]]:
    """Keep original references even when RLS display rows are grouped copies."""
    indices: dict[int, list[int]] = {}
    grouped: dict[tuple[str, bool], list[int]] = {}
    for index, finding in enumerate(raw_findings):
        indices.setdefault(id(finding), []).append(index)
        rule_id = str(finding.get("rule_id", ""))
        if rule_id in GROUPABLE:
            grouped.setdefault((rule_id, is_non_production(finding)), []).append(index)
    return {id(finding): indices.get(id(finding), grouped.get(
        (str(finding.get("rule_id", "")), is_non_production(finding)), []))
        for finding in displayed}


def _owner_roadmap_html(roadmap: dict, findings: list[dict]) -> str:
    tasks = roadmap["tasks"]
    parts = [
        '<section class="owner-roadmap" aria-label="Project roadmap"><h2>Project roadmap</h2>',
        '<p>Suggested next steps from this report. These tasks have not been carried out or verified.</p>',
    ]
    if not tasks:
        parts.append('<p>No next steps can be generated from the recorded findings and coverage. '
                     'This does not establish that the project is ready or safe.</p>')
    task_titles = {task["id"]: task["title"] for task in tasks}
    for stage, label in (("first", "First"), ("after", "After clarification"), ("when_needed", "If needed")):
        group = [task for task in tasks if task["stage"] == stage]
        if not group:
            continue
        parts.append('<h3>' + label + '</h3>')
        for task in group:
            references = []
            for index in task["finding_indices"]:
                finding = findings[index]
                location = str(finding.get("file") or "")
                if location and type(finding.get("line")) is int and finding["line"] > 0:
                    location += ':' + str(finding["line"])
                reference_label = "Observation " + str(index + 1) + (" · " + location if location else "")
                references.append('<li><a href="#roadmap-finding-' + str(index) + '">'
                                  + escape(reference_label) + '</a></li>')
            for ref in task["coverage_refs"]:
                label = {"dependency_cve": "Dependency coverage", "runtime_verified": "Runtime verification scope"}[ref]
                references.append('<li><a href="#roadmap-coverage">' + label + '</a></li>')
            after = ('<dt>After</dt><dd><ul>' + ''.join(
                '<li><a href="#roadmap-task-' + escape(task_id) + '">'
                + escape(task_titles[task_id]) + '</a></li>' for task_id in task["depends_on"]
            ) + '</ul></dd>') if task["depends_on"] else ''
            parts.append(
                '<article class="roadmap-task" id="roadmap-task-' + escape(task["id"]) + '" tabindex="-1">'
                '<h4>' + escape(task["title"]) + '</h4><p>' + escape(task["why"]) + '</p>'
                '<p><strong>Action:</strong> ' + escape(task["action"]) + '</p>'
                '<p><strong>Suggested owner:</strong> ' + escape(task["owner"]) + '</p>'
                '<details><summary>Completion criteria and references</summary><dl><dt>Needs</dt><dd><ul>'
                + ''.join('<li>' + escape(item) + '</li>' for item in task["needs"])
                + '</ul></dd>' + after + '<dt>This step is complete when</dt><dd>'
                + escape(task["done_when"]) + '</dd><dt>Based on</dt><dd><ul>'
                + ''.join(references) + '</ul></dd></dl></details></article>'
            )
    return ''.join(parts) + '</section>'


_REPORT_ANCHOR_SCRIPT = """<script>
(() => {
  function reveal(hash) {
    if (!/^#(?:roadmap-(?:finding-\\d+|task-[a-z-]+|coverage)|owner-finding-\\d+)$/.test(hash)) return;
    const target = document.getElementById(hash.slice(1));
    if (!target) return;
    for (let parent = target.parentElement; parent; parent = parent.parentElement) {
      if (parent.tagName === 'DETAILS') parent.open = true;
    }
    target.focus({preventScroll: true});
    target.scrollIntoView({block: 'start'});
  }
  document.addEventListener('click', event => {
    if (!(event.target instanceof Element)) return;
    const link = event.target.closest('a[href^="#"]');
    if (link) reveal(link.getAttribute('href'));
  });
  window.addEventListener('hashchange', () => reveal(window.location.hash));
  reveal(window.location.hash);
})();
</script>"""


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
    refreshed = baseline.get("origin") == "refreshed"
    if refreshed:
        origin = "Free audit with refreshed dependency snapshot"
    result = ('<section aria-label="Included free audit"><h2 class="sechead">Included free audit</h2>'
              f'<p>{origin}. Status: {status}.</p>'
              '<p>The complete baseline is preserved below, including observations repeated in the paid review. '
              'It includes static observations, dependency matches and any model hypotheses; repeated observations '
              'are not independent confirmation or additional current-scan findings.</p>')
    if refreshed:
        result += ('<p>Dependency matching was attempted again against the recorded snapshot. '
                   'Static observations and model hypotheses were reused without rerunning their checks. '
                   'Earlier matches may be retained when the snapshot check is incomplete.</p>')
    prior = baseline.get("score")
    if not prior:
        return (result + '<p>Free audit unavailable: '
                + escape(str(baseline.get("reason", "not recorded"))) + '.</p></section>')
    acceptance = model_acceptance_notice(prior)
    if acceptance:
        result += ('<aside aria-label="Free audit observation acceptance"><strong>'
                   + escape(acceptance[0]) + '</strong><p>' + escape(acceptance[1]) + '</p></aside>')
    for title, detail in non_model_status_notices(prior):
        result += (f'<aside aria-label="{escape(title)}"><strong>{escape(title)}</strong>'
                   f'<p>{escape(detail)}</p></aside>')
    findings = baseline.get("findings") or []
    rows = coverage_rows(prior, findings) + manifest_rows(prior)
    record = ''.join(f'<dt>{escape(label)}</dt><dd>{escape(value)}</dd>' for label, value in rows)
    return (result + '<details><summary>Full baseline findings and scope</summary>'
            + _findings_table(findings, historical=True, included=baseline.get("origin") == "included",
                              refreshed=refreshed)
            + '<dl style="overflow-wrap:anywhere">'
            + record + '</dl></details></section>')


def render_report(result: dict, project_name: str = "your app") -> str:
    score = result["score"]
    raw_findings = result.get("findings", [])
    owner_context = owner_report_context(result)
    owner_report = build_owner_report(raw_findings, owner_context)
    owner_roadmap_html = _owner_roadmap_html(build_owner_roadmap(raw_findings, owner_context), raw_findings)
    owner_cards = {id(raw_findings[card["finding_index"]]): card for card in owner_report["cards"]}
    owner_summary = owner_report["summary"]
    owner_summary_html = ""
    if owner_summary:
        owner_summary_html = (
            '<section class="owner-summary" aria-label="Report in brief">'
            '<h2>' + escape(owner_summary["title"]) + '</h2><p>' + escape(owner_summary["text"])
            + '</p><p><strong>Next action:</strong> ' + escape(owner_summary["next_action"]) + '</p><ul>'
            + ''.join('<li>' + escape(note) + '</li>' for note in owner_summary["coverage_notes"])
            + '</ul><a href="#owner-finding-' + str(owner_report["cards"][0]["finding_index"])
            + '">See the file-loading question</a></section>'
        )
    findings = sorted(
        group_for_display(raw_findings),
        key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity")), 9),
                       -float(f.get("confidence", 0))),
    )
    roadmap_indices = _roadmap_finding_indices(raw_findings, findings)
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
    status_note += "".join(
        f'<aside aria-label="{escape(title)}" style="border:1px solid #d9a441;padding:16px;margin:16px 0">'
        f'<strong>{escape(title)}</strong><p>{escape(detail)}</p></aside>'
        for title, detail in non_model_status_notices(score)
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
        body = _findings_table(production, owner_cards=owner_cards, roadmap_indices=roadmap_indices)
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
            + _findings_table(non_production, owner_cards=owner_cards, roadmap_indices=roadmap_indices)
        )
    if informational:
        body += ('<h2 class="sechead">Deployment inventory</h2>'
                 + _findings_table(informational, roadmap_indices=roadmap_indices))
    if unsupported:
        body += ('<h2 class="sechead">Credential transport requiring exposure evidence</h2>'
                 '<p class="secnote">These observations remain available for review. '
                 'Transport alone does not establish a leak; actual exposure paths require evidence.</p>'
                 + _findings_table(unsupported, roadmap_indices=roadmap_indices))

    if contradicted:
        body += ('<h2 class="sechead">Contradicted syntax premises</h2>'
                 '<p class="secnote">These model claims contradict the bounded syntax check. '
                 'They are retained for traceability and excluded from unresolved finding counts '
                 'and score penalties. This does not establish that the surrounding code is safe.</p>'
                 + _findings_table(contradicted, roadmap_indices=roadmap_indices))

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
        '<section id="roadmap-coverage" tabindex="-1"><h2 class="sechead">Scan record</h2>'
        '<dl style="overflow-wrap:anywhere">'
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
.owner-summary{{border:1px solid #4a4b52;border-radius:8px;padding:16px;margin:20px 0}}
.owner-summary h2{{font-size:18px;margin:0 0 8px}}
.owner-evidence dt{{font-weight:600;margin-top:10px}}
.owner-evidence dd{{margin:4px 0;overflow-wrap:anywhere}}
.owner-evidence ul{{margin:0;padding-left:20px}}
.owner-developer{{margin-top:12px;overflow-wrap:anywhere}}
.owner-roadmap{{border:1px solid #4a4b52;border-radius:8px;padding:16px;margin:20px 0;overflow-wrap:anywhere}}
.owner-roadmap h2{{font-size:18px;margin:0 0 8px}}
.owner-roadmap h3{{font-size:16px;margin:24px 0 8px}}
.roadmap-task{{border-top:1px solid #38393e;padding:12px 0;scroll-margin-top:16px}}
.roadmap-task h4{{font-size:15px;margin:0 0 8px}}
.roadmap-task p{{margin:8px 0}}
.roadmap-task dt{{font-weight:600;margin-top:10px}}
.roadmap-task dd{{margin:4px 0}}
.roadmap-task ul{{padding-left:20px}}
.roadmap-anchor{{display:block;scroll-margin-top:16px}}
.owner-roadmap a{{color:#93c5fd}}
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
 @media(max-width:600px){{
   header{{flex-wrap:wrap;gap:12px}}
   header>div{{min-width:0}}
   .cat{{align-items:flex-start}}
   .cat-name{{flex-shrink:0}}
   .cat-skip{{white-space:normal;overflow-wrap:anywhere}}
   table{{table-layout:fixed}}
   th,td,.tech{{overflow-wrap:anywhere}}
   .tiercell{{white-space:normal}}
   .sev{{display:inline-block}}
 }}
</style></head><body><div class="wrap">
<header>
  {header_left}
  <div>
    <h1>{heading}</h1>
    <div class="sub">stack: {escape(str(result.get("stack", "?")))} · {escape(summary)}</div>
  </div>
</header>
{owner_summary_html}
{owner_roadmap_html}
{tier_note}
{status_note}
{acceptance_note}
<section>{cats}</section>
{body}
{coverage_note}
<footer>Generated by Drydock — source audit with verification limits.</footer>
</div>{_REPORT_ANCHOR_SCRIPT}</body></html>"""
