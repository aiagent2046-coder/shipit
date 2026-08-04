"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape

from app.report.plain_language import plain_fields, tier
from app.scan.secrets import NON_PRODUCTION_CONTEXTS, is_non_production_path

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_SEVERITY_COLOR = {
    "critical": "#e5484d", "high": "#f76b15",
    "medium": "#f5d90a", "low": "#8b8d98",
}


def _score_color(total: float) -> str:
    if total >= 8:
        return "#30a46c"
    if total >= 5:
        return "#f5d90a"
    return "#e5484d"


def _bar(label: str, value: float) -> str:
    pct = int(value * 10)
    return (
        f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
        f'<div class="track"><div class="fill" style="width:{pct}%;'
        f'background:{_score_color(value)}"></div></div>'
        f'<span class="cat-val">{value:.1f}</span></div>'
    )


def _finding_row(f: dict) -> str:
    sev = str(f.get("severity", "low"))
    color = _SEVERITY_COLOR.get(sev, "#8b8d98")
    loc = escape(str(f.get("file", "")))
    if f.get("line"):
        loc += f":{int(f['line'])}"
    what, risk, fix = plain_fields(f)
    emoji, tier_label = tier(sev)
    risk_html = f'<div class="risk">{escape(risk)}</div>' if risk else ""
    fix_html = f'<div class="fix">→ {escape(fix)}</div>' if fix else ""
    tech_bits = " · ".join(x for x in (
        escape(str(f.get("title", ""))), loc,
        escape(str(f.get("masked", "")))) if x)
    return (
        '<tr>'
        f'<td class="tiercell"><span class="sev" style="background:{color}">'
        f'{emoji} {escape(tier_label)}</span></td>'
        f'<td class="title"><div class="what">{escape(what)}</div>'
        f'{risk_html}{fix_html}'
        f'<div class="tech">{tech_bits}</div></td>'
        '</tr>'
    )


def _is_non_production(f: dict) -> bool:
    """Whether a finding is about test, example or documentation material.

    Two sources because there are two producers. Secrets findings carry an
    explicit `context` set by the damping rules; LLM findings carry none, so
    they fall back to the path. Trusting `context` first matters: it is the
    scanner's own decision, and re-deriving it from the path here would let
    the two answers drift.
    """
    context = f.get("context")
    if context:
        return context in NON_PRODUCTION_CONTEXTS
    return is_non_production_path(str(f.get("file", "")))


def _findings_table(findings: list[dict]) -> str:
    rows = "".join(_finding_row(f) for f in findings)
    return (
        '<table><thead><tr><th></th><th>Finding</th></tr></thead>'
        f'<tbody>{rows}</tbody></table>'
    )


def render_report(result: dict, project_name: str = "your app") -> str:
    score = result["score"]
    total = float(score["total"])

    # A static-only scan gets no readiness score, and this is the whole reason:
    # the number goes UP when fewer checks run, because the findings that would
    # lower it were never looked for. Measured on audit ed402e63 -- 7.2 with the
    # auth and injection rubrics, 9.1 without them, Auth reading 10.0 for a repo
    # whose subscriptions table has no write RLS policies. Publishing that as a
    # "production readiness score" would be reassurance in the wrong direction.
    #
    # A missing basis means an audit from before the field existed: those keep
    # rendering exactly as they always did.
    scored = str(score.get("basis") or "") != "static_only"
    findings = sorted(
        result.get("findings", []),
        key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity")), 9),
                       -float(f.get("confidence", 0))),
    )

    cats = "".join(
        _bar(name, val) for name, val in score["categories"].items()
    ) if scored else ""

    n = len(result.get("findings", []))
    if scored:
        og_title = f"Production Readiness Score: {total:.1f}/10"
        header_left = f'<div class="ring">{total:.1f}</div>'
        heading = f"Production Readiness — {escape(project_name)}"
        tier_note = ""
    else:
        og_title = (f"Static scan: {n} issue{'' if n == 1 else 's'} found"
                    if n else "Static scan: nothing found")
        header_left = ""
        heading = f"Static scan — {escape(project_name)}"
        tier_note = (
            '<section><p class="secnote">This is the free static scan: '
            'credentials committed to the repository, a committed .env, a '
            '.gitignore that misses secret files, missing tests, missing CI and '
            'no Dockerfile. It does not review your authentication and does not '
            'look for injection paths, so it produces no readiness score \u2014 a '
            'score computed from half the checks reads as reassurance, and it '
            'goes up as fewer things are examined.</p></section>'
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
        body = ('<p class="clean">Nothing found in the code your app runs.</p>')
    else:
        body = '<p class="clean">No issues found by the current checks.</p>'

    if non_production:
        body += (
            '<h2 class="sechead">In tests, examples and documentation</h2>'
            '<p class="secnote">These files don\'t run in production. Usually '
            'the credentials here are deliberate fakes — worth a glance to '
            'confirm, not worth blocking a launch.</p>'
            + _findings_table(non_production)
        )

    counts = {}
    for f in findings:
        counts[f.get("severity")] = counts.get(f.get("severity"), 0) + 1
    summary = " · ".join(
        f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
        if s in counts
    ) or "clean"

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
 .ring{{width:110px;height:110px;border-radius:50%;display:flex;
       align-items:center;justify-content:center;flex-shrink:0;
       border:6px solid {_score_color(total)};font-size:30px;font-weight:700}}
 h1{{font-size:20px;margin:0 0 4px}} .sub{{color:#8b8d98;font-size:13px}}
 .cat{{display:flex;align-items:center;gap:10px;margin:6px 0}}
 .cat-name{{width:110px;color:#8b8d98;font-size:13px}}
 .cat-val{{width:34px;text-align:right;font-variant-numeric:tabular-nums}}
 .track{{flex:1;height:8px;background:#26262a;border-radius:4px;overflow:hidden}}
 .fill{{height:100%}}
 table{{width:100%;border-collapse:collapse;margin-top:24px;font-size:14px}}
 th{{text-align:left;color:#8b8d98;font-weight:500;font-size:12px;
    padding:6px 10px;border-bottom:1px solid #26262a}}
 td{{padding:8px 10px;border-bottom:1px solid #1c1c1f;vertical-align:top}}
 .what{{font-weight:600;margin-bottom:4px}}
.risk{{color:#3d3f46;margin-bottom:4px}}
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
<footer>Generated by Drydock — free audit, verified fixes as pull requests.</footer>
</div></body></html>"""
