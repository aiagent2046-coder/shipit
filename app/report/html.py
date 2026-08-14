"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape

from app.report.plain_language import plain_fields, tier
from app.scan.scoring import (GATE_THRESHOLD, GATED_MAX,
                              LLM_ONLY_CATEGORIES)
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


def _bar(label: str, value: float, examined: bool = True) -> str:
    """One category row. `examined=False` draws no bar and no number.

    An unexamined category sits at 10.0 because nothing produced a finding
    in it, not because it is clean. Drawing that as a full green bar is the
    most misleading thing this report can do -- it answers the reader's
    question ("is my auth safe?") with a confident yes nobody checked. The
    row stays, because hiding it would make the audit look narrower than it
    was; only the claim goes.
    """
    if not examined:
        return (
            f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
            f'<div class="track"></div>'
            f'<span class="cat-val cat-skip">not checked</span></div>'
        )
    pct = int(value * 10)
    return (
        f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
        f'<div class="track"><div class="fill" style="width:{pct}%;'
        f'background:{_score_color(value)}"></div></div>'
        f'<span class="cat-val">{value:.1f}</span></div>'
    )


def _unexamined_sentence(score: dict) -> str:
    """Name the categories nothing looked at, for the scope note.

    Reads the scorer's own `unexamined` list rather than re-deriving it from
    the basis: the rule for which categories an LLM-less scan cannot fill
    lives in app/scan/scoring.py, and a second copy here would drift from it.
    An older stored audit has no such key and gets a generic sentence.
    """
    names = [str(n) for n in score.get("unexamined") or []]
    if not names:
        return ("It does not review your authentication and does not look "
                "for injection paths.")
    if len(names) == 1:
        listed = escape(names[0])
    else:
        listed = escape(", ".join(names[:-1]) + " and " + names[-1])
    return f"Nothing here examined {listed}."


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

    # Both tiers publish a score now; `scored` only decides how it is framed
    # and how much scope the note has to declare. See the free-tier branch
    # below for why withholding it stopped being the honest option.
    #
    # A missing basis means an audit from before the field existed. It is
    # treated as a full audit, exactly as it always was.
    scored = str(score.get("basis") or "") != "static_only"
    findings = sorted(
        result.get("findings", []),
        key=lambda f: (_SEVERITY_ORDER.get(str(f.get("severity")), 9),
                       -float(f.get("confidence", 0))),
    )

    # Rendered for the free tier too now, with the unexamined rows marked.
    #
    # A stored row predating the key gets the same answer computed from the
    # basis, because absent must not read as "everything was examined": that
    # would draw Auth as a full 10.0 bar, the exact claim issue #181 is about.
    if "unexamined" in score:
        unexamined = set(str(n) for n in (score.get("unexamined") or []))
    elif not scored:
        unexamined = set(LLM_ONLY_CATEGORIES)
    else:
        unexamined = set()
    cats = "".join(
        _bar(name, val, examined=name not in unexamined)
        for name, val in score["categories"].items()
    )

    # Why the headline is capped, printed next to the bars it contradicts.
    # A subscore failure explains itself -- the bar is visibly short -- but a
    # lone critical does not: every bar can sit above 7.0 while the ring reads
    # 6.3. Reading the reasons the scorer recorded rather than re-deriving
    # them keeps this from drifting away from the rule that produced them.
    #
    # `gated_by` absent means an audit stored before the key existed, which is
    # not the same as "not gated" and must print nothing rather than a
    # reassurance the row cannot support.
    gate_note = ""
    if score.get("gated_by"):
        crit = [r for r in score["gated_by"] if r.get("kind") == "critical"]
        low = [r for r in score["gated_by"] if r.get("kind") == "subscore"]
        parts = []
        if crit:
            named = ", ".join(sorted({escape(str(r.get("title") or
                                                 r.get("rule_id")))
                                      for r in crit}))
            parts.append(
                f"a critical finding ({named})")
        if low:
            named = ", ".join(f"{escape(r['category'])} {r['value']:.1f}"
                              for r in low)
            parts.append(f"a safety category below {GATE_THRESHOLD:.1f} "
                         f"({named})")
        # "Capped at 6.9" described the flat ceiling that _apply_gate tried
        # first and rejected, and this sentence was never updated when the
        # gate became a scaling. It read as a contradiction on the page: a
        # real audit (ai-co-founder-matching) published 5.1 above the words
        # "capped at 6.9", and 6.9 appears nowhere else on it -- the mean was
        # 7.4 and the gate compressed it, it did not clip it. A reader who
        # tries to reconcile the two numbers cannot, which is the same defect
        # the gate itself exists to remove, relocated into its explanation.
        gate_note = (
            f'<section><p class="secnote">This score cannot exceed '
            f'{GATED_MAX:.1f} because the audit found {" and ".join(parts)}. '
            f'The whole scale is compressed into that range rather than the '
            f'number being clipped to it, so two repositories that both fail '
            f'this check are still ranked against each other — which is why '
            f'the score can read well below {GATED_MAX:.1f}. Categories are '
            f'scored independently and can read higher than the total.'
            f'</p></section>'
        )

    header_left = f'<div class="ring">{total:.1f}</div>'
    if scored:
        og_title = f"Production Readiness Score: {total:.1f}/10"
        heading = f"Production Readiness \u2014 {escape(project_name)}"
        tier_note = ""
    else:
        # The free tier used to publish no number at all, on the reasoning
        # that a score from half the checks reads as reassurance and goes UP
        # as fewer things are examined. That was measured and true: audit
        # ed402e63 scored 7.2 with the auth and injection rubrics and 9.1
        # without them.
        #
        # Two changes since removed the mechanism. Unexamined categories no
        # longer vote on the mean (LLM_ONLY_CATEGORIES), so a skipped rubric
        # cannot lift the total; and one confident critical now caps it,
        # which the free static rules can trigger on their own. Recomputed
        # on that same audit under today's engine: 5.4 full, 6.1 static-only
        # -- a 0.7 gap in the same direction as before, with both numbers
        # inside the failing band, against 1.9 the other way.
        #
        # So the number is now defensible, and withholding it costs the
        # visitor the one thing they came for. What must stay is the honest
        # scope: the note below names what was not examined, and the bars
        # render those categories as unchecked rather than as a perfect 10.
        # ...and then a second repository falsified it. The argument above
        # rests on one audit, where static-only read 6.1 against 5.4 full: a
        # small gap, both numbers failing. On donjonson-hash/kristina_agent_
        # center the same comparison is 9.9 static-only against 4.7 full -- a
        # gap of 5.2, with the free number reading as a clean bill of health
        # on a repository that lets an unauthenticated caller run commands as
        # root over SSH.
        #
        # The mechanism that was supposed to prevent this covers Auth, Money &
        # Data and Frontend, which no longer vote when unexamined. It cannot
        # cover Security, which BOTH tiers fill: with the static rules finding
        # only "no Dockerfile", Security read a clean 10.0 -- not because the
        # repository is clean but because regexes are not where its problems
        # live. The mean over Security 10.0, Deploy 9.9 and Testing 10.0 is
        # 9.9, and no confident critical existed to cap it.
        #
        # So the headline number goes. The bars stay, the findings stay, the
        # scope note stays. What a free scan can honestly say is WHAT IT
        # LOOKED AT AND WHAT IT FOUND, not a mark out of ten -- and the
        # pricing page has promised exactly that all along ("No readiness
        # score out of 10"); only the code disagreed.
        og_title = f"Free scan \u2014 {escape(project_name)}"
        heading = f"Free scan \u2014 {escape(project_name)}"
        header_left = (
            f'<div class="noring">{len(findings)}'
            f'<small>{"finding" if len(findings) == 1 else "findings"}'
            '</small></div>'
        )
        tier_note = (
            '<section><p class="secnote">A free scan does not produce a mark '
            'out of ten, because it does not look at enough to earn one. It '
            'checks credentials committed to the repository, a committed '
            '.env, a .gitignore that misses secret files, missing tests, '
            'missing CI and no Dockerfile. '
            + _unexamined_sentence(score) +
            ' Finding nothing in the checks that ran is not the same as '
            'being sound: on one real repository this scan reported a single '
            'low finding while a full audit found an unauthenticated endpoint '
            'running commands as root.</p></section>'
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
 /* The free scan's counterpart. Deliberately NOT _score_color: a verdict
    colour is a verdict, and counting what the checks found is not one. */
 .noring{{width:110px;height:110px;border-radius:50%;display:flex;
       flex-direction:column;align-items:center;justify-content:center;
       flex-shrink:0;border:6px solid #4a4b52;font-size:30px;
       font-weight:700}}
 .noring small{{font-size:11px;font-weight:400;color:#8b8d98}}
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
{gate_note}
{body}
<footer>Generated by Drydock — free audit, verified fixes as pull requests.</footer>
</div></body></html>"""
