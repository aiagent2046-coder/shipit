"""Self-contained HTML report for an audit result.

Every value that originates from the archive or the LLM (file names,
titles, evidence masks) is hostile and is HTML-escaped. No external
assets: the report is a single file that can be shared as-is.
"""

from __future__ import annotations

from html import escape

from app.report.grouping import group_for_display
from app.report.plain_language import plain_fields, tier
from app.scan.scoring import (CRITICAL_GATE_MIN_CONFIDENCE, GATE_THRESHOLD,
                              GATED_MAX, LLM_ONLY_CATEGORIES)
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


# A category is published as a band, not as a number, because a number is
# more precision than the measurement has.
#
# MEASURED. Three audits of Avisafety-1/blank-slate, same revision, same
# model, byte-identical input (prompt_chars 4,161,116 and input_tokens
# 1,463,735 on all three):
#
#     Security       3.1   1.8   2.2      swing 1.3
#     Money & Data   0.0   0.3   1.1      swing 1.1
#     Auth           6.9   7.5   6.8      swing 0.7
#     total          4.1   4.0   4.1      swing 0.1
#
# So one decimal place on a category claims +/-0.05 where the measurement
# carries +/-1.3. The total is a different matter and keeps its number: the
# static categories are constant and damp it, and it moved a tenth across
# those three runs.
#
# The boundary at GATE_THRESHOLD is not chosen for looks. It is the line the
# scorer already treats as the difference between a safety category that
# holds and one that does not (see _apply_gate), so a reader who crosses it
# has crossed something the engine acts on. The lower boundary is half of it:
# a category at 3.5 has roughly twice the penalty of one at 7.0, which is the
# coarsest statement the numbers support.
#
# Three bands rather than four: at a swing of 1.3, narrower bands would put
# the same repository in different bands on consecutive runs, which is the
# defect this replaces wearing fewer decimal places.
_BAND_FLOOR = GATE_THRESHOLD / 2.0


# The row's CSS class is `.cat-band`: the same shape as `.cat-skip`, because
# a phrase does not fit `.cat-val`'s 34px numeric column, but in the body
# colour rather than the muted grey -- "serious problems" is a verdict the
# scan stands behind, where "not checked" is an absence.
#
# Written here and not beside the rule, because that stylesheet is emitted
# verbatim into the customer's report: a CSS comment is shipped prose. This
# one said the words "not checked" and broke a test that reads the whole
# document, which is a cheap way to be reminded that the style block is
# output and not source.


# The categories whose rows may not claim the top band, because they hold a
# finding the same page marks "Fix before launch" or "Important".
#
# Measured twice, two days apart. Audit ba360e21: Auth held an
# unauthenticated endpoint taking user_id from the query string and unsalted
# SHA-256 passwords -- two highs -- and banded "nothing serious found",
# because one high costs 1.0 x confidence against a threshold of 7.0: a
# category needs FOUR confident highs to leave the top band. Audit b4bf9c07:
# Auth top-banded over "No authentication on any API endpoint". Banding made
# this worse than the number it replaced -- "7.2" invited doubt, a sentence
# asserts.
#
# Render-side, not scorer-side. The scorer already keeps a critical-holding
# category out of the top band (the GATED_MAX ceiling in compute_scores), but
# extending that to highs would push gated categories under GATE_THRESHOLD
# and fire the total's gate -- a fleet-wide scoring change wearing a wording
# fix's clothes. Only the sentence lies; only the sentence changes. Doing it
# here also fixes every STORED audit, including pre-ceiling rows like
# kristina_agent_center's Auth 8.1 over a root-shell endpoint, which no
# scorer change can reach.
#
# The floor is the critical gate's own (0.7), for its own reason: severity is
# a claim about impact, confidence a claim about certainty, and a band -- a
# categorical sentence -- needs a floor rather than the weighted arithmetic.
def _serious_categories(findings: list[dict]) -> set[str]:
    return {str(f.get("category")) for f in findings
            if str(f.get("severity")) in ("critical", "high")
            and float(f.get("confidence", 0)) >= CRITICAL_GATE_MIN_CONFIDENCE}


def _band(value: float, holds_serious: bool = False) -> tuple[str, int, str]:
    """(what the row says, how full the bar is drawn, what colour) for a
    scored category.

    Everything visible about the row comes from here, and that is the point.
    The bar snaps to the band because leaving it proportional would re-publish
    the exact number as a width -- the same claim, made in pixels. The colour
    is here for the same reason and was missed the first time: the row kept
    _score_color, whose boundaries are 8 and 5, and the bands' are 7.0 and
    3.5. A real report (audit b504326, Drydock auditing itself) drew Security
    5.3 yellow and Money & Data 3.9 red under identical text and identical
    width -- two rows in the same band, told apart only by colour, with
    nothing on the page to say what the colour meant. Three channels, one
    source.

    _score_color still colours the headline ring, which is correct: the total
    IS published as a number, and its swing across three byte-identical runs
    was 0.1.
    """
    if value >= GATE_THRESHOLD:
        if holds_serious:
            # The override forbids the top band; it never lifts a row. A
            # category whose arithmetic already reads lower keeps its lower
            # band -- the two branches below are unreachable from here.
            return "problems found", 60, "#f5d90a"
        return "nothing serious found", 100, "#30a46c"
    if value >= _BAND_FLOOR:
        return "problems found", 60, "#f5d90a"
    return "serious problems", 25, "#e5484d"


def _bar(label: str, value: float, examined: bool = True,
         elsewhere: list[str] | None = None, partial: bool = False,
         serious: bool = False) -> str:
    """One category row. Neither flag set means a real bar and a real number.

    An unexamined category sits at 10.0 because nothing produced a finding
    in it, not because it is clean. Drawing that as a full green bar is the
    most misleading thing this report can do -- it answers the reader's
    question ("is my auth safe?") with a confident yes nobody checked. The
    row stays, because hiding it would make the audit look narrower than it
    was; only the claim goes.

    `elsewhere` is the second way a 10.0 lies, and it needs its own wording
    rather than reusing "not checked": the rubric DID run, and it DID find
    something -- the finding is simply filed under the category it belongs to.
    Auth read 10.0 on a repository whose endpoint runs shell commands with no
    login check, because the model correctly called that a Security problem.
    """
    if elsewhere:
        # Examined, and NOT clean: this rubric found things and they are
        # counted under another heading. "not checked" would be a second
        # falsehood -- it sends the reader hunting for an audit that already
        # happened -- so the row names the destination instead.
        where = ", ".join(escape(c) for c in elsewhere)
        return (
            f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
            f'<div class="track"></div>'
            f'<span class="cat-val cat-skip">reported under {where}</span></div>'
        )
    if partial:
        # The third state, and the one that took two tabs side by side to see.
        # A free scan drew Security as a full green 10.0 on a repository whose
        # paid audit found an SSRF, a service-role key used as an HMAC secret
        # and hardcoded bot credentials -- because the regexes that ran found
        # nothing, and a category checked one way renders identically to a
        # category checked every way.
        #
        # "not checked" would be wrong here (something did run) and a number
        # would be worse (it reads as a verdict). The row says the scan was
        # partial and the scope note above it says exactly what ran.
        return (
            f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
            f'<div class="track"></div>'
            f'<span class="cat-val cat-skip">partly checked</span></div>'
        )
    if not examined:
        return (
            f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
            f'<div class="track"></div>'
            f'<span class="cat-val cat-skip">not checked</span></div>'
        )
    label_text, pct, colour = _band(value, holds_serious=serious)
    return (
        f'<div class="cat"><span class="cat-name">{escape(label)}</span>'
        f'<div class="track"><div class="fill" style="width:{pct}%;'
        f'background:{colour}"></div></div>'
        f'<span class="cat-val cat-band">{label_text}</span></div>'
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


def _category_label(f: dict) -> str:
    """Which bar this finding scored in, and where it was filed from.

    The page draws six category bars and a table of findings, and until now
    nothing joined them. A real paid report (audit fb00b177) published
    Security 9.0 directly above a table containing predictable hardcoded
    passwords for a hundred accounts, an SSRF, and a service-role key used to
    derive user passwords. Both halves can be right -- a finding is filed by
    what it IS, not by which rubric found it, so those three can legitimately
    score under Auth -- but the page gave the reader no way to establish that.
    Unreconcilable is its own defect, whichever number turns out to be
    correct: 10.0 - sum(weight x confidence) is checkable arithmetic, and the
    one input it needs was the one thing not printed.

    `origin_category` is named when the finding moved, because that is the
    question the bars raise most often: a category can read a perfect 10.0
    for the specific reason that everything it found now scores next door.
    """
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
    emoji, tier_label = tier(sev)
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
        f'{risk_html}{fix_html}'
        f'<div class="tech">{tech_bits}</div></td>'
        '</tr>'
    )


# The heading and note over the damped findings. Constants, not literals in
# the middle of an f-string, because eight tests use the heading as a MARKER
# for where the section starts -- `html.index(heading) < html.index(path)` --
# and pinning placement should not pin the wording. Copy that eight
# assertions have to agree with is copy nobody corrects.
#
# "scaffolding", not "documentation", and "isn't part of your running app"
# rather than "doesn't run in production", because `ci_service` joined this
# section and a CI workflow is neither a test nor documentation, and it DOES
# run. What is true of every row here is that none of it serves the reader's
# users -- which is the claim the reassurance underneath actually rests on.
NON_PRODUCTION_HEADING = "In tests, examples and scaffolding"
NON_PRODUCTION_NOTE = (
    "These files aren't part of your running app. Usually the credentials "
    "here are deliberate fakes — worth a glance to confirm, not worth "
    "blocking a launch."
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

    # Whether this page publishes a headline number at all. It said "both
    # tiers publish a score now" and that has been false since the free tier
    # stopped: see the free-tier branch below, where the argument was made,
    # reversed on kristina_agent_center (9.9 static-only against 4.7 full, on
    # a repository that lets an unauthenticated caller run commands as root),
    # and never carried back up to here.
    #
    # A stale comment on a flag is not decoration. This one described the
    # opposite of the truth directly above the branch that decides what the
    # free page may claim, and the cap paragraph below shipped on the free
    # page for exactly as long as it stood.
    #
    # A missing basis means an audit from before the field existed. It is
    # treated as a full audit, exactly as it always was.
    scored = str(score.get("basis") or "") not in ("static_only",
                                                   "static+preview")
    # Grouped BEFORE sorting so a group sorts by the severity it kept, and
    # for display only — the score was computed over every row upstream and is
    # not recomputed here. See app/report/grouping.py for why the penalty is
    # deliberately left alone.
    findings = sorted(
        group_for_display(result.get("findings", [])),
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
    # Absent on every row stored before the key existed, which reads as "no
    # category handed its findings away" -- the same answer those rows already
    # give today, so nothing changes retroactively.
    moved = score.get("reported_elsewhere") or {}
    # On the free tier no category number is published. Not because the
    # arithmetic is wrong, but because none of these numbers is earned: the
    # free scan reads Security with regexes and one rubric on the cheapest
    # model, and Deploy and Testing by asking whether a file exists. A 10.0
    # from that is indistinguishable on the page from a 10.0 a full audit
    # produced, and the visitor cannot tell which they are looking at.
    #
    # What a free scan can honestly publish is what it looked at and what it
    # found. The scope note says the first; the findings table says the second.
    serious_cats = _serious_categories(findings)
    cats = "".join(
        _bar(name, val, examined=name not in unexamined,
             elsewhere=[str(d) for d in (moved.get(name) or [])],
             partial=not scored and name not in unexamined
             and name not in moved,
             serious=name in serious_cats)
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
    #
    # AND ONLY WHERE A SCORE IS PUBLISHED. This paragraph explains a headline
    # number, and a free scan has none. It shipped on the free page anyway and
    # a real report (audit 544b91bd) carried all three consequences at once:
    # it opened "This score cannot exceed 6.9" two paragraphs under "A free
    # scan does not produce a mark out of ten"; it published "Security 5.5",
    # the exact category number the page had just declined to publish, for a
    # row it had labelled "partly checked"; and 6.9 appears nowhere else on
    # that page, so the reader has nothing to reconcile it against.
    #
    # The free page already says what it looked at and shows what it found.
    # Withholding a number in one section and printing it in the next is not
    # a smaller claim than publishing it -- it is the same claim, made where
    # nobody thought to check it.
    gate_note = ""
    if scored and score.get("gated_by"):
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
            # Names only. This printed "Security 5.3, Money & Data 3.9" three
            # lines under the bars that had just declined to publish those
            # numbers -- the second time this paragraph has leaked a category
            # value the rows withhold (the first was on the free page, see
            # above). Withholding a number in one section and printing it in
            # the next is not a smaller claim; it is the same claim, made
            # where nobody thought to check it.
            #
            # The threshold itself stays, and is not a leak: it is the band
            # boundary the rows are drawn against, so naming a category here
            # says exactly what its row already says and nothing more.
            named = ", ".join(sorted({escape(str(r["category"]))
                                      for r in low}))
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
        # The third route into the gate does not fit "the audit found X", and
        # forcing it there would misdescribe it. A critical says the code is
        # dangerous; this says THE REPORT MAY NOT BE ABOUT THE RUNNING CODE.
        # It gets its own sentence, and it is the only one that can appear
        # alone -- a repository whose every category is clean still cannot
        # present a passing headline when its own CI deploys something else.
        scope = [r for r in score["gated_by"]
                 if r.get("kind") == "unaudited_deployment"]
        sentences = []
        if parts:
            sentences.append(
                f'This score cannot exceed {GATED_MAX:.1f} because the audit '
                f'found {" and ".join(parts)}.')
        if scope:
            named = ", ".join(sorted({escape(str(r.get("title") or
                                                 r.get("rule_id")))
                                      for r in scope}))
            sentences.append(
                f'This score cannot exceed {GATED_MAX:.1f} because the audit '
                f'may not describe the code you actually run ({named}). A '
                f'score is a statement about what we read, and this '
                f'repository ships something else.'
                if not parts else
                f'It is held there for a second reason: the audit may not '
                f'describe the code you actually run ({named}).')
        sentences.append(
            f'The whole scale is compressed into that range rather than the '
            f'number being clipped to it, so two repositories that both fail '
            f'this check are still ranked against each other — which is why '
            f'the score can read well below {GATED_MAX:.1f}. Categories are '
            f'scored independently and can read higher than the total.')
        gate_note = (
            f'<section><p class="secnote">{" ".join(sentences)}</p></section>'
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
        # The scope sentence is basis-specific because the two free depths are
        # no longer the same scan. A preview reaches a model; a static-only
        # result did not, either because the spend cap was reached or because
        # the provider failed. Printing the wider claim over the narrower scan
        # would overstate exactly the audit that is already the thinnest.
        if str(score.get("basis") or "") == "static+preview":
            ran = ('It checks credentials committed to the repository, a '
                   'committed .env, a .gitignore that misses secret files, '
                   'missing tests, missing CI and no Dockerfile, and then '
                   'runs one quick security review over the code.')
        else:
            ran = ('It checks credentials committed to the repository, a '
                   'committed .env, a .gitignore that misses secret files, '
                   'missing tests, missing CI and no Dockerfile.')
        tier_note = (
            '<section><p class="secnote">A free scan does not produce a mark '
            'out of ten, because it does not look at enough to earn one. '
            + ran + ' '
            + _unexamined_sentence(score) +
            ' The categories it did look at are marked "partly checked" '
            'rather than scored, because one pass with the fastest model is '
            'not the same examination a full audit makes. Finding nothing in '
            'the checks that ran is not the same as being sound: on one real '
            'repository this scan reported a single low finding while a full '
            'audit found an unauthenticated endpoint running commands as '
            'root.</p></section>'
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
            f'<h2 class="sechead">{NON_PRODUCTION_HEADING}</h2>'
            f'<p class="secnote">{NON_PRODUCTION_NOTE}</p>'
            + _findings_table(non_production)
        )

    # The paid tier's counterpart to the free scope note: what the list is and
    # is not. A full audit reads the code with a model twice and reports the
    # union (PAID_AUDIT_PASSES, app/scan/pipeline.py), because a model's
    # findings are a sample -- measured on four same-engine runs of unchanged
    # code, criticals reproduced ~81-100% but high-severity keys only 65-84%,
    # and one real BOLA appeared in two runs of four. Two passes lift union
    # coverage to roughly three-quarters, which is what this note claims and no
    # more. Only where a score is published: a free scan is one pass of the
    # cheapest model and may not promise "twice", exactly as the tier_note
    # above is basis-specific for the same reason.
    coverage_note = ""
    if scored:
        coverage_note = (
            '<section><h2 class="sechead">How complete is this list</h2>'
            '<p class="secnote">A full audit reads your code with a language '
            'model twice and reports the union of both passes. A model’s '
            'findings are not perfectly repeatable: on unchanged code, a '
            'second reading surfaces issues the first missed, which is why we '
            'run two. In our own measurements two passes catch roughly '
            'three-quarters of what repeated readings agree is there — '
            'criticals almost every time, lower-severity findings less '
            'reliably. So a finding here is real; the absence of one is weaker '
            'evidence than its presence. Treat this as the strongest issues we '
            'can confirm, not a proof the rest is clean.</p></section>')

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
.cat-band{{font-size:12px;width:auto;white-space:nowrap}}
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
{coverage_note}
<footer>Generated by Drydock — free audit, verified fixes as pull requests.</footer>
</div></body></html>"""
