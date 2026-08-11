#!/usr/bin/env python3
"""Measure whether a rubric about the browser earns a place in the audit.

WHY THIS ONE, AND WHY NOW

The two oldest rubrics look for an attacker. The money rubric looks for what a
normal year in production does to code written fast, and that framing is what
made it worth its cost: on dubinc/dub it found four CRITICAL findings the
security rubric was silent about.

This candidate applies the same framing one layer out. Nobody attacks a user
into losing the form they were filling in; a refresh does it. Nobody exploits
a missing error boundary; a render error does it, and the user sees a white
page instead of an app.

There is a second reason, and it is the decisive one. A measurement run on
2026-08-11 showed that `digital-rolecraft` -- a Lovable export, which is the
segment this product exists for -- reads NO environment variables at all and
has no backend. Its whole surface is the browser. The money and config
questions cannot find anything there by construction, so for that customer
this is the only rubric that can say anything at all.

WHY THE RUBRIC LIVES HERE AND NOT IN RUBRICS

Same reason validate_money_rubric.py held its own copy until #219: nothing has
shipped, and running this must not change what a paying customer receives.

That copy later became a trap -- the shipped prompt and the script's draft
drifted by 185 characters, and anyone running it to decide whether the rubric
paid for itself was measuring something production never sent. So the moment
this ships, DELETE the dict below and read RUBRICS["web"] instead, exactly as
validate_money_rubric.py does now.

WHAT THE FIRST MEASUREMENT SHOWED, AND WHAT IT CHANGED

Run of 2026-08-11, hand-verified against local clones: 6 findings on
digital-rolecraft (4 real), 6 on nextjs-subscription-payments (6 real), 10 on
dub (1 real). Every one of dub's seven false findings said the same thing --
"this submit button is not disabled while its request is in flight" -- and
every one of them was refuted by a single line the model never saw:

    packages/ui/src/button.tsx:114   disabled={props.disabled || loading}

In dub, passing `loading` sets the HTML `disabled` attribute. In
nextjs-subscription-payments it does not, and there the model read Button.tsx
-- it was one of only 23 selected files -- and got every finding right,
reasoning out loud from that file. Precision tracked exactly one thing:
whether the design-system primitive was in the context.

So the defect was in selection, not in the prompt. select_files ranks by
keyword density and path class, and on a 4212-file monorepo the shared
primitives lose that race to the 325 components that consume them -- the
question is asked in the consumer and answered in the primitive.

Hence select_with_primitives below. It lives here, not in llm_scan, for the
same reason CANDIDATE does: nothing has shipped, and a change to select_files
moves PROMPT_FINGERPRINT and AUDIT_ENGINE_VERSION, which invalidates the
audit cache for every paying customer.

THAT THEORY WAS WRONG, AND HOW THE SECOND RUN SHOWED IT

Second run, same three repositories, with the buffer in place and the prompt
deliberately untouched so only one variable moved: 5 of 6 real on
digital-rolecraft, 5 of 7 on nextjs-subscription-payments, 2 of 12 on dub.
Precision 12 of 25, against 11 of 22 before. No improvement.

packages/ui/src/button.tsx WAS in the prompt -- the script prints it in the
list of files the buffer recovered -- and the model still wrote, ten times,
that a button only shows a spinner and is never disabled. The clearest case
was oauth-apps/add-edit-app-form.tsx, reported as "not disabled while
`saving` is true" when line 602 of that same file reads `loading={saving}`.

So availability was never the variable. In nextjs-subscription-payments the
Button is 1.4 KB in a 23-file prompt and the model reads it, quotes it, and
gets all six findings right; in dub it is 5 KB in a 272-file prompt and the
model does not consult it. The fix therefore belongs in the prompt: the
instructions now refuse the claim unless the props-to-`disabled` mapping is
quoted. That is the third run's single variable.

The buffer stays. It is cheap, it broke nothing, and one of dub's two real
findings came from a file it recovered -- but it does not sell the rubric,
and it was adopted for a reason that turned out to be false.

THIRD RUN: THE RULE WORKED, AND EXPOSED THE NEXT LAYER

8 of 8 real on nextjs-subscription-payments, up from 6: given the rule, the
model applied the Button.tsx mapping across the whole codebase rather than
only where it had tripped, and found three more real ones in the auth forms.
On dub every false double-submit claim disappeared -- it now quotes
`packages/ui/src/button.tsx line 114` and reaches the right conclusion every
time.

And then reports that conclusion as a finding. Five of dub's six read like
"[HIGH conf=0.9] Retry payment: double-submit correctly guarded via ref ...
No action needed." Correct analysis, useless output, on a list the customer
is paying to be a list of repairs. Hence the paragraph that says silence is
the right answer for code that is already right -- the rubric had never been
told, because until this run it had never been correct often enough for it
to matter.

Two false positives at 0.95 survived on digital-rolecraft, both of the form
"the handler calls an async function that sets the flag on its own first
line, so the flag is set too late". It is not: the call is synchronous and
the await inside it happens afterwards.

FOURTH RUN: THE PATTERN UNDERNEATH ALL FOUR

Worst of the four. 3 of 6 real on digital-rolecraft, 5 of 5 on
nextjs-subscription-payments -- down from 8, the suppression rule took three
true auth-form findings with it -- and 0 of 8 on dub. Running totals, all
hand-verified against clones: 11/22, 12/25, 12/21, 8/19.

Two things are now clear, and neither is a prompt bug.

The first is variance. GroupChat.tsx:22, a real Rules-of-Hooks crash, appears
in runs 1, 2 and 3 and is absent from run 4. The three auth-form findings
appear only in run 3. CreatePersonaForm's missing beforeunload appears in 1,
2 and 4 but not 3. The input is byte-identical every time. Run-to-run spread
is larger than the effect of any edit made here, which is why three rounds of
reading a signal out of it produced three different theories.

The second is a clean split in what survives. Findings that rest on SYNTAX --
a `loading` prop the component never maps to `disabled`, a `handleRequest`
called without `await`, no error boundary above the routes, no beforeunload
on a dirty form, a setTimeout with no cleanup -- were correct in every run
they appeared in. Findings that rest on TIMING -- a flag set 'too late', a
state update that 'has not propagated', a click that lands 'before the
re-render' -- were wrong in every run, all four, including the run whose
instructions refuted that exact argument in advance. Run 4's dub findings
quote `packages/ui/src/button.tsx line 114`, note that it disables the
button, and then argue past it anyway.

That is a capability boundary, not a wording problem, and it was addressed
three times with words. So the timing argument is no longer refuted; it is
forbidden as a ground. The syntactic half of the same question stays, because
it is what found Pricing.tsx, CustomerPortalForm, NameForm, EmailForm and the
three auth forms -- every real double-submit finding across four runs.

WHAT THE RUBRIC ASKS NOW, AND WHY IT IS SIX THINGS

The same split, applied to the whole rubric rather than to one question. The
instructions were four themes; they are now six numbered questions, each
settled by reading lines. Every one of them earned its place by producing a
finding that survived hand-verification in the runs it appeared in:

  1. no error boundary above the routes      (4 of 4 runs, always true)
  2. a flag cleared after an await, no finally (SimulatorChat:33, GroupChat:80)
  3. a dirty form with no beforeunload        (3 of 4 runs, always true)
  4. a timer or listener with no cleanup      (4 of 4 runs, always true)
  5. a hook called conditionally              (3 of 4 runs; GroupChat:22 is a
     real crash, and Navlinks:16 is why the condition must be able to change)
  6. an in-flight prop the component never maps to `disabled`, and the
     missing `await`                          (4 of 4 runs on the money path)

What was cut had four runs to prove itself and did not: the racing fetches,
the optimistic update that might diverge, the swallowed error behind a toast.
Each produced confident prose about code that turned out to be correct. A
rubric that asks a question the model cannot answer reliably does not fail
quietly -- it fails by inventing an answer, and the verifier cannot catch it
because the quoted line really is there.

WHAT ADOPTION WOULD COST, BEYOND THE PROMPT

  * One more LLM call per rubric per pass.

  * The primitive buffer, permanently, in select_files: measured at 105 KB of
    a 900 KB budget on dub, 30 KB on digital-rolecraft, 2 KB on
    nextjs-subscription-payments.

  * A new score category. Auth, Deploy, Testing, Security and Money & Data are
    what compute_scores knows; none of them is where "the page goes blank"
    belongs. Adding a sixth renormalises every weight, and a category that is
    usually clean sits at 10.0 and props up every total -- measured at +0.29
    on the average for the money rubric's fifth category. That is a scoring
    decision, not a prompt decision, and it is not made by this script.

USAGE

    python scripts/validate_web_rubric.py <repo_url> [<repo_url> ...]

Read the findings. The count is not the answer: a rubric that reliably
produces plausible-looking nonsense is worse than no rubric, because the
verifier only proves the quoted line exists -- not that the concern is real.
"""

from __future__ import annotations

import io
import re
import sys
import zipfile
from pathlib import Path

# Same line as eleven sibling scripts, for the same reason: Python puts the
# SCRIPT's directory on sys.path, never the working directory, so `python
# scripts/validate_web_rubric.py` from the repo root cannot import app/ on its
# own. It ran anyway for two days because every invocation carried
# `PYTHONPATH=.` in front of it, and it kept passing the test suite because
# the development venv holds an editable install of this package -- two
# separate reasons the defect could not be seen from here. It surfaced on the
# server, whose venv is a built release with neither.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ingest.github_fetch import fetch_repo_zip as github_fetch_repo_zip  # noqa: E402
from app.llm import pricing  # noqa: E402
from app.llm.client import LLMClient  # noqa: E402
from app.scan.llm_scan import (  # noqa: E402
    MAX_FILE_CHARS,
    MAX_TOTAL_CHARS,
    PRESENTATION,
    RUBRICS,
    SYSTEM_PROMPT,
    _iter_code_files,
    build_prompt,
    parse_findings,
    select_files,
    verify_finding,
)

CANDIDATE_KEY = "web"

# Files whose NAME is a design-system primitive: button.tsx, not
# retry-payment-modal.tsx. The leading (^|/) is what draws that line -- it
# anchors the word at the start of the basename, so the twenty consumer
# components with "modal" or "form" somewhere in their name do not match and
# do not spend the buffer.
#
# Deliberately crude, and named by hand rather than resolved from imports. One
# import hop from the selected files would be more precise and would also
# catch a primitive nobody thought to list; it is also a real change to
# select_files, and the point of this pass is to find out whether the theory
# is right at all before paying for the precise version.
_PRIMITIVE_NAME = re.compile(
    r"(^|/)(button|buttons|form|input|textarea|select|checkbox|switch|toggle"
    r"|modal|dialog|drawer|sheet|popover|dropdown|tooltip|spinner)"
    r"\.[jt]sx?$",
    re.I,
)

# packages/ui/src/icons/nucleo/checkbox.tsx is an SVG, not the checkbox.
_PRIMITIVE_NOISE = re.compile(r"(^|/)icons?/", re.I)

# Measured ceiling, not a guess: the largest of the three repositories spends
# 105 KB here. The cap exists so that a repository which names three hundred
# files button.tsx cannot quietly eat the prompt -- the buffer is supposed to
# answer a question, not become the answer.
PRIMITIVE_BUDGET = 140_000

CANDIDATE = {
    # Only used if this ever ships; nothing here is scored. See the module
    # docstring on why the category is an open question.
    "category": "Deploy",
    # PRESENTATION is the whole reason the weighting became per-rubric. Under
    # the old global weighting, ui/ and components/ were divided by four, so a
    # rubric about the frontend would have been shown everything except the
    # frontend -- and would have looked like a bad idea rather than a
    # misconfigured one.
    "lives_in": PRESENTATION,
    "keywords": re.compile(
        r"\b(useState|useEffect|useRef|useCallback|onSubmit|onClick|onChange"
        r"|preventDefault|disabled|isLoading|isSubmitting|isPending|setLoading"
        r"|spinner|skeleton|ErrorBoundary|componentDidCatch|Suspense|fallback"
        r"|localStorage|sessionStorage|beforeunload|toast|notify"
        r"|useSWR|useQuery|useMutation|AbortController|router)\b"
        r"|\bfetch\(|\baxios\b|\balert\(|\bconfirm\(",
        re.I,
    ),
    "instructions": (
        "Review what breaks for the person using this app in a browser. "
        "Assume the code is deployed, the user behaves normally, and the "
        "network is sometimes slow. No attacker is involved. Report only "
        "concrete issues you can point at a line for.\n"
        "\n"
        "Six questions, and only these six. Each is settled by reading lines, "
        "not by reasoning about what happens between them.\n"
        "\n"
        "1. THE SCREEN GOES BLANK. No error boundary anywhere above the "
        "routes, so one render error replaces the whole app with a white "
        "page. In the Next.js app router an error.tsx or global-error.tsx "
        "file is that boundary; if you see one, there is nothing to report.\n"
        "\n"
        "2. THE APP STAYS STUCK. A handler sets a flag before an await and "
        "clears it after, with no try/finally around them, so a throw leaves "
        "the spinner running and the input disabled until the user reloads. "
        "The proof is the absence of `finally`, and that the clear sits after "
        "an await rather than inside one. A `catch` that does not clear the "
        "flag counts too. Check the callee for expressions outside its own "
        "try -- an argument built from `x.y.join()` before the try begins can "
        "throw where a reader assumes it cannot.\n"
        "\n"
        "3. WORK DISAPPEARS. A form the user fills in over minutes, kept only "
        "in component state, with no beforeunload listener and no router "
        "blocker, so a stray click on a nav link discards it silently.\n"
        "\n"
        "4. SOMETHING KEEPS RUNNING. A setTimeout, setInterval, subscription "
        "or event listener started in an effect or a callback with no cleanup "
        "that cancels it, so it fires against a component the user has left.\n"
        "\n"
        "5. A HOOK IS CALLED CONDITIONALLY. A useState or useEffect after an "
        "early return, or a useRouter() inside a ternary. Report it only when "
        "the condition can differ between two renders of the same mounted "
        "component -- a prop, state or fetched data. When it reads a "
        "build-time constant the order never actually changes and the app "
        "does not crash: that is a lint violation and not a finding here.\n"
        "\n"
        "6. THE USER ACTS TWICE: a form or button left enabled while its own "
        "submit is in flight, so an impatient second click sends a second "
        "request. This is the browser half of a duplicate charge -- the "
        "server half is a missing idempotency key -- and it is the half the "
        "person clicking can see. An impatient double click is not an edge "
        "case; it is what people do when nothing visibly happens.\n"
        "\n"
        "Before you claim a control is still clickable, QUOTE the line in the "
        "component that renders it -- Button, Switch, the control itself -- "
        "that maps its props onto the HTML disabled attribute. Codebases "
        "differ here and the difference decides the finding: in one, "
        "`disabled` must be passed explicitly and a `loading` prop only draws "
        "a spinner; in another, the same component reads "
        "`disabled={props.disabled || loading}`, so `loading={isSubmitting}` "
        "already disables the button and there is nothing to report. A "
        "`disabled` prop that omits the in-flight flag proves nothing on its "
        "own. If you have not read that mapping, you do not know which "
        "codebase you are in: say so, phrase the finding as the question it "
        "is, and report confidence 0.5 or lower.\n"
        "\n"
        "There is exactly ONE ground for this finding: the control has no "
        "in-flight prop at all, or it has one and the component you just "
        "quoted does not turn it into `disabled`. That is a fact about two "
        "lines of code, and it is the only fact you may report here.\n"
        "\n"
        "TIMING IS NOT A GROUND. Never report that a flag is set 'too late', "
        "that a state update 'has not propagated yet', that the button 'is "
        "not disabled at the moment of the first click', or that a second "
        "click lands 'before the re-render'. If a handler sets its flag, or "
        "a ref, or calls a function that does -- anywhere before its first "
        "await -- the control is guarded and there is nothing to report. So "
        "is a disabled input or textarea, which receives no key events at "
        "all. Once you have quoted a guard, you are finished: an argument "
        "that gets past it is wrong, and it is wrong every time, because the "
        "click that would exploit the window is delivered after the update "
        "that closes it.\n"
        "\n"
        "When you check one of these and the code turns out to be correct, "
        "report NOTHING. Not a finding at confidence 0.9 whose explanation "
        "ends in 'no issue here', not an informational confirmation that a "
        "guard is present, not a finding whose fix reads 'no action needed'. "
        "The reader is paying for a list of things to repair; an item on that "
        "list that needs no repair costs them the time to discover it does "
        "not belong there, and makes them trust the rest of the list less. "
        "Silence is the correct output for code that is already right.\n"
        "\n"
        "The missing `await` belongs to question 6 as well, and is the "
        "clearest form of it: a handler that calls an async function without "
        "awaiting it and clears its in-flight flag on the next line. The flag "
        "is true for no time at all, so the spinner never appears and the "
        "control is never protected, whatever the component does with the "
        "prop.\n"
        "\n"
        "Severity, for the cases that are not judgement calls. A submit path "
        "that can fire twice is CRITICAL when the request spends money, "
        "creates an order or sends a message, and high otherwise. A missing "
        "error boundary above the application's routes is high: it converts "
        "every other bug in the app into a blank page.\n"
        "\n"
        "Point at the line that PROVES the claim. If the code that would "
        "settle it is not among the files you were given -- the provider that "
        "might wrap these routes in a boundary, the hook that might already "
        "disable the button -- say so, phrase the finding as the question it "
        "is, and report confidence 0.5 or lower.\n"
        "\n"
        "Do NOT report styling, layout, accessibility or bundle size. Those "
        "are real and they are not this rubric.\n"
        "\n"
        "Do NOT report server-side issues: a missing idempotency key on the "
        "handler, an unindexed query, a webhook with no signature check. "
        "Other rubrics cover those, and a duplicate here spends a finding "
        "slot on something already reported.\n"
        "\n"
        "Do NOT report a missing loading state on something that resolves "
        "locally and instantly.\n"
        "\n"
        "Do NOT report anything outside the six questions, however real it "
        "looks. A race between two fetches, an optimistic update that could "
        "diverge from the server, a catch that shows a toast the user might "
        "miss -- these were measured, and what came back was confident prose "
        "about code that turned out to be correct. If it is not one of the "
        "six, it is not a finding."
    ),
}


def install_candidate() -> None:
    """Put the candidate where select_files and build_prompt look for it.

    Called from main(), NOT at import. The first version did it at import and
    three tests failed the moment the whole suite ran in one process: the
    cost-cap check counted a fourth rubric, the prompt fingerprint moved, and
    the guard that every shipped rubric keeps the BEHAVIOUR weighting saw a
    PRESENTATION one. The comment there claimed the injection was harmless
    because llm_scan's import-time category assertion had already run. That
    was true and beside the point -- it cannot weaken that assertion, and it
    disturbs everything that reads RUBRICS afterwards.

    A measurement harness that quietly reweights the rubrics it is not
    measuring would invalidate its own numbers, so the mutation happens once,
    in the process that is about to make LLM calls and nowhere else.
    """
    RUBRICS[CANDIDATE_KEY] = CANDIDATE


def select_with_primitives(
    files: list[tuple[str, str]], rubric: str,
) -> list[tuple[str, str]]:
    """select_files, with the design-system primitives it drops put back.

    Seeded FIRST and unconditionally -- in particular without consulting the
    rubric's keyword regex, which is the whole point. On digital-rolecraft
    `tooltip.tsx`, `popover.tsx` and `form.tsx` do not match a single one of
    the rubric's keywords, and all three decide whether a control is disabled.
    Ranking them would not help; they are not in the ranking at all.

    Smallest first, so the buffer buys as many distinct primitives as it can
    rather than one large one. Whatever budget is left goes to select_files
    exactly as before, and its tail is dropped to stay inside MAX_TOTAL_CHARS
    -- the tail is the breadth pass, the least relevant end of it.
    """
    primitives = sorted(
        (
            (n, t[:MAX_FILE_CHARS]) for n, t in files
            if _PRIMITIVE_NAME.search(n) and not _PRIMITIVE_NOISE.search(n)
        ),
        key=lambda x: (len(x[1]), x[0]),
    )

    selected: list[tuple[str, str]] = []
    seeded: set[str] = set()
    total = 0

    for n, t in primitives:
        if total + len(t) > PRIMITIVE_BUDGET:
            continue
        selected.append((n, t))
        seeded.add(n)
        total += len(t)

    for n, t in select_files(files, rubric):
        if n in seeded or total + len(t) > MAX_TOTAL_CHARS:
            continue
        selected.append((n, t))
        total += len(t)

    return selected


def fetch_repo_zip(repo_url: str) -> io.BytesIO:
    """Fetch through the same path a real audit uses, so the file set matches."""
    owner_repo = repo_url.rstrip("/").removeprefix("https://github.com/")
    owner_repo = owner_repo.removesuffix(".git")
    owner, _, repo = owner_repo.partition("/")
    return io.BytesIO(github_fetch_repo_zip(owner, repo))


def digest_line(finding: dict) -> str:
    """One finding, reduced to what two runs can be compared on.

    Wanted because run-to-run spread turned out larger than the effect of any
    edit made to this rubric: GroupChat.tsx:22, a real crash, is present in
    three of four runs and absent from the fourth, on byte-identical input.
    Reading two transcripts side by side to notice that is how three rounds
    of prompt work each read a signal out of the noise.

    The prose is deliberately dropped -- it is reworded every run for the same
    defect, which is exactly what defeats eyeballing. File, line and severity
    identify the claim; confidence is left out so a 0.85/0.9 wobble on the
    same finding does not read as a difference.

        grep '^DIGEST' run-a.txt | sort > a
        grep '^DIGEST' run-b.txt | sort > b
        diff a b
    """
    where = f"{finding['file']}:{finding['line_start']}"
    return f"DIGEST {finding['severity'].upper():8} {where}"


def run_one(repo_url: str, client: LLMClient) -> tuple[int, float]:
    print(f"\n{'=' * 70}\n{repo_url}\n{'=' * 70}")
    buf = fetch_repo_zip(repo_url)
    with zipfile.ZipFile(buf) as zf:
        files = _iter_code_files(zf)
    files_by_name = dict(files)

    selected = select_with_primitives(files, CANDIDATE_KEY)
    if not selected:
        print("no rubric-relevant files")
        return 0, 0.0

    baseline = {n for n, _ in select_files(files, CANDIDATE_KEY)}
    added = [n for n, _ in selected if n not in baseline]
    print(f"{len(selected)} files selected "
          f"({len(added)} primitives the ranking had dropped)")
    for name in added:
        print(f"    + {name}")
    raw, usage = client.complete(
        SYSTEM_PROMPT,
        build_prompt(selected, CANDIDATE_KEY),
        max_tokens=8192,
    )

    kept, digest = 0, []
    for f in parse_findings(raw):
        if not verify_finding(f, files_by_name):
            print(f"  [DISCARDED by verifier] {f.get('title', '?')}")
            continue
        kept += 1
        digest.append(digest_line(f))
        print(f"\n  [{f['severity'].upper()} conf={f['confidence']}] {f['title']}")
        print(f"    {f['file']}:{f['line_start']}")
        print(f"    why:  {f.get('explanation', '')}")
        print(f"    fix:  {f.get('fix_hint', '')}")

    cost = float(pricing.cost_usd(
        usage.model, usage.input_tokens, usage.output_tokens))
    print(f"\n  -> {kept} verified findings, ${cost:.4f}")

    for line in sorted(digest):
        print(line)

    return kept, cost


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    install_candidate()

    client = LLMClient()          # providers come from the environment
    if not client.providers:
        print("no LLM provider configured", file=sys.stderr)
        return 1

    results, total = [], 0.0
    for repo_url in sys.argv[1:]:
        try:
            found, cost = run_one(repo_url, client)
        except Exception as error:                    # noqa: BLE001
            print(f"  FAILED: {type(error).__name__}: {error}")
            continue
        results.append((repo_url, found))
        total += cost

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    for repo_url, found in results:
        print(f"  {found:4d} findings  {repo_url}")
    hits = sum(1 for _, found in results if found)
    print(f"\nhit rate: {hits}/{len(results)} repos scanned")
    print(f"total spend: ${total:.2f}")
    print(
        "\nNow read the findings above. The count is not the answer -- the "
        "question is whether a user would notice the bug, and whether the "
        "quoted line really shows it."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
