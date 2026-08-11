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

WHAT ADOPTION WOULD COST, BEYOND THE PROMPT

  * One more LLM call per rubric per pass.

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

from app.ingest.github_fetch import fetch_repo_zip as github_fetch_repo_zip
from app.llm import pricing
from app.llm.client import LLMClient
from app.scan.llm_scan import (
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
        "The screen goes blank or stays empty: a component tree with no error "
        "boundary above the routes, so one render error replaces the whole "
        "app with a white page; a render that reads through data before it "
        "has arrived, with no loading branch; an error path that returns null "
        "and shows the user nothing at all.\n"
        "\n"
        "The user acts twice: a form or button left enabled while its own "
        "submit is in flight, so an impatient second click sends a second "
        "request. This is the browser half of a duplicate charge -- the "
        "server half is a missing idempotency key -- and it is the half the "
        "person clicking can see. An impatient double click is not an edge "
        "case; it is what people do when nothing visibly happens.\n"
        "\n"
        "Work disappears: state a long flow keeps only in memory, so a "
        "refresh or a back gesture loses what the user typed; leaving a "
        "dirty form with nothing asking them to confirm.\n"
        "\n"
        "The screen lies about what happened: a catch that swallows the error "
        "and leaves the previous state on screen, so a failed save looks like "
        "a successful one; a success message shown before the request "
        "resolves; two fetches racing in an effect with no cleanup or abort, "
        "so a slow first response overwrites a fresher second one.\n"
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
        "locally and instantly."
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


def fetch_repo_zip(repo_url: str) -> io.BytesIO:
    """Fetch through the same path a real audit uses, so the file set matches."""
    owner_repo = repo_url.rstrip("/").removeprefix("https://github.com/")
    owner_repo = owner_repo.removesuffix(".git")
    owner, _, repo = owner_repo.partition("/")
    return io.BytesIO(github_fetch_repo_zip(owner, repo))


def run_one(repo_url: str, client: LLMClient) -> tuple[int, float]:
    print(f"\n{'=' * 70}\n{repo_url}\n{'=' * 70}")
    buf = fetch_repo_zip(repo_url)
    with zipfile.ZipFile(buf) as zf:
        files = _iter_code_files(zf)
    files_by_name = dict(files)

    selected = select_files(files, CANDIDATE_KEY)
    if not selected:
        print("no rubric-relevant files")
        return 0, 0.0

    print(f"{len(selected)} files selected")
    raw, usage = client.complete(
        SYSTEM_PROMPT,
        build_prompt(selected, CANDIDATE_KEY),
        max_tokens=8192,
    )

    kept = 0
    for f in parse_findings(raw):
        if not verify_finding(f, files_by_name):
            print(f"  [DISCARDED by verifier] {f.get('title', '?')}")
            continue
        kept += 1
        print(f"\n  [{f['severity'].upper()} conf={f['confidence']}] {f['title']}")
        print(f"    {f['file']}:{f['line_start']}")
        print(f"    why:  {f.get('explanation', '')}")
        print(f"    fix:  {f.get('fix_hint', '')}")

    cost = float(pricing.cost_usd(
        usage.model, usage.input_tokens, usage.output_tokens))
    print(f"\n  -> {kept} verified findings, ${cost:.4f}")

    return kept, cost


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    install_candidate()

    client = LLMClient.from_env()
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
