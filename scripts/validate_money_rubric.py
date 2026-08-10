#!/usr/bin/env python3
"""Measure whether the money/data/bill rubric earns a place in the audit.

WHY THIS EXISTS, AND WHY IT IS NOT app/scan/llm_scan.py

Both shipped rubrics look for an attacker. Nothing looks for what a founder
actually loses sleep over: money taken wrongly, data deleted for good, or a
bill nobody budgeted for. None of those need an attacker -- they are what a
normal Tuesday does to code written fast.

Adding a rubric is not free in either direction:

  * Cost. One more LLM call per rubric per pass -- roughly +$0.20 on a free
    audit and +$0.40 on a Fix Pack's two passes, against a measured $0.55
    average audit cost today.

  * Score inflation. A new scored category renormalises every weight. If the
    rubric usually finds nothing, its subscore sits at a constant 10.0 and
    props up every total -- exactly the dead weight that got Correctness and
    Config deleted in issue #181. Measured against the 72 real audits holding
    category data, a fifth category that is always clean raises the average
    total by +0.29, landing entirely on the 32 audits the safety gate does
    not already cap.

Both objections come down to one number nobody has: how often does this
rubric find something real? So this script measures it before any of it ships.
It deliberately touches no production path -- the rubric lives here, not in
RUBRICS, so running it cannot change what a paying customer receives.

USAGE

    python scripts/validate_money_rubric.py <repo_url> [<repo_url> ...]

Prints, per repo, every finding with the file and line to check by hand, and
a summary of the hit rate. Read the findings; do not trust the count. A rubric
that reliably produces plausible-looking nonsense is worse than no rubric,
because the verifier only proves the quoted line exists -- not that the
concern is real.

WHAT TO DO WITH THE RESULT

  * Findings in most repos, and they hold up on inspection -> the rubric is
    earning the weight it already carries.
  * Findings rare but real -> its category sits near 10.0 and inflates every
    total; fold it into Security instead.
  * Mostly noise -> the prompt is wrong, not the idea. Tighten and re-run.

THE QUESTION ABOVE IS SETTLED; THIS NOW MEASURES THE SHIPPED RUBRIC

The rubric was wired into RUBRICS and CATEGORIES in #219, so "does it earn a
place" became "is it still earning it". This script used to carry its own
copy of the candidate prompt, which was correct while nothing shipped and a
trap afterwards: the two drifted by 185 characters, and the shipped one had
gained specifics -- content created by OTHER users, a scheduled job running
more often than its work needs -- that the copy never got. Anyone running
this to decide whether the rubric pays for itself was measuring a draft.

It reads RUBRICS["money"] directly now. One definition, and the numbers this
prints describe what a paying customer actually receives. It still touches
no production path: it reads the rubric, sends its own LLM calls, and writes
nothing.
"""

from __future__ import annotations

import io
import sys
import zipfile

from app.ingest.github_fetch import fetch_repo_zip as github_fetch_repo_zip
from app.llm import pricing
from app.llm.client import LLMClient
from app.scan.llm_scan import (
    RUBRICS,
    SYSTEM_PROMPT,
    _iter_code_files,
    build_prompt,
    parse_findings,
    select_files,
    verify_finding,
)

# The shipped rubric, by name. Not a copy: this script used to hold its own
# draft, which was right while nothing shipped and wrong the moment #219 wired
# one in -- the two drifted, and the numbers printed here stopped describing
# what production sends. Reading the key means a prompt change is measured the
# next time this runs, with no second edit to remember.
MEASURED_RUBRIC = "money"
assert MEASURED_RUBRIC in RUBRICS, (
    f"{MEASURED_RUBRIC!r} is not a shipped rubric; this script measures what "
    "app/scan/llm_scan.py actually sends, so a renamed rubric must be renamed "
    "here too rather than silently measuring nothing"
)



def fetch_repo_zip(repo_url: str) -> io.BytesIO:
    """Fetch through the same path a real audit uses.

    Not a hand-rolled archive download: app/ingest/github_fetch.py resolves
    the default branch via the API zipball endpoint and enforces the same
    size cap the free scan does. A validation run that fetched differently
    could select a different file set than production would, which is the
    one thing this measurement must not do.
    """
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

    selected = select_files(files, MEASURED_RUBRIC)
    if not selected:
        print("no rubric-relevant files")
        return 0, 0.0
    print(f"{len(selected)} files selected")
    raw, usage = client.complete(
        SYSTEM_PROMPT,
        build_prompt(selected, MEASURED_RUBRIC),
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


def main() -> None:
    repos = sys.argv[1:]
    if not repos:
        raise SystemExit(__doc__)

    # Line-buffered so a long run shows progress as it goes and, more to the
    # point, so nothing already printed is lost in the buffer if a later repo
    # kills the process -- output is normally block-buffered when piped to a
    # file or tee, which is exactly how this script is meant to be run.
    sys.stdout.reconfigure(line_buffering=True)

    client = LLMClient()          # providers come from the environment
    if not client.providers:
        raise SystemExit("no LLM providers configured")

    # One repo must not take the run down with it. A renamed or deleted repo
    # raises RepoFetchError, a provider hiccup raises LLMError, and either one
    # landing on the seventh of ten repos would otherwise discard the summary
    # for the six already paid for -- the same "money the provider bills
    # regardless" that pipeline.py keeps llm_usage separate from `llm` to
    # avoid. Failures are recorded as failures, never as a zero: counting a
    # crash as "found nothing" would quietly corrupt the one number this
    # script exists to produce.
    results: list[tuple[str, int | None]] = []
    total_cost = 0.0
    for repo in repos:
        try:
            found, cost = run_one(repo, client)
        except Exception as exc:                       # noqa: BLE001
            print(f"\n  !! FAILED: {type(exc).__name__}: {exc}")
            results.append((repo, None))
            continue
        results.append((repo, found))
        total_cost += cost

    print(f"\n{'=' * 70}\nSUMMARY\n{'=' * 70}")
    scanned = [(r, n) for r, n in results if n is not None]
    failed = [r for r, n in results if n is None]
    with_findings = sum(1 for _, n in scanned if n)

    for repo, n in results:
        print(f"  {'  --' if n is None else f'{n:>4}'} {'(failed)' if n is None else 'findings'}  {repo}")
    if scanned:
        print(f"\nhit rate: {with_findings}/{len(scanned)} repos scanned")
    if failed:
        print(f"not scanned ({len(failed)}): " + ", ".join(failed))
    print(f"total spend: ${total_cost:.2f}")
    print(
        "\nNow read the findings above. The count is not the answer -- the "
        "question is whether a founder would act on them."
    )


if __name__ == "__main__":
    main()
