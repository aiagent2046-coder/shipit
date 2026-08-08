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

  * Findings in most repos, and they hold up on inspection -> the category
    earns its weight; wire it into RUBRICS and CATEGORIES together, in one
    change, so the weight and its producer land at the same time.
  * Findings rare but real -> keep the rubric, fold it into Security rather
    than giving it a category that would sit at 10.0 and inflate.
  * Mostly noise -> the prompt is wrong, not the idea. Tighten and re-run.
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
    RUBRICS,
    SYSTEM_PROMPT,
    _iter_code_files,
    build_prompt,
    parse_findings,
    select_files,
    verify_finding,
)

# The candidate rubric, in the shape RUBRICS expects.
#
# "category" is deliberately absent: it is the open question this script
# exists to answer, and llm_scan asserts at import that every rubric in
# RUBRICS declares one the scorer knows. Leaving it out is what keeps this
# from being wired in by accident.
#
# The instructions name concrete, checkable patterns for the same reason the
# two shipped rubrics do -- "review for problems" returns essays, a list of
# specific mistakes returns findings with line numbers. Grouped by the three
# fears rather than by technology, because that is how the person reading the
# report holds them.
CANDIDATE = {
    # Anchored on word boundaries and on terms specific to the three fears.
    #
    # The first draft used bare substrings -- pay, order, limit, token, delete
    # -- which match ordinary prose and identifiers: "pay" is inside payload,
    # "order" inside any "in order to" comment, "limit" inside unlimited. A
    # dry run against this repository selected a Spinner component and the
    # terms-of-service page.
    #
    # That is not merely untidy. select_files fills a fixed content budget
    # smallest-file-first and stops, so junk does not just come along -- it
    # takes the place of something relevant. The broad draft matched 232 files
    # and could send only 112; 120 matched files were never seen by the model
    # at all. Anchoring cut matches to 162 and spends that same budget on
    # payments, migrations and scheduled work.
    "keywords": re.compile(
        # money
        r"\b(stripe|paypal|checkout|invoice|billing|subscription|refund|"
        r"payout|coupon|discount|currency|idempotenc\w*|webhook)\b"
        # data loss
        r"|\bdrop\s+table\b|\btruncate\b|\bon\s+delete\s+cascade\b"
        r"|\b(migration|rollback|soft.?delete)\b"
        # runaway spend
        r"|\b(openai|anthropic|cron|setInterval|max_tokens|backoff)\b"
        r"|\brate.?limit\w*\b",
        re.I,
    ),
    "instructions": (
        "Review for ways this app loses its owner money, loses user data, or "
        "runs up a bill -- WITHOUT an attacker. Assume every user behaves "
        "normally and the code still runs in production for a year. Report "
        "only concrete issues you can point at a line for.\n"
        "\n"
        "Money taken or lost wrongly: a price, amount or currency read from "
        "the client request instead of looked up on the server; a payment or "
        "webhook handler with no idempotency key or duplicate check, so the "
        "provider's normal retry credits the order twice; an order marked "
        "paid before the provider confirms; a refund, discount or credit "
        "computed client-side; money held in a float instead of a decimal or "
        "integer minor units; a paid feature gated only in the UI.\n"
        "\n"
        "Data lost for good: destructive SQL in a migration (DROP TABLE, "
        "TRUNCATE, DELETE or UPDATE with no WHERE) with nothing guarding it; "
        "ON DELETE CASCADE reaching user-created content; a multi-step write "
        "with no transaction, so a mid-way failure leaves half-written state; "
        "a delete path with no soft delete, no backup and no confirmation; "
        "object-storage deletion keyed on unvalidated user input.\n"
        "\n"
        "A bill nobody expects: a paid API, LLM or third-party call inside a "
        "loop, recursion or per-row iteration with no cap; an expensive "
        "endpoint reachable without auth or rate limiting; a query with no "
        "LIMIT or pagination over a table that grows forever; a scheduled job "
        "running far more often than its work needs; retry logic with no "
        "maximum attempts or backoff; an LLM call with no token ceiling.\n"
        "\n"
        "Do NOT report attacker-driven vulnerabilities -- injection, XSS, "
        "auth bypass, SSRF. Other rubrics cover those, and a duplicate here "
        "spends a finding slot on something already reported."
    ),
}


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

    RUBRICS["_candidate"] = CANDIDATE          # scoped to this process only
    try:
        selected = select_files(files, "_candidate")
        if not selected:
            print("no rubric-relevant files")
            return 0, 0.0
        print(f"{len(selected)} files selected")
        raw, usage = client.complete(
            SYSTEM_PROMPT,
            build_prompt(selected, "_candidate"),
            max_tokens=8192,
        )
    finally:
        RUBRICS.pop("_candidate", None)

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
