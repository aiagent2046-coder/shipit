"""A scanner may not join the engine without invalidating the cache.

WHY THIS EXISTS, and it is not hypothetical. Audits are cached on
`(content_hash, engine_version)`. Between 2026-08-18 and 2026-08-20 four
changes landed in the static stage — schema_drift (#298), service_role (#299),
the Fix Pack sellability stamp (#305) and ci_deploy_source (#306) — and none of
them moved AUDIT_ENGINE_VERSION. Every repository already in the cache went on
being served its pre-change result.

The failure is silent in the worst way: the customer re-runs the audit, gets a
byte-identical report, and concludes the new rule is broken. It is not broken.
It never ran, because the audit never ran.

The constant's own comment has said "bump when the static rules change" since
it was written. Three consecutive pull requests read past it, mine included.
So the instruction is now a test.

WHAT IT PINS is the set of scanners `run_static_scan` calls and the VOCABULARY
they emit — rule ids and damping contexts — not the rules inside them. A rule's
internals (a threshold, a pattern, the wording of an explanation) change
constantly and a test that noticed would be noise nobody keeps.

The vocabulary half was added after the same defect recurred one gap to the
left. #358 added no scanner, so the set below stayed correct and this file
stayed green, but it added a rule id (`connection-string-local-host`) and a
context (`ci_service`) — so a cached row disagreed with the running engine
about the same bytes, still carrying the advice the release existed to stop
printing. Adding or removing a scanner, a rule id or a context is a coarse,
rare event that reliably means "the engine would now answer differently"; those
are exactly the events that have happened five times.

WHEN THIS FAILS, do both halves:
  1. update the pinned set (WIRED_SCANNERS / EMITTED_RULE_IDS / DAMPING_
     CONTEXTS) to match reality, and
  2. bump AUDIT_ENGINE_VERSION in app/scan/pipeline.py.
Doing only the first reproduces the defect this file exists to prevent.
"""

from __future__ import annotations

import inspect
import io
import zipfile

from app.scan import pipeline, static

# Every scanner run_static_scan feeds into the findings list, by the name it is
# called by. Sorted, so a diff reads as one added or removed line.
WIRED_SCANNERS = (
    "run_checks",
    "scan_ci_deploy_source",
    "scan_rls",
    "scan_schema_drift",
    "scan_secrets",
    "scan_service_role",
)

# Every rule id a static finding can reach the reader under. Taken from the
# plain-language dictionary rather than from the rules themselves, and that is
# deliberate: tests/test_plain_language.py already fails if a rule id exists
# without an entry here, so this key set is a faithful stand-in for "what the
# static engine can say" — and unlike the rules, it is a plain runtime value
# with no source-text parsing between it and the truth.
EMITTED_RULE_IDS = (
    "anthropic-api-key",
    "aws-access-key-id",
    "connection-string-dev-password",
    "connection-string-local-host",
    "connection-string-password",
    "dependency-dir-committed",
    "env-file-committed",
    "generic-assignment",
    "github-pat",
    "gitignore-missing-secrets",
    "jwt-in-code",
    "no-ci",
    "no-dockerfile",
    "no-tests",
    "private-key-block",
    "sql-secret-assignment",
    "stripe-live-key",
    "supabase-anon-key",
    "supabase-demo-key",
    "telegram-bot-token",
)

# The damping vocabulary. A context decides which section of the report a
# finding lands in and whether the Fix Pack will touch it, so a new one changes
# what a reader sees for unchanged bytes exactly as a new rule id does.
DAMPING_CONTEXTS = (
    "ci_service", "comment", "doc_example", "test_file", "test_fixture",
)

# The version that was current when all three sets above last matched.
# Changing any of them without changing this is the whole defect.
ENGINE_VERSION_FOR_THAT_SET = "2026-08-28-1"


def _called_scanners(monkeypatch) -> tuple[str, ...]:
    """Scanner names run_static_scan actually CALLS, observed by calling it.

    An earlier version of this read the function's source text and asked which
    names appeared in it. Mutation testing killed that: neutering a scanner in
    place —

        for d in [] and scan_ci_deploy_source(fileobj):

    — leaves the name in the source, so the text-reading version reported a
    scanner that runs on nothing. The cache does not care what the source
    says; it cares what ran. So this runs it.
    """
    called: list[str] = []
    for name in dir(static):
        if not (name.startswith("scan_") or name.startswith("run_")):
            continue
        if name == "run_static_scan" or not callable(getattr(static, name)):
            continue
        monkeypatch.setattr(
            static, name,
            (lambda n: lambda *_a, **_k: called.append(n) or [])(name),
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("r/README.md", "# nothing to find")
    buf.seek(0)
    static.run_static_scan(buf)
    return tuple(sorted(called))


def test_the_wired_scanners_are_the_ones_this_version_was_stamped_for(
    monkeypatch,
) -> None:
    assert _called_scanners(monkeypatch) == WIRED_SCANNERS, (
        "run_static_scan's scanners changed. Update WIRED_SCANNERS *and* bump "
        "AUDIT_ENGINE_VERSION in app/scan/pipeline.py — without the bump, every "
        "repository already in the audit cache keeps being served its "
        "pre-change result and the new scanner runs on nothing."
    )


def test_the_emitted_rule_ids_are_the_ones_this_version_was_stamped_for() -> None:
    """The gap #358 fell through. It added no scanner -- the test above stayed
    green -- but it added a rule id, so a cached audit and the running engine
    disagreed about the same bytes while the cache went on serving the old one.
    """
    from app.report.plain_language import PLAIN

    assert tuple(sorted(PLAIN)) == EMITTED_RULE_IDS, (
        "the static engine's rule ids changed. Update EMITTED_RULE_IDS *and* "
        "bump AUDIT_ENGINE_VERSION in app/scan/pipeline.py — without the bump, "
        "every repository already in the audit cache keeps being served a "
        "result the current engine would no longer produce."
    )


def test_the_damping_contexts_are_the_ones_this_version_was_stamped_for() -> None:
    """Same argument as the rule ids: a context decides which section of the
    report a finding lands in, so a new one changes the page for unchanged
    bytes."""
    from app.scan.secrets import NON_PRODUCTION_CONTEXTS

    assert tuple(sorted(NON_PRODUCTION_CONTEXTS)) == DAMPING_CONTEXTS, (
        "the damping vocabulary changed. Update DAMPING_CONTEXTS *and* bump "
        "AUDIT_ENGINE_VERSION in app/scan/pipeline.py."
    )


def test_the_engine_version_moved_with_them() -> None:
    assert pipeline.AUDIT_ENGINE_VERSION == ENGINE_VERSION_FOR_THAT_SET, (
        "AUDIT_ENGINE_VERSION changed. If that was deliberate, update "
        "ENGINE_VERSION_FOR_THAT_SET here too — this is the record of which "
        "engine the current scanners, rule ids and contexts were cached under."
    )


def test_the_version_is_folded_into_the_cache_key() -> None:
    """The pin above is worth nothing if the cache stops consulting the
    version. Both call sites that reuse an audit pass it, and this is what
    notices if one of them stops."""
    from app import main

    source = inspect.getsource(main)
    assert "get_by_content_hash" in source
    for call in ("digest, AUDIT_ENGINE_VERSION", "engine_version=AUDIT_ENGINE_VERSION"):
        assert call in source, call
