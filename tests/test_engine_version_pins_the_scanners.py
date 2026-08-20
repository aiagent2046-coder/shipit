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

WHAT IT PINS is the set of scanners `run_static_scan` calls, not the rules
inside them — a rule's internals change constantly and a test that noticed
would be noise nobody keeps. Adding or removing a SCANNER is the coarse event
that reliably means "the engine now sees something it did not see before", and
it is exactly the event that happened four times.

WHEN THIS FAILS, do both halves:
  1. update WIRED_SCANNERS to match reality, and
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

# The version that was current when WIRED_SCANNERS last matched. Changing the
# scanner set without changing this is the whole defect.
ENGINE_VERSION_FOR_THAT_SET = "2026-08-20-2"


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


def test_the_engine_version_moved_with_them() -> None:
    assert pipeline.AUDIT_ENGINE_VERSION == ENGINE_VERSION_FOR_THAT_SET, (
        "AUDIT_ENGINE_VERSION changed. If that was deliberate, update "
        "ENGINE_VERSION_FOR_THAT_SET here too — this pair is the record of "
        "which engine the current scanner set was cached under."
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
