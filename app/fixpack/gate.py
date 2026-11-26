"""Top-level Fix Pack semantic gate: composition layer.

The semantic machinery (runner detection, patched-ZIP build, suite
comparison) lives in `semantic_check` (the bottom layer); the verified-build
gate orchestration lives in `verified_build` (middle). This module owns the
top-level verdict and is the only place that knows both, which keeps the
import graph acyclic: gate -> verified_build -> semantic_check.
"""

from __future__ import annotations

from app.fixpack import semantic_check as sc
from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import SemanticCheckResult
from app.fixpack.verified_build import run_verified_build_gate


def run_semantic_check(
    original_zip: bytes,
    plan: FixpackPlan,
    *,
    suite_runner=None,
    minimal_checker=None,
    profile_runner=None,
    verified_build_enabled: bool | None = None,
) -> SemanticCheckResult:
    """Top-level gate. Detect the client's test runner; if present, run both
    versions in Docker and compare; if absent, do the minimal check and
    attach a soft recommendation note.

    Orchestration and all pure steps (detect / build_patched_zip / compare)
    run in-process; the two docker-touching seams are injectable. The backend
    passes the sandbox-runner HTTP client (Variant A) so it never execs docker;
    the defaults are the real local implementations, which the runner itself
    uses.

    This is synchronous and may take minutes (real Docker) — callers MUST run
    it in a threadpool, exactly like `run_scan` (see main.py).
    """
    if verified_build_enabled is None:
        verified_build_enabled = (
            sc.verified_build_gate_enabled()
        )

    if verified_build_enabled:
        verification_report = run_verified_build_gate(
            original_zip,
            plan,
            profile_runner=profile_runner,
        )

        if verification_report is not None:
            return sc.semantic_result_from_verification_report(
                verification_report
            )

    # Resolve at call time through the semantic_check module (not as default
    # arg values) so a module-level monkeypatch of run_suite / minimal_check
    # still takes effect, and so the backend can inject the sandbox-runner
    # client.
    suite_runner = suite_runner or sc.run_suite
    minimal_checker = minimal_checker or sc.minimal_check

    runner = sc.detect_test_runner(original_zip)

    if runner is None:
        mc = minimal_checker(plan)
        if mc.unavailable:
            # Not "syntax-only verification passed": the syntax check never ran.
            # Saying "no client test suite detected" here would report an
            # infrastructure outage as a clean, if shallow, verification.
            return sc.SemanticCheckResult(
                ran=False, ecosystem=None, original=None, patched=None,
                regression=False,
                detail=("could not verify: no client test suite detected, and "
                        f"the sandbox runner was unreachable for the "
                        f"syntax-only check ({mc.error})"),
                pr_note=None, verification_unavailable=True,
            )
        if mc.failed > 0:
            return sc.SemanticCheckResult(
                ran=False, ecosystem=None, original=None, patched=None,
                regression=True,
                detail="minimal check failed: " + (mc.error or "changed file is invalid"),
                pr_note=None,
            )
        return sc.SemanticCheckResult(
            ran=False, ecosystem=None, original=None, patched=None,
            regression=False,
            detail="no client test suite detected; syntax-only verification",
            pr_note=sc.missing_tests_pr_note(),
        )

    patched_zip = sc.build_patched_zip(original_zip, plan)
    original = suite_runner(original_zip, runner)
    patched = suite_runner(patched_zip, runner)
    verdict = sc.is_regression(original, patched)
    return sc.SemanticCheckResult(
        # `ran` claims a real client suite executed, so an unreachable runner
        # must not set it: detecting a runner is not running one.
        ran=not verdict.verification_unavailable, ecosystem=runner.ecosystem,
        original=original, patched=patched,
        regression=verdict.regression, detail=verdict.detail, pr_note=None,
        verification_unavailable=verdict.verification_unavailable,
    )
