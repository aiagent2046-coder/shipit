"""Original/patched orchestration for the Fix Pack verified build gate.

This module contains no delivery decisions and no HTTP behavior. It detects a
supported profile from the original repository, executes the same profile
against both repository versions, and returns the comparison report.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import (
    build_patched_zip,
    run_verification_profile,
)
from app.fixpack.verification import (
    VerificationProfile,
    VerificationReport,
    VerificationStage,
    compare_verification_stages,
    detect_verification_profile,
    required_stage_failed_on_both,
)


VerificationRunner = Callable[
    [bytes, VerificationProfile],
    Iterable[VerificationStage],
]


def run_verified_build_gate(
    original_zip: bytes,
    plan: FixpackPlan,
    *,
    profile_runner: VerificationRunner | None = None,
) -> VerificationReport | None:
    """Verify original and patched repositories using one detected profile.

    The profile is intentionally detected only from ``original_zip``. A patch
    must not change which framework, image or commands are used to judge that
    same patch.

    ``None`` means that the repository is outside the currently supported
    Next.js, Vite and FastAPI profile set. The existing semantic-check fallback
    remains responsible for unsupported repositories.
    """

    profile = detect_verification_profile(
        original_zip
    )

    if profile is None:
        return None

    patched_zip = build_patched_zip(
        original_zip,
        plan,
    )

    runner = (
        run_verification_profile
        if profile_runner is None
        else profile_runner
    )

    original_stages = tuple(
        runner(
            original_zip,
            profile,
        )
    )

    patched_stages = tuple(
        runner(
            patched_zip,
            profile,
        )
    )

    # Same meaning as an undetected profile: the semantic check owns this
    # repository. A required stage that fails for the ORIGINAL too says the
    # repository cannot be built in this sandbox -- a fact about the
    # repository, not evidence about the patch -- and reporting it as a
    # verification failure would refuse delivery of a Fix Pack because code
    # the customer never touched was already failing.
    if required_stage_failed_on_both(
        profile,
        original_stages,
        patched_stages,
    ):
        return None

    return compare_verification_stages(
        profile,
        original_stages,
        patched_stages,
    )
