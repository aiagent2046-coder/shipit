from app.fixpack.verification import (
    VerificationProfile,
    VerificationStage,
    VerificationStep,
    compare_verification_stages,
)


def profile() -> VerificationProfile:
    return VerificationProfile(
        ecosystem="node",
        framework="nextjs",
        image="node:20-slim",
        install_command="npm ci",
        steps=(
            VerificationStep(
                name="typecheck",
                command="npm run typecheck",
                required=True,
            ),
            VerificationStep(
                name="build",
                command="npm run build",
                required=True,
            ),
            VerificationStep(
                name="tests",
                command="npm test",
                required=False,
            ),
        ),
    )


def stages(
    *,
    install: str = "passed",
    typecheck: str = "passed",
    build: str = "passed",
    tests: str = "passed",
) -> tuple[VerificationStage, ...]:
    return (
        VerificationStage(
            name="install",
            status=install,
            command="npm ci",
        ),
        VerificationStage(
            name="typecheck",
            status=typecheck,
            command="npm run typecheck",
        ),
        VerificationStage(
            name="build",
            status=build,
            command="npm run build",
        ),
        VerificationStage(
            name="tests",
            status=tests,
            command="npm test",
        ),
    )


def test_all_passed_is_deliverable():
    report = compare_verification_stages(
        profile(),
        stages(),
        stages(),
    )

    assert report.deliverable is True
    assert report.regression is False
    assert report.detail == (
        "required patched verification passed"
    )


def test_new_build_failure_is_regression():
    report = compare_verification_stages(
        profile(),
        stages(),
        stages(build="failed"),
    )

    assert report.deliverable is False
    assert report.regression is True
    assert report.detail == (
        "new verification regression: build"
    )


def test_existing_required_build_failure_still_blocks_delivery():
    report = compare_verification_stages(
        profile(),
        stages(build="failed"),
        stages(build="failed"),
    )

    assert report.deliverable is False
    assert report.regression is False
    assert report.detail == (
        "patched required verification failed: build"
    )


def test_existing_optional_test_failure_does_not_block_build_verified():
    report = compare_verification_stages(
        profile(),
        stages(tests="failed"),
        stages(tests="failed"),
    )

    assert report.deliverable is True
    assert report.regression is False
    assert report.detail == (
        "required patched verification passed; "
        "baseline optional failures remain: tests"
    )


def test_new_optional_test_failure_is_regression():
    report = compare_verification_stages(
        profile(),
        stages(),
        stages(tests="failed"),
    )

    assert report.deliverable is False
    assert report.regression is True
    assert report.detail == (
        "new verification regression: tests"
    )


def test_patched_required_improvement_is_deliverable():
    report = compare_verification_stages(
        profile(),
        stages(build="failed"),
        stages(build="passed"),
    )

    assert report.deliverable is True
    assert report.regression is False
    assert report.detail == (
        "required patched verification passed; "
        "improvements: build"
    )


def test_unavailable_infrastructure_blocks_delivery():
    report = compare_verification_stages(
        profile(),
        stages(),
        stages(build="unavailable"),
    )

    assert report.deliverable is False
    assert report.regression is False
    assert report.detail == (
        "verification infrastructure unavailable"
    )


def test_pending_stage_blocks_delivery():
    report = compare_verification_stages(
        profile(),
        stages(),
        stages(build="pending"),
    )

    assert report.deliverable is False
    assert report.regression is False
    assert report.detail == (
        "verification report is incomplete"
    )


def test_optional_failure_without_comparable_baseline_blocks_delivery():
    report = compare_verification_stages(
        profile(),
        stages(tests="skipped"),
        stages(tests="failed"),
    )

    assert report.deliverable is False
    assert report.regression is False
    assert report.detail == (
        "optional verification could not be compared: tests"
    )


def test_stage_contract_mismatch_blocks_delivery():
    original = stages()
    patched = stages()[:-1]

    report = compare_verification_stages(
        profile(),
        original,
        patched,
    )

    assert report.deliverable is False
    assert report.regression is False
    assert report.detail == (
        "verification stage contract mismatch"
    )
