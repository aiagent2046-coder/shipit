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
        install_command=(
            "npm install --no-audit --no-fund"
        ),
        steps=(
            VerificationStep(
                name="build",
                command="npm run build",
                required=True,
            ),
        ),
    )


def stages(
    *,
    install: str = "passed",
    build: str = "passed",
) -> tuple[VerificationStage, ...]:
    current = profile()

    return (
        VerificationStage(
            name="install",
            status=install,
            command=current.install_command,
        ),
        VerificationStage(
            name="build",
            status=build,
            command="npm run build",
        ),
    )


def test_original_install_failure_cannot_become_improvement():
    report = compare_verification_stages(
        profile(),
        stages(
            install="failed",
            build="skipped",
        ),
        stages(
            install="passed",
            build="passed",
        ),
    )

    assert report.regression is False
    assert report.deliverable is False

    assert report.detail == (
        "original dependency install did not pass; "
        "verification baseline is invalid"
    )


def test_non_install_build_improvement_remains_deliverable():
    report = compare_verification_stages(
        profile(),
        stages(
            install="passed",
            build="failed",
        ),
        stages(
            install="passed",
            build="passed",
        ),
    )

    assert report.regression is False
    assert report.deliverable is True

    assert report.detail == (
        "required patched verification passed; "
        "improvements: build"
    )
