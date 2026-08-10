import io
import json
import zipfile

import app.fixpack.verified_build as verified_build
from app.fixpack.generate import FixpackPlan
from app.fixpack.verification import (
    VerificationProfile,
    VerificationStage,
)


def make_zip(
    entries: dict[str, str],
) -> bytes:
    buffer = io.BytesIO()

    with zipfile.ZipFile(
        buffer,
        "w",
        zipfile.ZIP_DEFLATED,
    ) as archive:
        for name, text in entries.items():
            archive.writestr(
                f"customer-repo-deadbeef/{name}",
                text,
            )

    return buffer.getvalue()


def nextjs_zip() -> bytes:
    return make_zip(
        {
            "package.json": json.dumps(
                {
                    "scripts": {
                        "build": "next build",
                    },
                    "dependencies": {
                        "next": "14.2.0",
                        "react": "18.3.0",
                    },
                }
            ),
            "package-lock.json": "{}\n",
            "pages/index.js": (
                "export default function Home() "
                "{ return null; }\n"
            ),
        }
    )


def plan(
    files: dict[str, str] | None = None,
) -> FixpackPlan:
    return FixpackPlan(
        files=files or {
            "pages/index.js": (
                "export default function Home() "
                "{ return 'patched'; }\n"
            )
        },
        deletions=[],
    )


def stages(
    profile: VerificationProfile,
    *,
    install: str = "passed",
    build: str = "passed",
    tests: str = "passed",
) -> tuple[VerificationStage, ...]:
    output = [
        VerificationStage(
            name="install",
            status=install,
            command=profile.install_command,
        )
    ]

    for step in profile.steps:
        status = {"build": build, "tests": tests}.get(step.name, "passed")

        output.append(
            VerificationStage(
                name=step.name,
                status=status,
                command=step.command,
            )
        )

    return tuple(output)


def zip_text(
    raw: bytes,
    relative_name: str,
) -> str:
    with zipfile.ZipFile(
        io.BytesIO(raw),
        "r",
    ) as archive:
        matches = [
            info
            for info in archive.infolist()
            if (
                not info.is_dir()
                and (
                    info.filename == relative_name
                    or info.filename.endswith(
                        f"/{relative_name}"
                    )
                )
            )
        ]

        assert len(matches) == 1

        return archive.read(
            matches[0]
        ).decode("utf-8")


def test_gate_uses_original_profile_for_both_versions():
    calls = []

    patched_package = json.dumps(
        {
            "scripts": {
                "build": "vite build",
            },
            "devDependencies": {
                "vite": "5.4.0",
            },
        }
    )

    def fake_runner(raw, profile):
        calls.append(
            (raw, profile)
        )

        # A list is intentional: orchestration normalises runner output
        # before storing it in the immutable report.
        return list(
            stages(profile)
        )

    report = verified_build.run_verified_build_gate(
        nextjs_zip(),
        plan(
            {
                "package.json": patched_package,
            }
        ),
        profile_runner=fake_runner,
    )

    assert report is not None
    assert report.deliverable is True
    assert report.regression is False

    assert len(calls) == 2

    original_raw, original_profile = calls[0]
    patched_raw, patched_profile = calls[1]

    assert original_raw != patched_raw

    assert original_profile is patched_profile
    assert original_profile.framework == "nextjs"

    assert zip_text(
        patched_raw,
        "package.json",
    ) == patched_package

    assert isinstance(
        report.original,
        tuple,
    )

    assert isinstance(
        report.patched,
        tuple,
    )


def test_new_patched_build_failure_is_regression():
    call_number = 0

    def fake_runner(raw, profile):
        nonlocal call_number
        call_number += 1

        return stages(
            profile,
            build=(
                "passed"
                if call_number == 1
                else "failed"
            ),
        )

    report = verified_build.run_verified_build_gate(
        nextjs_zip(),
        plan(),
        profile_runner=fake_runner,
    )

    assert report is not None
    assert report.regression is True
    assert report.deliverable is False
    assert report.detail == (
        "new verification regression: build"
    )


def test_a_repository_that_already_fails_to_build_is_not_verifiable_here():
    """None, not a blocking report -- the semantic check takes over.

    This test asserted the opposite until a real run showed what the old
    answer cost. A required stage that fails for the ORIGINAL too says the
    repository cannot be built in this sandbox; it says nothing about the
    patch. Reporting it as a verification failure refuses delivery of a Fix
    Pack the customer paid for, because code they never touched was already
    failing -- and it does so precisely for the large repositories that only
    became eligible when workspace members started being detected.
    dubinc/dub is the case: its build script wants database credentials the
    offline container deliberately withholds.
    """
    def fake_runner(raw, profile):
        return stages(
            profile,
            build="failed",
        )

    report = verified_build.run_verified_build_gate(
        nextjs_zip(),
        plan(),
        profile_runner=fake_runner,
    )

    assert report is None


def test_runner_unavailable_fails_closed():
    call_number = 0

    def fake_runner(raw, profile):
        nonlocal call_number
        call_number += 1

        if call_number == 1:
            return stages(profile)

        return tuple(
            VerificationStage(
                name=stage.name,
                status="unavailable",
                command=stage.command,
                detail="sandbox runner unavailable",
            )
            for stage in stages(profile)
        )

    report = verified_build.run_verified_build_gate(
        nextjs_zip(),
        plan(),
        profile_runner=fake_runner,
    )

    assert report is not None
    assert report.regression is False
    assert report.deliverable is False
    assert report.detail == (
        "verification infrastructure unavailable"
    )


def test_patched_build_improvement_is_deliverable():
    call_number = 0

    def fake_runner(raw, profile):
        nonlocal call_number
        call_number += 1

        return stages(
            profile,
            build=(
                "failed"
                if call_number == 1
                else "passed"
            ),
        )

    report = verified_build.run_verified_build_gate(
        nextjs_zip(),
        plan(),
        profile_runner=fake_runner,
    )

    assert report is not None
    assert report.regression is False
    assert report.deliverable is True
    assert report.detail == (
        "required patched verification passed; "
        "improvements: build"
    )


def test_unsupported_repository_short_circuits_without_patch_or_runner(
    monkeypatch,
):
    original = make_zip(
        {
            "package.json": json.dumps(
                {
                    "dependencies": {
                        "lodash": "4.17.21",
                    }
                }
            )
        }
    )

    def must_not_run(*args, **kwargs):
        raise AssertionError(
            "unsupported repository must short-circuit"
        )

    monkeypatch.setattr(
        verified_build,
        "build_patched_zip",
        must_not_run,
    )

    result = verified_build.run_verified_build_gate(
        original,
        plan(),
        profile_runner=must_not_run,
    )

    assert result is None


def test_a_new_build_failure_still_blocks():
    """The boundary. Falling back when the original ALSO failed must not
    become falling back whenever the patch fails -- that would delete the
    gate. Original green, patched red is a regression and stays one."""
    call_number = 0

    def fake_runner(raw, profile):
        nonlocal call_number
        call_number += 1
        return stages(profile, build="failed" if call_number == 2 else "passed")

    report = verified_build.run_verified_build_gate(
        nextjs_zip(), plan(), profile_runner=fake_runner,
    )

    assert report is not None
    assert report.regression is True
    assert report.deliverable is False


def test_an_optional_stage_failing_on_both_sides_does_not_trigger_the_fallback():
    """Only REQUIRED stages say the repository cannot be built. A client test
    suite that was already red is an ordinary condition the report is designed
    to describe, not a reason to abandon the verification entirely."""
    with_a_test_suite = make_zip({
        "package.json": json.dumps({
            "scripts": {"build": "next build", "test": "jest"},
            "dependencies": {"next": "14.2.0", "react": "18.3.0"},
        }),
        "package-lock.json": "{}\n",
        "pages/index.js": "export default function Home() { return null; }\n",
    })

    def fake_runner(raw, profile):
        return stages(profile, tests="failed")

    report = verified_build.run_verified_build_gate(
        with_a_test_suite, plan(), profile_runner=fake_runner,
    )

    # The fixture must actually HAVE the optional stage, or this asserts
    # nothing: nextjs_zip() declares no test script, so its profile has no
    # tests step and `tests="failed"` was quietly a no-op.
    assert any(step.name == "tests" for step in report.profile.steps)
    assert report is not None


def test_an_unavailable_stage_is_not_treated_as_unbuildable():
    """`unavailable` means the run did not happen -- an infrastructure outage.
    Degrading it into a quiet fallback would hide the one thing an operator
    needs to see, so it keeps its own explicit report."""
    def fake_runner(raw, profile):
        return stages(profile, build="unavailable")

    report = verified_build.run_verified_build_gate(
        nextjs_zip(), plan(), profile_runner=fake_runner,
    )

    assert report is not None
    assert report.detail == "verification infrastructure unavailable"
