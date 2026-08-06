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
) -> tuple[VerificationStage, ...]:
    output = [
        VerificationStage(
            name="install",
            status=install,
            command=profile.install_command,
        )
    ]

    for step in profile.steps:
        status = (
            build
            if step.name == "build"
            else "passed"
        )

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


def test_existing_required_failure_is_not_new_regression():
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

    assert report is not None
    assert report.regression is False
    assert report.deliverable is False
    assert report.detail == (
        "patched required verification failed: build"
    )


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
