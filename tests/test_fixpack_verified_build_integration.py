import io
import json
import zipfile

import pytest

from app.fixpack.generate import FixpackPlan
from app.fixpack.semantic_check import (
    RunResult,
    run_semantic_check,
    verified_build_gate_enabled,
)
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


def nextjs_zip(
    *,
    legacy_tests: bool = False,
) -> bytes:
    scripts = {
        "build": "next build",
    }

    if legacy_tests:
        scripts["test"] = "jest"

    return make_zip(
        {
            "package.json": json.dumps(
                {
                    "scripts": scripts,
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


def python_test_zip() -> bytes:
    return make_zip(
        {
            "requirements.txt": (
                "pytest==8.2.0\n"
            ),
            "app.py": "VALUE = 1\n",
            "tests/test_app.py": (
                "def test_value():\n"
                "    assert 1\n"
            ),
        }
    )


def plan() -> FixpackPlan:
    return FixpackPlan(
        files={
            "pages/index.js": (
                "export default function Home() "
                "{ return 'patched'; }\n"
            )
        },
        deletions=[],
    )


def profile_stages(
    profile: VerificationProfile,
    *,
    build_status: str = "passed",
    unavailable: bool = False,
) -> tuple[VerificationStage, ...]:
    output = [
        VerificationStage(
            name="install",
            status=(
                "unavailable"
                if unavailable
                else "passed"
            ),
            command=profile.install_command,
            detail=(
                "sandbox runner unavailable"
                if unavailable
                else None
            ),
        )
    ]

    for step in profile.steps:
        status = (
            "unavailable"
            if unavailable
            else (
                build_status
                if step.name == "build"
                else "passed"
            )
        )

        output.append(
            VerificationStage(
                name=step.name,
                status=status,
                command=step.command,
                detail=(
                    "sandbox runner unavailable"
                    if unavailable
                    else None
                ),
            )
        )

    return tuple(output)


@pytest.mark.parametrize(
    "value",
    [
        "1",
        "true",
        "TRUE",
        "yes",
        "on",
    ],
)
def test_verified_build_flag_accepts_explicit_truthy_values(
    monkeypatch,
    value,
):
    monkeypatch.setenv(
        "FIXPACK_VERIFIED_BUILD_GATE",
        value,
    )

    assert verified_build_gate_enabled() is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "0",
        "false",
        "no",
        "unexpected",
    ],
)
def test_verified_build_flag_is_fail_safe_off(
    monkeypatch,
    value,
):
    monkeypatch.setenv(
        "FIXPACK_VERIFIED_BUILD_GATE",
        value,
    )

    assert verified_build_gate_enabled() is False


def test_verified_build_flag_defaults_to_off(
    monkeypatch,
):
    monkeypatch.delenv(
        "FIXPACK_VERIFIED_BUILD_GATE",
        raising=False,
    )

    assert verified_build_gate_enabled() is False


def test_flag_off_preserves_legacy_semantic_path():
    suite_calls = []

    def legacy_suite(raw, runner):
        suite_calls.append(
            (raw, runner)
        )

        return RunResult(
            passed=3,
            failed=0,
            timed_out=False,
            error=None,
        )

    def structured_must_not_run(*args, **kwargs):
        raise AssertionError(
            "structured runner must stay disabled"
        )

    verdict = run_semantic_check(
        nextjs_zip(legacy_tests=True),
        plan(),
        suite_runner=legacy_suite,
        profile_runner=structured_must_not_run,
        verified_build_enabled=False,
    )

    assert len(suite_calls) == 2
    assert verdict.ran is True
    assert verdict.regression is False
    assert verdict.blocked is False
    assert verdict.verification_unavailable is False


def test_enabled_supported_stack_uses_structured_gate():
    calls = []

    def structured_runner(raw, profile):
        calls.append(
            (raw, profile)
        )

        return profile_stages(profile)

    def legacy_must_not_run(*args, **kwargs):
        raise AssertionError(
            "legacy semantic path must not run"
        )

    verdict = run_semantic_check(
        nextjs_zip(),
        plan(),
        suite_runner=legacy_must_not_run,
        minimal_checker=legacy_must_not_run,
        profile_runner=structured_runner,
        verified_build_enabled=True,
    )

    assert len(calls) == 2
    assert calls[0][1] is calls[1][1]

    assert verdict.ran is True
    assert verdict.ecosystem == "node"
    assert verdict.original is None
    assert verdict.patched is None
    assert verdict.regression is False
    assert verdict.blocked is False
    assert verdict.verification_unavailable is False
    assert verdict.detail.startswith(
        "verified build (nextjs):"
    )


def test_existing_required_build_failure_blocks_without_regression():
    def structured_runner(raw, profile):
        return profile_stages(
            profile,
            build_status="failed",
        )

    verdict = run_semantic_check(
        nextjs_zip(),
        plan(),
        profile_runner=structured_runner,
        verified_build_enabled=True,
    )

    assert verdict.ran is True
    assert verdict.regression is False
    assert verdict.blocked is True
    assert verdict.verification_unavailable is False
    assert (
        "patched required verification failed: build"
        in verdict.detail
    )


def test_new_patched_build_failure_is_regression_and_blocked():
    call_number = 0

    def structured_runner(raw, profile):
        nonlocal call_number
        call_number += 1

        return profile_stages(
            profile,
            build_status=(
                "passed"
                if call_number == 1
                else "failed"
            ),
        )

    verdict = run_semantic_check(
        nextjs_zip(),
        plan(),
        profile_runner=structured_runner,
        verified_build_enabled=True,
    )

    assert verdict.ran is True
    assert verdict.regression is True
    assert verdict.blocked is True
    assert verdict.verification_unavailable is False


def test_structured_runner_outage_is_deferred_not_blocked():
    call_number = 0

    def structured_runner(raw, profile):
        nonlocal call_number
        call_number += 1

        return profile_stages(
            profile,
            unavailable=(call_number == 2),
        )

    verdict = run_semantic_check(
        nextjs_zip(),
        plan(),
        profile_runner=structured_runner,
        verified_build_enabled=True,
    )

    assert verdict.ran is False
    assert verdict.regression is False
    assert verdict.blocked is False
    assert verdict.verification_unavailable is True
    assert "infrastructure unavailable" in verdict.detail


def test_enabled_unsupported_stack_falls_back_to_legacy_path():
    suite_calls = []

    def legacy_suite(raw, runner):
        suite_calls.append(
            (raw, runner)
        )

        return RunResult(
            passed=1,
            failed=0,
            timed_out=False,
            error=None,
        )

    def structured_must_not_run(*args, **kwargs):
        raise AssertionError(
            "unsupported stack must not use structured runner"
        )

    verdict = run_semantic_check(
        python_test_zip(),
        FixpackPlan(
            files={
                "app.py": "VALUE = 2\n",
            },
            deletions=[],
        ),
        suite_runner=legacy_suite,
        profile_runner=structured_must_not_run,
        verified_build_enabled=True,
    )

    assert len(suite_calls) == 2
    assert verdict.ecosystem == "python"
    assert verdict.regression is False
    assert verdict.blocked is False
