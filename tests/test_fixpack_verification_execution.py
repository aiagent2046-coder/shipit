import io
import subprocess
import zipfile

import app.fixpack.semantic_check as semantic_check
from app.fixpack.verification import (
    VerificationProfile,
    VerificationStep,
)


def make_zip(
    entries: dict[str, str] | None = None,
) -> bytes:
    entries = entries or {
        "package.json": "{}",
    }

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


def node_profile() -> VerificationProfile:
    return VerificationProfile(
        ecosystem="node",
        framework="nextjs",
        image="node:20-slim",
        install_command="npm ci --no-audit --no-fund",
        steps=(
            VerificationStep(
                name="typecheck",
                command="npx --no-install tsc --noEmit",
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


def completed(
    argv: list[str],
    returncode: int = 0,
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout="",
        stderr="",
    )


def test_executor_installs_online_then_runs_all_steps_offline(
    monkeypatch,
):
    calls: list[tuple[list[str], int]] = []

    def fake_run(argv, *, timeout):
        calls.append((argv, timeout))
        return completed(argv)

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert [stage.name for stage in stages] == [
        "install",
        "typecheck",
        "build",
        "tests",
    ]

    assert [stage.status for stage in stages] == [
        "passed",
        "passed",
        "passed",
        "passed",
    ]

    assert len(calls) == 4

    install_argv, install_timeout = calls[0]

    assert install_timeout == (
        semantic_check.INSTALL_TIMEOUT_SECONDS
    )

    assert not any(
        install_argv[index : index + 2]
        == ["--network", "none"]
        for index in range(len(install_argv) - 1)
    )

    assert any(
        argument.startswith("HTTP_PROXY=")
        for argument in install_argv
    )

    for argv, timeout in calls[1:]:
        assert timeout == semantic_check.RUN_TIMEOUT_SECONDS

        network_index = argv.index("--network")

        assert argv[network_index + 1] == "none"
        assert not any(
            "PROXY" in argument or "proxy" in argument
            for argument in argv
        )


def test_install_failure_skips_every_verification_step(
    monkeypatch,
):
    calls = []

    def fake_run(argv, *, timeout):
        calls.append(argv)
        return completed(argv, returncode=17)

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert len(calls) == 1

    assert [stage.status for stage in stages] == [
        "failed",
        "skipped",
        "skipped",
        "skipped",
    ]

    assert stages[0].exit_code == 17
    assert stages[0].detail == (
        "dependency install failed (exit 17)"
    )


def test_failed_build_is_recorded_and_tests_still_run(
    monkeypatch,
):
    returncodes = iter(
        [
            0,  # install
            0,  # typecheck
            2,  # build
            0,  # tests
        ]
    )

    calls = []

    def fake_run(argv, *, timeout):
        calls.append(argv)
        return completed(
            argv,
            returncode=next(returncodes),
        )

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert len(calls) == 4

    assert [stage.status for stage in stages] == [
        "passed",
        "passed",
        "failed",
        "passed",
    ]

    build = stages[2]

    assert build.name == "build"
    assert build.exit_code == 2
    assert build.detail == "build failed (exit 2)"


def test_stage_timeout_fails_that_stage_without_hiding_later_results(
    monkeypatch,
):
    call_number = 0

    def fake_run(argv, *, timeout):
        nonlocal call_number
        call_number += 1

        if call_number == 2:
            raise subprocess.TimeoutExpired(
                argv,
                timeout,
            )

        return completed(argv)

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert [stage.status for stage in stages] == [
        "passed",
        "failed",
        "passed",
        "passed",
    ]

    assert stages[1].name == "typecheck"
    assert stages[1].exit_code is None
    assert "timed out" in (stages[1].detail or "")


def test_missing_docker_marks_the_whole_run_unavailable(
    monkeypatch,
):
    def fake_run(argv, *, timeout):
        raise FileNotFoundError("docker")

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert [stage.status for stage in stages] == [
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
    ]

    assert all(
        stage.detail == "docker CLI not available"
        for stage in stages
    )


def test_workspace_limit_prevents_extraction_and_execution(
    monkeypatch,
):
    called = False

    def fake_run(argv, *, timeout):
        nonlocal called
        called = True
        return completed(argv)

    monkeypatch.setattr(
        semantic_check,
        "_run",
        fake_run,
    )

    monkeypatch.setattr(
        semantic_check,
        "_zip_uncompressed_size",
        lambda raw: (
            semantic_check.MAX_WORKSPACE_BYTES + 1
        ),
    )

    stages = semantic_check.run_verification_profile(
        make_zip(),
        node_profile(),
    )

    assert called is False

    assert [stage.status for stage in stages] == [
        "unavailable",
        "unavailable",
        "unavailable",
        "unavailable",
    ]

    assert all(
        stage.detail
        == "client workspace exceeds size limit"
        for stage in stages
    )
