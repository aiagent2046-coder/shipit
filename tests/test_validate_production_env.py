"""Tests for deploy/scripts/validate-production-env.py.

This script runs as `ExecStartPre=` on shipit.service, so its exit code is not
advisory: a non-zero return means systemd refuses to start the API. That makes
the boundary between "error" and "warning" a production-availability decision
rather than a style choice, and it is the thing worth pinning here -- a token
that only gates a read-only stats endpoint must never be able to keep the
service down.

Loaded by path because the filename is hyphenated and not importable.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy" / "scripts" / "validate-production-env.py"
)

SPEC = importlib.util.spec_from_file_location(
    "shipit_validate_production_env", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
validator = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = validator
SPEC.loader.exec_module(validator)


# Obviously-fake values: this file must never carry a real project secret.
COMPLETE_ENV = {
    "ENVIRONMENT": "production",
    # No password in the URL: the validator only checks the name is non-empty,
    # and .github/scripts/scan-added-secrets.py flags any user:pass@ form.
    "DATABASE_URL": "postgresql://fake-user@localhost:5432/fake-db",
    "API_KEY_PEPPER": "fake-pepper-not-a-real-secret",
    "PREVIEW_REAP_TOKEN": "fake-reap-token",
    "FIXPACK_PROCESS_TOKEN": "fake-fixpack-token",
    "MONITORING_PROCESS_TOKEN": "fake-monitoring-token",
    "SERVICE_FLAGS_TOKEN": "fake-flags-token",
    "CORS_ALLOWED_ORIGINS": "https://example.invalid",
    "AUDIT_JOBS_STATS_TOKEN": "fake-stats-token",
}


def _run(tmp_path: Path, monkeypatch, env: dict[str, str]) -> int:
    """Run main() against an env file.

    This helper used to clear the ambient environment of every name the script
    reads, because os.environ was merged in. That workaround was the reason no
    test could see the bug it was working around: the suite neutralised the
    leak instead of failing on it, and production paid for the difference.

    The environment is deliberately NOT cleared now -- see
    test_the_ambient_environment_cannot_satisfy_a_check below.
    """
    env_file = tmp_path / "test.env"
    env_file.write_text(
        "".join(f"{k}={v}\n" for k, v in env.items()), encoding="utf-8"
    )
    monkeypatch.setattr(sys, "argv", ["validate", "--env-file", str(env_file)])
    return validator.main()


def test_a_complete_production_env_passes(tmp_path, monkeypatch):
    assert _run(tmp_path, monkeypatch, COMPLETE_ENV) == 0


def test_missing_audit_jobs_stats_token_warns_but_still_starts(
    tmp_path, monkeypatch, capsys,
):
    """The whole point of the warning tier. AUDIT_JOBS_STATS_TOKEN gates only
    GET /internal/stats and GET /internal/audit-jobs/stats, both read-only, so
    an operator who has not set it loses a dashboard -- not the service. If this
    ever becomes an error, a host that booted fine yesterday stops booting."""
    env = {k: v for k, v in COMPLETE_ENV.items() if k != "AUDIT_JOBS_STATS_TOKEN"}

    assert _run(tmp_path, monkeypatch, env) == 0

    err = capsys.readouterr().err
    assert "AUDIT_JOBS_STATS_TOKEN" in err
    assert err.startswith("Warning:")
    # Not reported as a validation failure.
    assert "Invalid production configuration" not in err


def test_a_missing_required_token_is_still_fatal(tmp_path, monkeypatch, capsys):
    """The other side of the boundary: MONITORING_PROCESS_TOKEN drives a
    side-effecting timer, so its absence silently stops real work and is worth
    refusing to boot over. Guards against the warning tier being reached for
    the next time someone adds a token."""
    env = {k: v for k, v in COMPLETE_ENV.items() if k != "MONITORING_PROCESS_TOKEN"}

    assert _run(tmp_path, monkeypatch, env) == 78
    assert "MONITORING_PROCESS_TOKEN is required" in capsys.readouterr().err


def test_warnings_are_printed_alongside_errors(tmp_path, monkeypatch, capsys):
    """Both tiers are reported in one pass, so a failing start does not hide
    the warning an operator also needs to act on."""
    env = {
        k: v for k, v in COMPLETE_ENV.items()
        if k not in {"AUDIT_JOBS_STATS_TOKEN", "MONITORING_PROCESS_TOKEN"}
    }

    assert _run(tmp_path, monkeypatch, env) == 78

    err = capsys.readouterr().err
    assert "AUDIT_JOBS_STATS_TOKEN" in err
    assert "MONITORING_PROCESS_TOKEN is required" in err


def test_nothing_is_checked_outside_production(tmp_path, monkeypatch, capsys):
    """A development env with nothing set exits 0 in silence, so the new
    warning cannot become noise in every local run."""
    assert _run(tmp_path, monkeypatch, {"ENVIRONMENT": "development"}) == 0
    assert capsys.readouterr().err == ""


@pytest.mark.parametrize("blank", ["", "   "])
def test_a_blank_stats_token_warns_like_an_absent_one(
    tmp_path, monkeypatch, capsys, blank,
):
    """`.env.example` ships the name with an empty value, so "present but
    blank" is the shape a real host most often has."""
    env = dict(COMPLETE_ENV, AUDIT_JOBS_STATS_TOKEN=blank)

    assert _run(tmp_path, monkeypatch, env) == 0
    assert "AUDIT_JOBS_STATS_TOKEN" in capsys.readouterr().err


# --- the env file is the whole environment ---
#
# From a real outage. A nano edit of /opt/shipit/.env silently deleted the
# neighbouring USDT_POLL_TOKEN line. systemd's ExecStartPre run of this script
# correctly refused to start the service; the identical command typed by hand
# printed "Production configuration is valid", because the operator's shell
# happened to export that variable. The one check that exists to catch a
# broken config reported green about a broken config, and the operator spent
# the outage looking somewhere else.
#
# This process is not the service. Under systemd it runs as ExecStartPre with
# root's environment, while shipit.service starts from EnvironmentFile= alone.
# Anything os.environ contributes is a value the service will never see.


def test_the_ambient_environment_cannot_satisfy_a_check(
    tmp_path, monkeypatch, capsys
):
    """The outage, reproduced. The file is missing a required token and the
    process environment has it."""
    monkeypatch.setenv("API_KEY_PEPPER", "value-only-in-the-operators-shell")

    incomplete = {k: v for k, v in COMPLETE_ENV.items() if k != "API_KEY_PEPPER"}

    assert _run(tmp_path, monkeypatch, incomplete) == 78
    assert "API_KEY_PEPPER is required" in capsys.readouterr().err


def test_the_conditional_requirement_that_actually_broke(
    tmp_path, monkeypatch, capsys
):
    """The exact pair from the outage: USDT_POLL_TOKEN is required only
    because USDT_TRC20_ADDRESS is set, and it was the ambient copy that hid
    its absence from the file."""
    monkeypatch.setenv("USDT_POLL_TOKEN", "value-only-in-the-operators-shell")

    assert _run(tmp_path, monkeypatch, {
        **COMPLETE_ENV, "USDT_TRC20_ADDRESS": "TFakeAddressNotReal000000000000000",
    }) == 78
    assert "USDT_POLL_TOKEN is required" in capsys.readouterr().err


def test_an_ambient_environment_cannot_turn_the_checks_on_either(
    tmp_path, monkeypatch, capsys
):
    """The mirror case. A file that says nothing about ENVIRONMENT is not
    made production by the shell that happens to run the validator -- but the
    skip has to be loud, or it becomes the same false green in a new place."""
    monkeypatch.setenv("ENVIRONMENT", "production")

    no_environment = {k: v for k, v in COMPLETE_ENV.items()
                      if k != "ENVIRONMENT"}
    del no_environment["API_KEY_PEPPER"]        # would be fatal in production

    assert _run(tmp_path, monkeypatch, no_environment) == 0
    err = capsys.readouterr().err
    assert "defines no ENVIRONMENT" in err
    assert "production checks skipped" in err


def test_without_an_env_file_the_process_environment_is_the_subject(
    monkeypatch, capsys
):
    """The other invocation stays intact. Asked to validate no file, the
    script validates what it can see -- that IS the request, and CI uses it."""
    for name, value in COMPLETE_ENV.items():
        monkeypatch.setenv(name, value)
    monkeypatch.delenv("API_KEY_PEPPER")
    monkeypatch.setattr(sys, "argv", ["validate"])

    assert validator.main() == 78
    assert "API_KEY_PEPPER is required" in capsys.readouterr().err


def test_a_complete_file_still_passes_with_a_hostile_environment(
    tmp_path, monkeypatch
):
    """The boundary that keeps this from being a blunt instrument: ambient
    values must not break a valid file either. Only the file is read, so a
    shell exporting nonsense changes nothing."""
    monkeypatch.setenv("ENVIRONMENT", "development")
    monkeypatch.setenv("PAYPAL_ENV", "live")          # would demand a webhook id
    monkeypatch.setenv("USDT_TRC20_ADDRESS", "TFake000000000000000000000000000")

    assert _run(tmp_path, monkeypatch, COMPLETE_ENV) == 0
