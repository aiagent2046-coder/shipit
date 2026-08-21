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
    """A requirement that exists only because another variable is set, hidden
    by an ambient copy of the missing one.

    The pair from the 2026-07-31 outage was USDT_POLL_TOKEN / USDT_TRC20_ADDRESS,
    and that rail is gone. The SHAPE of the defect is not: the surviving
    conditional is that configuring a payment rail requires a confirmation
    path, and the same ambient shell can hide the same absence. Retargeted
    rather than deleted -- the bug was never about USDT."""
    monkeypatch.setenv("TELEGRAM_BOT_TOKEN", "value-only-in-the-operators-shell")

    assert _run(tmp_path, monkeypatch, {
        **COMPLETE_ENV, "BANK_TRANSFER_CARD": "0000 0000 0000 0000",
    }) == 78
    assert "TELEGRAM_BOT_TOKEN is required" in capsys.readouterr().err


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
    # Would demand TELEGRAM_BOT_TOKEN / _ADMIN_CHAT_ID / _WEBHOOK_SECRET if the
    # script merged the shell into the file. It does not.
    monkeypatch.setenv("BANK_TRANSFER_CARD", "0000 0000 0000 0000")

    assert _run(tmp_path, monkeypatch, COMPLETE_ENV) == 0


def test_the_glued_line_that_cost_two_days_of_payments(
    tmp_path, monkeypatch, capsys,
):
    """The exact shape of the 2026-07-31 corruption, and the reason this whole
    tier exists.

    A nano paste appended the USDT_POLL_TOKEN line to the value of the variable
    above it. USDT_POLL_TOKEN was then restored from a backup, so BOTH names
    were present and non-empty -- and every check in the script passed. The
    address was garbage, poll-usdt answered 503 on every run for two days, and
    no USDT payment was confirmed in that window.

    Against main this file validates clean, exit 0.
    """
    env = dict(COMPLETE_ENV)
    env["USDT_TRC20_ADDRESS"] = "USDT_POLL_TOKEN=fake-usdt-token-not-real"
    env["USDT_POLL_TOKEN"] = "fake-usdt-token-not-real"

    assert _run(tmp_path, monkeypatch, env) == 78

    err = capsys.readouterr().err
    assert "USDT_TRC20_ADDRESS starts with 'USDT_POLL_TOKEN='" in err


def test_the_glue_is_caught_on_any_variable_not_just_the_address(
    tmp_path, monkeypatch, capsys,
):
    """The check keys on the SHAPE of the value, not on which variable holds
    it. A rule that only knew about TRON addresses would have to be extended
    every time the paste lands somewhere new -- and the next paste will."""
    env = dict(COMPLETE_ENV)
    env["CORS_ALLOWED_ORIGINS"] = "SERVICE_FLAGS_TOKEN=fake-flags-token"

    assert _run(tmp_path, monkeypatch, env) == 78
    assert "CORS_ALLOWED_ORIGINS starts with 'SERVICE_FLAGS_TOKEN='" in (
        capsys.readouterr().err
    )


def test_an_equals_sign_inside_a_value_is_left_alone(
    tmp_path, monkeypatch,
):
    """The boundary that keeps this from being a nuisance. Only the START of a
    value is examined: connection strings carry query parameters and base64
    carries padding, and neither is a glued line."""
    env = dict(COMPLETE_ENV)
    env["DATABASE_URL"] = (
        "postgresql://fake-user@localhost:5432/fake-db?sslmode=require"
    )

    assert _run(tmp_path, monkeypatch, env) == 0


def test_a_lowercase_prefix_is_not_treated_as_a_glued_line(
    tmp_path, monkeypatch,
):
    """Environment variable names are upper-case by convention and the pattern
    relies on it. A value that merely contains 'word=' at the front, like a
    URL-encoded parameter, must not refuse to boot the API."""
    env = dict(COMPLETE_ENV)
    env["CORS_ALLOWED_ORIGINS"] = "mode=strict"

    assert _run(tmp_path, monkeypatch, env) == 0


def test_a_variable_for_a_removed_rail_is_named_out_loud(
    tmp_path, monkeypatch, capsys,
):
    """A .env on a running host is not rewritten by a deploy. When USDT and
    PayPal were removed, their lines stayed exactly where the operator put
    them -- and a set USDT_TRC20_ADDRESS reads as a live rail to the person
    who set it. Nothing reads it now, so money sent there is money nobody
    sees.

    A WARNING, not an error, and the boundary matters: refusing to boot over a
    leftover line would turn tidiness into an outage. It has to be said, not
    enforced."""
    env = dict(COMPLETE_ENV)
    env["USDT_TRC20_ADDRESS"] = "TBTwuY1oQMLw2wxc3FWB8TFtu1dTnuvZuf"

    assert _run(tmp_path, monkeypatch, env) == 0

    err = capsys.readouterr().err
    assert "USDT_TRC20_ADDRESS is set" in err
    assert "will not be seen by anything" in err


def test_an_empty_line_for_a_removed_rail_says_nothing(tmp_path, monkeypatch, capsys):
    """The boundary. An operator who cleared the value has already done the
    thing the warning asks for; repeating it every boot trains the reader to
    scroll past the whole block."""
    env = dict(COMPLETE_ENV)
    env["USDT_TRC20_ADDRESS"] = ""
    env["PAYPAL_CLIENT_ID"] = "   "

    assert _run(tmp_path, monkeypatch, env) == 0
    assert "USDT_TRC20_ADDRESS is set" not in capsys.readouterr().err


def test_no_check_ever_prints_the_value_it_rejected(
    tmp_path, monkeypatch, capsys,
):
    """On 2026-08-02 an error message that echoed USDT_TRC20_ADDRESS put a live
    bearer token -- which is what the variable wrongly held -- into the journal
    and into an HTTP response body. This script runs under systemd, so anything
    it prints is journalled on every boot. Naming the variable is just as
    actionable as showing it."""
    # Repetition rather than a 32-character hex literal: a fixture that
    # looks like a secret trips the scanner that exists to find real ones.
    secret = "deadbeef" * 8
    env = dict(COMPLETE_ENV)
    env["USDT_TRC20_ADDRESS"] = f"USDT_POLL_TOKEN={secret}"
    env["USDT_POLL_TOKEN"] = secret

    assert _run(tmp_path, monkeypatch, env) == 78

    captured = capsys.readouterr()
    assert secret not in captured.err
    assert secret not in captured.out


def test_a_database_url_with_the_wrong_scheme_is_refused(
    tmp_path, monkeypatch, capsys,
):
    env = dict(COMPLETE_ENV)
    env["DATABASE_URL"] = "mysql://fake-user@localhost/fake-db"

    assert _run(tmp_path, monkeypatch, env) == 78
    assert "DATABASE_URL does not start with" in capsys.readouterr().err


def test_a_short_token_warns_but_still_starts(tmp_path, monkeypatch, capsys):
    """Truncation is the sibling of gluing: the value is present and non-empty,
    so every existing check passes, but it is not the token. A warning rather
    than an error -- nothing enforces the `openssl rand -hex 32` convention,
    and refusing to boot over a short-but-working token would turn a note about
    strength into an outage."""
    env = dict(COMPLETE_ENV)
    env["SERVICE_FLAGS_TOKEN"] = "abc123"

    assert _run(tmp_path, monkeypatch, env) == 0

    err = capsys.readouterr().err
    assert "SERVICE_FLAGS_TOKEN is shorter than 16 characters" in err
    assert "Invalid production configuration" not in err


# --- a payment rail must have a way to confirm a payment --------------------

_BANK_RAIL = {"BANK_TRANSFER_CARD": "0000 0000 0000 0000"}
_TELEGRAM = {
    "TELEGRAM_BOT_TOKEN": "000:fake-bot-token",
    "TELEGRAM_ADMIN_CHAT_ID": "12345",
    "TELEGRAM_WEBHOOK_SECRET": "fake-webhook-secret",
}


def test_a_payment_rail_without_telegram_refuses_to_boot(tmp_path, monkeypatch):
    """The worst shape this file can let through, because every part of it
    fails closed correctly and so nothing complains.

    The payer gets bank details, pays, and presses "I've paid". That pages the
    operator on Telegram, and access is granted only when the operator taps
    Confirm. Without the bot token or the admin chat id, notify_operator sends
    nothing and _is_operator rejects everyone -- including the operator. Money
    arrives, nobody can act on it, and no error is raised anywhere.
    """
    env = {**COMPLETE_ENV, **_BANK_RAIL}

    assert _run(tmp_path, monkeypatch, env) == 78


def test_each_telegram_variable_is_required_on_its_own(tmp_path, monkeypatch):
    """All three break the confirmation path, at different steps: the token
    and chat id silence the notification, the webhook secret makes the
    endpoint 503 so the Confirm tap never arrives."""
    for missing in _TELEGRAM:
        env = {**COMPLETE_ENV, **_BANK_RAIL, **_TELEGRAM}
        del env[missing]

        assert _run(tmp_path, monkeypatch, env) == 78, missing


def test_a_complete_payment_setup_boots(tmp_path, monkeypatch):
    env = {**COMPLETE_ENV, **_BANK_RAIL, **_TELEGRAM}

    assert _run(tmp_path, monkeypatch, env) == 0


def test_a_deployment_selling_nothing_is_unaffected(tmp_path, monkeypatch):
    """The check keys on a configured rail, not on Telegram itself: an
    instance that sells nothing has no confirmation path to break, and
    demanding a bot token from it would refuse to boot over an unused
    feature."""
    assert _run(tmp_path, monkeypatch, dict(COMPLETE_ENV)) == 0


# --- half a delivery channel ------------------------------------------------

def test_smtp_host_without_a_from_address_is_refused(
    tmp_path, monkeypatch, capsys,
):
    """The same shape as the USDT_POLL_TOKEN outage: a value required only
    because another one is set.

    It matters more here than it looks. app/notify/email.py returns False and
    raises nothing when either is missing -- deliberately, so a deployment
    without mail does not fail a refund it could not announce. The cost of
    that contract is that a TYPO looks exactly like a decision: the customer
    is never told their money came back, nothing goes red, and the only trace
    is an operator alert saying nobody could be reached."""
    env = dict(COMPLETE_ENV)
    env["SMTP_HOST"] = "smtp.example.invalid"

    assert _run(tmp_path, monkeypatch, env) == 78
    err = capsys.readouterr().err
    assert "SMTP_HOST and SMTP_FROM must be configured together" in err
    # It says what the operator loses, not just which variable is missing.
    assert "never told their refund was sent" in err


def test_a_from_address_without_a_host_is_refused(tmp_path, monkeypatch, capsys):
    """Both directions. Setting only SMTP_FROM is the likelier typo -- it is
    the one an operator writes from memory."""
    env = dict(COMPLETE_ENV)
    env["SMTP_FROM"] = "support@drydock.co"

    assert _run(tmp_path, monkeypatch, env) == 78
    assert "SMTP_HOST and SMTP_FROM" in capsys.readouterr().err


def test_both_together_pass(tmp_path, monkeypatch):
    """The boundary. A configured mail channel must not be an error."""
    env = dict(COMPLETE_ENV)
    env["SMTP_HOST"] = "smtp.example.invalid"
    env["SMTP_FROM"] = "support@drydock.co"

    assert _run(tmp_path, monkeypatch, env) == 0


def test_neither_is_not_an_error_either(tmp_path, monkeypatch):
    """Mail is optional. A deployment that has not set it up is not broken,
    and refusing to boot over it would make the channel mandatory by
    accident."""
    assert _run(tmp_path, monkeypatch, dict(COMPLETE_ENV)) == 0


def test_a_username_with_no_password_is_refused(tmp_path, monkeypatch, capsys):
    """It authenticates as nobody: every send fails, inside a best-effort call
    whose whole contract is not to complain."""
    env = dict(COMPLETE_ENV)
    env["SMTP_HOST"] = "smtp.example.invalid"
    env["SMTP_FROM"] = "support@drydock.co"
    env["SMTP_USERNAME"] = "support@drydock.co"

    assert _run(tmp_path, monkeypatch, env) == 78
    assert "SMTP_USERNAME and SMTP_PASSWORD" in capsys.readouterr().err


def test_neither_credential_is_fine(tmp_path, monkeypatch):
    """A relay on localhost, or one that authenticates by IP, needs neither --
    and app/notify/email.py skips the login for exactly that case. Demanding a
    password would invent a requirement the code does not have."""
    env = dict(COMPLETE_ENV)
    env["SMTP_HOST"] = "localhost"
    env["SMTP_FROM"] = "support@drydock.co"

    assert _run(tmp_path, monkeypatch, env) == 0
