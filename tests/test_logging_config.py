"""Tests for the shared logging configuration (app/logging_config.py).

Three things are load-bearing here and each is tested as a contract, not as
an implementation detail:

  * the allowlist -- a field nobody added to ALLOWED_FIELDS never reaches the
    output, so a future extra={} carrying a secret is dropped by default;
  * redaction -- secrets are masked in the *interpolated* message, in both
    output formats, because every existing call site is `logger.x("%s", val)`;
  * context isolation -- two concurrent worker slots cannot mix up each
    other's job ids.

The secrets below are all obviously fake, hand-written shapes: never a real
project credential, only something that matches the pattern.
"""

from __future__ import annotations

import asyncio
import json
import logging
from contextlib import contextmanager

import pytest

from app import log_context
from app.logging_config import (
    ALLOWED_FIELDS,
    StripAccessQueryFilter,
    TEXT_FORMAT,
    ContextFilter,
    JsonFormatter,
    RedactionFilter,
    build_handler,
    configure_logging,
    redact,
)


@pytest.fixture(autouse=True)
def _clean_log_context():
    """No test may inherit correlation ids from the one before it."""
    log_context.clear_log_context()
    yield
    log_context.clear_log_context()


def make_record(msg="hello", args=(), *, name="app.test", level=logging.INFO,
                exc_info=None, **extra) -> logging.LogRecord:
    record = logging.LogRecord(
        name=name, level=level, pathname="app/test.py", lineno=42,
        msg=msg, args=args, exc_info=exc_info,
    )
    for key, value in extra.items():
        setattr(record, key, value)
    return record


def emit_json(record: logging.LogRecord) -> dict:
    """Run a record through the real filter chain, then the JSON formatter."""
    RedactionFilter().filter(record)
    ContextFilter().filter(record)
    return json.loads(JsonFormatter().format(record))


def emit_text(record: logging.LogRecord) -> str:
    RedactionFilter().filter(record)
    ContextFilter().filter(record)
    return logging.Formatter(TEXT_FORMAT).format(record)


# --- the allowlist ----------------------------------------------------------

def test_json_output_carries_the_baseline_fields():
    out = emit_json(make_record("hello"))
    assert out["msg"] == "hello"
    assert out["level"] == "INFO"
    assert out["logger"] == "app.test"
    assert out["line"] == 42
    assert out["ts"].endswith("Z")
    assert isinstance(out["pid"], int)


def test_no_field_outside_the_allowlist_is_ever_serialised():
    out = emit_json(make_record("hello"))
    assert set(out) <= set(ALLOWED_FIELDS)


def test_a_secret_smuggled_through_extra_is_dropped_by_the_allowlist():
    """The whole reason the formatter allowlists instead of denylists: this
    field was never reviewed by anyone, and it still cannot reach the log."""
    record = make_record("saving account", raw_password="hunter2-not-real")
    out = emit_json(record)
    assert "raw_password" not in out
    assert "hunter2-not-real" not in json.dumps(out)


def test_step_and_duration_ms_from_extra_do_reach_the_output():
    """They are not contextvars (they change many times per job), so they
    arrive as extra={} on the individual call -- PR2 starts using this."""
    out = emit_json(make_record("stage done", step="llm_scan", duration_ms=1234))
    assert out["step"] == "llm_scan"
    assert out["duration_ms"] == 1234


def test_duration_ms_of_zero_is_kept_not_treated_as_absent():
    assert emit_json(make_record("fast", duration_ms=0))["duration_ms"] == 0


def test_unset_context_fields_are_omitted_rather_than_erroring():
    out = emit_json(make_record("no context here"))
    assert "job_id" not in out
    assert "audit_id" not in out


def test_exception_fields_appear_only_when_there_is_an_exception():
    assert "exc_type" not in emit_json(make_record("fine"))
    try:
        raise ValueError("boom")
    except ValueError:
        import sys
        out = emit_json(make_record("failed", exc_info=sys.exc_info()))
    assert out["exc_type"] == "ValueError"
    assert "Traceback" in out["exc_stack"]


def test_a_non_serialisable_extra_degrades_to_its_repr():
    """One bad value must not cost us the whole line."""
    out = emit_json(make_record("odd", error_code=object()))
    assert "object object at" in out["error_code"]


# --- redaction --------------------------------------------------------------

FAKE_SECRETS = [
    ("github classic pat", "ghp_0123456789abcdefghijABCDEFGHIJklmn"),
    ("github installation token", "ghs_0123456789abcdefghijABCDEFGHIJklmn"),
    ("github fine-grained pat",
     "github_pat_11ABCDE0123456789_abcdefghijKLMNOPQRSTUVWX"),
    ("telegram bot token", "1234567890:AAExampleFakeTelegramBotToken-000000"),
    ("anthropic-style key", "sk-ant-api03-0000000000000000000000000000"),
    ("openai-style key", "sk-000000000000000000000000000000"),
    ("jwt", "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiI0Mjc4NDgyIn0.ZmFrZXNpZw"),
]


@pytest.mark.parametrize("label,secret", FAKE_SECRETS,
                         ids=[label for label, _ in FAKE_SECRETS])
def test_each_secret_shape_is_masked_and_the_rest_of_the_line_survives(
        label, secret):
    out = redact(f"before {secret} after")
    assert secret not in out
    assert out.startswith("before ") and out.endswith(" after")
    assert "[REDACTED]" in out


def test_a_pem_private_key_block_is_masked_whole():
    pem = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "MIIEfakekeymaterialthatisnotreal\nAAAABBBBCCCC\n"
           "-----END RSA PRIVATE KEY-----")
    out = redact(f"PEM parse failed: {pem} | done")
    assert "fakekeymaterial" not in out
    assert out == "PEM parse failed: [REDACTED] | done"


def test_a_postgres_dsn_keeps_its_scheme_and_loses_its_credentials():
    """The scheme is the useful half of a connection diagnostic; the password
    is the half that must never be written down."""
    out = redact("connect failed for postgresql://appuser:s3cr3t@db.host:5432/shipit")
    assert "s3cr3t" not in out and "appuser" not in out
    assert out == ("connect failed for postgresql://[REDACTED]@db.host:5432/shipit")


@pytest.mark.parametrize("name", ["token", "SECRET", "password", "api_key",
                                  "API-KEY", "pepper"])
def test_a_named_credential_is_masked_but_its_name_is_kept(name):
    """Fallback for a secret whose shape we do not recognise: the line still
    says which credential was involved, which is the diagnostic value."""
    out = redact(f"resolve failed: {name}=unrecognised-shape-value rest")
    assert "unrecognised-shape-value" not in out
    assert name in out
    assert out.endswith(" rest")


def test_benign_key_shaped_text_is_not_redacted():
    """Over-redaction is its own failure: these are real lines from
    app/alerts.py and app/worker/main.py and they must stay readable."""
    assert redact("operator alert failed to send (dedupe_key=systemd-onfailure)") == (
        "operator alert failed to send (dedupe_key=systemd-onfailure)")
    assert redact("job abc failed (repo_fetch, permanent=False)") == (
        "job abc failed (repo_fetch, permanent=False)")


def test_redaction_applies_to_percent_s_args_not_just_the_literal_template():
    """Every one of the ~50 existing call sites is old-style interpolation, so
    a filter reading record.msg alone would inspect the template and miss the
    secret entirely."""
    record = make_record("resolved token %s for %s",
                         ("ghp_0123456789abcdefghijABCDEFGHIJklmn", "owner/repo"))
    out = emit_json(record)
    assert "ghp_" not in out["msg"]
    assert "[REDACTED]" in out["msg"]
    assert "owner/repo" in out["msg"]


def test_redaction_works_in_text_format_too():
    """Redaction is a filter, not a property of the JSON formatter -- a
    protection that only holds in the format you happen to have enabled is
    not a protection."""
    record = make_record("token is %s",
                         ("ghp_0123456789abcdefghijABCDEFGHIJklmn",))
    line = emit_text(record)
    assert "ghp_" not in line
    assert "[REDACTED]" in line


def test_a_secret_inside_a_traceback_is_masked():
    import sys
    try:
        raise ValueError("upstream rejected sk-000000000000000000000000000000")
    except ValueError:
        out = emit_json(make_record("failed", exc_info=sys.exc_info()))
    assert "sk-0000" not in out["exc_stack"]
    assert "[REDACTED]" in out["exc_stack"]


def test_a_broken_format_string_still_logs_rather_than_disappearing():
    record = make_record("two placeholders %s %s", ("only-one",))
    assert RedactionFilter().filter(record) is True


# --- context ----------------------------------------------------------------

def test_context_values_reach_the_record_without_touching_the_call_site():
    """The premise of the whole design: this logging call knows nothing about
    job ids and still emits one."""
    with log_context.log_context(job_id="job-1", audit_id="audit-2",
                                 trace_id="job-1"):
        out = emit_json(make_record("slot 0 claimed a job"))
    assert out["job_id"] == "job-1"
    assert out["audit_id"] == "audit-2"
    assert out["trace_id"] == "job-1"


def test_context_is_restored_after_the_block():
    with log_context.log_context(job_id="job-1"):
        pass
    assert "job_id" not in emit_json(make_record("after"))


def test_an_explicit_extra_wins_over_the_ambient_value():
    with log_context.log_context(job_id="ambient"):
        out = emit_json(make_record("explicit", job_id="stated"))
    assert out["job_id"] == "stated"


def test_an_unknown_context_field_raises_instead_of_being_ignored():
    with pytest.raises(ValueError, match="unknown log context field"):
        log_context.set_log_context(jobb_id="typo")


def test_concurrent_tasks_do_not_see_each_other_context():
    """The audit worker runs its slots as concurrent asyncio tasks in one
    process. If contextvars leaked between them, every job's log lines would
    be attributed to whichever slot last set the id."""
    seen: dict[str, dict] = {}

    async def slot(name: str, delay: float):
        with log_context.log_context(job_id=name, trace_id=name):
            await asyncio.sleep(delay)  # force the tasks to interleave
            seen[name] = emit_json(make_record(f"{name} working"))

    async def run():
        await asyncio.gather(slot("job-a", 0.02), slot("job-b", 0.01))

    asyncio.run(run())
    assert seen["job-a"]["job_id"] == "job-a"
    assert seen["job-b"]["job_id"] == "job-b"


# --- configure_logging ------------------------------------------------------

@contextmanager
def fresh_root():
    """Run a block against an empty root logger, then put it back.

    basicConfig no-ops when root already has a handler -- which is exactly the
    contract configure_logging relies on, and exactly what pytest's own
    capture handler provides. It is re-attached at the start of each test
    phase, so clearing has to happen inside the test body rather than in a
    fixture.
    """
    root = logging.getLogger()
    saved, saved_level = list(root.handlers), root.level
    for handler in saved:
        root.removeHandler(handler)
    try:
        yield root
    finally:
        for handler in list(root.handlers):
            root.removeHandler(handler)
        for handler in saved:
            root.addHandler(handler)
        root.setLevel(saved_level)


def test_default_format_is_the_plain_text_line_we_have_always_emitted(
        monkeypatch):
    monkeypatch.delenv("LOG_FORMAT", raising=False)
    with fresh_root() as root:
        configure_logging()
        assert root.handlers[0].formatter._fmt == TEXT_FORMAT


def test_log_format_json_installs_the_json_formatter(monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "json")
    with fresh_root() as root:
        configure_logging()
        assert isinstance(root.handlers[0].formatter, JsonFormatter)


def test_an_unrecognised_log_format_falls_back_to_text(monkeypatch):
    monkeypatch.setenv("LOG_FORMAT", "yaml-please")
    with fresh_root() as root:
        configure_logging()
        assert root.handlers[0].formatter._fmt == TEXT_FORMAT


def test_an_unrecognised_log_level_falls_back_to_info(monkeypatch):
    """The worker used to pass LOG_LEVEL straight to basicConfig, which raises
    on a typo; going through the shared config it degrades like the API's."""
    monkeypatch.setenv("LOG_LEVEL", "CHATTY")
    with fresh_root() as root:
        configure_logging()
        assert root.level == logging.INFO


def test_log_level_is_honoured(monkeypatch):
    monkeypatch.setenv("LOG_LEVEL", "debug")
    with fresh_root() as root:
        configure_logging()
        assert root.level == logging.DEBUG


def test_both_filters_are_installed_on_the_handler():
    kinds = {type(f) for f in build_handler().filters}
    assert kinds == {RedactionFilter, ContextFilter}


def test_the_api_and_the_worker_configure_logging_identically(monkeypatch):
    """Both entry points import the same function now; before this change
    they each had their own basicConfig call and could drift apart."""
    import app.main as main_mod
    import app.worker.main as worker_mod
    assert main_mod.configure_logging is worker_mod.configure_logging


def test_configure_logging_does_not_fight_an_existing_handler():
    """basicConfig without force= is a no-op once a handler exists -- the
    contract that keeps this from stomping on uvicorn's own logging setup."""
    with fresh_root() as root:
        existing = logging.StreamHandler()
        root.addHandler(existing)
        configure_logging()
        assert root.handlers == [existing]


def test_service_release_and_env_come_from_the_environment(monkeypatch):
    monkeypatch.setenv("SHIPIT_SERVICE", "shipit-audit-worker")
    monkeypatch.setenv("SHIPIT_RELEASE", "abc1234")
    monkeypatch.setenv("ENVIRONMENT", "production")
    out = emit_json(make_record("up"))
    assert out["service"] == "shipit-audit-worker"
    assert out["release"] == "abc1234"
    assert out["env"] == "production"


def test_version_endpoint_and_log_records_read_the_same_source(monkeypatch):
    """/version and the log line must never disagree about which build is
    running, so they read release/env through the same helpers."""
    from fastapi.testclient import TestClient
    from app.main import app

    monkeypatch.setenv("SHIPIT_RELEASE", "deadbee")
    monkeypatch.setenv("ENVIRONMENT", "production")
    body = TestClient(app).get("/version").json()
    out = emit_json(make_record("up"))
    assert body["release"] == out["release"] == "deadbee"
    assert body["environment"] == out["env"] == "production"


# --- uvicorn's access log ------------------------------------------------
#
# The audit access_token rides in the query string (?token=...), so every
# access log line used to carry the ownership secret for the row it served.
# RedactionFilter never saw those records: uvicorn.access has propagate=False
# and its own handler, so nothing on the root handler applies to it.


@contextmanager
def uvicorn_access_logger():
    """A uvicorn.access logger configured the way uvicorn configures it,
    writing into a buffer. Restored afterwards so this never leaks into
    other tests."""
    import io
    import logging.config

    from uvicorn.config import LOGGING_CONFIG

    logger = logging.getLogger("uvicorn.access")
    saved_handlers, saved_propagate = logger.handlers[:], logger.propagate
    try:
        logging.config.dictConfig(LOGGING_CONFIG)
        configure_logging()
        buf = io.StringIO()
        for handler in logging.getLogger("uvicorn.access").handlers:
            handler.stream = buf
        yield logging.getLogger("uvicorn.access"), buf
    finally:
        logger.handlers, logger.propagate = saved_handlers, saved_propagate


def _access(logger, path):
    """One access record in uvicorn's own five-argument shape."""
    logger.info('%s - "%s %s HTTP/%s" %d',
                "1.2.3.4", "GET", path, "1.1", 200)


def test_access_log_does_not_carry_the_audit_access_token():
    token = "deadbeefdeadbeefdeadbeefdeadbeef"  # fake, hand-written shape
    with uvicorn_access_logger() as (logger, buf):
        _access(logger, f"/v1/audits/abc123?token={token}")
    out = buf.getvalue()
    assert token not in out
    assert "/v1/audits/abc123" in out, "the path itself must survive"


def test_access_log_line_is_not_dropped_by_the_filter():
    """The obvious fix -- adding RedactionFilter here -- empties record.args,
    and uvicorn's AccessFormatter unpacks exactly five of them, so the line
    dies with a ValueError instead of being masked. Both lines must arrive."""
    with uvicorn_access_logger() as (logger, buf):
        _access(logger, "/v1/audits/abc123?token=deadbeefdeadbeef")
        _access(logger, "/healthz")
    assert buf.getvalue().count("\n") == 2


def test_access_log_leaves_a_query_less_path_alone():
    with uvicorn_access_logger() as (logger, buf):
        _access(logger, "/healthz")
    assert "?" not in buf.getvalue()


def test_configure_logging_does_not_stack_duplicate_access_filters():
    with uvicorn_access_logger() as (logger, _buf):
        configure_logging()
        configure_logging()
        for handler in logger.handlers:
            assert sum(isinstance(f, StripAccessQueryFilter)
                       for f in handler.filters) == 1
