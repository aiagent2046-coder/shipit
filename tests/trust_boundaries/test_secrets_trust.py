"""Trust boundary 3: a committed secret contradicts every other control.

Two families of tests:

* golden behaviour of the secrets scanner per storage context (source,
  docs, tests, migrations), and
* the scanner's load-bearing invariant -- a finding NEVER carries the
  secret value itself, only a masked preview. A regression here turns the
  audit report into the leak it describes.
"""

from __future__ import annotations

import dataclasses

import pytest

from tests.detector_samples import SAMPLES

from app.scan.secrets import RULES, scan_secrets
from app.scan.static import run_static_scan

from .conftest import make_zip

STRIPE_KEY = SAMPLES["STRIPE"]
DSN = SAMPLES["REMOTE_DSN"]
PRIVATE_KEY = SAMPLES["PRIVATE_KEY"]
TELEGRAM_TOKEN = SAMPLES["TELEGRAM"]

# The payloads the no-leak invariant is checked against. Every payload must
# match at least one rule, or the invariant test passes vacuously.
LEAK_PAYLOADS = {
    "src/config.ts": f'export const KEY = "{STRIPE_KEY}"',
    "src/db.ts": f'const url = "{DSN}"',
    "keys/id_rsa": PRIVATE_KEY,
    "src/bot.ts": f'const token = "{TELEGRAM_TOKEN}"',
}


def test_every_payload_is_detected_otherwise_the_invariant_is_vacuous():
    for fname, body in LEAK_PAYLOADS.items():
        found = scan_secrets(make_zip({fname: body}))
        assert found, f"payload in {fname} matched no rule -- test is vacuous"


def test_findings_never_contain_the_secret_value():
    for fname, body in LEAK_PAYLOADS.items():
        secret = {STRIPE_KEY, DSN, "Z" * 24, TELEGRAM_TOKEN, "INCOMPLETE-SYNTHETIC-MATERIAL"}
        for f in scan_secrets(make_zip({fname: body})):
            blob = " ".join(
                str(getattr(f, fld.name)) for fld in dataclasses.fields(f)
            )
            for value in secret:
                assert value not in blob, (
                    f"{f.rule_id} in {fname} leaks the secret value "
                    f"through field content: {blob!r}"
                )


def test_key_in_source_is_critical_security():
    found = scan_secrets(make_zip({"src/config.ts": f'export const K = "{STRIPE_KEY}"'}))
    assert [(f.rule_id, f.severity) for f in found] == [
        ("stripe-live-key", "critical")
    ]


def test_same_key_in_docs_is_capped_not_dropped():
    """A real key pasted into a tutorial is still a leak -- but capped at
    medium so one blog post cannot zero the Security score."""
    found = scan_secrets(make_zip({"docs/guide.md": f"set {STRIPE_KEY} in env"}))
    assert [f.rule_id for f in found] == ["stripe-live-key"]
    assert found[0].severity == "medium"
    assert found[0].context == "doc_example"


def test_same_key_in_a_test_file_is_capped_not_dropped():
    found = scan_secrets(
        make_zip({"src/lib/__tests__/pay.test.ts": f'const K = "{STRIPE_KEY}"'})
    )
    assert [f.rule_id for f in found] == ["stripe-live-key"]
    assert found[0].severity == "medium"


def test_key_in_a_migration_keeps_full_confidence():
    """A secret in a migration is committed, applied state -- doc-style
    damping must NOT reach it."""
    found = scan_secrets(
        make_zip({"supabase/migrations/0001.sql": f"insert into cfg values ('{STRIPE_KEY}');"})
    )
    assert found[0].severity == "critical"
    assert found[0].confidence >= 0.9


def test_placeholder_value_is_not_a_finding():
    found = scan_secrets(make_zip({"src/config.ts": f'const K = "{SAMPLES["STRIPE_PLACEHOLDER"]}"'}))
    assert found == []


def test_env_file_with_credentials_is_critical_and_gates_the_score():
    out = run_static_scan(make_zip({
        ".env": f"DATABASE_URL={DSN}\n",
        "package.json": '{"dependencies": {"next": "14.0.0"}}',
    }))
    by_rule = {f["rule_id"]: f for f in out["findings"]}
    assert by_rule["env-file-committed"]["severity"] == "critical"
    # One committed credential is enough: the gate must cap the headline.
    assert out["score"]["total"] <= 6.9
    assert out["score"]["gated_by"] != []


def test_env_example_file_is_not_reported_as_committed():
    out = run_static_scan(make_zip({
        ".env.example": f"DATABASE_URL={SAMPLES['DEV_DSN']}\n",
        "package.json": "{}",
    }))
    assert "env-file-committed" not in {f["rule_id"] for f in out["findings"]}


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason="known gap: a secret assembled by string concatenation "
           "('sk_live_' + rest) defeats the line-based rules",
)
def test_split_string_secret_is_detected():
    found = scan_secrets(make_zip({
        "src/config.ts": f'const K = "sk_live_" + "{STRIPE_KEY.removeprefix("sk_live_")}"'
    }))
    assert any(f.rule_id == "stripe-live-key" for f in found)


def test_every_secrets_rule_has_a_distinct_id_and_pattern():
    ids = [r.id for r in RULES]
    assert len(ids) == len(set(ids))
