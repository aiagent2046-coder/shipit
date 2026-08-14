"""Tests for scripts/audit_test_data.py (issue #197).

The load-bearing property is the NEGATIVE one: no value a real payment
provider or the real app can produce may classify as synthetic. Every
positive fixture below is paired with the nearest real value that a
loosened pattern would swallow -- each such test fails on the mutation
that widens its pattern, which is what keeps --delete safe.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import audit_test_data as atd  # noqa: E402


# ---------------------------------------------------------------- classify

def test_smoke_fixtures_classify_as_synthetic():
    row = {"repo_url": "https://github.com/acme/app",
           "content_hash": "smoke-278bcdc68ae9",
           "engine_version": "smoke-engine-1"}
    reasons = atd.classify("audits", row)
    assert len(reasons) == 3  # every audit signature fires on its own column


def test_real_audits_do_not_classify():
    row = {"repo_url": "https://github.com/tiangolo/fastapi",
           "content_hash": "9f2c1ab" * 8,
           "engine_version": "2026-08-14-7"}
    assert atd.classify("audits", row) == []


@pytest.mark.parametrize("value", [
    "ORDER-278bcdc68ae9", "CAPTURE-278bcdc68ae9",
    "0xcompleted-278bcdc68ae9", "0xfixpack-278bcdc68ae9",
])
def test_smoke_payment_refs_classify(value):
    assert atd.classify("payments", {"external_ref": value}) != []


@pytest.mark.parametrize("value", [
    "5O190127TN364715T",          # real PayPal capture id shape
    "0x" + "ab" * 32,             # real USDT tx hash: 0x + 64 hex, no dash
    "DRY-KX2V9Q",                 # real bank-transfer reference
    "tc_3PzQwF2eZvKYlo2CqR0xYz",  # real Telegram charge id shape
])
def test_real_payment_refs_do_not_classify(value):
    assert atd.classify("payments", {"external_ref": value}) == []


def test_smoke_subscription_classifies():
    row = {"telegram_user_id": "user-278bcdc68ae9",
           "invoice_payload": "sub-278bcdc68ae9",
           "telegram_chat_id": "chat-278bcdc68ae9",
           "paypal_subscription_id": "I-278bcdc68ae9"}
    assert len(atd.classify("subscriptions", row)) == 4


@pytest.mark.parametrize("column,value", [
    ("telegram_user_id", "5123456789"),        # real Telegram ids are numeric
    ("invoice_payload", "sub:monitor:acme/app"),  # real: colon, not dash
    ("invoice_payload", "pro"),
    ("invoice_payload", "fixpack:9f2c1ab"),
    ("telegram_chat_id", "-1001234567890"),
    ("paypal_subscription_id", "I-BW452GLLEP1G"),  # real: uppercase alnum
])
def test_real_subscription_values_do_not_classify(column, value):
    assert atd.classify("subscriptions", {column: value}) == []


def test_paypal_regex_rejects_uppercase_real_ids():
    # The mutation that matters most: widening [0-9a-f] to [0-9a-zA-Z]
    # would classify every real PayPal subscription on file.
    rule = next(r for r in atd.RULES if r.column == "paypal_subscription_id")
    assert atd._matches(rule, "I-278bcdc68ae9") is True
    assert atd._matches(rule, "I-BW452GLLEP1G") is False
    assert atd._matches(rule, "I-278BCDC68AE9") is False  # uppercase hex
    assert atd._matches(rule, "I-278bcdc68ae9ff") is False  # wrong length


def test_none_values_never_match():
    for rule in atd.RULES:
        assert atd._matches(rule, None) is False


def test_unknown_rule_kind_raises():
    rule = atd.Rule("t", "c", "bogus", "x", "r")
    with pytest.raises(ValueError):
        atd._matches(rule, "x")


# ---------------------------------------------------------------- probe_sql

def test_probe_sql_covers_every_rule_of_the_table():
    sql, params = atd.probe_sql("subscriptions")
    n_rules = len([r for r in atd.RULES if r.table == "subscriptions"])
    assert sql.count("%s") == n_rules == len(params)
    assert " OR " in sql  # one rule must not silently replace the rest


def test_probe_sql_rejects_unruled_table():
    with pytest.raises(ValueError):
        atd.probe_sql("llm_usage")  # transitive-only by design


def test_every_rule_table_is_in_deletion_order():
    ruled = {r.table for r in atd.RULES} | set(atd.TRANSITIVE_TABLES)
    assert ruled <= set(atd.DELETION_ORDER)


# ---------------------------------------------------------------- ordering

def test_deletion_order_respects_foreign_keys():
    order = {t: i for i, t in enumerate(atd.DELETION_ORDER)}
    # children before parents -- every FK is ON DELETE NO ACTION
    assert order["fix_outcomes"] < order["fixpack_jobs"] < order["audits"]
    assert order["llm_usage"] < order["audit_jobs"]
    assert order["payments"] < order["accounts"]
    assert order["subscriptions"] < order["accounts"]
    assert order["audit_jobs"] < order["accounts"]
    assert order["accounts"] == len(atd.DELETION_ORDER) - 1


# ---------------------------------------------------------------- accounts

def test_account_synthetic_truth_table():
    assert atd.account_is_synthetic(1, 0) is True   # only test rows
    assert atd.account_is_synthetic(0, 0) is False  # nothing proven synthetic
    assert atd.account_is_synthetic(0, 3) is False  # quiet real account
    assert atd.account_is_synthetic(2, 1) is False  # touched real account


# ------------------------------------------------------- schema consistency

def _schema_from_migrations() -> dict[str, set[str]]:
    """table -> columns, parsed from migrations/*.sql.

    The script's SQL is verified structurally here rather than against a
    live database: a renamed or mistyped column fails this test instead of
    the operator's cleanup run.
    """
    import re as _re

    schema: dict[str, set[str]] = {}
    migrations = (Path(__file__).resolve().parent.parent / "migrations")
    for path in sorted(migrations.glob("*.sql")):
        sql = path.read_text()
        for m in _re.finditer(
                r"create table if not exists (\w+) \((.*?)\n\);",
                sql, _re.S):
            table, body = m.group(1), m.group(2)
            cols = schema.setdefault(table, set())
            for line in body.splitlines():
                line = line.strip()
                if line and not line.startswith(("--", ")", "create")):
                    cols.add(line.split()[0].rstrip(","))
        for m in _re.finditer(
                r"alter table (\w+) add column if not exists (\w+)", sql):
            schema.setdefault(m.group(1), set()).add(m.group(2))
    return schema


def test_every_rule_column_exists_in_the_migrations():
    schema = _schema_from_migrations()
    for rule in atd.RULES:
        assert rule.column in schema.get(rule.table, set()), (
            f"{rule.table}.{rule.column} not found in migrations")


def test_account_link_columns_exist_in_the_migrations():
    schema = _schema_from_migrations()
    for table, col in atd.ACCOUNT_CHILDREN.items():
        assert col in schema.get(table, set())
    assert "id" in schema["accounts"]


def test_deletion_order_tables_exist_in_the_migrations():
    schema = _schema_from_migrations()
    for table in atd.DELETION_ORDER:
        assert table in schema


# ---------------------------------------------------------------- masking

def test_mask_dsn_never_prints_the_password():
    url = "postgresql://postgres.refs:s3cret-pass@aws-0-eu.pooler.supabase.com:5432/postgres"
    masked = atd.mask_dsn(url)
    assert "s3cret-pass" not in masked
    assert "aws-0-eu.pooler.supabase.com/postgres" == masked
