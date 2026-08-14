"""Count -- and optionally delete -- test-suite rows in a live database.

Run this YOURSELF, locally, with your own DATABASE_URL. Never send that
connection string to anyone else, including an AI assistant: it contains
your Postgres password. Same boundary as scripts/verify_db_locally.py.

Why this exists (issue #197): on 2026-07-22 tests/test_db_postgres_smoke.py
was run four times against the PRODUCTION database. The suite writes real
rows and cleans up nothing, so production ended up holding synthetic
subscriptions, payments, audits and fix outcomes -- and every operator
metric derived from those tables ("how many accounts", "what is our PR
merge rate") became unverifiable until the blast radius is measured.

The recurrence is already impossible: tests/conftest.py's pytest_configure
refuses to start the suite against a non-loopback host. This script is the
other two thirds of the issue -- measuring what is already there, and
removing what is identifiably synthetic.

What counts as synthetic is a SIGNATURE, not a guess. Every pattern below
matches a string only the test suite generates, checked against the real
producers in app/ first:

  * acme/... repo names -- no real repository is hosted under github.com/acme
    in this product's intake, and the smoke tests hardcode acme/app,
    acme/paypal-smoke-<run>, acme/monitor-smoke-<run>;
  * smoke-<run> content hashes / engine versions -- real engine versions are
    date-stamped (2026-08-14-7), real content hashes are sha256 hex;
  * ORDER-<run> / CAPTURE-<run> / 0xcompleted-<run> / 0xfixpack-<run>
    external refs -- real PayPal refs are raw uppercase-alnum ids, real USDT
    refs are 0x + 64 hex, real bank refs are DRY-XXXXXX; none contain a
    dash after the prefix;
  * user-<run> / sub-<run> / chat-<run> Telegram fields -- real Telegram
    user ids are numeric, real invoice payloads are "pro" / "sub:..." /
    "fixpack:..." (colon, not dash), real chat ids are numeric;
  * paypal_subscription_id matching ^I-[0-9a-f]{12}$ -- real PayPal
    subscription ids are uppercase alphanumeric (I-BW452GLLEP1G); the smoke
    test mints I-<12 lowercase hex>.

Deliberately NOT patterns: tier='test-monitoring' (a real tier name -- the
operator's own subscription carries it, see issue #197's "not in scope"),
and created_at windows (a date is a coincidence, not a signature).

Usage:
    export DATABASE_URL="postgresql://...pooler.supabase.com:5432/postgres"
    python scripts/audit_test_data.py              # report only
    python scripts/audit_test_data.py --delete     # asks for confirmation
    python scripts/audit_test_data.py --delete --yes   # non-interactive

The report is the deliverable of issue #197 step 1 ("establish the blast
radius"); --delete is step 2. Deletion runs in ONE transaction, children
before parents (every FK is ON DELETE NO ACTION by design), and touches
only rows carrying a signature or belonging to an account that carries one
and nothing else.
"""

from __future__ import annotations

import argparse
import re
import sys
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

import psycopg  # noqa: E402
from psycopg.rows import dict_row  # noqa: E402


@dataclass(frozen=True)
class Rule:
    """One synthetic-data signature on one column of one table.

    kind "prefix" matches value LIKE pattern||'%'; kind "regex" matches
    value ~ pattern. Both are checked in Python by classify() as well, so
    the rows the SQL returns are re-verified before being reported or
    deleted -- the SQL narrows, the Python decides.
    """

    table: str
    column: str
    kind: str  # "prefix" | "regex"
    pattern: str
    reason: str


RULES: tuple[Rule, ...] = (
    # audits
    Rule("audits", "repo_url", "prefix", "https://github.com/acme/",
         "smoke-test repo (acme/)"),
    Rule("audits", "content_hash", "prefix", "smoke-",
         "smoke-test content hash"),
    Rule("audits", "engine_version", "prefix", "smoke-",
         "smoke-test engine version"),
    # fixpack_jobs
    Rule("fixpack_jobs", "pr_url", "prefix", "https://github.com/acme/",
         "smoke-test PR url (acme/)"),
    Rule("fixpack_jobs", "detail", "prefix", "smoke ",
         "smoke-test failure detail"),
    # fix_outcomes
    Rule("fix_outcomes", "pr_url", "prefix", "https://github.com/acme/",
         "smoke-test PR url (acme/)"),
    # payments -- real refs: PayPal raw uppercase ids, USDT 0x+64hex,
    # bank DRY-XXXXXX, Telegram charge ids. None carry these prefixes.
    Rule("payments", "external_ref", "prefix", "ORDER-",
         "smoke-test PayPal order id"),
    Rule("payments", "external_ref", "prefix", "CAPTURE-",
         "smoke-test PayPal capture id"),
    Rule("payments", "external_ref", "prefix", "0xcompleted-",
         "smoke-test USDT ref"),
    Rule("payments", "external_ref", "prefix", "0xfixpack-",
         "smoke-test USDT ref"),
    # subscriptions -- real user/chat ids are numeric; real payloads use
    # "sub:" with a colon (app/billing/telegram_stars.py), not "sub-".
    Rule("subscriptions", "telegram_user_id", "prefix", "user-",
         "smoke-test Telegram user id"),
    Rule("subscriptions", "invoice_payload", "prefix", "sub-",
         "smoke-test invoice payload"),
    Rule("subscriptions", "telegram_chat_id", "prefix", "chat-",
         "smoke-test chat id"),
    Rule("subscriptions", "paypal_subscription_id", "regex",
         r"^I-[0-9a-f]{12}$",
         "synthetic PayPal sub id (real ones are uppercase alnum)"),
    # monitoring_runs
    Rule("monitoring_runs", "repo_full_name", "prefix", "acme/",
         "smoke-test repo (acme/)"),
    # audit_jobs
    Rule("audit_jobs", "source_ref", "prefix", "https://github.com/acme/",
         "smoke-test repo (acme/)"),
    Rule("audit_jobs", "content_hash", "prefix", "smoke-",
         "smoke-test content hash"),
    Rule("audit_jobs", "engine_version", "prefix", "smoke-",
         "smoke-test engine version"),
)

# Tables the smoke test touches that carry NO signature column of their
# own. Their rows are identified transitively: llm_usage by the synthetic
# job it paid for, accounts by owning only synthetic children.
TRANSITIVE_TABLES = ("llm_usage", "accounts")

# Children before parents: every FK in this schema is ON DELETE NO ACTION
# by design (see docs/status-active.md "Known gaps"), so a parent delete
# while a child remains is refused. accounts is last: everything
# references it.
DELETION_ORDER = (
    "fix_outcomes", "llm_usage", "monitoring_runs", "payments",
    "subscriptions", "fixpack_jobs", "audit_jobs", "audits", "accounts",
)

# Columns linking a child table to an account, for the transitive check.
ACCOUNT_CHILDREN = {
    "payments": "account_id",
    "subscriptions": "account_id",
    "llm_usage": "account_id",
    "audit_jobs": "account_id",
}


def _matches(rule: Rule, value: object) -> bool:
    """Python-side re-verification of one row against one rule."""
    if value is None:
        return False
    text = str(value)
    if rule.kind == "prefix":
        return text.startswith(rule.pattern)
    if rule.kind == "regex":
        return re.match(rule.pattern, text) is not None
    raise ValueError(f"unknown rule kind: {rule.kind}")


def classify(table: str, row: dict) -> list[str]:
    """Reasons a row is synthetic, empty when it is not.

    A row is synthetic iff at least one rule fires. Reporting the reasons
    (not just a bool) is what lets the operator audit the classifier
    itself before trusting --delete with it.
    """
    return [r.reason for r in RULES
            if r.table == table and _matches(r, row.get(r.column))]


def probe_sql(table: str) -> tuple[str, list[str]]:
    """SELECT narrowing a table to candidate rows, plus its params.

    Every candidate is re-checked by classify() after fetching, so an
    over-broad predicate costs rows read, never rows misreported.
    """
    rules = [r for r in RULES if r.table == table]
    if not rules:
        raise ValueError(f"no rules for table {table}")
    clauses, params = [], []
    for r in rules:
        if r.kind == "prefix":
            clauses.append(f"{r.column} LIKE %s")
            params.append(r.pattern + "%")
        else:
            clauses.append(f"{r.column} ~ %s")
            params.append(r.pattern)
    where = " OR ".join(f"({c})" for c in clauses)
    return f"SELECT * FROM {table} WHERE {where}", params


def mask_dsn(url: str) -> str:
    """Host and dbname for the report, never the password.

    2026-08-02: an error echoing a config value put a live bearer token
    into the journal. A DSN is the same class of secret, and this
    script's whole output is meant to be pasted into issue #197.
    """
    parsed = urllib.parse.urlsplit(url)
    db = parsed.path.lstrip("/")
    return f"{parsed.hostname}/{db}"


def account_is_synthetic(synthetic_children: int, other_children: int) -> bool:
    """An account is test data iff it owns synthetic rows and NOTHING else.

    Both directions matter. Zero synthetic children: a real account that
    happens to be quiet. Any non-synthetic child: a real account the
    smoke test merely touched -- deleting it would take a customer's
    billing history with it.
    """
    return synthetic_children > 0 and other_children == 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--delete", action="store_true",
                        help="delete signature rows (default: report only)")
    parser.add_argument("--yes", action="store_true",
                        help="skip the interactive confirmation")
    args = parser.parse_args()

    import os
    url = os.environ.get("DATABASE_URL", "")
    if not url:
        print("FAIL: DATABASE_URL is not set -- export it first.")
        return 2

    target = mask_dsn(url)
    print(f"Target: {target}")
    if args.delete:
        print("Mode: DELETE (signature rows only, one transaction)")
    else:
        print("Mode: REPORT ONLY (pass --delete to remove)")

    if args.delete and not args.yes:
        typed = input(f"Type the target host ({target}) to confirm: ")
        if typed.strip() != target:
            print("Aborted: confirmation did not match.")
            return 2

    synthetic: dict[str, list[tuple[dict, list[str]]]] = {}
    with psycopg.connect(url, row_factory=dict_row) as conn:
        with conn.cursor() as cur:
            # Phase A: direct signatures.
            tables = sorted({r.table for r in RULES})
            for table in tables:
                sql, params = probe_sql(table)
                cur.execute(sql, params)
                rows = [(row, classify(table, row))
                        for row in cur.fetchall()]
                rows = [(row, reasons) for row, reasons in rows if reasons]
                synthetic[table] = rows

            # Phase B: transitive -- llm_usage rows paid for by a
            # synthetic audit or audit_job, and accounts owning only
            # synthetic children.
            syn_audit_ids = [r["id"] for r, _ in synthetic.get("audits", [])]
            syn_job_ids = [r["id"] for r, _ in synthetic.get("audit_jobs", [])]
            synthetic["llm_usage"] = []
            if syn_audit_ids or syn_job_ids:
                cur.execute(
                    "SELECT * FROM llm_usage WHERE job_id = ANY(%s) "
                    "OR audit_job_id = ANY(%s)",
                    (syn_audit_ids, syn_job_ids))
                synthetic["llm_usage"] = [
                    (row, ["belongs to a synthetic audit/job"])
                    for row in cur.fetchall()
                ]

            candidate_accounts: set = set()
            for table, col in ACCOUNT_CHILDREN.items():
                for row, _ in synthetic.get(table, []):
                    if row.get(col):
                        candidate_accounts.add(row[col])
            synthetic["accounts"] = []
            for account_id in sorted(candidate_accounts):
                syn_children, other_children = 0, 0
                for table, col in ACCOUNT_CHILDREN.items():
                    syn_ids = {r["id"] for r, _ in synthetic.get(table, [])}
                    cur.execute(
                        f"SELECT id FROM {table} WHERE {col} = %s",
                        (account_id,))
                    for child in cur.fetchall():
                        if child["id"] in syn_ids:
                            syn_children += 1
                        else:
                            other_children += 1
                if account_is_synthetic(syn_children, other_children):
                    cur.execute("SELECT * FROM accounts WHERE id = %s",
                                (account_id,))
                    row = cur.fetchone()
                    if row:
                        synthetic["accounts"].append(
                            (row, ["owns only synthetic rows"]))

        # Report -- the issue #197 step-1 deliverable.
        print("\n=== Blast radius ===")
        total_rows = 0
        for table in DELETION_ORDER:
            rows = synthetic.get(table, [])
            total_rows += len(rows)
            print(f"{table:20s} {len(rows):4d} synthetic rows")
            for row, reasons in rows[:5]:
                print(f"  {row['id']}  {row.get('created_at', '')}  "
                      f"{'; '.join(reasons)}")
            if len(rows) > 5:
                print(f"  ... and {len(rows) - 5} more")
        print(f"{'TOTAL':20s} {total_rows:4d}")

        if not args.delete:
            print("\nReport only. Re-run with --delete to remove these rows.")
            return 0

        # Delete, children first, one transaction.
        print("\n=== Deleting ===")
        with conn.transaction():
            for table in DELETION_ORDER:
                ids = [row["id"] for row, _ in synthetic.get(table, [])]
                if not ids:
                    continue
                cur.execute(f"DELETE FROM {table} WHERE id = ANY(%s)", (ids,))
                print(f"{table:20s} deleted {cur.rowcount}")
        print("Committed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
