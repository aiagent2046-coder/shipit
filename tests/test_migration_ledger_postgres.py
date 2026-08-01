"""Real-Postgres test for the two readers of the migration ledger.

Both parse psql's unaligned tab-separated output by hand, and both were broken
by the same one-character detail the moment the ledger grew a nullable column:
a NULL comes back as an EMPTY last field, so the row ends in a tab, and
`line.strip()` removed it -- turning a four-field row into a three-field one
and raising "unexpected migration ledger row format" on every read.

Nothing in the fake-based suite could have caught that. The gate's unit tests
exercise compare_migrations with dicts built in Python, and the manager's
exercise validation against files on disk; neither one has ever seen psql's
actual bytes. This file is the only place the parsing itself is executed.

SKIPPED unless DATABASE_URL is set, following tests/test_db_postgres_smoke.py:
the value is captured at IMPORT time because conftest's autouse fixture
deletes it before any test body runs.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[1]

_LEDGER_DB_URL = os.environ.get("DATABASE_URL")

pytestmark = pytest.mark.skipif(
    not _LEDGER_DB_URL,
    reason=(
        "real-Postgres ledger test: set DATABASE_URL to a live Postgres "
        "(CI does; local runs without it are skipped)"
    ),
)


def _load(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, REPO_ROOT / relative)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


migration_manager = _load(
    "shipit_migration_manager_pg", "scripts/migration_manager.py"
)
migration_gate = _load(
    "shipit_release_migration_gate_pg",
    "deploy/scripts/check_release_migrations.py",
)


@pytest.fixture
def ledger_db(monkeypatch):
    """The CI database with every migration already applied by the workflow's
    earlier step, so the ledger holds one row per migration file."""
    monkeypatch.setenv("DATABASE_URL", _LEDGER_DB_URL)
    return _LEDGER_DB_URL


def _psql(database_url: str, sql: str) -> None:
    completed = subprocess.run(
        ["psql", database_url, "--no-psqlrc", "-X",
         "-v", "ON_ERROR_STOP=1", "--quiet"],
        input=sql, text=True, capture_output=True, check=False,
    )
    assert completed.returncode == 0, completed.stderr


def test_manager_reads_a_ledger_full_of_null_flags(ledger_db) -> None:
    """Every row applied so far predates the directive, so every rollback_safe
    is NULL. That is the case that broke, and it is the normal case."""
    applied = migration_manager.load_applied()

    assert applied, "the workflow applies all migrations before this runs"
    assert all(row.rollback_safe is None for row in applied.values())
    assert all(len(row.checksum) == 64 for row in applied.values())


def test_gate_reads_the_same_ledger(ledger_db) -> None:
    """The gate has its own parser, so it needs its own proof."""
    applied = migration_gate.query_applied_migrations(ledger_db)

    assert set(applied) == set(migration_manager.load_applied())
    assert all(row.rollback_safe is None for row in applied.values())


def test_both_readers_round_trip_true_and_false(ledger_db) -> None:
    """A NULL flag and a set flag take different paths through psql's output
    ('' vs 'true'/'false'), so all three are asserted end to end rather than
    only the one the ledger happens to contain today."""
    _psql(ledger_db, """
        INSERT INTO public.shipit_schema_migrations
            (filename, checksum, git_sha, execution_mode, rollback_safe)
        VALUES
            ('9998_safe.sql', repeat('a', 64), 'test', 'apply', true),
            ('9999_unsafe.sql', repeat('b', 64), 'test', 'apply', false);
    """)
    try:
        from_manager = migration_manager.load_applied()
        from_gate = migration_gate.query_applied_migrations(ledger_db)

        for applied in (from_manager, from_gate):
            assert applied["9998_safe.sql"].rollback_safe is True
            assert applied["9999_unsafe.sql"].rollback_safe is False
    finally:
        _psql(ledger_db, """
            DELETE FROM public.shipit_schema_migrations
            WHERE filename IN ('9998_safe.sql', '9999_unsafe.sql');
        """)


def test_the_column_is_added_to_an_existing_ledger(ledger_db) -> None:
    """ensure_ledger_columns is what upgrades a production ledger in place.
    Dropping the column and reading it back also proves the to_jsonb read
    tolerates its absence -- which is what keeps `status` and the gate working
    on a deployment where nothing has been applied since the upgrade."""
    _psql(ledger_db, """
        ALTER TABLE public.shipit_schema_migrations
            DROP COLUMN IF EXISTS rollback_safe;
    """)
    try:
        # Both readers must survive the column simply not being there.
        assert all(
            row.rollback_safe is None
            for row in migration_manager.load_applied().values()
        )
        assert all(
            row.rollback_safe is None
            for row in migration_gate.query_applied_migrations(
                ledger_db
            ).values()
        )

        migration_manager.ensure_ledger_columns()
        migration_manager.ensure_ledger_columns()  # idempotent
    finally:
        migration_manager.ensure_ledger_columns()
