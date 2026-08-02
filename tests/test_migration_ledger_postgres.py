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


def test_manager_reads_a_ledger_of_mostly_null_flags(ledger_db) -> None:
    """A NULL rollback_safe is the normal case and the one that broke the
    parser: almost every migration predates the directive.

    This used to assert that EVERY flag was NULL, which stopped being true the
    moment 0028 became the first migration to declare one. The property worth
    holding is that the parser survives a ledger where most rows are NULL --
    not that the project never adopts its own directive.
    """
    applied = migration_manager.load_applied()

    assert applied, "the workflow applies all migrations before this runs"
    assert any(row.rollback_safe is None for row in applied.values())
    assert all(row.rollback_safe in (None, True, False)
               for row in applied.values())
    assert all(len(row.checksum) == 64 for row in applied.values())


def test_gate_reads_the_same_ledger(ledger_db) -> None:
    """The gate has its own parser, so it needs its own proof."""
    applied = migration_gate.query_applied_migrations(ledger_db)

    assert set(applied) == set(migration_manager.load_applied())
    # Same flags, read by a different parser -- that agreement is the point,
    # not any particular value. Asserting they were all NULL made this test
    # fail on the first migration that declared the directive.
    from_manager = migration_manager.load_applied()
    assert {name: row.rollback_safe for name, row in applied.items()} == \
           {name: row.rollback_safe for name, row in from_manager.items()}


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


# --- marking an already-applied migration ---
#
# The directive belongs in the migration file, but a file that has already
# been applied cannot be edited to add one: the checksum would change and the
# gate would read that as tampering. So the migrations applied before the
# directive existed -- including 0027, the one that made the current
# production release irreversible -- can only be classified against a
# database, by an operator, here.


def _flag(filename: str):
    return migration_manager.load_applied()[filename].rollback_safe


def _clear_flag(database_url: str, filename: str) -> None:
    _psql(database_url, f"""
        UPDATE public.shipit_schema_migrations
        SET rollback_safe = NULL
        WHERE filename = '{filename}';
    """)


@pytest.fixture
def unmarked(ledger_db):
    """Every migration back to NULL after the test, whatever it did."""
    yield ledger_db
    _psql(ledger_db, """
        UPDATE public.shipit_schema_migrations SET rollback_safe = NULL;
    """)


def test_mark_records_the_flag(unmarked) -> None:
    target = "0027_payments_provider_status_index.sql"
    migrations = migration_manager.discover_migrations()

    assert _flag(target) is None
    migration_manager.mark_migration(
        migrations, filename=target, rollback_safe=True
    )
    assert _flag(target) is True


def test_mark_refuses_to_overwrite_an_existing_flag(unmarked) -> None:
    """Widening a `no` into a `yes` from a command line, with no file diff and
    no review, is the one thing here that could quietly authorise a rollback
    that loses data."""
    target = "0027_payments_provider_status_index.sql"
    migrations = migration_manager.discover_migrations()

    migration_manager.mark_migration(
        migrations, filename=target, rollback_safe=True
    )

    with pytest.raises(migration_manager.MigrationError,
                       match="already marked rollback-safe: yes"):
        migration_manager.mark_migration(
            migrations, filename=target, rollback_safe=False
        )

    assert _flag(target) is True


def test_mark_refuses_a_migration_the_database_never_applied(unmarked) -> None:
    """Otherwise a typo would open a rollback past a migration that is not
    there, and report success doing it."""
    with pytest.raises(migration_manager.MigrationError,
                       match="not in the ledger"):
        migration_manager.mark_migration(
            migration_manager.discover_migrations(),
            filename="9999_typo.sql", rollback_safe=True,
        )


def test_mark_applies_the_same_sql_check_as_the_directive(unmarked) -> None:
    """0019 drops a column. No operator assertion makes the previous
    release's code survive that, so the claim is refused rather than stored."""
    target = "0019_drop_accounts_api_key.sql"

    with pytest.raises(migration_manager.MigrationError, match="contains DROP"):
        migration_manager.mark_migration(
            migration_manager.discover_migrations(),
            filename=target, rollback_safe=True,
        )

    assert _flag(target) is None

    # `no` on the same migration is fine -- that is the honest answer.
    migration_manager.mark_migration(
        migration_manager.discover_migrations(),
        filename=target, rollback_safe=False,
    )
    assert _flag(target) is False


def test_mark_refuses_when_the_file_does_not_match_the_ledger(
    unmarked, tmp_path
) -> None:
    """The claim is checked against the SQL on disk, so the SQL on disk has to
    be the SQL that was applied. A file that drifted describes some other
    schema and can answer nothing about this one."""
    target = "0027_payments_provider_status_index.sql"
    real = [
        m for m in migration_manager.discover_migrations() if m.name == target
    ][0]
    tampered = migration_manager.Migration(
        number=real.number, name=real.name, path=real.path,
        checksum="0" * 64, destructive_reasons=(), rollback_safe=None,
    )

    with pytest.raises(migration_manager.MigrationError,
                       match="does not match the one recorded"):
        migration_manager.mark_migration(
            [tampered], filename=target, rollback_safe=True
        )

    assert _flag(target) is None


def test_mark_refuses_a_file_missing_from_this_release(unmarked) -> None:
    """Run from an older release that predates the migration, there is no SQL
    to check the claim against -- and taking the operator's word for it is
    exactly what the file-based directive exists to avoid."""
    target = "0027_payments_provider_status_index.sql"
    others = [
        m for m in migration_manager.discover_migrations() if m.name != target
    ]

    with pytest.raises(migration_manager.MigrationError,
                       match="not present in this release"):
        migration_manager.mark_migration(
            others, filename=target, rollback_safe=True
        )


def test_marking_0027_unblocks_the_gate(unmarked) -> None:
    """The end to end point of the command: a release that predates 0027 goes
    from blocked to deployable, which is what a rollback is."""
    target = "0027_payments_provider_status_index.sql"
    ledger = migration_manager.load_applied()
    older_release = {
        name: row.checksum for name, row in ledger.items() if name != target
    }

    before = migration_gate.compare_migrations(
        older_release, migration_gate.query_applied_migrations(unmarked)
    )
    assert before and "database is ahead of release" in before[0]

    migration_manager.mark_migration(
        migration_manager.discover_migrations(),
        filename=target, rollback_safe=True,
    )

    after = migration_gate.compare_migrations(
        older_release, migration_gate.query_applied_migrations(unmarked)
    )
    assert after == []
