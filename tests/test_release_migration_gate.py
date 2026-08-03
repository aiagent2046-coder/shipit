from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "deploy"
    / "scripts"
    / "check_release_migrations.py"
)

SPEC = importlib.util.spec_from_file_location(
    "shipit_release_migration_gate",
    MODULE_PATH,
)

assert SPEC is not None
assert SPEC.loader is not None

migration_gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration_gate
SPEC.loader.exec_module(migration_gate)


def applied(rows: dict[str, str], **safe: bool | None) -> dict:
    """Ledger rows keyed by filename. `safe` carries the rollback-safe flag,
    defaulting to None -- the state of every row written before the column
    existed, and the state the gate must keep treating as unsafe."""
    return {
        filename: migration_gate.AppliedRow(
            checksum=checksum,
            rollback_safe=safe.get(filename.split("_")[0]),
        )
        for filename, checksum in rows.items()
    }


def test_compare_accepts_exact_match() -> None:
    expected = {
        "0001_first.sql": "a" * 64,
        "0002_second.sql": "b" * 64,
    }

    assert (
        migration_gate.compare_migrations(
            expected,
            applied(expected),
        )
        == []
    )


def test_compare_detects_pending_database_migration() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
            "0002_second.sql": "b" * 64,
        },
        applied({
            "0001_first.sql": "a" * 64,
        }),
    )

    assert errors == [
        "database is missing release migration: 0002_second.sql"
    ]


def test_compare_blocks_database_ahead_of_release() -> None:
    """An undeclared migration blocks the rollback, as it always has. Silence
    is not consent: rows written before the column existed read as None, and
    None must not open the gate."""
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        applied({
            "0001_first.sql": "a" * 64,
            "0002_second.sql": "b" * 64,
        }),
    )

    assert errors == [
        "database is ahead of release: 0002_second.sql "
        "(no rollback-safe declaration; assuming unsafe)"
    ]


def test_compare_detects_checksum_drift() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        applied({
            "0001_first.sql": "b" * 64,
        }),
    )

    assert errors == [
        "migration checksum mismatch: 0001_first.sql"
    ]


def test_compare_allows_rollback_past_a_declared_safe_migration() -> None:
    """The whole point. An additive migration -- an index the old code never
    looks at -- must not make the release that carried it irreversible."""
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        applied(
            {
                "0001_first.sql": "a" * 64,
                "0002_second.sql": "b" * 64,
            },
            **{"0002": True},
        ),
    )

    assert errors == []


def test_compare_blocks_rollback_past_a_declared_unsafe_migration() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        applied(
            {
                "0001_first.sql": "a" * 64,
                "0002_second.sql": "b" * 64,
            },
            **{"0002": False},
        ),
    )

    assert errors == [
        "database is ahead of release: 0002_second.sql "
        "(declared rollback-safe: no)"
    ]


def test_one_unsafe_migration_blocks_the_whole_rollback() -> None:
    """A safe migration next to an unsafe one does not launder it. The gate
    answers one question -- can this release run against this schema -- and a
    single no is a no."""
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        applied(
            {
                "0001_first.sql": "a" * 64,
                "0002_second.sql": "b" * 64,
                "0003_third.sql": "c" * 64,
            },
            **{"0002": True, "0003": False},
        ),
    )

    assert errors == [
        "database is ahead of release: 0003_third.sql "
        "(declared rollback-safe: no)"
    ]


def test_a_safe_migration_does_not_excuse_a_missing_one() -> None:
    """Ahead and behind at once: the release has a migration the database
    lacks, and the database has a safe one the release lacks. The missing one
    is still fatal -- relaxing the ahead case must not relax anything else."""
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
            "0004_fourth.sql": "d" * 64,
        },
        applied(
            {
                "0001_first.sql": "a" * 64,
                "0002_second.sql": "b" * 64,
            },
            **{"0002": True},
        ),
    )

    assert errors == [
        "database is missing release migration: 0004_fourth.sql"
    ]
