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


def test_compare_accepts_exact_match() -> None:
    expected = {
        "0001_first.sql": "a" * 64,
        "0002_second.sql": "b" * 64,
    }

    assert (
        migration_gate.compare_migrations(
            expected,
            dict(expected),
        )
        == []
    )


def test_compare_detects_pending_database_migration() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
            "0002_second.sql": "b" * 64,
        },
        {
            "0001_first.sql": "a" * 64,
        },
    )

    assert errors == [
        "database is missing release migration: 0002_second.sql"
    ]


def test_compare_blocks_database_ahead_of_release() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        {
            "0001_first.sql": "a" * 64,
            "0002_second.sql": "b" * 64,
        },
    )

    assert errors == [
        "database is ahead of release: 0002_second.sql"
    ]


def test_compare_detects_checksum_drift() -> None:
    errors = migration_gate.compare_migrations(
        {
            "0001_first.sql": "a" * 64,
        },
        {
            "0001_first.sql": "b" * 64,
        },
    )

    assert errors == [
        "migration checksum mismatch: 0001_first.sql"
    ]
