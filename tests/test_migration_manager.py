from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


MODULE_PATH = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "migration_manager.py"
)

SPEC = importlib.util.spec_from_file_location(
    "shipit_migration_manager",
    MODULE_PATH,
)

assert SPEC is not None
assert SPEC.loader is not None

migration_manager = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = migration_manager
SPEC.loader.exec_module(migration_manager)


def write_migration(
    directory: Path,
    name: str,
    sql: str,
) -> Path:
    path = directory / name
    path.write_text(sql, encoding="utf-8")
    return path


def test_strip_sql_comments_removes_line_and_block_comments() -> None:
    sql = """
    -- DROP TABLE ignored_line_comment;
    SELECT 1;
    /*
      TRUNCATE ignored_block_comment;
    */
    """

    stripped = migration_manager.strip_sql_comments(sql)

    assert "DROP TABLE" not in stripped
    assert "TRUNCATE" not in stripped
    assert "SELECT 1" in stripped


def test_destructive_keywords_inside_comments_are_ignored() -> None:
    sql = """
    -- DROP TABLE accounts;
    /* DELETE FROM payments; */
    CREATE TABLE example (id integer);
    """

    assert migration_manager.classify_destructive(sql) == ()


@pytest.mark.parametrize(
    ("sql", "expected"),
    [
        ("DROP TABLE example;", ("DROP",)),
        ("TRUNCATE example;", ("TRUNCATE",)),
        ("DELETE FROM example;", ("DELETE",)),
        (
            "DROP TABLE example; DELETE FROM other;",
            ("DROP", "DELETE"),
        ),
    ],
)
def test_classify_destructive(
    sql: str,
    expected: tuple[str, ...],
) -> None:
    assert migration_manager.classify_destructive(sql) == expected


def test_discover_migrations_orders_files_and_hashes_content(
    tmp_path: Path,
) -> None:
    write_migration(
        tmp_path,
        "0002_second.sql",
        "SELECT 2;\n",
    )
    write_migration(
        tmp_path,
        "0001_first.sql",
        "SELECT 1;\n",
    )

    migrations = migration_manager.discover_migrations(tmp_path)

    assert [item.name for item in migrations] == [
        "0001_first.sql",
        "0002_second.sql",
    ]
    assert all(len(item.checksum) == 64 for item in migrations)


def test_discover_migrations_rejects_duplicate_number(
    tmp_path: Path,
) -> None:
    write_migration(
        tmp_path,
        "0001_first.sql",
        "SELECT 1;\n",
    )
    write_migration(
        tmp_path,
        "0001_second.sql",
        "SELECT 2;\n",
    )

    with pytest.raises(
        migration_manager.MigrationError,
        match="duplicate migration number",
    ):
        migration_manager.discover_migrations(tmp_path)


@pytest.mark.parametrize(
    "sql",
    [
        "BEGIN; SELECT 1; COMMIT;",
        "START TRANSACTION; SELECT 1;",
        "ROLLBACK;",
    ],
)
def test_validate_rejects_transaction_control(
    tmp_path: Path,
    sql: str,
) -> None:
    path = write_migration(
        tmp_path,
        "0001_test.sql",
        sql,
    )

    migration = migration_manager.Migration(
        number=1,
        name=path.name,
        path=path,
        checksum=migration_manager.migration_checksum(path),
        destructive_reasons=(),
    )

    with pytest.raises(
        migration_manager.MigrationError,
        match="transaction control",
    ):
        migration_manager.validate_migration_sql(migration)


def test_validate_rejects_psql_meta_command(
    tmp_path: Path,
) -> None:
    path = write_migration(
        tmp_path,
        "0001_test.sql",
        "\\i another.sql\n",
    )

    migration = migration_manager.Migration(
        number=1,
        name=path.name,
        path=path,
        checksum=migration_manager.migration_checksum(path),
        destructive_reasons=(),
    )

    with pytest.raises(
        migration_manager.MigrationError,
        match="meta-commands",
    ):
        migration_manager.validate_migration_sql(migration)


def test_verify_applied_integrity_detects_checksum_drift(
    tmp_path: Path,
) -> None:
    path = write_migration(
        tmp_path,
        "0001_test.sql",
        "SELECT 1;\n",
    )

    migration = migration_manager.Migration(
        number=1,
        name=path.name,
        path=path,
        checksum=migration_manager.migration_checksum(path),
        destructive_reasons=(),
    )

    applied = {
        migration.name: migration_manager.AppliedMigration(
            name=migration.name,
            checksum="0" * 64,
            execution_mode="apply",
        )
    }

    with pytest.raises(
        migration_manager.MigrationError,
        match="checksum drift",
    ):
        migration_manager.verify_applied_integrity(
            [migration],
            applied,
        )


def test_verify_applied_integrity_detects_ordering_gap(
    tmp_path: Path,
) -> None:
    first_path = write_migration(
        tmp_path,
        "0001_first.sql",
        "SELECT 1;\n",
    )
    second_path = write_migration(
        tmp_path,
        "0002_second.sql",
        "SELECT 2;\n",
    )

    migrations = migration_manager.discover_migrations(tmp_path)
    second = migrations[1]

    applied = {
        second.name: migration_manager.AppliedMigration(
            name=second.name,
            checksum=second.checksum,
            execution_mode="apply",
        )
    }

    with pytest.raises(
        migration_manager.MigrationError,
        match="ordering gap",
    ):
        migration_manager.verify_applied_integrity(
            migrations,
            applied,
        )


def test_baseline_refuses_partial_legacy_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(
        "SHIPIT_BASELINE_CONFIRM",
        "I_HAVE_VERIFIED_THE_PRODUCTION_SCHEMA",
    )
    monkeypatch.setattr(
        migration_manager,
        "existing_app_table_count",
        lambda: 1,
    )

    with pytest.raises(
        migration_manager.MigrationError,
        match=r"detected 1/9",
    ):
        migration_manager.baseline_migrations(
            [],
            confirmed=True,
        )
