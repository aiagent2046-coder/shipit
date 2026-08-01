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
        rollback_safe=None,
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
        rollback_safe=None,
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
        rollback_safe=None,
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


# --- the rollback-safe directive ---
#
# The release migration gate used to block every rollback past every
# migration, which made any release carrying one irreversible. It now asks the
# ledger whether the migration was declared safe for the previous release's
# code. That declaration is made here, in the file, by the author.


def only(directory: Path, name: str, sql: str):
    directory.mkdir(parents=True, exist_ok=True)
    write_migration(directory, name, sql)
    return migration_manager.discover_migrations(directory)[0]


def test_directive_is_parsed_from_the_header(tmp_path: Path) -> None:
    yes = only(tmp_path / "y", "0028_a.sql",
               "-- rollback-safe: yes\ncreate index i on t (c);\n")
    assert yes.rollback_safe is True

    no = only(tmp_path / "n", "0028_a.sql",
              "-- rollback-safe: no\nalter table t drop column c;\n")
    assert no.rollback_safe is False


def test_a_file_with_no_directive_reads_as_unknown(tmp_path: Path) -> None:
    """Not False. The gate treats both as blocking, but the ledger records the
    difference, and an operator reading it deserves to know whether someone
    considered the question or nobody did."""
    migration = only(tmp_path, "0001_a.sql", "create index i on t (c);\n")
    assert migration.rollback_safe is None


def test_contradicting_directives_are_an_error(tmp_path: Path) -> None:
    """The likeliest way to write a directive is to copy a header from another
    migration, so the likeliest bug is two of them. First-wins would resolve
    that silently and in whichever direction the copy happened to sit."""
    with pytest.raises(migration_manager.MigrationError, match="both yes"):
        only(tmp_path, "0028_a.sql",
             "-- rollback-safe: yes\n-- rollback-safe: no\nselect 1;\n")


def test_a_new_migration_must_carry_the_directive(tmp_path: Path) -> None:
    migration = only(tmp_path, "0028_a.sql", "create index i on t (c);\n")

    with pytest.raises(migration_manager.MigrationError,
                       match="missing required header directive"):
        migration_manager.validate_rollback_directive(migration)


def test_migrations_predating_the_directive_are_exempt(tmp_path: Path) -> None:
    """Everything below DIRECTIVE_REQUIRED_FROM is already applied wherever it
    matters. Demanding the directive retroactively would only break a fresh
    bootstrap of the existing history -- and editing those files to add one
    would change their checksums, which the gate reads as tampering."""
    migration = only(tmp_path, "0027_a.sql", "create index i on t (c);\n")
    migration_manager.validate_rollback_directive(migration)


@pytest.mark.parametrize("sql", [
    "alter table t drop column c;",
    "truncate table t;",
    "alter table t rename column a to b;",
    "alter table t alter column c type bigint;",
    "alter table t alter column c set not null;",
    "alter table t add column c text not null;",
])
def test_a_false_safe_claim_is_refused(tmp_path: Path, sql: str) -> None:
    """The declaration is trusted, but not blindly. These statements cannot be
    survived by the previous release's code, so claiming otherwise is refused
    rather than recorded."""
    migration = only(tmp_path / sql[:12].replace(" ", "_"), "0028_a.sql",
                     f"-- rollback-safe: yes\n{sql}\n")

    with pytest.raises(migration_manager.MigrationError,
                       match="declares .rollback-safe: yes. but contains"):
        migration_manager.validate_rollback_directive(migration)


def test_add_column_with_a_default_is_accepted(tmp_path: Path) -> None:
    """The boundary of the NOT NULL pattern. `add column not null default x`
    is fine for old code -- it never writes the column and the default fills
    it -- so the check must not swallow it along with the bare NOT NULL."""
    migration = only(tmp_path, "0028_a.sql",
                     "-- rollback-safe: yes\n"
                     "alter table t add column c text not null default '';\n")
    migration_manager.validate_rollback_directive(migration)


def test_the_claim_is_judged_on_sql_not_on_prose(tmp_path: Path) -> None:
    """Every migration in this repo explains itself in a header comment, and
    those comments discuss what was NOT done -- 0027's says "NOT a unique
    index" and the word DROP appears in others. Classifying on raw text would
    reject correct migrations for describing themselves."""
    migration = only(tmp_path, "0028_a.sql",
                     "-- rollback-safe: yes\n"
                     "-- Considered DROP INDEX here and rejected it.\n"
                     "create index i on t (c);\n")
    migration_manager.validate_rollback_directive(migration)


def test_declaring_no_is_never_second_guessed(tmp_path: Path) -> None:
    """A migration can be unsafe for a reason no pattern sees -- code that
    reads a column this one starts writing. Being wrong in that direction only
    costs a rollback that stays blocked, so `no` is taken at face value."""
    migration = only(tmp_path, "0028_a.sql",
                     "-- rollback-safe: no\ncreate index i on t (c);\n")
    migration_manager.validate_rollback_directive(migration)


def test_lint_reports_every_bad_file_not_just_the_first(tmp_path: Path) -> None:
    """CI feedback: fixing one migration and pushing again to discover the
    next one is a loop worth not having."""
    write_migration(tmp_path, "0028_a.sql", "create index i on t (c);\n")
    write_migration(tmp_path, "0029_b.sql",
                    "-- rollback-safe: yes\ndrop table t;\n")

    migrations = migration_manager.discover_migrations(tmp_path)
    assert migration_manager.lint_migrations(migrations) == 1


def test_lint_passes_on_the_real_migration_directory() -> None:
    """The repo's own 27 files must keep linting clean, or CI blocks every PR
    that touches migrations."""
    assert migration_manager.lint_migrations(
        migration_manager.discover_migrations()
    ) == 0
