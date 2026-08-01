#!/usr/bin/env python3
"""Versioned PostgreSQL migration manager for ShipIt.

The manager uses psql rather than a Python database driver so it can execute
the existing SQL migration files exactly as written.

Modes:

    status
        Inspect the ledger, checksum drift, ordering gaps and pending files.

    baseline
        Register an already-existing schema without executing historical SQL.
        This is intentionally guarded and is meant only for the initial
        production adoption of the ledger.

    apply
        Apply only pending migrations. Each migration and its ledger row are
        committed atomically.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import NoReturn, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MIGRATIONS_DIR = REPO_ROOT / "migrations"

LEDGER_TABLE = "public.shipit_schema_migrations"
ADVISORY_LOCK_NAME = "shipit-schema-migrations"
LOCAL_LOCK_PATH = Path(
    os.environ.get(
        "SHIPIT_MIGRATION_LOCK_FILE",
        "/tmp/shipit-schema-migrations.lock",
    )
)

MIGRATION_NAME_RE = re.compile(
    r"^(?P<number>[0-9]{4})_[a-z0-9_]+\.sql$"
)

APP_TABLES = (
    "accounts",
    "audits",
    "fix_outcomes",
    "fixpack_jobs",
    "llm_usage",
    "monitoring_runs",
    "payments",
    "service_flags",
    "subscriptions",
)

TRANSACTION_CONTROL_RE = re.compile(
    r"\b(?:BEGIN|COMMIT|ROLLBACK|START\s+TRANSACTION)\b",
    re.IGNORECASE,
)

PSQL_META_COMMAND_RE = re.compile(
    r"^[ \t]*\\",
    re.MULTILINE,
)

CONCURRENT_INDEX_RE = re.compile(
    r"\bCREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\b",
    re.IGNORECASE,
)

# A migration declares, in its own header, whether the PREVIOUS release's code
# runs correctly against the schema once this migration is applied. That is the
# only question a rollback needs answered, and it cannot be inferred from the
# SQL: `create index` is safe, `alter table add column` almost always is,
# `add column not null` without a default is not, and a rename never is.
# Guessing here means guessing wrong once, during an incident. So the author
# declares it and ROLLBACK_UNSAFE_PATTERNS refuses the obviously false claims.
ROLLBACK_SAFE_DIRECTIVE_RE = re.compile(
    r"^[ \t]*--[ \t]*rollback-safe:[ \t]*(yes|no)[ \t]*$",
    re.IGNORECASE | re.MULTILINE,
)

# The migration number from which the directive is mandatory. Everything below
# it predates the directive and is already applied everywhere, so demanding it
# retroactively would only break a fresh bootstrap of the existing history.
DIRECTIVE_REQUIRED_FROM = 28

# Statements that contradict a `rollback-safe: yes` claim. Not a completeness
# check -- a migration can be rollback-unsafe without matching any of these,
# which is why the directive is a declaration and not a derivation.
ROLLBACK_UNSAFE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("DROP", re.compile(r"\bDROP\b", re.IGNORECASE)),
    ("TRUNCATE", re.compile(r"\bTRUNCATE\b", re.IGNORECASE)),
    ("RENAME", re.compile(r"\bRENAME\b", re.IGNORECASE)),
    ("ALTER TYPE", re.compile(r"\bALTER\s+(?:COLUMN\s+\S+\s+)?TYPE\b",
                              re.IGNORECASE)),
    ("SET NOT NULL", re.compile(r"\bSET\s+NOT\s+NULL\b", re.IGNORECASE)),
)

# `add column ... not null` needs the whole statement, not a pattern: DEFAULT
# can sit on either side of NOT NULL, so any single regex either misses
# `not null default ''` or misses `default '' not null`.
ADD_COLUMN_STATEMENT_RE = re.compile(
    r"\bADD\s+COLUMN\b[^;]*",
    re.IGNORECASE,
)

NOT_NULL_RE = re.compile(r"\bNOT\s+NULL\b", re.IGNORECASE)
DEFAULT_RE = re.compile(r"\bDEFAULT\b", re.IGNORECASE)

DESTRUCTIVE_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "DROP",
        re.compile(r"\bDROP\b", re.IGNORECASE),
    ),
    (
        "TRUNCATE",
        re.compile(r"\bTRUNCATE\b", re.IGNORECASE),
    ),
    (
        "DELETE",
        re.compile(r"\bDELETE\s+FROM\b", re.IGNORECASE),
    ),
)


@dataclass(frozen=True)
class Migration:
    number: int
    name: str
    path: Path
    checksum: str
    destructive_reasons: tuple[str, ...]
    # None when the file carries no directive: "unknown", not "unsafe" and not
    # "safe". Only migrations below DIRECTIVE_REQUIRED_FROM may be None.
    rollback_safe: bool | None


@dataclass(frozen=True)
class AppliedMigration:
    name: str
    checksum: str
    execution_mode: str
    # None for rows written before the ledger had the column, and for rows
    # whose file predates the directive. The release migration gate reads this
    # and treats None as "assume unsafe", which is the behaviour it had for
    # every row before any of this existed.
    rollback_safe: bool | None = None


class MigrationError(RuntimeError):
    """Expected operational or validation failure."""


def fail(message: str, exit_code: int = 1) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(exit_code)


def strip_sql_comments(sql: str) -> str:
    """Remove SQL line and block comments for safety classification."""

    without_blocks = re.sub(
        r"/\*.*?\*/",
        "",
        sql,
        flags=re.DOTALL,
    )

    return re.sub(
        r"--[^\n]*",
        "",
        without_blocks,
    )


def migration_checksum(path: Path) -> str:
    digest = hashlib.sha256()

    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def classify_destructive(sql: str) -> tuple[str, ...]:
    stripped = strip_sql_comments(sql)

    return tuple(
        name
        for name, pattern in DESTRUCTIVE_PATTERNS
        if pattern.search(stripped)
    )


def parse_rollback_safe(sql: str) -> bool | None:
    """Read the `-- rollback-safe: yes|no` header, or None when absent.

    Read from the raw file, not the comment-stripped SQL: the directive IS a
    comment. A second, contradicting directive is a hard error rather than a
    silent first-wins, because the two most likely ways to write one are
    copying a header from another migration and forgetting to change it.
    """
    matches = ROLLBACK_SAFE_DIRECTIVE_RE.findall(sql)

    if not matches:
        return None

    values = {value.lower() for value in matches}

    if len(values) > 1:
        raise MigrationError(
            "migration declares rollback-safe both yes and no"
        )

    return values.pop() == "yes"


def classify_rollback_unsafe(sql: str) -> tuple[str, ...]:
    """Reasons the SQL contradicts a `rollback-safe: yes` claim.

    Judged on comment-stripped SQL. Every migration in this repo explains
    itself in a header comment and those comments discuss what was NOT done --
    0027's says "NOT a unique index" -- so classifying on raw text would
    reject correct migrations for describing themselves.
    """
    stripped = strip_sql_comments(sql)

    reasons = [
        name
        for name, pattern in ROLLBACK_UNSAFE_PATTERNS
        if pattern.search(stripped)
    ]

    for statement in ADD_COLUMN_STATEMENT_RE.findall(stripped):
        if NOT_NULL_RE.search(statement) and not DEFAULT_RE.search(statement):
            reasons.append("NOT NULL without a default")
            break

    return tuple(reasons)


def validate_rollback_directive(migration: Migration) -> None:
    """A missing directive on a new migration, or a false `yes`, is an error.

    Only `yes` is cross-checked. A migration is free to declare `no` for a
    reason no pattern could see -- code that reads a column this migration
    starts writing, say -- and being wrong in that direction only costs a
    rollback that stays blocked.
    """
    if migration.rollback_safe is None:
        if migration.number >= DIRECTIVE_REQUIRED_FROM:
            raise MigrationError(
                f"{migration.name}: missing required header directive. Add "
                "`-- rollback-safe: yes` if the previous release's code runs "
                "correctly once this migration is applied, `no` otherwise. "
                "The release migration gate uses it to decide whether a "
                "rollback past this migration is allowed."
            )
        return

    if not migration.rollback_safe:
        return

    sql = migration.path.read_text(encoding="utf-8", errors="strict")
    reasons = classify_rollback_unsafe(sql)

    if reasons:
        raise MigrationError(
            f"{migration.name}: declares `rollback-safe: yes` but contains "
            f"{', '.join(reasons)}. The previous release's code cannot be "
            "assumed to survive that. Declare `no`, or split the compatible "
            "part into its own migration."
        )


def validate_migration_sql(migration: Migration) -> None:
    sql = migration.path.read_text(
        encoding="utf-8",
        errors="strict",
    )
    stripped = strip_sql_comments(sql)

    if TRANSACTION_CONTROL_RE.search(stripped):
        raise MigrationError(
            f"{migration.name}: migration contains explicit transaction "
            "control. Transactions are managed by migration_manager.py."
        )

    if PSQL_META_COMMAND_RE.search(stripped):
        raise MigrationError(
            f"{migration.name}: psql meta-commands are not allowed."
        )

    if CONCURRENT_INDEX_RE.search(stripped):
        raise MigrationError(
            f"{migration.name}: CREATE INDEX CONCURRENTLY cannot run "
            "inside the required migration transaction."
        )


def discover_migrations(
    directory: Path = MIGRATIONS_DIR,
) -> list[Migration]:
    if not directory.is_dir():
        raise MigrationError(
            f"migration directory does not exist: {directory}"
        )

    migrations: list[Migration] = []
    seen_numbers: dict[int, str] = {}

    for path in sorted(directory.glob("*.sql")):
        match = MIGRATION_NAME_RE.fullmatch(path.name)

        if match is None:
            raise MigrationError(
                f"invalid migration filename: {path.name}"
            )

        number = int(match.group("number"))

        if number in seen_numbers:
            raise MigrationError(
                "duplicate migration number "
                f"{number:04d}: {seen_numbers[number]} and {path.name}"
            )

        seen_numbers[number] = path.name

        sql = path.read_text(
            encoding="utf-8",
            errors="strict",
        )

        migrations.append(
            Migration(
                number=number,
                name=path.name,
                path=path.resolve(),
                checksum=migration_checksum(path),
                destructive_reasons=classify_destructive(sql),
                rollback_safe=parse_rollback_safe(sql),
            )
        )

    if not migrations:
        raise MigrationError("no migration files found")

    return migrations


def require_command(command: str) -> None:
    completed = subprocess.run(
        ["sh", "-c", f"command -v {command} >/dev/null 2>&1"],
        check=False,
    )

    if completed.returncode != 0:
        raise MigrationError(
            f"required command is not installed: {command}"
        )


def database_url() -> str:
    value = os.environ.get("DATABASE_URL", "").strip()

    if not value:
        raise MigrationError(
            "DATABASE_URL is required"
        )

    return value


def run_psql(
    sql: str,
    *,
    quiet: bool = True,
) -> str:
    command = [
        "psql",
        database_url(),
        "--no-psqlrc",
        "-X",
        "-v",
        "ON_ERROR_STOP=1",
    ]

    if quiet:
        command.append("--quiet")

    completed = subprocess.run(
        command,
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip()

        if not detail:
            detail = completed.stdout.strip()

        raise MigrationError(
            f"psql failed with exit code {completed.returncode}: "
            f"{detail or 'no diagnostic output'}"
        )

    return completed.stdout.strip()


def scalar(sql: str) -> str:
    wrapped = (
        "\\pset tuples_only on\n"
        "\\pset format unaligned\n"
        f"{sql.rstrip(';')};\n"
    )

    output = run_psql(wrapped)

    lines = [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]

    return lines[-1] if lines else ""


def ledger_exists() -> bool:
    return scalar(
        "SELECT to_regclass("
        f"'{LEDGER_TABLE}'"
        ") IS NOT NULL"
    ) == "t"


def existing_app_table_count() -> int:
    table_names = ", ".join(
        f"'{name}'"
        for name in APP_TABLES
    )

    value = scalar(
        """
        SELECT count(DISTINCT c.relname)
        FROM pg_catalog.pg_class AS c
        JOIN pg_catalog.pg_namespace AS n
          ON n.oid = c.relnamespace
        WHERE n.nspname = 'public'
          AND c.relkind IN ('r', 'p')
          AND c.relname IN (
        """
        + table_names
        + """
          )
        """
    )

    try:
        return int(value)
    except ValueError as error:
        raise MigrationError(
            f"unexpected application table count: {value!r}"
        ) from error


def existing_app_schema() -> bool:
    """Return true when at least part of a legacy ShipIt schema exists."""

    return existing_app_table_count() > 0


def create_ledger() -> None:
    run_psql(
        f"""
        BEGIN;

        SELECT pg_advisory_xact_lock(
            hashtextextended('{ADVISORY_LOCK_NAME}', 0)
        );

        CREATE TABLE IF NOT EXISTS {LEDGER_TABLE} (
            filename text PRIMARY KEY,
            checksum char(64) NOT NULL,
            applied_at timestamptz NOT NULL DEFAULT now(),
            applied_by text NOT NULL DEFAULT current_user,
            git_sha text NOT NULL,
            execution_mode text NOT NULL
                CHECK (execution_mode IN ('apply', 'baseline')),
            -- Nullable on purpose: NULL means "nobody said", which the
            -- release migration gate treats as unsafe. Rows written before
            -- this column existed keep that meaning without a backfill.
            rollback_safe boolean
        );

        REVOKE ALL ON TABLE {LEDGER_TABLE} FROM PUBLIC;

        COMMIT;
        """
    )


def ensure_ledger_columns() -> None:
    """Bring an existing ledger up to the current shape.

    Deliberately NOT a migration in migrations/. The ledger is this script's
    own bookkeeping and has never been part of the migration history -- and a
    migration here would be self-defeating, since the whole point of the
    change is that shipping a migration must stop making a release
    irreversible.
    """
    run_psql(
        f"""
        ALTER TABLE {LEDGER_TABLE}
            ADD COLUMN IF NOT EXISTS rollback_safe boolean;
        """
    )


def load_applied() -> dict[str, AppliedMigration]:
    if not ledger_exists():
        return {}

    output = run_psql(
        f"""
        \\pset tuples_only on
        \\pset format unaligned
        \\pset fieldsep '\t'

        SELECT
            filename,
            checksum,
            execution_mode,
            -- Through to_jsonb rather than naming the column, so that reading
            -- a ledger that predates rollback_safe yields NULL instead of an
            -- error. `status` must stay read-only; the column is added by
            -- ensure_ledger_columns on the write paths.
            coalesce(to_jsonb(ledger) ->> 'rollback_safe', '')
        FROM {LEDGER_TABLE} AS ledger
        ORDER BY filename;
        """
    )

    applied: dict[str, AppliedMigration] = {}

    for line in output.splitlines():
        line = line.strip()

        if not line:
            continue

        parts = line.split("\t")

        if len(parts) != 4:
            raise MigrationError(
                "unexpected migration ledger row format"
            )

        name, checksum, execution_mode, rollback_safe = parts

        applied[name] = AppliedMigration(
            name=name,
            checksum=checksum.strip(),
            execution_mode=execution_mode,
            rollback_safe={"true": True, "false": False}.get(
                rollback_safe.strip().lower()
            ),
        )

    return applied


def git_sha() -> str:
    environment_sha = os.environ.get("GITHUB_SHA", "").strip()

    if re.fullmatch(r"[0-9a-fA-F]{7,64}", environment_sha):
        return environment_sha.lower()

    completed = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        check=False,
    )

    candidate = completed.stdout.strip()

    if (
        completed.returncode == 0
        and re.fullmatch(r"[0-9a-fA-F]{40,64}", candidate)
    ):
        return candidate.lower()

    return "unknown"


def sql_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def psql_include_path(path: Path) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def verify_applied_integrity(
    migrations: Sequence[Migration],
    applied: dict[str, AppliedMigration],
) -> None:
    by_name = {
        migration.name: migration
        for migration in migrations
    }

    errors: list[str] = []

    for name, record in applied.items():
        migration = by_name.get(name)

        if migration is None:
            errors.append(
                f"ledger contains migration missing from repository: {name}"
            )
            continue

        if record.checksum != migration.checksum:
            errors.append(
                f"checksum drift for {name}: "
                f"ledger={record.checksum} "
                f"repository={migration.checksum}"
            )

    pending_seen = False

    for migration in migrations:
        is_applied = migration.name in applied

        if not is_applied:
            pending_seen = True
            continue

        if pending_seen:
            errors.append(
                "migration ordering gap: "
                f"{migration.name} is applied after an earlier pending file"
            )

    if errors:
        raise MigrationError(
            "\n".join(errors)
        )


def pending_migrations(
    migrations: Sequence[Migration],
    applied: dict[str, AppliedMigration],
) -> list[Migration]:
    return [
        migration
        for migration in migrations
        if migration.name not in applied
    ]


def print_status(
    migrations: Sequence[Migration],
) -> int:
    if not ledger_exists():
        print("Ledger: absent")

        if existing_app_schema():
            print("State: BASELINE_REQUIRED")
            print(
                "Existing ShipIt tables were detected, but no migration "
                "ledger exists."
            )
            return 3

        print("State: FRESH_DATABASE")
        print(f"Pending migrations: {len(migrations)}")

        for migration in migrations:
            suffix = (
                " [destructive]"
                if migration.destructive_reasons
                else ""
            )
            print(f"  PENDING {migration.name}{suffix}")

        return 0

    applied = load_applied()
    verify_applied_integrity(migrations, applied)
    pending = pending_migrations(migrations, applied)

    print("Ledger: present")
    print(f"Applied migrations: {len(applied)}")
    print(f"Pending migrations: {len(pending)}")

    for migration in migrations:
        record = applied.get(migration.name)

        if record is not None:
            print(
                f"  APPLIED {migration.name} "
                f"mode={record.execution_mode}"
            )
            continue

        suffix = (
            " [destructive: "
            + ",".join(migration.destructive_reasons)
            + "]"
            if migration.destructive_reasons
            else ""
        )

        print(f"  PENDING {migration.name}{suffix}")

    print("State: OK")
    return 0


def baseline_migrations(
    migrations: Sequence[Migration],
    *,
    confirmed: bool,
) -> None:
    expected_confirmation = "I_HAVE_VERIFIED_THE_PRODUCTION_SCHEMA"

    if not confirmed:
        raise MigrationError(
            "baseline requires --confirm-existing-schema"
        )

    if os.environ.get("SHIPIT_BASELINE_CONFIRM") != expected_confirmation:
        raise MigrationError(
            "baseline requires "
            "SHIPIT_BASELINE_CONFIRM="
            f"{expected_confirmation}"
        )

    table_count = existing_app_table_count()

    if table_count != len(APP_TABLES):
        raise MigrationError(
            "baseline requires all expected ShipIt tables; "
            f"detected {table_count}/{len(APP_TABLES)}"
        )

    create_ledger()
    applied = load_applied()

    if applied:
        raise MigrationError(
            "baseline refused because the migration ledger is not empty"
        )

    revision = git_sha()
    values = ",\n".join(
        "            ("
        f"{sql_literal(migration.name)}, "
        f"{sql_literal(migration.checksum)}, "
        f"{sql_literal(revision)}, "
        "'baseline'"
        ")"
        for migration in migrations
    )

    run_psql(
        f"""
        BEGIN;

        SELECT pg_advisory_xact_lock(
            hashtextextended('{ADVISORY_LOCK_NAME}', 0)
        );

        INSERT INTO {LEDGER_TABLE} (
            filename,
            checksum,
            git_sha,
            execution_mode
        )
        VALUES
{values};

        COMMIT;
        """
    )

    print(
        f"Baselined {len(migrations)} migrations at git SHA {revision}."
    )


def apply_one(
    migration: Migration,
    *,
    revision: str,
) -> None:
    name = sql_literal(migration.name)
    checksum = sql_literal(migration.checksum)
    revision_literal = sql_literal(revision)
    include_path = psql_include_path(migration.path)
    rollback_safe = (
        "NULL" if migration.rollback_safe is None
        else str(migration.rollback_safe).lower()
    )

    sql = f"""
\\set ON_ERROR_STOP on

BEGIN;

SELECT pg_advisory_xact_lock(
    hashtextextended('{ADVISORY_LOCK_NAME}', 0)
);

SELECT EXISTS (
    SELECT 1
    FROM {LEDGER_TABLE}
    WHERE filename = {name}
) AS already_applied
\\gset

\\if :already_applied

    SELECT checksum = {checksum} AS checksum_matches
    FROM {LEDGER_TABLE}
    WHERE filename = {name}
    \\gset

    \\if :checksum_matches
        \\echo 'Migration already applied with matching checksum.'
    \\else
        \\echo 'Migration checksum mismatch.'
        \\quit 4
    \\endif

\\else

    \\i {include_path}

    INSERT INTO {LEDGER_TABLE} (
        filename,
        checksum,
        git_sha,
        execution_mode,
        rollback_safe
    )
    VALUES (
        {name},
        {checksum},
        {revision_literal},
        'apply',
        {rollback_safe}
    );

\\endif

COMMIT;
"""

    run_psql(sql, quiet=False)


def lint_migrations(migrations: Sequence[Migration]) -> int:
    """Validate every migration file. Used by CI, needs no database."""

    errors: list[str] = []

    for migration in migrations:
        for check in (validate_migration_sql, validate_rollback_directive):
            try:
                check(migration)
            except MigrationError as error:
                errors.append(str(error))

    if errors:
        for message in errors:
            print(f"ERROR: {message}", file=sys.stderr)
        return 1

    declared = sum(
        1 for migration in migrations if migration.rollback_safe is not None
    )
    print(
        f"Migration lint: PASSED ({len(migrations)} files, "
        f"{declared} with a rollback-safe directive)"
    )
    return 0


def apply_migrations(
    migrations: Sequence[Migration],
    *,
    allow_destructive: bool,
) -> None:
    has_ledger = ledger_exists()
    has_existing_schema = existing_app_schema()
    bootstrap = not has_ledger and not has_existing_schema

    if not has_ledger and has_existing_schema:
        raise MigrationError(
            "existing ShipIt schema detected without a migration ledger; "
            "run status and complete the guarded baseline procedure"
        )

    if not has_ledger:
        create_ledger()
    else:
        ensure_ledger_columns()

    applied = load_applied()
    verify_applied_integrity(migrations, applied)
    pending = pending_migrations(migrations, applied)

    if not pending:
        print("No pending migrations.")
        return

    for migration in pending:
        validate_migration_sql(migration)
        validate_rollback_directive(migration)

    destructive = [
        migration
        for migration in pending
        if migration.destructive_reasons
    ]

    if destructive and not bootstrap and not allow_destructive:
        names = ", ".join(
            migration.name
            for migration in destructive
        )

        raise MigrationError(
            "destructive pending migrations require "
            f"--allow-destructive: {names}"
        )

    revision = git_sha()

    for migration in pending:
        print(f"Applying {migration.name}...")

        apply_one(
            migration,
            revision=revision,
        )

        print(f"Applied {migration.name}.")

    final_applied = load_applied()
    verify_applied_integrity(migrations, final_applied)

    print(
        f"Applied {len(pending)} migration(s) successfully."
    )


def acquire_local_lock() -> object:
    LOCAL_LOCK_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    handle = LOCAL_LOCK_PATH.open("a+", encoding="utf-8")

    try:
        fcntl.flock(
            handle.fileno(),
            fcntl.LOCK_EX | fcntl.LOCK_NB,
        )
    except BlockingIOError as error:
        handle.close()

        raise MigrationError(
            f"another migration process holds {LOCAL_LOCK_PATH}"
        ) from error

    return handle


def parse_args(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="ShipIt PostgreSQL migration manager"
    )

    subparsers = parser.add_subparsers(
        dest="mode",
        required=True,
    )

    subparsers.add_parser(
        "status",
        help="show applied, pending and drifted migrations",
    )

    subparsers.add_parser(
        "lint",
        help="validate migration files without touching the database",
    )

    apply_parser = subparsers.add_parser(
        "apply",
        help="apply pending migrations",
    )
    apply_parser.add_argument(
        "--allow-destructive",
        action="store_true",
        help="allow pending DROP/TRUNCATE/DELETE migrations",
    )

    baseline_parser = subparsers.add_parser(
        "baseline",
        help="register an existing schema without executing SQL",
    )
    baseline_parser.add_argument(
        "--confirm-existing-schema",
        action="store_true",
        help="confirm that the existing schema was independently verified",
    )

    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = parse_args(argv)

    if arguments.mode == "lint":
        # No psql, no DATABASE_URL: this runs in CI on a pull request, where
        # the point is to catch a missing or false directive before the
        # migration is ever applied anywhere.
        return lint_migrations(discover_migrations())

    require_command("psql")
    database_url()

    migrations = discover_migrations()
    lock_handle = acquire_local_lock()

    try:
        if arguments.mode == "status":
            return print_status(migrations)

        if arguments.mode == "baseline":
            baseline_migrations(
                migrations,
                confirmed=arguments.confirm_existing_schema,
            )
            return 0

        if arguments.mode == "apply":
            apply_migrations(
                migrations,
                allow_destructive=arguments.allow_destructive,
            )
            return 0

        raise MigrationError(
            f"unsupported mode: {arguments.mode}"
        )
    finally:
        lock_handle.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationError as error:
        fail(str(error))
