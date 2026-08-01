#!/usr/bin/env python3
"""Verify that a release exactly matches the production migration ledger."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, NamedTuple, NoReturn, Sequence


METADATA_FILE = ".shipit-release.json"
CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")


class MigrationGateError(RuntimeError):
    """Release and database migration state are incompatible."""


class AppliedRow(NamedTuple):
    checksum: str
    # Whether the release BEFORE this migration can run against a schema that
    # has it. Declared by the migration author, recorded at apply time by
    # scripts/migration_manager.py. None means nobody said, which is not the
    # same as no and is treated here the same as no.
    rollback_safe: bool | None


def fail(message: str) -> NoReturn:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def read_metadata(release: Path) -> dict[str, Any]:
    path = release / METADATA_FILE

    try:
        value = json.loads(
            path.read_text(encoding="utf-8")
        )
    except (OSError, json.JSONDecodeError) as error:
        raise MigrationGateError(
            f"cannot read release metadata: {path}"
        ) from error

    if not isinstance(value, dict):
        raise MigrationGateError(
            f"release metadata is not an object: {path}"
        )

    return value


def expected_migrations(
    metadata: dict[str, Any],
) -> dict[str, str]:
    manifest = metadata.get("migration_manifest")

    if not isinstance(manifest, list):
        raise MigrationGateError(
            "release metadata has no migration manifest"
        )

    expected: dict[str, str] = {}

    for item in manifest:
        if not isinstance(item, dict):
            raise MigrationGateError(
                "invalid migration manifest entry"
            )

        filename = item.get("filename")
        checksum = item.get("checksum")

        if not isinstance(filename, str):
            raise MigrationGateError(
                "invalid migration filename"
            )

        if (
            not isinstance(checksum, str)
            or CHECKSUM_RE.fullmatch(checksum) is None
        ):
            raise MigrationGateError(
                f"invalid checksum for migration {filename}"
            )

        if filename in expected:
            raise MigrationGateError(
                f"duplicate migration in release: {filename}"
            )

        expected[filename] = checksum

    return expected


def load_env_values(
    release: Path,
    env_file: Path,
) -> dict[str, str]:
    validator = (
        release
        / "deploy"
        / "scripts"
        / "validate-production-env.py"
    )

    if not validator.is_file():
        raise MigrationGateError(
            f"production validator missing: {validator}"
        )

    spec = importlib.util.spec_from_file_location(
        "shipit_release_env_validator",
        validator,
    )

    if spec is None or spec.loader is None:
        raise MigrationGateError(
            f"cannot load production validator: {validator}"
        )

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)

    reader = getattr(module, "read_env_file", None)

    if not callable(reader):
        raise MigrationGateError(
            "validator does not expose read_env_file()"
        )

    values = dict(os.environ)
    parsed = reader(env_file)

    if not isinstance(parsed, dict):
        raise MigrationGateError(
            "read_env_file() returned an invalid value"
        )

    values.update(
        {
            str(key): str(value)
            for key, value in parsed.items()
        }
    )

    return values


def query_applied_migrations(
    database_url: str,
) -> dict[str, AppliedRow]:
    # rollback_safe is read through to_jsonb rather than named directly, so a
    # ledger that predates the column yields NULL instead of an error. NULL is
    # "nobody said", which this gate treats as unsafe -- exactly the behaviour
    # it had for every row before the column existed.
    sql = r"""
\pset tuples_only on
\pset format unaligned
\pset fieldsep '	'

SELECT
    filename,
    btrim(checksum),
    coalesce(to_jsonb(ledger) ->> 'rollback_safe', '')
FROM public.shipit_schema_migrations AS ledger
ORDER BY filename;
"""

    completed = subprocess.run(
        [
            "psql",
            database_url,
            "--no-psqlrc",
            "-X",
            "-v",
            "ON_ERROR_STOP=1",
            "--quiet",
        ],
        input=sql,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    if completed.returncode != 0:
        detail = completed.stderr.strip()

        raise MigrationGateError(
            "cannot read migration ledger"
            + (f": {detail}" if detail else "")
        )

    applied: dict[str, str] = {}

    for raw_line in completed.stdout.splitlines():
        line = raw_line.strip()

        if not line:
            continue

        parts = line.split("\t")

        if len(parts) != 2:
            raise MigrationGateError(
                "unexpected migration ledger row"
            )

        filename, checksum = parts
        checksum = checksum.strip()

        if filename in applied:
            raise MigrationGateError(
                f"duplicate migration in database: {filename}"
            )

        applied[filename] = checksum

    return applied


def compare_migrations(
    expected: dict[str, str],
    applied: dict[str, AppliedRow],
) -> list[str]:
    """Three kinds of divergence, and they are not equally dangerous.

    The database MISSING a release migration means new code against an old
    schema. Always fatal, no exceptions -- that is the case this gate exists
    for.

    A CHECKSUM mismatch means a migration file was edited after it was
    applied. Always fatal: whatever the database contains, it is no longer
    what the file says it contains.

    The database being AHEAD of the release means old code against a newer
    schema, which is what every rollback looks like. Treating that as fatal
    made any release carrying a migration irreversible, however harmless the
    migration was -- an index nobody reads would block the rollback of an
    unrelated outage. So it is fatal only when the extra migration is not
    declared rollback-safe.
    """
    errors: list[str] = []

    for filename in sorted(expected.keys() - applied.keys()):
        errors.append(
            f"database is missing release migration: {filename}"
        )

    for filename in sorted(applied.keys() - expected.keys()):
        if applied[filename].rollback_safe:
            continue

        errors.append(
            f"database is ahead of release: {filename} "
            + (
                "(declared rollback-safe: no)"
                if applied[filename].rollback_safe is False
                else "(no rollback-safe declaration; assuming unsafe)"
            )
        )

    for filename in sorted(expected.keys() & applied.keys()):
        if expected[filename] != applied[filename].checksum:
            errors.append(
                f"migration checksum mismatch: {filename}"
            )

    return errors


def parse_args(
    argv: Sequence[str] | None = None,
) -> argparse.Namespace:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--release",
        type=Path,
        required=True,
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        required=True,
    )

    return parser.parse_args(argv)


def main(
    argv: Sequence[str] | None = None,
) -> int:
    arguments = parse_args(argv)

    release = arguments.release.resolve()

    metadata = read_metadata(release)
    expected = expected_migrations(metadata)

    values = load_env_values(
        release,
        arguments.env_file,
    )

    database_url = values.get("DATABASE_URL", "").strip()

    if not database_url:
        raise MigrationGateError(
            "DATABASE_URL is missing"
        )

    applied = query_applied_migrations(database_url)
    errors = compare_migrations(expected, applied)

    if errors:
        raise MigrationGateError("\n".join(errors))

    print(
        "Release migration gate: PASSED "
        f"({len(expected)} migrations)"
    )

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except MigrationGateError as error:
        fail(str(error))
