"""Run the trusted SQL recipe contract against an explicit disposable local DB.

Only SQL_CONTRACT_DATABASE_URL is read. No project path or SQL input is accepted.
Exit 0 means the synthetic contract passed, 1 a failed contract, 2 unavailable.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import unquote, urlsplit

import psycopg

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from app.proof.sql_runtime_contract import run_contract  # noqa: E402


class TargetError(ValueError):
    pass


def target_options(dsn: str) -> dict:
    """Pin the actual TCP address; libpq service/query overrides are not accepted."""
    if not isinstance(dsn, str) or not dsn or len(dsn) > 4096:
        raise TargetError('database_not_configured')
    try:
        parsed = urlsplit(dsn)
        port = 5432 if parsed.port is None else parsed.port
        host = {'localhost': '127.0.0.1', '127.0.0.1': '127.0.0.1', '::1': '::1'}.get(parsed.hostname)
        user = unquote(parsed.username or '')
        password = unquote(parsed.password or '')
        database = unquote(parsed.path.removeprefix('/'))
    except ValueError:
        raise TargetError('invalid_database_target') from None
    if (parsed.scheme not in {'postgres', 'postgresql'} or not host or parsed.query or parsed.fragment
            or database != 'drydock_sql_contract' or not 1 <= port <= 65535
            or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', user)
            or not password or '\x00' in password):
        raise TargetError('invalid_database_target')
    # Even hostaddr/servicefile/options environment settings must not replace
    # the explicitly selected disposable target or introduce unreviewed options.
    if any(name.startswith('PG') for name in os.environ):
        raise TargetError('ambient_libpq_options')
    return {'host': host, 'hostaddr': host, 'port': port, 'dbname': database,
            'user': user, 'password': password, 'connect_timeout': 5, 'autocommit': True,
            'application_name': 'drydock-synthetic-sql-contract', 'client_encoding': 'UTF8',
            'options': '-c statement_timeout=3000 -c lock_timeout=1000'}


def connect_target(dsn: str):
    return psycopg.connect(**target_options(dsn))


def unavailable(reason: str) -> dict:
    return {'version': 1, 'scope': 'synthetic_recipe',
            'contract_id': 'sql-value-parameterization-python-psycopg3',
            'status': 'unavailable', 'reason': reason, 'synthetic_recipe_verified': False,
            'runtime_verified': False, 'customer_project_verified': False, 'automatic_patch': False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, help='New JSON evidence file; existing files are never overwritten')
    args = parser.parse_args(argv)
    # Reserve the output before connecting so an existing artifact cannot be
    # overwritten after a successful experiment.
    output = args.output.open('x', encoding='utf-8') if args.output else None
    try:
        try:
            with connect_target(os.environ.get('SQL_CONTRACT_DATABASE_URL', '')) as connection:
                result = run_contract(connection)
        except TargetError as exc:
            result = unavailable(str(exc))
        except Exception:
            # Driver exception strings may include credentials or server data.
            result = unavailable('execution_unavailable')
        encoded = json.dumps(result, ensure_ascii=False, indent=2) + '\n'
        if output:
            output.write(encoded)
        print(encoded, end='')
        return {'passed': 0, 'failed': 1}.get(result.get('status'), 2)
    finally:
        if output:
            output.close()


if __name__ == '__main__':
    raise SystemExit(main())
