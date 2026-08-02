"""The guard that stops this suite writing to a database it does not own.

On 2026-07-22 tests/test_db_postgres_smoke.py was run four times against the
PRODUCTION database. It records a fix_outcomes row and then calls
set_pr_merged_by_pr_url on its own fabricated PR link, so production ended up
holding four outcomes claiming a merged pull request that never existed. They
were still there on 2026-08-02, one distinct audit short of declaring SEC001
and CFG002 ready to learn from, on a 100% merge rate that was entirely our own
test data.

Nothing failed at the time. The suite passed, because from its point of view
it had done exactly what it meant to.
"""

from __future__ import annotations

import pytest

from tests.conftest import is_disposable_database


# The two that must keep working, copied from where they actually live.
@pytest.mark.parametrize("url", [
    # .github/workflows/db-postgres-smoke.yml
    "postgresql://postgres:postgres@localhost:5432/shipit_smoke",
    # A Unix socket cannot reach a hosted database at all.
    "postgresql://postgres@/shipit?host=/tmp/pg&port=55432",
    "postgresql://postgres@/shipit?host=/var/run/postgresql",
    "postgresql://u:p@127.0.0.1:5432/anything",
    "postgresql://u:p@[::1]:5432/anything",
])
def test_a_local_database_is_allowed(url):
    assert is_disposable_database(url) is True


@pytest.mark.parametrize("url", [
    # The shape of the real production URL (Supabase pooler).
    "postgresql://postgres.abcdef:pw@aws-0-eu-central-1.pooler.supabase.com"
    ":5432/postgres",
    # The one that makes the host the right thing to check: a remote database
    # whose NAME says test is still someone else's server.
    "postgresql://u:p@db.example.com:5432/shipit_test",
    # The production VPS by hostname, in case Postgres ever moves onto it.
    "postgresql://u:p@ala-1-vm-7z3r:5432/shipit",
])
def test_a_remote_database_is_refused(url):
    assert is_disposable_database(url) is False


def test_the_check_is_on_the_host_not_the_database_name():
    """Stated as its own test because it is the design decision, not a detail.

    A database name is a convention someone can match by accident; a loopback
    address or a local socket cannot reach anyone else's data by construction.
    """
    assert is_disposable_database(
        "postgresql://u:p@db.example.com/shipit_smoke") is False
    assert is_disposable_database(
        "postgresql://u:p@localhost/postgres") is True
