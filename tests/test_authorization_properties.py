"""Resource capabilities through the real HTTP routes, across generated owners.

Repository doubles model the documented token contract; these properties test
route wiring and observable side effects, not PostgreSQL's authorization SQL.
The existing real-db repository tests cover that layer. Every generated case
has readable resources and a successful authorized operation as controls.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
import io
import string
from unittest.mock import patch
import zipfile

from fastapi.testclient import TestClient
from hypothesis import given, settings, strategies as st

from app.main import app
from app.ratelimit import RateLimiter
from app.routes.dependencies import (
    get_audit_job_repo,
    get_audit_repo,
    get_rate_limiter,
    get_repo_fetcher,
    get_rls_fetch,
    get_rls_live_check_repo,
)
from app.routes.rls_check import CONSENT_PHRASE


class _Audits:
    def __init__(self, rows):
        self.rows = {row["id"]: row for row in rows}

    async def get(self, audit_id):
        return deepcopy(self.rows.get(audit_id))

    async def get_authorized(self, audit_id, access_token):
        row = self.rows.get(audit_id)
        if row is None or not access_token or row["access_token"] != access_token:
            return None
        return deepcopy({key: value for key, value in row.items() if key != "access_token"})


class _Jobs(_Audits):
    async def get_authorized(self, *, job_id, access_token):
        return await super().get_authorized(job_id, access_token)


@st.composite
def _resources(draw):
    ids = draw(st.lists(st.uuids(), min_size=5, max_size=5, unique=True))
    stem = draw(st.text(string.ascii_letters + string.digits + "-_", min_size=8, max_size=64))
    # Long shared prefixes exercise exact capability forwarding. These are
    # synthetic fixtures, not production tokens minted by PostgreSQL.
    audits = [{
        "id": str(ids[index]), "access_token": f"synthetic-{stem}-{index}",
        "stack": "fastapi", "status": "completed", "findings_json": [],
        "repo_url": f"https://github.com/synthetic/project-{index}",
    } for index in range(2)]
    jobs = [{
        "id": str(ids[index + 2]), "access_token": f"synthetic-{stem}-{index + 2}",
        "state": "succeeded", "error_code": None,
        "audit_id": audit["id"], "audit_access_token": audit["access_token"],
        "created_at": "2026-09-17T10:00:00+00:00",
        "completed_at": "2026-09-17T10:01:00+00:00",
    } for index, audit in enumerate(audits)]
    return audits, jobs, str(ids[4])


@contextmanager
def _client(overrides):
    # A Hypothesis example, rather than a pytest function, owns the state.
    # Restore existing overrides as well, including conftest's rate limiter.
    with patch.dict(app.dependency_overrides, overrides), TestClient(app) as client:
        yield client


def _token_field(token):
    return {} if token is None else {"token": token}


@settings(max_examples=24, deadline=None)
@given(resources=_resources(), order=st.permutations((0, 1)))
def test_job_capability_handoff_only_opens_its_own_audit(resources, order):
    audits, jobs, missing_id = resources
    audit_repo, job_repo = _Audits(audits), _Jobs(jobs)
    with _client({
        get_audit_repo: lambda: audit_repo,
        get_audit_job_repo: lambda: job_repo,
    }) as client:
        for index in order:
            audit, job, foreign = audits[index], jobs[index], jobs[1 - index]
            job_url = f"/v1/audit-jobs/{job['id']}"
            missing = client.get(
                f"/v1/audit-jobs/{missing_id}", params={"token": job["access_token"]},
            )
            assert missing.status_code == 404
            for token in (None, "", foreign["access_token"], audit["access_token"], job["access_token"][:-1]):
                denied = client.get(job_url, params=_token_field(token))
                assert denied.status_code == 404
                assert denied.content == missing.content

            allowed = client.get(job_url, params={"token": job["access_token"]})
            assert allowed.status_code == 200
            handoff = allowed.json()
            assert handoff["audit_id"] == audit["id"]
            assert handoff["audit_access_token"] == audit["access_token"]
            assert "access_token" not in handoff
            report = client.get(
                f"/v1/audits/{handoff['audit_id']}",
                params={"token": handoff["audit_access_token"]},
            )
            assert report.status_code == 200
            assert report.json()["id"] == audit["id"]
            assert report.json()["repo_url"] == audit["repo_url"]
            assert "access_token" not in report.json()

            # Successfully reading one resource must not authorize another,
            # and a job token is not itself the audit's token.
            for target, token in (
                (audits[1 - index]["id"], handoff["audit_access_token"]),
                (audit["id"], job["access_token"]),
                (audit["id"], None),
            ):
                denied = client.get(f"/v1/audits/{target}", params=_token_field(token))
                unknown = client.get(f"/v1/audits/{missing_id}", params=_token_field(token))
                assert denied.status_code == unknown.status_code == 404
                assert denied.content == unknown.content


class _Ledger:
    def __init__(self):
        self.started = []
        self.completed = []

    async def start(self, **fields):
        row = {"id": "synthetic-live-check", **fields}
        self.started.append(row)
        return row

    async def complete(self, check_id, **fields):
        self.completed.append({"id": check_id, **fields})


def _archive():
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr(
            "repo/supabase/migrations/0001.sql",
            "create table public.users (id uuid primary key);",
        )
    return output.getvalue()


@settings(max_examples=24, deadline=None)
@given(resources=_resources(), index=st.integers(0, 1), order=st.permutations(range(5)))
def test_rejected_rls_capabilities_do_not_fetch_write_or_spend_owner_budget(resources, index, order):
    audits, jobs, missing_id = resources
    audit = audits[index]
    audit_repo, ledger = _Audits(audits), _Ledger()
    repo_calls, probe_calls = [], []
    archive = _archive()
    limiter = RateLimiter(limit=1, clock=lambda: 0)

    def fetch_repo(owner, repo):
        repo_calls.append((owner, repo))
        return archive

    def fetch_rows(*args):
        probe_calls.append(args)
        return 200, [{"id": "synthetic-private-row"}]

    form = {
        "consent": CONSENT_PHRASE,
        "anon_key": "sb_publishable_syntheticAuthorizationProperty",
        "project_url": "https://abcdefghijklmnopqrst.supabase.co",
    }
    tokens = (None, "", audits[1 - index]["access_token"], jobs[index]["access_token"], audit["access_token"][:-1])
    with _client({
        get_audit_repo: lambda: audit_repo,
        get_rls_live_check_repo: lambda: ledger,
        get_repo_fetcher: lambda: fetch_repo,
        get_rls_fetch: lambda: fetch_rows,
        get_rate_limiter: lambda: limiter,
    }) as client:
        foreign = audits[1 - index]
        assert client.get(
            f"/v1/audits/{foreign['id']}", params={"token": foreign["access_token"]},
        ).status_code == 200
        unknown = client.post(
            f"/v1/audits/{missing_id}/rls-check",
            data={**form, "token": audit["access_token"]},
        )
        assert unknown.status_code == 404
        url = f"/v1/audits/{audit['id']}/rls-check"
        for position in order:
            denied = client.post(url, data={**form, **_token_field(tokens[position])})
            assert denied.status_code == 404
            assert denied.content == unknown.content
            assert (repo_calls, probe_calls, ledger.started, ledger.completed) == ([], [], [], [])

        allowed = client.post(url, data={**form, "token": audit["access_token"]})
        assert allowed.status_code == 200
        assert allowed.json()["status"] == "checked"
        assert allowed.json()["persisted"] is True
        assert allowed.json()["exposed_tables"] == ["users"]
        assert repo_calls == [("synthetic", f"project-{index}")]
        assert probe_calls == [(form["project_url"], form["anon_key"], "users", 3)]
        assert len(ledger.started) == len(ledger.completed) == 1
        assert ledger.started[0]["audit_id"] == audit["id"]
        assert ledger.completed[0]["outcome"] == "checked"

        effects = deepcopy((repo_calls, probe_calls, ledger.started, ledger.completed))
        exhausted = client.post(url, data={**form, "token": audit["access_token"]})
        assert exhausted.status_code == 429
        assert (repo_calls, probe_calls, ledger.started, ledger.completed) == effects

        # With exhaustion confirmed by a legitimate request, denied
        # capabilities still receive the same opaque 404 without side effects.
        for position in reversed(order):
            denied = client.post(url, data={**form, **_token_field(tokens[position])})
            assert denied.status_code == 404
            assert denied.content == unknown.content
            assert (repo_calls, probe_calls, ledger.started, ledger.completed) == effects
