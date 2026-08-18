"""The API edge of the one request this product makes into somebody's database.

Everything below this is unit-tested. What is tested here is the edge: that
consent cannot be submitted by a default, that a refusal is not dressed up as a
result, that the ledger row exists before any request goes out, and that the
credential does not come back in the response.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.routes.dependencies import (
    get_audit_repo,
    get_repo_fetcher,
    get_rls_fetch,
    get_rls_live_check_repo,
)
from app.routes.rls_check import CONSENT_PHRASE

REF = "egoprezwkjaqacxtjwfl"


def jwt(role: str = "anon", ref: str = REF) -> str:
    def seg(data: dict) -> str:
        return base64.urlsafe_b64encode(
            json.dumps(data, separators=(",", ":")).encode()).decode().rstrip("=")
    return (f"{seg({'alg': 'HS256', 'typ': 'JWT'})}."
            f"{seg({'iss': 'supabase', 'ref': ref, 'role': role, 'iat': 1779635486, 'exp': 2095211486})}."
            f"XaMB3mjNqMf757EmpUpjnsJ5mldVtmsDiag7FQDjubg")


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    return buf.getvalue()


REPO = make_zip({
    "repo/.env": f"VITE_SUPABASE_ANON_KEY={jwt()}\n",
    "repo/supabase/migrations/0001.sql":
        "create table public.users (id uuid primary key, email text);",
})


class FakeLedger:
    """Records what the ledger was told, in order."""

    def __init__(self) -> None:
        self.started: list[dict] = []
        self.completed: list[dict] = []

    async def start(self, *, audit_id, client_key, consent_phrase):
        row = {"id": "00000000-0000-0000-0000-000000000001",
               "audit_id": audit_id, "client_key": client_key,
               "consent_phrase": consent_phrase}
        self.started.append(row)
        return row

    async def complete(self, check_id, *, project_ref, outcome, tables_asked,
                       result):
        self.completed.append({"id": check_id, "project_ref": project_ref,
                               "outcome": outcome, "tables_asked": tables_asked,
                               "result": result})
        return self.completed[-1]


@pytest.fixture
def ledger():
    fake = FakeLedger()
    app.dependency_overrides[get_rls_live_check_repo] = lambda: fake
    yield fake
    app.dependency_overrides.pop(get_rls_live_check_repo, None)


@pytest.fixture
def client(ledger):
    with TestClient(app) as c:
        yield c


def use_fetch(fn):
    app.dependency_overrides[get_rls_fetch] = lambda: fn


@pytest.fixture(autouse=True)
def _no_real_requests():
    """A test that forgot to set a transport would probe a real project."""
    def refuse(*_a, **_k):
        raise AssertionError("the test did not override get_rls_fetch")
    use_fetch(refuse)
    yield
    app.dependency_overrides.pop(get_rls_fetch, None)


def post(client, *, consent=CONSENT_PHRASE, data=REPO, **extra):
    return client.post(
        "/v1/rls-check",
        files={"archive": ("repo.zip", data, "application/zip")},
        data={"consent": consent, **extra},
    )


# --- consent -----------------------------------------------------------------

@pytest.mark.parametrize("value",
                         ["true", "1", "yes", "on", "I-OWN-THIS-PROJECT"])
def test_only_the_exact_phrase_is_consent(client, ledger, value) -> None:
    """`consent=true` is what a client library sets by default, what a copied
    curl carries, and what a form submits because a checkbox was ticked. None
    of those is somebody deciding.

    `I-OWN-THIS-PROJECT` is in the list on purpose: case-insensitive matching
    would let a shell that upcases arguments consent on the caller's behalf.
    """
    response = post(client, consent=value)
    assert response.status_code == 422
    assert response.json()["detail"]["reason"] == "consent_not_given"
    assert ledger.started == []


@pytest.mark.parametrize("kwargs", [
    {"data": {"consent": ""}},   # submitted, but empty
    {"data": {}},                # not submitted at all
])
def test_no_consent_field_is_rejected_before_anything_runs(
        client, ledger, kwargs) -> None:
    """FastAPI answers these with its own validation error rather than ours —
    a different body, the same refusal. What matters is that neither reaches
    the check, so both are asserted on the ledger rather than on the shape."""
    response = client.post(
        "/v1/rls-check",
        files={"archive": ("repo.zip", REPO, "application/zip")},
        **kwargs,
    )
    assert response.status_code == 422
    assert ledger.started == []


# --- the ledger --------------------------------------------------------------

def test_the_ledger_row_exists_before_any_request_goes_out(client, ledger) -> None:
    """A ledger that only records completed checks cannot show the one that
    crashed halfway, which is the case somebody would actually ask about."""
    order: list[str] = []

    def fetch(*_a, **_k):
        order.append("request")
        return 200, []

    original_start = ledger.start

    async def spy_start(**kwargs):
        order.append("ledger")
        return await original_start(**kwargs)

    ledger.start = spy_start
    use_fetch(fetch)

    assert post(client).status_code == 200
    assert order[0] == "ledger"
    assert "request" in order


def test_the_ledger_records_the_phrase_the_caller_typed(client, ledger) -> None:
    """Not a boolean. A boolean stores our interpretation of their act; the
    phrase stores the act."""
    use_fetch(lambda *_a, **_k: (200, []))
    post(client, audit_id=None)
    assert ledger.started[0]["consent_phrase"] == CONSENT_PHRASE


def test_a_refusal_is_still_written_to_the_ledger(client, ledger) -> None:
    """We attempted a check against a customer's project. That it stopped at
    "which project?" does not make it something that did not happen."""
    use_fetch(lambda *_a, **_k: (200, []))
    response = post(client, data=make_zip({"repo/README.md": "# nothing"}))
    assert response.json()["status"] == "refused"
    assert ledger.started
    assert ledger.completed[0]["outcome"] == "refused"


# --- what comes back ---------------------------------------------------------

def test_rows_coming_back_are_reported_as_exposed(client) -> None:
    use_fetch(lambda *_a, **_k: (200, [{"id": "1", "email": "a@b.c"}]))
    body = post(client).json()
    assert body["status"] == "checked"
    assert body["exposed_tables"] == ["users"]
    assert body["project_ref"] == REF


def test_an_empty_answer_is_not_an_all_clear(client) -> None:
    """RLS filters rather than denies, so a protected table and an empty one
    answer identically."""
    use_fetch(lambda *_a, **_k: (200, []))
    body = post(client).json()
    assert body["exposed_tables"] == []
    assert body["status"] == "checked"


def test_the_response_never_carries_the_key_or_a_row_value(client) -> None:
    use_fetch(lambda *_a, **_k: (200, [{"id": "1", "email": "a@b.c"}]))
    blob = json.dumps(post(client).json())
    assert jwt() not in blob
    assert "eyJ" not in blob
    assert "a@b.c" not in blob


def test_a_service_role_key_is_refused_at_the_edge_too(client) -> None:
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))
    body = post(client, data=make_zip({
        "repo/.env": f"SUPABASE_SERVICE_KEY={jwt(role='service_role')}\n",
    })).json()
    assert body["status"] == "refused"
    assert "service_role" in body["reason"]
    assert body["exposed_tables"] == []


# --- a key supplied at the edge ---------------------------------------------

def test_a_supplied_key_lets_a_tidy_repository_be_checked(client) -> None:
    """MEASURED: our own project commits no key — a `.env.example` and nothing
    else. Without this the check refuses exactly the customers with the best
    hygiene."""
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))
    body = post(client, data=make_zip({
        "repo/supabase/migrations/0001.sql":
            "create table public.users (id uuid primary key, email text);",
    }), anon_key=jwt()).json()
    assert body["status"] == "checked"
    assert body["project_ref"] == REF
    assert body["key_source"] == "supplied"
    assert body["exposed_tables"] == ["users"]


def test_a_supplied_service_role_key_is_refused_at_the_edge(client) -> None:
    calls = []
    use_fetch(lambda *a, **k: (calls.append(a), (200, [{"id": "1"}]))[1])
    body = post(client, data=make_zip({"repo/a.ts": "x"}),
                anon_key=jwt(role="service_role")).json()
    assert body["status"] == "refused"
    assert "service_role" in body["reason"]
    assert calls == []


def test_the_supplied_key_does_not_come_back_in_the_response(client) -> None:
    """It arrives in a request body and must not leave in a response one."""
    use_fetch(lambda *_a, **_k: (200, []))
    blob = json.dumps(post(client, anon_key=jwt()).json())
    assert jwt() not in blob
    assert "eyJ" not in blob


def test_the_ledger_never_receives_the_key(client, ledger) -> None:
    """The ledger row is rendered and kept. A credential belonging to a
    customer must not acquire a second home in our database."""
    use_fetch(lambda *_a, **_k: (200, []))
    post(client, anon_key=jwt())
    blob = json.dumps({"started": ledger.started, "completed": ledger.completed})
    assert jwt() not in blob
    assert "eyJ" not in blob


def test_no_supplied_key_still_reads_the_repository(client) -> None:
    """The control: adding the parameter must not turn the original path off."""
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))
    body = post(client).json()
    assert body["key_source"] == "repository"
    assert body["status"] == "checked"


def test_the_response_says_how_many_answers_prove_nothing(client) -> None:
    """The first live run returned `exposed_tables: []` and `inconclusive: 0`
    over nine answers that each carried `alone_proves_nothing`. Both numbers
    were correct and the pair read as an all-clear."""
    use_fetch(lambda *_a, **_k: (200, []))
    body = post(client).json()
    assert body["exposed_tables"] == []
    assert body["inconclusive"] == 0
    assert body["empty_but_unproven"] == len(body["attempts"]) > 0


# --- reachable from a report the customer is already looking at -------------
#
# `POST /v1/rls-check` takes an archive because it has to work standalone. A
# browser rendering a finished report does not have the customer's repository,
# and asking for it again is a bad trade for a button — so the audit-scoped
# route re-fetches from the stored repo_url, the way the Fix Pack already does.

class FakeAudits:
    def __init__(self, row=None):
        self.row = row
        self.asked = []

    async def get_authorized(self, audit_id, token):
        self.asked.append((audit_id, token))
        return self.row


AUDIT_ID = "11111111-1111-1111-1111-111111111111"


def use_audits(row):
    fake = FakeAudits(row)
    app.dependency_overrides[get_audit_repo] = lambda: fake
    return fake


def use_fetcher(fn):
    app.dependency_overrides[get_repo_fetcher] = lambda: fn


@pytest.fixture(autouse=True)
def _clean_audit_overrides():
    yield
    app.dependency_overrides.pop(get_audit_repo, None)
    app.dependency_overrides.pop(get_repo_fetcher, None)


def post_audit(client, *, consent=CONSENT_PHRASE, token="t", **extra):
    return client.post(
        f"/v1/audits/{AUDIT_ID}/rls-check",
        data={"consent": consent, "token": token, **extra},
    )


def test_the_audit_route_re_reads_the_repository_itself(client) -> None:
    use_audits({"id": AUDIT_ID,
                "repo_url": "https://github.com/acme/app"})
    fetched = []

    def fetcher(owner, repo):
        fetched.append((owner, repo))
        return REPO

    use_fetcher(fetcher)
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))

    body = post_audit(client, anon_key=jwt()).json()
    assert fetched == [("acme", "app")]
    assert body["status"] == "checked"
    assert body["exposed_tables"] == ["users"]


def test_a_wrong_token_is_answered_404_and_checks_nothing(client) -> None:
    """The same rule as GET /v1/audits/{id}: 404 rather than 403, so this never
    confirms an id exists to somebody who does not hold its token."""
    audits = use_audits(None)
    calls = []
    use_fetcher(lambda o, r: calls.append((o, r)) or REPO)
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))

    response = post_audit(client, token="wrong")
    assert response.status_code == 404
    assert audits.asked == [(AUDIT_ID, "wrong")]
    assert calls == []


def test_consent_is_checked_before_the_audit_is_even_looked_up(client) -> None:
    audits = use_audits({"id": AUDIT_ID, "repo_url": "https://github.com/a/b"})
    response = post_audit(client, consent="true")
    assert response.status_code == 422
    assert audits.asked == []


def test_an_uploaded_archive_audit_is_refused_with_a_way_forward(client) -> None:
    """No repo_url to re-read. That is a refusal with a reason — the customer
    can still use the archive route — not a 400 that reads like a breakage."""
    use_audits({"id": AUDIT_ID, "repo_url": None})
    use_fetch(lambda *_a, **_k: (200, [{"id": "1"}]))
    body = post_audit(client).json()
    assert body["status"] == "refused"
    assert "/v1/rls-check" in body["reason"]
    assert body["exposed_tables"] == []


def test_a_failed_re_fetch_closes_the_ledger_row(client, ledger) -> None:
    """A row left open means "a check was started and we do not know what
    happened", which is more alarming than what actually happened."""
    use_audits({"id": AUDIT_ID, "repo_url": "https://github.com/acme/app"})

    def boom(owner, repo):
        raise RuntimeError("404 from github")

    use_fetcher(boom)
    use_fetch(lambda *_a, **_k: (200, []))

    body = post_audit(client).json()
    assert body["status"] == "refused"
    assert ledger.started
    assert ledger.completed[0]["outcome"] == "refused"


def test_both_routes_answer_in_the_same_shape(client) -> None:
    """Two hand-built dicts is how a count added in one place goes missing from
    the other."""
    use_audits({"id": AUDIT_ID, "repo_url": "https://github.com/acme/app"})
    use_fetcher(lambda o, r: REPO)
    use_fetch(lambda *_a, **_k: (200, []))

    from_archive = post(client).json()
    from_audit = post_audit(client).json()
    assert set(from_archive) == set(from_audit)
