"""Cross-tenant read: a freshly-created account reads rows it cannot own.

This closes the gap the anon probe cannot see. A table with RLS ON but a policy
scoped to "any authenticated user" (`using (auth.role() = 'authenticated')`,
`using (true) TO authenticated`, `auth.uid() IS NOT NULL`) returns 200 [] to the
anon key -- so app/proof/rls_probe.py reads it as not-exposed -- while every
signed-in user reads every row. Measured at 10% of committed read policies and
one in seven apps (scripts/measure_rls_policy_scope.py), which is why it earns
the most invasive probe in the project.

THE PROOF, and why a fresh account is the whole trick. A brand-new signup owns
no rows. So if it authenticates and a `select` returns rows, those rows belong
to OTHER users -- reading them is cross-tenant by construction, with no second
identity and no ownership-column reasoning needed. The fix is a per-user policy
(`using (auth.uid() = user_id)`), under which the same fresh account reads [].
That is a real before/after:

    BEFORE (auth-only policy):  fresh account authenticates, reads rows -> success
    AFTER  (per-user policy):   same account reads []                   -> failure

THIS PROBE WRITES. Every other probe in the project is read-only; this one is
not. To get an authenticated session it must create a user -- `POST
/auth/v1/signup` -- which is a write to the customer's auth system, and one it
CANNOT undo: deleting an auth user needs the service-role admin key, which this
probe neither has nor should require. So it leaves a throwaway account behind.
That is named loudly, not hidden: the created email is recorded in the evidence
(with a `drydock-probe+` prefix so it is obvious and greppable) so the customer
can delete it, and this docstring says plainly that they must.

TWO CONSENTS, because a write is not a read. `consent` (read the project, the
same gate rls_probe uses) is necessary but NOT sufficient here. `signup_consent`
is a SEPARATE, defaultless gate for the account-creating write, so a caller that
approved a read cannot trigger a write by omission. assert_signup_consent is the
hard code gate, the twin of assert_probe_allowed in disclosure.py. The ONLY
write this module performs is the signup; there is no code path that deletes,
updates, or writes anything else, by construction.

AND SIGNUP SENDS MAIL, which is the second blocker and the one the first
review of this module missed. With email confirmation on -- the Supabase
default -- the customer's project sends a confirmation message to the
throwaway address, from THEIR sender, against THEIR auth-email quota. On the
built-in SMTP that quota is a handful of messages an hour, so one probe can
lock a customer's real signups out for an hour, and a customer on a paid
mail provider pays for a message to a domain nobody reads. Until this and the
cleanup above are settled, this module is imported by tests and by the
measurement script and by nothing that serves a request;
tests/test_cross_tenant_probe_is_not_wired.py enforces that.

SIGNUP CAN FAIL, and failing is not safety. Signups may be disabled, or email
confirmation may withhold a session token. Either way the probe learned nothing
and returns `error`/`skipped` with a reason -- never `failure`. "We could not
create a test user, so we could not check" must never read as "your table is
safe", the inflation this project has removed repeatedly.

THE JUDGEMENT IS SHARED. Whether a response means rows-were-read is decided by
app.proof.rls_oracle.evaluate_rls_response, the same function the anon probe
uses -- the `200 []` ambiguity (`alone_proves_nothing`) and the denial/404
handling are identical and must not be re-implemented. Only the customer-facing
`detail` is rewritten here, because the actor is a fresh account, not the anon
key.
"""

from __future__ import annotations

import secrets as _secrets
import time
from collections.abc import Callable
from typing import Any

from app.proof.rls_oracle import evaluate_rls_response
from app.proof.rls_probe import (
    UnsafeProjectUrl,
    _safe_table_name,
    validate_project_url,
)
from app.proof.types import ExploitAttempt

TEMPLATE_ID = "rls_cross_tenant_runtime"

# The email prefix every throwaway account carries, so a customer can find and
# delete what the probe left behind. Never reused across runs -- a random
# suffix keeps two probes from colliding on one account.
_PROBE_EMAIL_PREFIX = "drydock-probe+"


class SignupNotPermitted(PermissionError):
    """Raised when the account-creating write is attempted without its own
    consent. The read consent does not authorise it."""


def assert_signup_consent(*, consent: bool, signup_consent: bool) -> None:
    """The hard gate for the write. BOTH must hold: consent to touch the
    project at all, and a separate consent to create the throwaway account.
    The twin of disclosure.assert_probe_allowed -- a rule enforced in code, not
    documented and hoped for."""
    if not consent:
        raise SignupNotPermitted("no consent to probe this project")
    if not signup_consent:
        raise SignupNotPermitted(
            "cross-tenant probe creates a test account (a write); that needs "
            "signup_consent, which the read consent does not grant")


# signup(base, anon_key, email, password) -> (status_code, body).
# Injectable for tests; the default posts to /auth/v1/signup.
Signup = Callable[[str, str, str, str], tuple[int, Any]]
# fetch(base, token, anon_key, table, limit) -> (status_code, body).
FetchAuthed = Callable[[str, str, str, str, int], tuple[int, Any]]


def _attempt(status: str, success: bool, detail: str,
             evidence: dict[str, Any], started: float) -> ExploitAttempt:
    return ExploitAttempt(
        template_id=TEMPLATE_ID,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        success=success,
        detail=detail,
        evidence=evidence,
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def run_cross_tenant_probe(
    *,
    project_url: str,
    anon_key: str,
    table: str,
    consent: bool,
    signup_consent: bool,
    limit: int = 3,
    allow_loopback: bool = False,
    signup: Signup | None = None,
    fetch: FetchAuthed | None = None,
    email: str | None = None,
) -> ExploitAttempt:
    """Create a throwaway account, authenticate, and read `table` with it.

    Returns `success` when the fresh account read rows it cannot own (cross-
    tenant), `failure` when it read [], and `error`/`skipped` when it could not
    check -- never `failure` for a check that did not happen.
    """
    started = time.monotonic()

    # --- the two consents, read first then write ------------------------- #
    if not consent:
        return _attempt(
            "skipped", False,
            "проба не запускалась: нет подтверждённого согласия владельца "
            "проекта",
            {"table": table, "reason": "no_consent"}, started)
    if not signup_consent:
        # NOT an error and NOT a failure: the probe was declined its write, so
        # it did not run. A distinct reason so the caller can offer the
        # stronger consent rather than reading this as "safe".
        return _attempt(
            "skipped", False,
            "проба не запускалась: cross-tenant проверка создаёт тестовый "
            "аккаунт (запись), для этого нужно отдельное согласие",
            {"table": table, "reason": "no_signup_consent"}, started)

    try:
        base = validate_project_url(project_url, allow_loopback=allow_loopback)
    except UnsafeProjectUrl as exc:
        return _attempt(
            "skipped", False, str(exc),
            {"table": table, "reason": "unsafe_project_url"}, started)

    if not _safe_table_name(table):
        return _attempt(
            "skipped", False, f"недопустимое имя таблицы: {table[:40]!r}",
            {"table": table, "reason": "unsafe_table_name"}, started)

    test_email = email or f"{_PROBE_EMAIL_PREFIX}{_secrets.token_hex(8)}@example.com"
    password = _secrets.token_urlsafe(24)

    # --- the ONE write: create a throwaway account ----------------------- #
    signup = signup or _default_signup
    try:
        s_status, s_body = signup(base, anon_key, test_email, password)
    except Exception as exc:  # noqa: BLE001
        return _attempt(
            "error", False,
            f"signup-запрос не выполнился: {type(exc).__name__}",
            {"table": table, "reason": "signup_request_failed",
             "test_account": test_email}, started)

    token = _access_token(s_body)
    if s_status >= 400 or not token:
        # Signups disabled, or email confirmation withheld the session token:
        # we could not get an authenticated identity, so we could not check.
        # `error`, never `failure` -- this is "undetermined", not "safe".
        return _attempt(
            "error", False,
            "не удалось создать сессию тестового аккаунта (регистрация "
            "закрыта или требует подтверждения email) — cross-tenant проверка "
            "не выполнена",
            {"table": table, "reason": "signup_no_session",
             "status": s_status, "test_account": test_email}, started)

    # --- read the table as the fresh account ----------------------------- #
    fetch = fetch or _default_fetch_authed
    try:
        r_status, r_body = fetch(base, token, anon_key, table, limit)
    except Exception as exc:  # noqa: BLE001
        return _attempt(
            "error", False,
            f"запрос к таблице не выполнился: {type(exc).__name__}",
            {"table": table, "reason": "request_failed",
             "test_account": test_email}, started)

    # Judgement shared with the anon oracle; only the framing differs.
    verdict = evaluate_rls_response(r_status, r_body, table=table)
    ev = {**verdict.evidence, "reason": verdict.reason,
          "actor": "fresh_account", "test_account": test_email}

    if not verdict.conclusive:
        return _attempt("error", False, verdict.detail, ev, started)

    if verdict.exposed:
        rows = verdict.evidence.get("rows_read", "?")
        return _attempt(
            "success", True,
            f"свежесозданный аккаунт (владеет 0 строк) прочитал {rows} "
            f"строк(и) из `{table}` — это чужие данные: политика пускает "
            f"любого залогиненного, а не владельца",
            ev, started)

    # empty_result: the same `alone_proves_nothing` caveat as the anon probe —
    # a fresh account reading [] is a per-user policy working OR an empty
    # table, and only the BEFORE half of a pair that read rows tells them
    # apart. compare.build_proof_report enforces that shape.
    return _attempt(
        "failure", False,
        f"свежий аккаунт получил пустой результат из `{table}` — политика "
        f"скоупит на владельца (или таблица пуста)",
        ev, started)


def _access_token(body: Any) -> str:
    """The session token from a Supabase signup response, or "".

    GoTrue returns the token at the top level on an immediate session and
    nowhere when email confirmation is on -- the empty string is the signal
    that we have no identity to probe with."""
    if isinstance(body, dict):
        tok = body.get("access_token")
        if isinstance(tok, str) and tok:
            return tok
        session = body.get("session")
        if isinstance(session, dict):
            tok = session.get("access_token")
            if isinstance(tok, str) and tok:
                return tok
    return ""


def _default_signup(base: str, anon_key: str, email: str,
                    password: str) -> tuple[int, Any]:
    import json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"{base}/auth/v1/signup",
        data=json.dumps({"email": email, "password": password}).encode(),
        headers={"apikey": anon_key, "Content-Type": "application/json",
                 "Authorization": f"Bearer {anon_key}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        body = exc.read() or b"null"
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, None


def _default_fetch_authed(base: str, token: str, anon_key: str, table: str,
                          limit: int) -> tuple[int, Any]:
    import json
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"{base}/rest/v1/{table}?select=*&limit={int(limit)}",
        headers={"apikey": anon_key, "Authorization": f"Bearer {token}",
                 "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"null")
    except urllib.error.HTTPError as exc:
        body = exc.read() or b"null"
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, None
