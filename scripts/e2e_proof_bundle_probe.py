"""End-to-end: the service-role-in-bundle proof, from `vite build` to a verdict.

Part B of SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md. Part A closed the committed-
bundle survey as a dead end (93% of the market commits no bundle); this proves
the PROVER regardless, because the prover never took its input from committed
bundles — it takes it from a served one. Two halves:

  HALF 1 — the leak, provable here with no Docker. Build the stand at
    smoke/service_role_bundle/ in two variants from one source. Extract every
    JWT from each `dist_*/assets/*.js` and classify it with PRODUCTION's oracle
    (app.scan.secrets._jwt_severity / _is_demo_jwt). Assert the VULNERABLE
    bundle ships a real `service_role` key and the PATCHED one does not. This is
    the novel claim of the class — that a service-role key survives a real
    minifying production build into client JS — and it is checked against the
    actual emitted bundle, not a mock.

  HALF 2 — the bypass, live against a PostgREST we own (needs Docker). The
    table has RLS ON with a restrictive policy, so it is CORRECTLY protected
    the whole time — unlike the RLS e2e, nothing about the table changes. What
    changes is the key the bundle ships:

      BEFORE  probe with the service_role key extracted from dist_vulnerable.
              service_role BYPASSES RLS, so the RLS-on table reads its rows.
              Probe expects `success`.
      AFTER   probe with the anon key extracted from dist_patched. RLS applies,
              the policy denies, the same table returns `200 []`.
              Probe expects `failure`.

    The pair goes through app.proof.compare.build_proof_report — the SAME
    function the RLS and CORS pairs use — and must come out `verified`. The
    `200 []` ambiguity resolves itself in the pair: BEFORE read real rows out of
    that same table, so AFTER returning none is a change, not an empty table.

ZERO PRODUCTION CHANGES. This script only imports existing functions:
run_rls_probe (the key is passed where `anon_key` is named — the parameter is
"the key the client ships", and here the client shipped service_role), the
production secret oracle, and build_proof_report. A dedicated
`service_role_bundle_runtime` template id is a ship-time decision (Part C), not
a Part-B one; reusing `rls_open_runtime` keeps the proof honest — an RLS-on
table that read rows anyway is exactly an "RLS open at runtime" observation.

THE DATA IS FABRICATED and the keys are throwaway, signed with the stand's own
local secret (smoke/service_role_bundle/keys.env). They authenticate against
nothing real — the point of Part B is to prove the prover without pointing it
at anyone.

Usage:
    python scripts/e2e_proof_bundle_probe.py --logic-check   # no Docker, CI-fast
    python scripts/e2e_proof_bundle_probe.py                 # Docker, full live
    NEGATIVE_CONTROL=1 python scripts/e2e_proof_bundle_probe.py

--logic-check runs HALF 1 for real (it builds and extracts) and drives HALF 2
through an injected fetch whose response is decided by the role in the key it is
handed — so it proves the extraction produced distinguishable keys and that the
compare/oracle wiring turns them into verified success->failure, all without a
container. The Docker run is what proves PostgREST actually behaves that way.

NEGATIVE_CONTROL uses the service_role key for the AFTER probe too — the state
where the developer never removed the key from the bundle. The exploit must
still succeed, the pair must NOT verify, and this script must exit non-zero.
A green that has never been red proves only that it ran.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.compare import build_proof_report  # noqa: E402
from app.proof.rls_probe import run_rls_probe  # noqa: E402
from app.scan.secrets import _is_demo_jwt, _jwt_severity  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
STAND = ROOT / "smoke" / "service_role_bundle"

NEGATIVE_CONTROL = (os.environ.get("NEGATIVE_CONTROL") or "").strip().lower() in (
    "1", "true", "yes")

# The same JWT shape the shipped secrets scanner matches.
_JWT = re.compile(
    r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")

# Docker stand — mirrors e2e_proof_rls_probe.py, one PostgREST difference.
PG = "shipit-bundle-e2e-pg"
REST = "shipit-bundle-e2e-rest"
NET = "shipit-bundle-e2e-net"
PG_PASSWORD = "e2e-not-a-real-password"  # noqa: S105 — local throwaway container
REST_PORT = 54399

# Must match the secret the stand signed its JWTs with (keys.env). PostgREST
# validates the bearer token against it and assigns the DB role from the `role`
# claim — which is the entire mechanism: service_role -> BYPASSRLS, anon -> not.
JWT_SECRET = "e2e-bundle-stand-jwt-secret-not-a-real-one-xxxxxxxx"  # noqa: S105


# --------------------------------------------------------------------------- #
# HALF 1 — the leak, no Docker
# --------------------------------------------------------------------------- #

def _fail(msg: str) -> None:
    print("\n" + msg, file=sys.stderr)
    raise SystemExit(1)


def _role_of(token: str) -> str:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return str(json.loads(base64.urlsafe_b64decode(payload)).get("role", ""))
    except Exception:  # noqa: BLE001
        return ""


def extract_key(dist_dir: Path, want_role: str) -> str | None:
    """Return the first REAL (non-demo) JWT of ``want_role`` in the bundle.

    Classification is production's: a demo-signed service_role token is a
    fixture that happens to say service_role, and treating it as a credential
    is the inverse of the CORS `*`-credentials error.
    """
    for path in sorted(glob.glob(str(dist_dir / "assets" / "*.js"))):
        text = Path(path).read_text(encoding="utf-8", errors="replace")
        for token in _JWT.findall(text):
            if _role_of(token) != want_role:
                continue
            if _is_demo_jwt(token):
                continue
            return token
    return None


def build_stand() -> None:
    if not (STAND / "node_modules").exists():
        print("installing stand deps…", flush=True)
        _sh("npm", "install", "--no-audit", "--no-fund", cwd=str(STAND))
    print("building both variants…", flush=True)
    _sh("bash", "build_variants.sh", cwd=str(STAND))


def half1_extract() -> tuple[str, str]:
    """Build, extract, and assert the leak. Returns (service_role_key, anon_key).

    The service_role key is what the VULNERABLE bundle leaked; the anon key is
    what the PATCHED bundle ships instead. Both are what HALF 2 then probes with.
    """
    build_stand()

    vuln_service = extract_key(STAND / "dist_vulnerable", "service_role")
    vuln_anon = extract_key(STAND / "dist_vulnerable", "anon")
    patched_service = extract_key(STAND / "dist_patched", "service_role")
    patched_anon = extract_key(STAND / "dist_patched", "anon")

    print("\nHALF 1 — the leak, checked against the emitted bundle:")
    print(f"  dist_vulnerable ships service_role: {vuln_service is not None} "
          f"(expect True)")
    # The variant swap must REPLACE the key, not add one. A vulnerable build
    # carrying both keys would make the BEFORE probe ambiguous about which one
    # did the read, which is the whole thing this pair is asserting.
    print(f"  dist_vulnerable ships anon        : {vuln_anon is not None} "
          f"(expect False)")
    print(f"  dist_patched    ships service_role: {patched_service is not None} "
          f"(expect False)")
    print(f"  dist_patched    ships anon        : {patched_anon is not None} "
          f"(expect True)")

    if vuln_service is None:
        _fail("HALF 1 FAILED: the vulnerable build did not leak a service_role "
              "key.\n        Either the key was tree-shaken (the build is not "
              "representative)\n        or the oracle rejected it — both mean "
              "the class is not demonstrated.")
    if patched_service is not None:
        _fail("HALF 1 FAILED: the patched build ALSO ships a service_role key.\n"
              "        The 'fix' variant is not actually fixed, so any "
              "before/after is meaningless.")
    if patched_anon is None:
        _fail("HALF 1 FAILED: the patched build ships no anon key, so there is "
              "no\n        credential to run the AFTER probe with.")

    # Confirm the word matches what a customer's report would say.
    sev, _c, _m = _jwt_severity(vuln_service)
    assert sev == "critical", f"expected critical for a service_role key, got {sev}"
    print("  production oracle grades the leaked key: critical (full RLS bypass)")

    # The after-probe credential. Under negative control we deliberately keep
    # the service_role key — the developer who never removed it from the bundle.
    after_key = vuln_service if NEGATIVE_CONTROL else patched_anon
    return vuln_service, after_key


# --------------------------------------------------------------------------- #
# HALF 2 — the bypass, live (Docker) or injected (--logic-check)
# --------------------------------------------------------------------------- #

def _authed_fetch(base: str, key: str, table: str, limit: int):
    """PostgREST behind no gateway, but WITH the bearer token — unlike the RLS
    e2e's fetch, which dropped it. Here the token is the whole point: PostgREST
    reads its `role` claim and switches DB role, so service_role bypasses RLS
    and anon does not."""
    url = f"{base}/{table}?select=*&limit={int(limit)}"
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {key}",
        "apikey": key,
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        body = exc.read() or b"null"
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, None


def _injected_fetch(_base: str, key: str, _table: str, _limit: int):
    """No network. The response is decided by the ROLE in the key handed to us,
    which is exactly what a correctly-configured PostgREST would do — and proves
    HALF 1 produced two keys the probe can tell apart. service_role bypasses RLS
    (rows); anon is filtered by the policy (empty)."""
    role = _role_of(key)
    if role == "service_role":
        return 200, [
            {"id": "11111111-1111-1111-1111-111111111111",
             "email": "ada@example.invalid", "sentiment": "positive"},
        ]
    return 200, []  # anon, filtered by RLS — same bytes an empty table gives


def probe(key: str, fetch):
    return run_rls_probe(
        project_url=f"http://127.0.0.1:{REST_PORT}",
        anon_key=key,           # "the key the client ships" — here, service_role or anon
        table="founders",
        consent=True,           # our own throwaway stand
        allow_loopback=True,    # the parameter production never sets
        fetch=fetch,
    )


def run_pair(service_key: str, after_key: str, fetch) -> int:
    before = probe(service_key, fetch)
    print(f"\nBEFORE (service_role key from the bundle): "
          f"status={before.status} detail={before.detail}")

    if NEGATIVE_CONTROL:
        print("NEGATIVE CONTROL: the key was never removed from the bundle — "
              "AFTER reuses service_role. This run MUST NOT verify.")
    after = probe(after_key, fetch)
    print(f"AFTER  ({'service_role (control)' if NEGATIVE_CONTROL else 'anon key from patched bundle'}): "
          f"status={after.status} detail={after.detail}")

    report = build_proof_report(before, after, informational=False)
    print(f"\nverified={report.verified}  {report.detail}")

    ok = (before.status == "success" and after.status == "failure"
          and report.verified)

    if NEGATIVE_CONTROL:
        if ok:
            print("\nNEGATIVE CONTROL FAILED: the pair verified while the "
                  "service_role key\n        was still in the bundle. This "
                  "proves nothing about the fix.", file=sys.stderr)
            return 1
        print("\nOK (negative control): with the key still shipped, the "
              "exploit still\n        succeeded and nothing verified.")
        return 0

    if not ok:
        print("\nFAILED: expected success -> failure -> verified.\n"
              "        BEFORE not reading means service_role did not bypass RLS "
              "(role/\n        BYPASSRLS misconfigured); AFTER still reading "
              "means the anon key\n        was not actually anon, or RLS is off.",
              file=sys.stderr)
        return 1

    assert "ada@example.invalid" not in repr(before.evidence)
    print("\nOK: the leaked key bypassed RLS, the anon key did not, and no row "
          "value\n    reached the evidence.")
    return 0


# --------------------------------------------------------------------------- #
# Docker stand (mirrors e2e_proof_rls_probe.py)
# --------------------------------------------------------------------------- #

# service_role is granted BYPASSRLS — the same authority the real Supabase role
# has, and the reason a leaked service_role key ignores every policy. anon is
# the ordinary filtered role.
SCHEMA = f"""
create role anon nologin;
create role service_role nologin bypassrls;
create role authenticator noinherit login password '{PG_PASSWORD}';
grant anon to authenticator;
grant service_role to authenticator;

create schema if not exists public;
grant usage on schema public to anon, service_role;

create table public.founders (
  id uuid primary key default gen_random_uuid(),
  email text not null,
  phone text,
  sentiment text
);
insert into public.founders (email, phone, sentiment) values
  ('ada@example.invalid',   '+10000000001', 'positive'),
  ('grace@example.invalid', '+10000000002', 'wary'),
  ('alan@example.invalid',  '+10000000003', 'neutral');

-- RLS is ON and correct the whole time. anon gets nothing; service_role
-- bypasses it. The table is never misconfigured — the leaked key is.
alter table public.founders enable row level security;
grant select on public.founders to anon, service_role;
create policy "own row only" on public.founders
  for select using (auth_uid() = id);
"""

AUTH_UID_STUB = """
create or replace function auth_uid() returns uuid language sql stable as
$$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
"""


def _sh(*args: str, cwd: str | None = None, check: bool = True) -> str:
    proc = subprocess.run(args, cwd=cwd, capture_output=True, text=True,
                          timeout=600)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args[:3])}… failed ({proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[-600:]}")
    return proc.stdout


def _psql(sql: str) -> None:
    proc = subprocess.run(
        ["docker", "exec", "-i", PG, "psql", "-h", "127.0.0.1",
         "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"],
        input=sql, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed: {proc.stderr.strip()[-800:]}")


def _teardown() -> None:
    for name in (REST, PG):
        subprocess.run(["docker", "rm", "-f", name],
                       capture_output=True, text=True, timeout=60)
    subprocess.run(["docker", "network", "rm", NET],
                   capture_output=True, text=True, timeout=60)


def _wait_for(fn, what: str, timeout_s: int = 90) -> None:
    deadline = time.time() + timeout_s
    last = ""
    while time.time() < deadline:
        try:
            fn()
            return
        except Exception as exc:  # noqa: BLE001
            last = f"{type(exc).__name__}: {exc}"
            time.sleep(1)
    raise RuntimeError(f"{what} never became ready ({last})")


def _rest_is_up() -> None:
    urllib.request.urlopen(
        f"http://127.0.0.1:{REST_PORT}/founders?limit=1", timeout=5).read()


def run_docker(service_key: str, after_key: str) -> int:
    try:
        _sh("docker", "version")
    except Exception as exc:  # noqa: BLE001
        print(f"docker is required for the live half: {exc}", file=sys.stderr)
        return 2

    _teardown()
    try:
        _sh("docker", "network", "create", NET)
        print("starting postgres…", flush=True)
        _sh("docker", "run", "-d", "--name", PG, "--network", NET,
            "-e", "POSTGRES_PASSWORD=postgres", "postgres:16-alpine")
        _wait_for(lambda: _psql("select 1;"), "postgres")

        print("seeding schema (RLS ON, service_role BYPASSRLS)…", flush=True)
        _psql(SCHEMA)
        _psql(AUTH_UID_STUB)

        print("starting postgrest (with JWT secret)…", flush=True)
        db_uri = f"postgres://authenticator:{PG_PASSWORD}@{PG}:5432/postgres"  # scan-allow: throwaway e2e container
        _sh("docker", "run", "-d", "--name", REST, "--network", NET,
            "-p", f"127.0.0.1:{REST_PORT}:3000",
            "-e", f"PGRST_DB_URI={db_uri}",
            "-e", "PGRST_DB_SCHEMAS=public",
            "-e", "PGRST_DB_ANON_ROLE=anon",
            "-e", f"PGRST_JWT_SECRET={JWT_SECRET}",
            "postgrest/postgrest:v12.2.3")
        _wait_for(_rest_is_up, "postgrest")

        return run_pair(service_key, after_key, _authed_fetch)
    finally:
        _teardown()


def main() -> int:
    logic_check = "--logic-check" in sys.argv[1:]

    # HALF 1 always runs for real — it needs only npm, and it is the claim the
    # whole class rests on.
    service_key, after_key = half1_extract()

    if logic_check:
        print("\nHALF 2 — injected fetch (no Docker): proving the wiring.")
        return run_pair(service_key, after_key, _injected_fetch)

    print("\nHALF 2 — live PostgREST (Docker).")
    return run_docker(service_key, after_key)


if __name__ == "__main__":
    raise SystemExit(main())
