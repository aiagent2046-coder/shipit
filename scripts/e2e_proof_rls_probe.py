"""End-to-end: the RLS probe against a real Postgres + PostgREST we own.

Part B of SUPABASE_RLS_YIELD_PLAN.md, and the reason it exists is the same
reason the CORS e2e did: every other test of this feature drives an injected
`fetch`, so until a real database has answered, what the probe does against
PostgREST is assumed rather than known. The CORS e2e is the precedent — it
failed on its first run and the failure was real, catching a missing Cookie
that made an exploitable app read as safe.

WHAT IT PROVES

  VULNERABLE — a `founders` table with RLS never enabled. The anon role reads
               the rows. Probe expects `success`.
  PATCHED    — the same table with RLS on and a policy keyed to auth.uid().
               The anon role gets an empty array. Probe expects `failure`.

The pair goes through app.proof.compare.build_proof_report, the same function
the static and CORS pairs use, and must come out `verified`. That pairing is
also what makes the empty answer mean anything: PostgREST returns `200 []` for
a protected table AND for an empty one, and only a BEFORE that read real rows
out of that same table settles which happened.

THE DATA IS FABRICATED. Names and addresses below are invented for this
fixture. The whole point of Part B is that the prover can be proven without
pointing it at anyone — no real project, no customer's key, nothing that
belongs to a person.

REQUIREMENTS: docker, and nothing else. It runs postgres and postgrest
directly rather than the Supabase CLI, because what is under test is
PostgREST's behaviour, and pulling in the whole Supabase stack would add
Kong, GoTrue, Realtime and Studio to prove a fact about one HTTP endpoint.

    python scripts/e2e_proof_rls_probe.py
    NEGATIVE_CONTROL=1 python scripts/e2e_proof_rls_probe.py

The second form skips the fix and asserts the run FAILS. This script passed on
its first real attempt, so unlike the CORS e2e it has never been seen to go
red — and a green that has never been red proves only that it ran.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.proof.compare import build_proof_report  # noqa: E402
from app.proof.rls_probe import run_rls_probe  # noqa: E402

PG = "shipit-rls-e2e-pg"
REST = "shipit-rls-e2e-rest"
NET = "shipit-rls-e2e-net"
PG_PASSWORD = "e2e-not-a-real-password"  # noqa: S105 — local throwaway container
REST_PORT = 54399

NEGATIVE_CONTROL = (os.environ.get("NEGATIVE_CONTROL") or "").strip().lower() in (
    "1", "true", "yes")

# Fabricated. See the module docstring: nothing here belongs to a person.
SCHEMA_VULNERABLE = f"""
create role anon nologin;
create role authenticator noinherit login password '{PG_PASSWORD}';
grant anon to authenticator;

create schema if not exists public;
grant usage on schema public to anon;

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

-- The hole: RLS is never enabled, so PostgREST hands the rows to anon.
grant select on public.founders to anon;
"""

SCHEMA_PATCHED = """
alter table public.founders enable row level security;
create policy "own row only" on public.founders
  for select using (auth_uid() = id);
"""

# PostgREST resolves auth.uid() from the JWT; the anon role has none. A local
# stand-in keeps the policy shape honest without dragging GoTrue in: it returns
# NULL, which is exactly what an unauthenticated caller has.
AUTH_UID_STUB = """
create or replace function auth_uid() returns uuid language sql stable as
$$ select nullif(current_setting('request.jwt.claim.sub', true), '')::uuid $$;
"""


def sh(*args: str, check: bool = True, quiet: bool = False) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=300)
    if check and proc.returncode != 0:
        raise RuntimeError(
            f"{' '.join(args[:3])}… failed ({proc.returncode}): "
            f"{(proc.stderr or proc.stdout).strip()[-500:]}")
    if not quiet and proc.stdout.strip():
        pass
    return proc.stdout


def psql(sql: str) -> None:
    """Run SQL in the container, over TCP rather than the Unix socket.

    `-h 127.0.0.1` is load-bearing, not style. The official postgres image
    initialises by starting a TEMPORARY server with `listen_addresses=\'\'` —
    reachable on the Unix socket and not on TCP — running its init scripts,
    then shutting it down and starting the real one. A readiness check over the
    socket therefore passes against the temporary server and the next statement
    hits the gap while it restarts.

    Measured in CI 2026-08-18: wait_for() reported postgres ready, and the very
    next call failed with "connection to server on socket … No such file or
    directory". The host run had passed because the timing fell differently,
    which is the whole reason this job exists in CI as well.

    Since the temporary server has no TCP listener at all, connecting this way
    cannot see it, and readiness means what it says.
    """
    proc = subprocess.run(
        ["docker", "exec", "-i", PG, "psql", "-h", "127.0.0.1",
         "-U", "postgres", "-v", "ON_ERROR_STOP=1", "-q"],
        input=sql, capture_output=True, text=True, timeout=120)
    if proc.returncode != 0:
        raise RuntimeError(f"psql failed: {proc.stderr.strip()[-800:]}")


def teardown() -> None:
    for name in (REST, PG):
        subprocess.run(["docker", "rm", "-f", name],
                       capture_output=True, text=True, timeout=60)
    subprocess.run(["docker", "network", "rm", NET],
                   capture_output=True, text=True, timeout=60)


def wait_for(fn, what: str, timeout_s: int = 90) -> None:
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


def rest_is_up() -> None:
    urllib.request.urlopen(
        f"http://127.0.0.1:{REST_PORT}/founders?limit=1", timeout=5).read()


def probe(anon_key: str = "unused-locally"):
    """The real probe, pointed at the local stand.

    `allow_loopback` is the only concession to it being local, and it is the
    parameter production never sets — a loopback address accepted there would
    make the probe an SSRF into our own host.
    """
    return run_rls_probe(
        project_url=f"http://127.0.0.1:{REST_PORT}",
        anon_key=anon_key,
        table="founders",
        consent=True,      # our own throwaway container
        allow_loopback=True,
        fetch=_local_fetch,
    )


def _local_fetch(base: str, _key: str, table: str, limit: int):
    """PostgREST without the Supabase gateway: no apikey header, since there
    is no Kong in front of it. The request the probe makes is otherwise the
    same one."""
    url = f"{base}/{table}?select=*&limit={int(limit)}"
    try:
        with urllib.request.urlopen(url, timeout=15) as response:
            return response.status, json.loads(response.read() or b"null")
    except urllib.error.HTTPError as exc:
        body = exc.read() or b"null"
        try:
            return exc.code, json.loads(body)
        except ValueError:
            return exc.code, None


def main() -> int:
    try:
        sh("docker", "version", quiet=True)
    except Exception as exc:  # noqa: BLE001
        print(f"docker is required: {exc}", file=sys.stderr)
        return 2

    teardown()
    try:
        sh("docker", "network", "create", NET, quiet=True)
        print("starting postgres…", flush=True)
        sh("docker", "run", "-d", "--name", PG, "--network", NET,
           "-e", "POSTGRES_PASSWORD=postgres", "postgres:16-alpine", quiet=True)
        wait_for(lambda: psql("select 1;"), "postgres")

        print("seeding the VULNERABLE schema (RLS never enabled)…", flush=True)
        psql(SCHEMA_VULNERABLE)
        psql(AUTH_UID_STUB)

        print("starting postgrest…", flush=True)
        # PG_PASSWORD is a literal defined at the top of this file for a
        # container on a docker-internal network that `finally` tears down. It
        # reaches no real database and is not a credential for anything.
        db_uri = f"postgres://authenticator:{PG_PASSWORD}@{PG}:5432/postgres"  # scan-allow: throwaway e2e container
        sh("docker", "run", "-d", "--name", REST, "--network", NET,
           "-p", f"127.0.0.1:{REST_PORT}:3000",
           "-e", f"PGRST_DB_URI={db_uri}",
           "-e", "PGRST_DB_SCHEMAS=public",
           "-e", "PGRST_DB_ANON_ROLE=anon",
           "postgrest/postgrest:v12.2.3", quiet=True)
        wait_for(rest_is_up, "postgrest")

        before = probe()
        print(f"\nBEFORE: status={before.status} detail={before.detail}")
        print(f"        evidence={before.evidence}")

        # NEGATIVE CONTROL, same idea as the TMPDIR=/tmp control in
        # check_runner_bindmount_namespace.py. This script passed on its first
        # real run, which means nobody has yet seen it FAIL — and a green that
        # has never been red proves only that it ran. With the fix skipped the
        # after-probe must still read rows, the pair must not verify, and this
        # script must exit non-zero. CI runs both directions.
        if NEGATIVE_CONTROL:
            print("\nNEGATIVE CONTROL: skipping the fix. This run MUST fail.",
                  flush=True)
        else:
            print("\napplying the FIX (RLS on, policy keyed to the caller)…",
                  flush=True)
            psql(SCHEMA_PATCHED)
        # PostgREST caches the schema; make it re-read rather than waiting.
        sh("docker", "kill", "-s", "SIGUSR1", REST, quiet=True)
        time.sleep(2)

        after = probe()
        print(f"\nAFTER : status={after.status} detail={after.detail}")
        print(f"        evidence={after.evidence}")

        report = build_proof_report(before, after, informational=False)
        print(f"\nverified={report.verified}  {report.detail}")

        ok = (before.status == "success" and after.status == "failure"
              and report.verified)

        if NEGATIVE_CONTROL:
            if ok:
                print("\nNEGATIVE CONTROL FAILED: the pair verified without "
                      "the fix ever being applied.\n        Whatever this "
                      "script proves, it is not that RLS closed anything.",
                      file=sys.stderr)
                return 1
            print("\nOK (negative control): without the fix the table still "
                  "read, and nothing verified.")
            return 0

        if not ok:
            print("\nFAILED: expected success -> failure -> verified.\n"
                  "        A vulnerable table that did not read means the "
                  "probe or the\n        oracle is wrong about PostgREST; a "
                  "patched table that still\n        reads means the fix shape "
                  "is wrong.", file=sys.stderr)
            return 1

        # The claim this whole class rests on, checked rather than assumed.
        assert "ada@example.invalid" not in repr(before.evidence)
        print("\nOK: the exposure was real, the fix closed it, and no row "
              "value reached the evidence.")
        return 0
    finally:
        teardown()


if __name__ == "__main__":
    raise SystemExit(main())
