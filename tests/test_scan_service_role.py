"""The rule that says RLS is not the boundary on this route.

WHY IT EXISTS is in app/scan/service_role.py's docstring: a paying customer's
re-audit found the pattern on 21 of 29 routes and every static rule we owned
was silent, because they all read the schema and the schema was not the
question.

WHAT THESE TESTS DEFEND is mostly the OTHER direction. A rule that says "this
file is reachable from the internet and holds an all-powerful key" is a
sentence a customer will act on, so the expensive error here is the false one:
a seed script called a route, a comment read as a call, an edge function told
off for following Supabase's own manual. Most of what follows is about not
saying it.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.collapse import collapse_repeats
from app.scan.service_role import (
    RULE_ID,
    is_request_handler,
    scan_service_role,
    service_role_env_reads,
)


def make_zip(entries: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, body in entries.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def scan(entries: dict[str, str]):
    return scan_service_role(make_zip(entries))


def files(entries: dict[str, str]) -> list[str]:
    return sorted(f.file for f in scan(entries))


ROUTE = """
import { createClient } from '@supabase/supabase-js';

const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

export async function GET(req: Request) {
  const { data } = await admin.from('messages').select('*').eq('user_id', uid);
  return Response.json(data);
}
"""

SCOPED_ROUTE = """
import { createClient } from '@supabase/supabase-js';

export async function GET(req: Request) {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    { global: { headers: { Authorization: req.headers.get('authorization')! } } },
  );
  return Response.json(await supabase.from('messages').select('*'));
}
"""


# --- the finding itself -----------------------------------------------------

def test_a_next_app_router_route_holding_the_key_is_reported() -> None:
    found = scan({"repo/app/api/messages/route.ts": ROUTE})
    assert [f.rule_id for f in found] == [RULE_ID]
    assert found[0].file == "app/api/messages/route.ts"
    assert found[0].severity == "high"
    assert found[0].category == "Auth"


def test_the_same_route_on_the_anon_key_is_not_reported() -> None:
    """The correct pattern must be silent, or the rule says nothing at all:
    a finding that fires on every route is a finding about Next.js."""
    assert scan({"repo/app/api/messages/route.ts": SCOPED_ROUTE}) == []


def test_the_line_points_at_the_read_not_at_the_file() -> None:
    """A 400-line route named without a line is a finding the owner has to
    re-find by hand."""
    found = scan({"repo/app/api/x/route.ts": ROUTE})
    assert found[0].line == 6           # the SUPABASE_SERVICE_ROLE_KEY line


def test_the_policy_count_names_what_is_being_bypassed() -> None:
    """"You wrote 3 policies and this route goes around them" is the sentence
    that separates a project that never adopted RLS — where this is a design —
    from one that adopted it and then went around it."""
    found = scan({
        "repo/app/api/x/route.ts": ROUTE,
        "repo/supabase/migrations/0001.sql": """
            create table public.notes (id uuid primary key, user_id uuid);
            alter table public.notes enable row level security;
            create policy a on public.notes for select using (auth.uid() = user_id);
            create policy b on public.notes for insert with check (auth.uid() = user_id);
            create policy c on public.notes for update using (auth.uid() = user_id);
        """,
    })
    assert "3 Row Level Security policies" in found[0].explanation


def test_a_repo_with_no_committed_schema_still_gets_the_finding() -> None:
    """32% of Supabase repos commit no schema at all (measured, see
    SUPABASE_RLS_YIELD_PLAN.md). The policy count is an amplifier; its absence
    must not cost the finding, because the route is reachable either way."""
    found = scan({"repo/app/api/x/route.ts": ROUTE})
    assert len(found) == 1
    assert "Row Level Security policies. This route" not in found[0].explanation


# --- what must NOT be called a request handler ------------------------------

def test_a_seed_script_holding_the_key_is_not_reported() -> None:
    """This is what the key is FOR. A script that runs on someone's laptop is
    not reachable from the internet, and reporting it is the whole rule
    discredited on the first repo that has one."""
    assert scan({"repo/scripts/seed.ts": ROUTE}) == []


def test_a_supabase_edge_function_is_not_reported() -> None:
    """The documented pattern: the edge function IS the trusted server. A
    finding here is telling the customer off for following the manual."""
    assert scan({"repo/supabase/functions/notify/index.ts": ROUTE}) == []


def test_a_module_named_route_outside_an_app_tree_is_not_a_route() -> None:
    """`lib/route.ts` is somebody's routing helper. The App Router convention
    is a file called route.ts INSIDE app/, and only there."""
    assert scan({"repo/lib/route.ts": ROUTE}) == []
    assert files({"repo/src/app/api/x/route.ts": ROUTE}) == ["src/app/api/x/route.ts"]


def test_a_test_file_is_not_a_route() -> None:
    assert scan({"repo/__tests__/app/api/x/route.ts": ROUTE}) == []
    assert scan({"repo/e2e/app/api/x/route.ts": ROUTE}) == []


def test_the_other_frameworks_conventions_are_recognised() -> None:
    assert is_request_handler("pages/api/hello.ts")
    assert is_request_handler("src/routes/x/+server.ts")
    assert is_request_handler("server/api/users.get.ts")
    assert not is_request_handler("app/page.tsx")
    assert not is_request_handler("supabase/functions/x/index.ts")


# --- what must NOT be called a read -----------------------------------------

def test_a_comment_warning_against_the_key_is_not_a_use_of_it() -> None:
    """The inversion a reader would least forgive: a file whose comment says
    "never use the service role key here" reported as using it here."""
    assert scan({"repo/app/api/x/route.ts": """
        // Do NOT use SUPABASE_SERVICE_ROLE_KEY in this route — it bypasses RLS.
        export async function GET() { return Response.json({ ok: true }); }
    """}) == []


def test_an_unrelated_secret_is_not_a_supabase_service_role_key() -> None:
    """SECRET_KEY alone belongs to Django, Stripe and half the ecosystem."""
    assert service_role_env_reads("process.env.SECRET_KEY") == []
    assert service_role_env_reads("process.env.STRIPE_SECRET_KEY") == []
    assert service_role_env_reads("process.env.SUPABASE_SECRET_KEY") == [
        ("SUPABASE_SECRET_KEY", 1)]


def test_supabases_OTHER_secrets_are_not_the_service_role_key() -> None:
    """MEASURED, and it is the one false positive the corpus sample turned up:
    kyleledbetter/dreamschemas app/api/auth/supabase/refresh/route.ts reads
    `SUPABASE_OAUTH_CLIENT_SECRET` — the Management API's OAuth secret, in a
    route that never touches a project database. `SUPABASE_JWT_SECRET` is the
    same shape. Neither bypasses a policy, and reporting either as the key
    that does is how a customer learns to distrust the whole report."""
    assert service_role_env_reads("process.env.SUPABASE_OAUTH_CLIENT_SECRET") == []
    assert service_role_env_reads("process.env.SUPABASE_JWT_SECRET") == []
    assert service_role_env_reads("process.env.SUPABASE_WEBHOOK_SECRET") == []


def test_the_env_readers_of_each_runtime_are_recognised() -> None:
    for source in (
        'process.env.SUPABASE_SERVICE_ROLE_KEY',
        'process.env["SUPABASE_SERVICE_ROLE_KEY"]',
        'Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")',
        'os.environ["SUPABASE_SERVICE_ROLE_KEY"]',
        'os.getenv("SUPABASE_SERVICE_ROLE_KEY")',
        'import.meta.env.SUPABASE_SERVICE_ROLE_KEY',
    ):
        assert service_role_env_reads(source), source


# --- the score, which is why collapse is not optional -----------------------

def test_many_routes_collapse_to_one_row_that_counts_them() -> None:
    """MEASURED on the customer's repository: 21 of 29 routes. Left
    uncollapsed that is 21 high findings — a report nobody can read, and a
    score sunk by one design decision counted twenty-one times."""
    found = scan({f"repo/app/api/r{i}/route.ts": ROUTE for i in range(21)})
    assert len(found) == 21

    rows = collapse_repeats([vars(f) for f in found])
    assert len(rows) == 1
    assert "found in 21 places" in rows[0]["title"]
    assert "app/api/r0/route.ts" in rows[0]["explanation"]


def test_the_collapsed_title_does_not_name_one_route_while_counting_many() -> None:
    """The representative's title carries the count, so it must not also carry
    a single path — "`app/api/r0/route.ts` … found in 21 places" is wrong
    about the one thing the suffix exists to say."""
    rows = collapse_repeats(
        [vars(f) for f in scan({f"repo/app/api/r{i}/route.ts": ROUTE
                                for i in range(4)})])
    assert "route.ts" not in rows[0]["title"]


def test_an_archive_with_no_wrapping_folder_reports_the_real_path() -> None:
    """A GitHub archive wraps everything in one folder; a zip a customer made
    by hand often does not, and an unconditional strip of the first segment
    eats the `app/` this rule is about.

    The finding survives that — the path is tested both ways — but the PATH
    does not: it would name `api/messages/route.ts`, a file that does not
    exist, in the one field the owner uses to go and look. A mutation that
    reintroduced the unconditional strip was caught by nothing until this.
    """
    found = scan({"app/api/messages/route.ts": ROUTE, "package.json": "{}"})
    assert [f.file for f in found] == ["app/api/messages/route.ts"]


def test_a_wrapping_folder_is_still_stripped() -> None:
    """The other direction, or the fix above becomes "never strip": a GitHub
    archive's `repo-8a1f2c/` prefix in every path is noise the owner did not
    write and cannot find in their editor."""
    found = scan({"ai-co-founder-matching-87553a7/app/api/x/route.ts": ROUTE})
    assert [f.file for f in found] == ["app/api/x/route.ts"]
