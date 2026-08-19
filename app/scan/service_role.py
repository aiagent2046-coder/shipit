"""A request handler holding the service-role key: RLS is not the boundary there.

WHY THIS EXISTS, and it is a defect in our own coverage rather than a new idea.
A paying customer bought a Fix Pack, applied it, and re-ran the audit. The
re-audit's one CRITICAL was "service-role client used for all agent-chat
queries — RLS bypassed". Every finding in that report came from the deep
review; the static side had nothing to say. Measured on that repository:

    21 of 29 API routes construct a Supabase client with the service-role key
    they reach 8 tables — founder_profiles, messages, agent_context, matches,
      agent_messages, github_connections, swipes, video_rooms
    all 8 have RLS enabled, carrying 11 policies between them

Our RLS detector read the schema, found those 8 tables correctly protected,
and said nothing. The one table it DID flag, `avatar_interactions`, is the one
table no application code queries at all. The schema was not the question.
Whether the code goes through RLS was, and nothing static was asking it.

HOW OFTEN IT FIRES, measured across 495 repositories (three strata, the same
corpus as scripts/measure_rls_blind_spot.py; see
scripts/measure_service_role_routes.py to reproduce):

    given the repo uses Supabase AND has server-side request handlers,
    a handler holds the service-role key in 35% [95% CI 23-49%] of them
      Lovable 2/5, bolt 4/9, control 11/35 — no pair distinguishable

The prior question is the bigger one: most vibe-coded Supabase repos have no
server at all. Handlers exist in 7% of Lovable's, 12% of bolt's and 45% of the
hand-written control — the generators emit SPAs that talk to Supabase straight
from the browser, where RLS genuinely IS the only boundary. So this rule is
silent on most of the market by construction, and on the part it does reach it
fires on about a third.

244 files OUTSIDE handlers read a service-role key in the same corpus — seed
scripts, edge functions, admin tooling. Every one would be a false positive
without is_request_handler(); the filter is doing more work than the match.

WHAT THE FINDING CLAIMS, and the wording is bounded by this. It claims a fact
that is fully readable from the repository: this file is reached over HTTP and
it names the credential that bypasses every Row Level Security policy in the
project. It does NOT claim the route is exploitable — the route may filter
correctly in application code, and many do. It claims that if the filter is
ever wrong, nothing is behind it. That is why the severity is high and the
confidence is not 1.0: the fact is certain, its consequence depends on code we
are not reading.

READING EIGHT HITS BY HAND is what set that confidence. Every one really did
build a service-role client inside an HTTP route — no false positive on the
claim — but they split on whether it is a DEFECT: circletel's admin route
calls authenticateAdmin() first, usesafe-DPC-UI's says in a comment that it
bypasses RLS deliberately and checks the session, Neural-Nexus needs
auth.admin.createUser and cannot do it any other way. devSync52's billing
route has a module-level admin client and no visible check at all. So the
finding must not read as "you have a vulnerability", and it does not; it says
what is true of all of them, which is that nothing is behind the filtering in
the file.

WHY A RULE RATHER THAN LEAVING IT TO THE MODEL. The deep review found it, and
the report itself tells the buyer that two passes catch roughly three-quarters
of what repeated readings agree is there. A grep for an environment variable
name catches it every time, on every route, for no tokens. The model's version
is also three separate findings on three routes out of twenty-one; this one is
collapsed to a single row that counts them (see COLLAPSIBLE in
app/scan/collapse.py).

NOT AUTO-FIXABLE, deliberately. Replacing a service-role client with a
user-scoped one means knowing how that route authenticates its caller and
which of its queries genuinely need to cross users — a rewrite, not a
substitution. app/fixpack/generate.py declines it by name and says so.
"""

from __future__ import annotations

import re
import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding, archive_root
from app.scan.rls import read_committed_sql
from app.scan.sql_schema import parse_schema

RULE_ID = "supabase-service-role-route"

# Server-side request handlers, by the framework conventions that put a file on
# an HTTP path by where it sits. Deliberately conventional-only: a rule that
# tried to recognise an Express handler would have to understand routing tables
# built at runtime, and a wrong guess here says "this is reachable from the
# internet" about a file that is not.
#
# Supabase Edge Functions (`supabase/functions/*/index.ts`) match none of these
# ON PURPOSE. The service-role key in an edge function is the documented
# pattern -- the function IS the trusted server -- so reporting it would be
# telling people off for following the manual.
_APP_ROUTER = ("route.ts", "route.tsx", "route.js", "route.jsx",
               "route.mts", "route.mjs")
_SVELTEKIT = ("+server.ts", "+server.js")
_PAGES_API = "pages/api/"
_NUXT_API = "server/api/"

_TEST_DIR_PARTS = ("/tests/", "/test/", "/__tests__/", "/spec/",
                   "/e2e/", "/cypress/", "/playwright/")

# The env-var NAMES that mean "the key that ignores every policy". Matched as
# whole identifiers: `SUPABASE_SERVICE_ROLE_KEY`, `SERVICE_ROLE_KEY`, and
# `SUPABASE_SECRET_KEY` — Supabase's newer name for the same authority.
#
# THE SECOND ALTERNATIVE ENDS AT `SECRET_KEY` ON PURPOSE, and the first version
# did not. "Supabase and secret, in any arrangement" reported
# `SUPABASE_OAUTH_CLIENT_SECRET` in
# kyleledbetter/dreamschemas app/api/auth/supabase/refresh/route.ts — the
# Management API's OAuth client secret, which has nothing to do with RLS and
# sits in a route that never touches a project database. `SUPABASE_JWT_SECRET`
# was the same mistake waiting to happen. One false positive in a sample of
# eight, found by reading the hits, which is what the sample is for.
_KEY_NAME = re.compile(
    r"^(?:[A-Z0-9_]*SERVICE_ROLE[A-Z0-9_]*"
    r"|[A-Z0-9_]*SUPABASE[A-Z0-9_]*SECRET_KEY)$",
    re.IGNORECASE,
)

# The name has to be READ FROM THE ENVIRONMENT, not merely mentioned. Without
# this, a comment saying "do not use the service role key here" becomes a
# finding that the file uses the service role key here -- the exact inversion
# the reader would least forgive.
_ENV_READ = re.compile(
    r"""(?:process\s*\.\s*env
        |import\s*\.\s*meta\s*\.\s*env
        |Deno\s*\.\s*env\s*\.\s*get
        |os\s*\.\s*environ(?:\s*\.\s*get)?
        |os\s*\.\s*getenv
        |\benv)
        \s*(?:\.\s*|\[\s*|\(\s*)
        ["'`]?([A-Za-z_][A-Za-z0-9_]*)["'`]?""",
    re.VERBOSE,
)

_SOURCE_EXTS = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".mts", ".cjs", ".py")

# One archive entry is one route file; a repo with hundreds is a monorepo and
# the finding is the same either way. Bounded so a pathological archive cannot
# turn one scan into a long one.
_MAX_FILES_READ = 400


def is_request_handler(path: str) -> bool:
    """Is this file on an HTTP path by framework convention?

    Takes the archive-relative path WITH its export root stripped or not --
    every test below is a suffix or a substring, so `repo/app/api/x/route.ts`
    and `app/api/x/route.ts` answer alike.
    """
    lowered = path.lower()
    if any(part in f"/{lowered}" for part in _TEST_DIR_PARTS):
        return False
    if not lowered.endswith(_SOURCE_EXTS):
        return False
    base = lowered.rsplit("/", 1)[-1]
    if base in _APP_ROUTER:
        # Next.js App Router only inside an `app/` tree. A file called
        # route.ts in lib/ is a module somebody named after what it does.
        return "app/" in lowered
    if base in _SVELTEKIT:
        return True
    return _PAGES_API in lowered or _NUXT_API in lowered


def service_role_env_reads(text: str) -> list[tuple[str, int]]:
    """(env var, line) for each service-role key this file READS, first
    occurrence of each name. Empty for a file that only talks about one.

    The line comes from the match offset rather than from a search for the
    name: a file whose header comment warns against the service-role key and
    whose body then reads it would otherwise be reported at the comment, which
    is the one line in it that is not the problem.
    """
    seen: dict[str, int] = {}
    for match in _ENV_READ.finditer(text):
        name = match.group(1)
        if _KEY_NAME.fullmatch(name) and name not in seen:
            seen[name] = text.count("\n", 0, match.start()) + 1
    return list(seen.items())


def _policy_count(fileobj: BinaryIO) -> int:
    """How many RLS policies the committed schema declares.

    Not decoration. "You wrote 11 policies and 21 routes go around them" is
    the sentence that makes this finding land, and it is the difference
    between a project that never adopted RLS -- where this is a design, not a
    defect -- and one that adopted it and then bypassed it.
    """
    try:
        fileobj.seek(0)
        sql, _ = read_committed_sql(fileobj)
        if not sql.strip():
            return 0
        return sum(len(table.policies) for table in parse_schema(sql).values())
    except Exception:                                          # noqa: BLE001
        # A schema we cannot parse must not cost the finding. The count is an
        # amplifier; its absence weakens the wording and nothing else.
        return 0


def scan_service_role(fileobj: BinaryIO) -> list[CheckFinding]:
    """One finding per request handler that reads a service-role key.

    Emitted per file rather than per repository so the report can name the
    routes, and collapsed back to one row by app/scan/collapse.py -- which
    keeps the score honest too: this is one fact about the project, not
    twenty-one independent problems, and twenty-one high findings would sink
    a score on their own.
    """
    policies = _policy_count(fileobj)

    hits: list[tuple[str, str, int]] = []
    fileobj.seek(0)
    with zipfile.ZipFile(fileobj) as zf:
        # The export's wrapping folder, and ONLY when there is one. Stripping
        # the first segment unconditionally is what a GitHub archive lets you
        # get away with and a hand-made zip does not: it ate the `app/` this
        # rule then looked for, and the scan came back clean on a repo full of
        # routes. See archive_root in app/scan/checks.py.
        root = archive_root(zf.namelist())
        for info in zf.infolist():
            if info.is_dir():
                continue
            rel = info.filename[len(root):] if root else info.filename
            # BOTH FORMS, because the wrapping folder cannot always be told
            # from a real one. An archive whose only top-level entry is `app/`
            # — a zip of a bare Next.js tree — makes `app/` look like the
            # export root, and stripping it turns every route into a nameless
            # file under api/. Asking both ways costs nothing and the failure
            # it prevents is silent: a clean scan over a repo full of routes.
            if not (is_request_handler(rel) or is_request_handler(info.filename)):
                continue
            if len(hits) >= _MAX_FILES_READ:
                break
            try:
                text = zf.read(info).decode("utf-8", errors="replace")
            except Exception:                                  # noqa: BLE001
                continue
            reads = service_role_env_reads(text)
            if reads:
                name, line = reads[0]
                hits.append((rel, name, line))

    return [_finding(rel, name, line, policies) for rel, name, line in sorted(hits)]


def _finding(path: str, env_name: str, line: int, policies: int) -> CheckFinding:
    bypassed = (
        f"Your migrations declare {policies} Row Level Security "
        f"{'policy' if policies == 1 else 'policies'}. This route goes around "
        f"all of them.\n\n"
        if policies
        else ""
    )
    return CheckFinding(
        rule_id=RULE_ID,
        # NO PATH IN THE TITLE. Repeats of this rule collapse into one row
        # whose title gains "— found in 21 places" (app/scan/collapse.py), and
        # a title that named one route while counting twenty-one would be
        # wrong about the one thing the suffix exists to say. The report
        # renders the file beside the title anyway.
        title="Request handler runs with the service-role key, bypassing Row Level Security",
        severity="high",
        # NOT higher. That the file reads this variable is certain; whether it
        # matters depends on the authorisation the route writes by hand, which
        # we are not reading. A route that filters correctly today is a route
        # with nothing behind it tomorrow, and that is worth saying -- at 0.7,
        # not at 0.95.
        confidence=0.7,
        category="Auth",
        file=path,
        line=line,
        explanation=(
            f"`{path}` is reachable over HTTP, and it reads `{env_name}` — the "
            f"Supabase key that bypasses every Row Level Security policy in "
            f"your project.\n\n"
            f"{bypassed}"
            f"Whatever stops one user reading another user's rows on this "
            f"route is the filtering written in this file, by hand, on every "
            f"query. Row Level Security is not a second line of defence here; "
            f"there is no second line. A missing `.eq('user_id', …)` on any "
            f"one query returns everyone's rows.\n\n"
            f"This is read from your repository, not from your database."
        ),
        fix_hint=(
            "Use the anon key with the caller's JWT for anything the user is "
            "entitled to see — then your policies do the work, and a forgotten "
            "filter fails closed instead of open:\n"
            "    createClient(url, ANON_KEY, { global: { headers: "
            "{ Authorization: req.headers.get('authorization') } } })\n"
            "Keep the service-role client for the operations that genuinely "
            "cross users, and build it inside those handlers only."
        ),
    )
