"""Detect tables the anonymous Supabase key can read or write, from committed SQL.

Promoted out of scripts/measure_supabase_rls_yield.py, where the heuristics
below were refined over three measurement rounds against real repositories.
The script now imports them from here: production owns the classification and
the measurement tool follows it, so a number and a customer's report cannot
disagree about the same table.

WHAT THIS CAN AND CANNOT SEE, stated here because the finding's wording depends
on it. MEASURED 2026-08-18 against a real deployment: the committed migrations
did not describe it. Two tables this method called exposed were protected, and
the one table that WAS exposed had no migration at all — created through the
dashboard, so no amount of SQL reading could reach it.

So a finding from here says what the repository says, and nothing about the
database. That is worth reporting — it is free, it needs no credential, and it
is right often enough to be useful — but it is not "your data is exposed", and
the explanation the customer reads must not claim to be.

TWO RULES, NOT ONE. Reading and writing are different questions about the same
table and they disagree: a catalogue anyone can read is an API, a catalogue
anyone can rewrite is not a design. So the read rule carries a
public-by-design exclusion and the write rule deliberately carries none. Only
the read rule has a Fix Pack behind it — see _why_not_fixable in
app/fixpack/generate.py for what the customer is told about the other.

APPLICABILITY: only SQL in explicit supabase/migrations or supabase/schemas
trees, or supabase/schema.sql. Each Supabase directory is a separate schema
history. Generic SQL, PostgreSQL syntax, comments mentioning Supabase, and a
Supabase client elsewhere do not establish anonymous grants for a table.
Custom migration layouts and generic PostgREST deployments remain unresolved;
silence outside this bounded scope is not evidence of correct authorization.
"""

from __future__ import annotations

import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding, archive_root
from app.scan.sql_schema import Table, parse_schema

RULE_ID = "rls-table-anon-readable"
WRITE_RULE_ID = "rls-table-anon-writable"

PRIVATE_TABLE_NAMES = frozenset({
    "users", "user", "profiles", "profile", "accounts", "account",
    "customers", "clients", "members", "subscribers", "leads", "contacts",
    "orders", "payments", "invoices", "transactions", "subscriptions",
    "messages", "chats", "conversations", "notifications", "sessions",
    "bookings", "appointments", "applications", "submissions", "responses",
    "waitlist", "signups", "feedback", "tickets", "documents", "files",
    "api_keys", "tokens", "credentials", "secrets", "settings",
})

# Checked FIRST. A catalogue or a blog is an API, and reporting one is the
# `*`-without-credentials error in another costume.
PUBLIC_BY_DESIGN = frozenset({
    "posts", "post", "blog", "blogs", "articles", "products", "product",
    "categories", "tags", "pages", "faqs", "features", "plans", "pricing",
    "testimonials", "reviews", "events", "locations", "stores",
})

# STRONG: one of these means the row is about a person and carries something
# they would not publish.
STRONG_COLUMN_HINTS: tuple[str, ...] = (
    "email", "phone", "mobile", "address", "postcode", "zip_code",
    "password", "passwd", "salt",
    "token", "api_key", "secret", "credential",
    "stripe_", "customer_id", "payment", "card_last", "iban",
    "ssn", "tax_id", "passport", "birth", "dob",
    "ip_address",
    # Model-derived judgements ABOUT a person — added after reading a real
    # table holding summary / key_points / next_actions / sentiment, one row
    # per pair of matched users, RLS never enabled. In an AI product the most
    # sensitive rows are rarely the profile; they are what the model concluded
    # about someone, and a leaked `sentiment` toward another user is worse
    # than a leaked email address.
    "sentiment", "summary", "transcript", "analysis", "assessment",
    "key_points", "insight", "recommendation", "diagnosis", "evaluation",
)

# WEAK: ownership markers. NOT sufficient alone — nearly every table in a
# multi-tenant app carries user_id, public ones included. Treating it as strong
# flagged a founder-MATCHING app's deliberately public profiles, which is the
# expensive direction of error because it is the one that reaches a report.
WEAK_OWNERSHIP_HINTS: tuple[str, ...] = (
    "user_id", "owner_id", "auth_id", "profile_id",
)

# WEAK: free text, which may hold anything or nothing. It is the half that
# makes a foreign key into auth.users mean something.
WEAK_FREE_TEXT_HINTS: tuple[str, ...] = (
    "notes", "message", "content", "body", "text", "description",
    "user_agent", "hash",
)

WEAK_COLUMN_HINTS: tuple[str, ...] = WEAK_OWNERSHIP_HINTS + WEAK_FREE_TEXT_HINTS

_IDENTITY_TARGETS = frozenset({"auth.users"})

_SCHEMA_PATH_HINTS = ("supabase/migrations/", "supabase/schema", "migrations/",
                      "schema.sql", "db/", "database/", "sql/")


def private_shape(
    name: str, columns: list[str], references_auth_users: bool = False,
) -> tuple[str, str]:
    """(verdict, why) where verdict is "yes", "uncertain" or "no".

    Three states, because two forced a table carrying only `user_id` into one
    bucket or the other and both answers were wrong. Only "yes" becomes a
    finding; "uncertain" is for a human to look at, and this scanner does not
    report it — an unconfident finding in a customer's report is worse than no
    finding.
    """
    low = name.lower()
    singular = low[:-1] if low.endswith("s") else low
    if low in PUBLIC_BY_DESIGN or singular in PUBLIC_BY_DESIGN:
        return "no", f"`{name}` reads as public-by-design"
    if low in PRIVATE_TABLE_NAMES or singular in PRIVATE_TABLE_NAMES:
        return "yes", f"table name `{name}`"

    strong = next((c for c in columns
                   if any(h in c.lower() for h in STRONG_COLUMN_HINTS)), "")
    if strong:
        return "yes", f"column `{strong}`"

    # Structural rather than a name guess: a foreign key into auth.users says
    # the row belongs to one authenticated person, and with free text beside it
    # an anonymous read crosses tenants.
    if references_auth_users and any(
        any(h in c.lower() for h in WEAK_FREE_TEXT_HINTS) for c in columns
    ):
        return "yes", "rows key off auth.users and carry free text"

    weak = next((c for c in columns
                 if any(h in c.lower() for h in WEAK_COLUMN_HINTS)), "")
    if weak:
        return "uncertain", (f"only `{weak}`, which nearly every table in a "
                             f"multi-tenant app carries")
    return "no", "no private-looking table name or column"


def table_is_reported(table: Table) -> tuple[bool, str]:
    """Does this table become a finding, and on what grounds?"""
    verdict, why_private = private_shape(
        table.name, table.columns,
        any(k.target in _IDENTITY_TARGETS for k in table.foreign_keys),
    )
    if verdict != "yes":
        return False, why_private
    readable, why_readable = table.anon_can_read
    if not readable:
        return False, why_readable
    return True, f"{why_private}; {why_readable}"


def write_finding(table: Table, commands: frozenset[str], why: str,
                  path: str) -> CheckFinding:
    """The finding for a table the anonymous key can modify.

    NO PUBLIC-BY-DESIGN EXCLUSION HERE, and that is the difference from the
    read rule rather than an oversight. A catalogue being readable is an API;
    a catalogue anyone can rewrite is not a design, and the heuristics that
    decide whether DATA is private have nothing to say about it. So this rule
    does not guess at what the table holds, which is also why it can be more
    confident than its read counterpart.

    UPDATE and DELETE are separated from INSERT because they are different
    claims. Anonymous INSERT is a real pattern — a waitlist, a contact form,
    feedback — and calling it a hole would be noise. Anonymous UPDATE or
    DELETE means any visitor can rewrite or erase rows belonging to somebody
    else, and no application intends that.
    """
    destructive = sorted(commands & {"update", "delete"})
    if destructive:
        verbs = " and ".join(destructive).upper()
        return CheckFinding(
            rule_id=WRITE_RULE_ID,
            title=f"Potential anonymous {verbs} access to `{table.name}`",
            severity="critical",
            # Higher than the read rule's 0.6: that one has to guess whether
            # the data is private, and this one does not. Deployment state,
            # API exposure and effective grants still require verification.
            confidence=0.75,
            category="Security",
            file=path,
            explanation=(
                f"Committed Supabase SQL suggests that `anon` could {verbs} "
                f"rows in `{table.name}` ({why}). This requires the table to "
                f"be exposed through the API, the corresponding role grants "
                f"to apply, and the deployed schema to match these files. If "
                f"those conditions hold, other users' rows may be changed or "
                f"deleted.\n\n"
                f"We read this from your repository, NOT from your database. "
                f"API exposure, effective grants and actual access were not "
                f"checked; treat this as a candidate to verify."
            ),
            fix_hint=(
                f"Inspect the applied schema for `{table.name}`, API exposed "
                f"schemas, effective `anon` grants and RLS policies. Verify "
                f"access in a controlled test environment using disposable "
                f"representative rows owned by different test users; do not "
                f"probe writes against production rows. Check actual row "
                f"changes: an HTTP success or empty response does not prove "
                f"that a write was allowed. If access is unintended, revoke "
                f"unneeded grants or enable RLS with policies that preserve "
                f"legitimate application operations."
            ),
        )

    return CheckFinding(
        rule_id=WRITE_RULE_ID,
        title=f"Potential anonymous inserts into `{table.name}`",
        # Deliberately not critical. A waitlist or a contact form is SUPPOSED
        # to accept anonymous inserts, and the customer knows which of their
        # tables those are.
        severity="medium",
        confidence=0.6,
        category="Security",
        file=path,
        explanation=(
            f"Committed Supabase SQL suggests that `anon` could add rows to "
            f"`{table.name}` ({why}), if the API exposes this table, insert "
            f"grants apply, and the deployed schema matches. For a signup, "
            f"contact or feedback form, this may be the intended design. "
            f"Otherwise, unrestricted inserts may allow rows attributed to "
            f"other users.\n\n"
            f"Read from your repository, not from your database. API exposure, "
            f"effective grants, constraints and actual access were not checked."
        ),
        fix_hint=(
            "Inspect the applied schema, API exposure, effective `anon` grants "
            "and insert policies. Check accepted column values with disposable "
            "representative rows in a controlled test environment, not with "
            "production writes. If anonymous inserts are intended, scope "
            "`WITH CHECK` to permitted values and review rate limiting. "
            "Otherwise, remove the unneeded grant or policy and verify that "
            "legitimate application operations still work."
        ),
    )


def _migration_order(rel: str) -> tuple[str, str]:
    """Sort key: FILENAME first, full path second.

    parse_schema applies statements in the order it receives them, so the order
    files are concatenated in is the order the migrations are believed to have
    run. Supabase names migrations with a timestamp prefix, and that prefix —
    not the directory — is what encodes time.

    MEASURED: a real repository keeps 258 superseded migrations in
    `supabase/migrations/archive/` beside 50 live ones. By full path,
    `…/archive/20251022…` sorts AFTER `…/20260523…`, because "a" is greater
    than "2" — so the oldest migrations in the repository were applied last and
    the schema came out reading like 2025. Sorting on the basename puts them
    back in the order they were written, and the archive then does what an
    archive should: it is history, superseded by everything after it.

    The full path breaks ties so the order is total and a run is repeatable.
    """
    return (rel.rsplit("/", 1)[-1], rel)


# archive_root detects a common first segment, which is ambiguous for a
# rootless archive containing only one source directory. Never consume these
# conventional content roots as if they were a GitHub export wrapper.
_CONTENT_ROOTS = frozenset({
    "supabase", "migrations", "schema", "schemas", "db", "database", "sql",
    "app", "apps", "src", "source", "packages", "services", "examples",
    "example", "tests", "test", "fixtures", "docs", "scripts", "backend",
    "frontend", "server", "client", "lib", "public", "vendor", "node_modules",
})


def _committed_sql_files(fileobj: BinaryIO) -> list[tuple[str, str]]:
    """Preserve rootless paths; remove only an inferred export wrapper."""
    kept: list[tuple[str, str]] = []
    with zipfile.ZipFile(fileobj) as zf:
        root = archive_root(zf.namelist())
        if root.rstrip("/").lower() in _CONTENT_ROOTS:
            root = ""
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".sql"):
                continue
            rel = info.filename[len(root):] if root else info.filename
            if not any(h in rel.lower() for h in _SCHEMA_PATH_HINTS) \
                    and "/" in rel:
                continue
            kept.append((rel, zf.read(info).decode("utf-8", errors="replace")))
    kept.sort(key=lambda pair: _migration_order(pair[0]))
    return kept


def read_committed_sql(fileobj: BinaryIO) -> tuple[str, list[str]]:
    """All selected committed SQL in migration order, plus source paths.

    This shared reader intentionally includes generic schemas for Fix Pack
    and measurement callers. Only scan_rls applies the Supabase scope gate.
    """
    kept = _committed_sql_files(fileobj)
    return "\n".join(text for _, text in kept), [rel for rel, _ in kept]


def _supabase_scope(path: str) -> str | None:
    """A conventional Supabase SQL tree, never a repository-wide hint."""
    parts = path.split("/")
    for index in range(len(parts) - 2, -1, -1):
        if parts[index] != "supabase":
            continue
        relative = parts[index + 1:]
        if (len(relative) > 1 and relative[0] in {"migrations", "schemas"}) or relative == ["schema.sql"]:
            return "/".join(parts[:index + 1])
    return None


def scan_rls(fileobj: BinaryIO) -> list[CheckFinding]:
    """Findings for private-shaped tables the anon key can read.

    Silent when the repository commits no schema. That is NOT "secure" — it is
    undetermined — but a scanner that says so on every repo without migrations
    would be noise, and the honest place for that distinction is the live
    probe, which can actually answer it.
    """
    fileobj.seek(0)
    groups: dict[str, list[tuple[str, str]]] = {}
    for path, text in _committed_sql_files(fileobj):
        scope = _supabase_scope(path)
        if scope is not None:
            groups.setdefault(scope, []).append((path, text))

    findings: list[CheckFinding] = []
    for entries in groups.values():
        # Independent Supabase applications can use the same table names.
        # Their declarations and policy changes must never be concatenated.
        schema = parse_schema("\n".join(text for _, text in entries))
        paths: dict[str, str] = {}
        for path, text in entries:
            # A source containing an actual table declaration is an actionable
            # location; the first SQL in the archive may belong to another table.
            for name in parse_schema(text):
                paths.setdefault(name, path)
        findings.extend(_schema_findings(schema, paths))
    return findings


def _schema_findings(schema: dict[str, Table], paths: dict[str, str]) -> list[CheckFinding]:
    findings: list[CheckFinding] = []
    for name, table in schema.items():
        path = paths.get(name, "")
        commands, why_write = table.anon_can_write()
        if commands:
            findings.append(write_finding(table, commands, why_write, path))

    for name, table in schema.items():
        reported, why = table_is_reported(table)
        if not reported:
            continue
        # RLS ON yet anon still reads it means a policy opens the table to
        # everyone -- the cross-tenant shape, distinct from no RLS at all. The
        # cause is already in `why` ("permissive policy" vs "RLS never
        # enabled"), but the customer-facing text read the same for both, so a
        # policy that lets any logged-in user read every row looked identical
        # to a table with no protection. The measurement that split cross-tenant
        # policies (10% auth-only, 7% public-true) is the reason this now says
        # which one it is. Read structurally off the table, not by parsing
        # `why`, so the two never drift.
        cross_tenant = table.rls_enabled
        if cross_tenant:
            title = (f"Potential anonymous reads of `{table.name}` despite "
                     f"Row Level Security")
            explanation = (
                f"Committed Supabase SQL enables Row Level Security for "
                f"`{table.name}`, but contains a permissive read policy "
                f"({why}). If the API exposes this table, SELECT grants apply "
                f"and the deployed schema matches, `anon` could read rows "
                f"belonging to other users: a potential cross-tenant leak. "
                f"Other policies and deployment controls may change access.\n\n"
                f"We read this from your repository, NOT from your database. "
                f"API exposure, effective grants and actual access were not "
                f"checked; treat this as a candidate to verify."
            )
        else:
            title = (f"Potential anonymous reads of `{table.name}` without "
                     f"Row Level Security")
            explanation = (
                f"Committed Supabase SQL defines `{table.name}` without "
                f"observed Row Level Security ({why}). If the API exposes "
                f"this table, SELECT grants apply and the deployed schema "
                f"matches, `anon` could read private rows.\n\n"
                f"We read this from your repository, NOT from your database. "
                f"API exposure, effective grants and actual access were not "
                f"checked; treat this as a candidate to verify."
            )
        findings.append(CheckFinding(
            rule_id=RULE_ID,
            title=title,
            severity="high",
            # Deliberately not 0.9. MEASURED against a real deployment: of
            # three tables this method judged, it was wrong twice and silent
            # about the one that was actually open. The repository is evidence,
            # not the database, and the number has to say so.
            confidence=0.6,
            category="Security",
            file=paths.get(name, ""),
            explanation=explanation,
            fix_hint=(
                f"Inspect the applied schema for `{table.name}`, API exposed "
                f"schemas, effective `anon` SELECT grants and RLS policies. "
                f"In a controlled test environment, compare anonymous and "
                f"authenticated reads using known representative rows owned "
                f"by different test users. An empty result alone does not "
                f"prove access is denied. If unintended access is confirmed, "
                f"remove unneeded grants or scope policies to the owner. "
                f"Enabling RLS without a policy may also block legitimate "
                f"application access; verify those operations before rollout."
            ),
        ))
    return findings
