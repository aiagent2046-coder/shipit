"""Detect tables the anonymous Supabase key can read, from committed SQL.

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
"""

from __future__ import annotations

import zipfile
from typing import BinaryIO

from app.scan.checks import CheckFinding
from app.scan.sql_schema import Table, parse_schema

RULE_ID = "rls-table-anon-readable"

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


def read_committed_sql(fileobj: BinaryIO) -> tuple[str, list[str]]:
    """Concatenated .sql from the archive, plus the paths it came from."""
    paths: list[str] = []
    chunks: list[str] = []
    with zipfile.ZipFile(fileobj) as zf:
        for info in zf.infolist():
            if info.is_dir() or not info.filename.lower().endswith(".sql"):
                continue
            rel = info.filename.split("/", 1)[-1]
            if not any(h in rel.lower() for h in _SCHEMA_PATH_HINTS) \
                    and "/" in rel:
                continue
            paths.append(rel)
            chunks.append(zf.read(info).decode("utf-8", errors="replace"))
    return "\n".join(chunks), paths


def scan_rls(fileobj: BinaryIO) -> list[CheckFinding]:
    """Findings for private-shaped tables the anon key can read.

    Silent when the repository commits no schema. That is NOT "secure" — it is
    undetermined — but a scanner that says so on every repo without migrations
    would be noise, and the honest place for that distinction is the live
    probe, which can actually answer it.
    """
    fileobj.seek(0)
    sql, paths = read_committed_sql(fileobj)
    if not sql.strip():
        return []

    schema = parse_schema(sql)
    findings: list[CheckFinding] = []
    for table in schema.values():
        reported, why = table_is_reported(table)
        if not reported:
            continue
        findings.append(CheckFinding(
            rule_id=RULE_ID,
            title=f"Table `{table.name}` is readable with your public key",
            severity="high",
            # Deliberately not 0.9. MEASURED against a real deployment: of
            # three tables this method judged, it was wrong twice and silent
            # about the one that was actually open. The repository is evidence,
            # not the database, and the number has to say so.
            confidence=0.6,
            category="Security",
            file=paths[0] if paths else "",
            explanation=(
                f"Your migrations define `{table.name}` and leave it readable "
                f"by the anonymous key ({why}). That key ships to every "
                f"visitor's browser by design, so anyone who opens your site "
                f"can request the whole table.\n\n"
                f"We read this from your repository, NOT from your database — "
                f"the two often differ, so treat it as something to check "
                f"rather than something we observed."
            ),
            fix_hint=(
                f"Confirm it in one request against your own project:\n"
                f"    curl '<project-url>/rest/v1/{table.name}?select=*&limit=3' "
                f"-H 'apikey: <anon-key>'\n"
                f"Rows coming back means it is open. The fix is Row Level "
                f"Security with a policy scoped the way your other tables "
                f"already scope theirs — enabling RLS *without* a policy "
                f"closes the table to your application too."
            ),
        ))
    return findings
