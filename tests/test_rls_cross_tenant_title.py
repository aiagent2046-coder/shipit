"""RLS on with an open policy is not the same finding as RLS off.

Both leave a table readable by the anonymous key, and until now the customer
read one sentence for both. They are different mistakes with different fixes:
no RLS at all is one ALTER TABLE away; a permissive policy under RLS is a
policy that scopes to "any logged-in user" instead of the owner -- the
cross-tenant shape, measured at one committed read policy in ten -- and the
fix is rewriting the USING clause. The title and explanation now say which
one it is, read structurally off the table rather than parsed out of `why`.
"""

from __future__ import annotations

import io
import zipfile

from app.scan.rls import scan_rls


def _zip(sql: str) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("supabase/migrations/0001_init.sql", sql)
    buf.seek(0)
    return buf


PRIVATE = ("create table public.profiles (id uuid primary key, "
           "user_id uuid references auth.users(id), email text, phone text);\n")


def _read_findings(findings):
    return [f for f in findings if f.rule_id != "rls-table-anon-writable"]


def test_rls_on_with_an_open_policy_is_named_as_cross_tenant():
    findings = scan_rls(_zip(
        PRIVATE
        + "alter table public.profiles enable row level security;\n"
        + "create policy p on public.profiles for select using (true);\n"))
    read = _read_findings(findings)

    assert read, "the permissive policy must still be a finding"
    f = read[0]
    assert "despite Row Level Security" in f.title
    assert "cross-tenant" in f.explanation
    # The old sentence must not survive for this shape: it read as "no RLS".
    assert "readable with your public key" not in f.title


def test_no_rls_at_all_keeps_the_original_wording():
    findings = scan_rls(_zip(PRIVATE))
    read = _read_findings(findings)

    assert read
    assert "readable with your public key" in read[0].title
    assert "despite" not in read[0].title
