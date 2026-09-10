"""Trust boundary 2+3 combined: a request handler holding a service-role
key silently bypasses every RLS policy the owner relies on.

These tests pin the detector's contract, including its least obvious
requirement: factoring the admin client into a helper module -- what a tidy
codebase does -- must NOT make the finding disappear (the detector follows
the import one hop).
"""

from __future__ import annotations

from app.scan.service_role import scan_service_role

from .conftest import NEXTJS_PACKAGE, make_zip

SERVICE_ROUTE = """
import { createClient } from '@supabase/supabase-js'
export async function GET(req: Request) {
  const supabase = createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!
  )
  const { id } = await req.json()
  const { data } = await supabase.from('profiles').select().eq('id', id)
  return Response.json(data)
}
"""


def test_route_reading_service_role_key_is_flagged():
    found = scan_service_role(make_zip({
        "package.json": NEXTJS_PACKAGE,
        "app/api/profile/route.ts": SERVICE_ROUTE,
    }))
    assert [f.rule_id for f in found] == ["supabase-service-role-route"]
    assert found[0].category == "Auth"
    assert found[0].severity in ("high", "critical")
    assert found[0].file == "app/api/profile/route.ts"
    assert found[0].line > 0  # the finding names the statement, not just the file


def test_admin_client_one_import_away_is_still_flagged():
    """8 of 16 routes on a real repo reached the key through a helper --
    a factored-out admin client must not silence the rule."""
    found = scan_service_role(make_zip({
        "package.json": NEXTJS_PACKAGE,
        "src/lib/supabase-admin.ts": (
            "import { createClient } from '@supabase/supabase-js'\n"
            "export const admin = createClient("
            "process.env.NEXT_PUBLIC_SUPABASE_URL!, "
            "process.env.SUPABASE_SERVICE_ROLE_KEY!)\n"
        ),
        "app/api/admin/route.ts": (
            "import { admin } from '../../../src/lib/supabase-admin'\n"
            "export async function DELETE() { await admin.from('x').delete() }\n"
        ),
    }))
    assert [f.rule_id for f in found] == ["supabase-service-role-route"]


def test_anon_key_route_is_not_a_finding():
    found = scan_service_role(make_zip({
        "package.json": NEXTJS_PACKAGE,
        "app/api/profile/route.ts": SERVICE_ROUTE.replace(
            "SUPABASE_SERVICE_ROLE_KEY", "NEXT_PUBLIC_SUPABASE_ANON_KEY"
        ),
    }))
    assert found == []


def test_service_key_outside_any_route_is_not_this_finding():
    """A lib module holding the key with no route importing it is a
    different problem class (and a different rule's job), not this one."""
    found = scan_service_role(make_zip({
        "package.json": NEXTJS_PACKAGE,
        "src/lib/admin.ts": (
            "export const key = process.env.SUPABASE_SERVICE_ROLE_KEY\n"
        ),
    }))
    assert found == []


def test_rooted_and_rootless_archives_agree():
    """A hand-made zip has no wrapping folder; a GitHub export has one.
    The unconditional strip that confused the two once made every route
    invisible (see archive_root in app/scan/checks.py)."""
    flat = scan_service_role(make_zip({
        "package.json": NEXTJS_PACKAGE,
        "app/api/profile/route.ts": SERVICE_ROUTE,
    }))
    rooted = scan_service_role(make_zip({
        "my-app/package.json": NEXTJS_PACKAGE,
        "my-app/app/api/profile/route.ts": SERVICE_ROUTE,
    }))
    assert [f.rule_id for f in flat] == [f.rule_id for f in rooted]
