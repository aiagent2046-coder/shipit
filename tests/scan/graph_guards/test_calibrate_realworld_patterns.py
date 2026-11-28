from __future__ import annotations

import io
import zipfile

from app.scan.detectors_app.graph_guards.bypass_detector import _collect_parsed_python_files
from app.scan.detectors_app.graph_guards.ts_bypass_detector import (
    _collect_parsed_ts_files,
    scan_ts_guard_bypass,
)
from app.scan.detectors_app.graph_guards.ts_call_summaries import build_ts_repository_summaries


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    buf.seek(0)
    return buf


def test_supabase_error_alias_disjunction_and_cross_module_returns_guard_discharge_sinks() -> None:
    archive = _make_zip({
        "lib/supabase-server.ts": '''
import { createServerClient } from "@supabase/ssr";

export async function getServerUser() {
  const supabase = createServerClient(url, anonKey, opts);
  const { data: { user } } = await supabase.auth.getUser();
  return user;
}
''',
        "app/api/avatar/identity/route.ts": '''
import { NextRequest, NextResponse } from "next/server";
import { createClient } from "@supabase/supabase-js";

export async function POST(req: NextRequest) {
  const supabase = createClient(url, key);
  const { data: { user }, error: userErr } = await supabase.auth.getUser(token);
  if (userErr || !user) return NextResponse.json({ error: "Invalid token" }, { status: 401 });
  await supabase.from("founder_profiles").update({ name: "Ada" }).eq("user_id", user.id);
  return NextResponse.json({ ok: true });
}
''',
        "app/api/github/connection/route.ts": '''
import { NextResponse } from "next/server";
import { getServerUser } from "@/lib/supabase-server";

export async function DELETE() {
  const user = await getServerUser();
  if (!user) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  await admin().from("github_connections").delete().eq("user_id", user.id);
  return NextResponse.json({ ok: true });
}
''',
        "app/api/auth/telegram/route.ts": '''
import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

function verifyInitData(initData: string):
  | { ok: true; user: any }
  | { ok: false; reason: string } {
  const computed = crypto.createHmac("sha256", secretKey).update(initData).digest("hex");
  if (computed !== hash) return { ok: false, reason: "bad hash" };
  return { ok: true, user: { id: 1 } };
}

export async function POST(req: NextRequest) {
  const v = verifyInitData(initData);
  if (!v.ok) return NextResponse.json({ error: "invalid" }, { status: 401 });
  await admin.from("founder_profiles").update({ telegram_id: 1 }).eq("user_id", uid);
  return NextResponse.json({ ok: true });
}
''',
    })
    parsed = _collect_parsed_ts_files(archive)
    idx = build_ts_repository_summaries(parsed)
    assert "authz" in idx.summaries["lib/supabase-server.ts:getServerUser"].returns_guard
    assert "signature" in idx.summaries["app/api/auth/telegram/route.ts:verifyInitData"].returns_guard
    unguarded = [s.qual_id for s in idx.summaries.values() if s.unguarded_sinks]
    assert unguarded == []
    archive.seek(0)
    assert scan_ts_guard_bypass(archive) == []


def test_conjunctive_route_prefix_filter_does_not_claim_global_must_guard() -> None:
    archive = _make_zip({
        "proxy.ts": '''
import { NextResponse } from "next/server";

export async function proxy(request: any) {
  const { data: { user } } = await supabase.auth.getUser();
  const p = request.nextUrl.pathname;
  if (!user && (p.startsWith("/app") || p.startsWith("/onboarding"))) {
    return NextResponse.redirect("/login");
  }
  return NextResponse.next();
}
''',
    })
    idx = build_ts_repository_summaries(_collect_parsed_ts_files(archive))
    assert idx.summaries["proxy.ts:proxy"].must_guards == frozenset()


def test_alembic_migrations_and_client_tsx_components_excluded_from_delegated_sinks() -> None:
    archive = _make_zip({
        "backend/app/alembic/versions/001_init.py": '''
from alembic import op

def downgrade() -> None:
    op.drop_table("item")
''',
        "frontend/src/components/Admin/DeleteUser.tsx": '''
export function DeleteUser() {
  const onDelete = async () => {
    await UsersService.deleteUser({ id: "1" });
  };
  return null;
}
''',
    })
    py_parsed = _collect_parsed_python_files(archive)
    assert py_parsed == []
    archive.seek(0)
    ts_idx = build_ts_repository_summaries(_collect_parsed_ts_files(archive))
    assert [s.qual_id for s in ts_idx.summaries.values() if s.unguarded_sinks] == []
