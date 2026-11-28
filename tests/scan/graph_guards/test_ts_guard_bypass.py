from __future__ import annotations

import io
import zipfile

from app.scan.detectors_app.graph_guards import TS_RULE_ID, scan_ts_guard_bypass
from app.scan.reporting.conformal.nonconformity import finding_nonconformity


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    buf.seek(0)
    return buf


def test_express_two_statement_403_return_dominates_cleanly_when_unconditional() -> None:
    archive = _make_zip({
        "src/routes/orders.ts": '''
import { Router } from "express";
const router = Router();

router.delete("/orders/:id", async (req, res) => {
  if (req.user.role !== "admin") {
    res.status(403).json({ error: "Forbidden" });
    return;
  }
  await prisma.order.delete({ where: { id: req.params.id } });
  res.json({ ok: true });
});
''',
    })
    assert scan_ts_guard_bypass(archive) == []


def test_express_route_catches_catch_block_fallthrough_and_computes_cut() -> None:
    archive = _make_zip({
        "src/routes/refunds.ts": '''
import { Router } from "express";
const router = Router();

router.post("/refunds", async (req, res) => {
  try {
    await requireAdmin(req);
  } catch (err) {
    console.warn("auth check failed, continuing for legacy client", err);
  }
  await stripe.refunds.create({ charge: req.body.chargeId });
  res.json({ refunded: true });
});
''',
    })
    hits = scan_ts_guard_bypass(archive)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == TS_RULE_ID
    assert hit.claim_evidence["language"] == "typescript"
    assert hit.claim_evidence["sink"] == "stripe.refunds.create"
    assert hit.claim_evidence["optimal_cut_lines"]
    assert finding_nonconformity(hit) <= 0.10


def test_supabase_destructured_get_user_partial_bypass_is_caught() -> None:
    archive = _make_zip({
        "src/app/api/accounts/route.ts": '''
import { NextResponse } from "next/server";

export async function POST(req: Request) {
  const body = await req.json();
  if (body.mode === "strict") {
    const { data: { user }, error } = await supabase.auth.getUser();
    if (error || !user) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
  }
  await supabase.from("accounts").delete().eq("id", body.accountId);
  return NextResponse.json({ ok: true });
}
''',
    })
    hits = scan_ts_guard_bypass(archive)
    assert len(hits) == 1
    assert hits[0].line == 12


def test_custom_file_local_throwing_helper_is_inferred_as_must_guard() -> None:
    archive = _make_zip({
        "src/actions/workspace.ts": '''
"use server";

async function enforceWorkspaceOwner(user: any, workspace: any) {
  if (workspace.ownerId !== user.id) {
    throw new Error("Forbidden");
  }
}

export async function removeWorkspace(user: any, workspace: any, skipCheck: boolean) {
  if (!skipCheck) {
    await enforceWorkspaceOwner(user, workspace);
  }
  await db.delete(workspaces);
}
''',
    })
    hits = scan_ts_guard_bypass(archive)
    assert len(hits) == 1
    assert hits[0].claim_evidence["function"] == "removeWorkspace"
