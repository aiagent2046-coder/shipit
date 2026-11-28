from __future__ import annotations

import io
import zipfile

from app.scan.detectors_app.graph_guards import (
    TS_RULE_ID,
    TS_TAINT_RULE_ID,
    scan_ts_guard_bypass,
    scan_ts_interproc_taint,
)
from app.scan.reporting.conformal.nonconformity import finding_nonconformity


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    buf.seek(0)
    return buf


def test_cross_module_ts_must_guard_and_delegated_sink_detect_bypass() -> None:
    archive = _make_zip({
        "src/lib/permissions.ts": '''
import { NextResponse } from "next/server";
import { getServerSession } from "next-auth";

export async function enforceTenantAdmin() {
  const session = await getServerSession();
  if (!session?.user) {
    throw new Error("Unauthorized");
  }
  return session.user;
}
''',
        "src/services/billing.ts": '''
import { stripe } from "@/lib/stripe";

export async function executeRefundPayout(paymentIntentId: string) {
  return await stripe.refunds.create({ payment_intent: paymentIntentId });
}
''',
        "src/app/api/refunds/route.ts": '''
import { NextResponse } from "next/server";
import { enforceTenantAdmin } from "@/lib/permissions";
import { executeRefundPayout } from "@/services/billing";

export async function POST(req: Request) {
  const { pi, internalFastTrack } = await req.json();
  if (!internalFastTrack) {
    await enforceTenantAdmin();
  }
  await executeRefundPayout(pi);
  return NextResponse.json({ ok: true });
}
''',
    })
    hits = scan_ts_guard_bypass(archive)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == TS_RULE_ID
    assert hit.file == "src/app/api/refunds/route.ts"
    assert hit.claim_evidence["delegated_callee_chain"] == ["executeRefundPayout"]


def test_cross_module_delegated_sink_already_guarded_in_service_is_discharged() -> None:
    archive = _make_zip({
        "src/services/billing.ts": '''
import { getServerSession } from "next-auth";
import { stripe } from "@/lib/stripe";

export async function executeRefundPayout(paymentIntentId: string) {
  const session = await getServerSession();
  if (!session?.user) {
    throw new Error("Unauthorized");
  }
  return await stripe.refunds.create({ payment_intent: paymentIntentId });
}
''',
        "src/app/api/refunds/route.ts": '''
import { NextResponse } from "next/server";
import { executeRefundPayout } from "@/services/billing";

export async function POST(req: Request) {
  const { pi, verbose } = await req.json();
  if (verbose) {
    await requireAdmin(req);
  }
  await executeRefundPayout(pi);
  return NextResponse.json({ ok: true });
}
''',
    })
    assert scan_ts_guard_bypass(archive) == []


def test_three_hop_express_alias_taint_flow_and_crc_bonus() -> None:
    archive = _make_zip({
        "src/http/parsers.ts": '''
export function extractFilterClause(req: any): string {
  return req.query.whereClause;
}
''',
        "src/services/analytics.ts": '''
import { runRawAnalyticsQuery } from "@/db/analyticsRepo";

export async function buildTenantReport(db: any, filterSql: string) {
  return await runRawAnalyticsQuery(db, filterSql);
}
''',
        "src/db/analyticsRepo.ts": '''
export async function runRawAnalyticsQuery(db: any, clause: string) {
  return await db.query(`SELECT count(*) FROM events WHERE ${clause}`);
}
''',
        "src/routes/analytics.ts": '''
import { Router } from "express";
import { extractFilterClause } from "../http/parsers";
import { buildTenantReport } from "@/services/analytics";

const router = Router();

router.get("/analytics", async (req, res) => {
  const clause = extractFilterClause(req);
  const rows = await buildTenantReport(db, clause);
  res.json({ rows });
});
''',
    })
    hits = scan_ts_interproc_taint(archive)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == TS_TAINT_RULE_ID
    assert hit.file == "src/db/analyticsRepo.ts"
    assert hit.claim_evidence["call_chain"] == [
        "GET /analytics",
        "extractFilterClause",
        "buildTenantReport",
        "runRawAnalyticsQuery",
    ]
    assert hit.claim_evidence["hop_count"] == 3
    assert finding_nonconformity(hit) < 0.10
