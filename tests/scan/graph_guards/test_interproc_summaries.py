from __future__ import annotations

import io
import zipfile

from app.scan.detectors_app.graph_guards.bypass_detector import scan_guard_bypass
from app.scan.detectors_app.graph_guards.call_summaries import tarjan_scc
from app.scan.detectors_app.graph_guards.interproc_taint import scan_interproc_taint
from app.scan.reporting.conformal.nonconformity import finding_nonconformity


def _make_zip(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, body in files.items():
            zf.writestr(path, body)
    buf.seek(0)
    return buf


def test_tarjan_scc_handles_mutual_recursion_and_topological_order() -> None:
    adj = {
        "route": {"svc_a"},
        "svc_a": {"svc_b", "leaf_guard"},
        "svc_b": {"svc_a"},
        "leaf_guard": set(),
    }
    sccs = tarjan_scc(adj.keys(), adj)
    flat = [n for comp in sccs for n in comp]
    assert flat.index("leaf_guard") < flat.index("svc_a")
    assert flat.index("svc_a") < flat.index("route")
    assert {"svc_a", "svc_b"} in [set(c) for c in sccs]


def test_interproc_custom_must_guard_and_delegated_sink_detects_bypass() -> None:
    archive = _make_zip({
        "app/security/policies.py": '''
def _enforce_org_member(user, org):
    if user.org_id != org.id:
        raise PermissionError("forbidden")
    return True
''',
        "app/services/billing.py": '''
def perform_payout_action(repo, order_id: str):
    return repo.issue_refund(order_id)
''',
        "app/routes/refunds.py": '''
from app.security.policies import _enforce_org_member
from app.services.billing import perform_payout_action

def refund_endpoint(user, org, repo, order_id: str, fast_track: bool):
    if not fast_track:
        _enforce_org_member(user, org)
    return perform_payout_action(repo, order_id)
''',
    })
    hits = scan_guard_bypass(archive)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.file == "app/routes/refunds.py"
    assert hit.claim_evidence["delegated_callee_chain"] == ["perform_payout_action"]


def test_delegated_sink_already_guarded_inside_callee_is_discharged_cleanly() -> None:
    archive = _make_zip({
        "app/services/billing.py": '''
def perform_payout_action(user, org, repo, order_id: str):
    if user.org_id != org.id:
        raise PermissionError("denied")
    return repo.issue_refund(order_id)
''',
        "app/routes/refunds.py": '''
from app.services.billing import perform_payout_action

def refund_endpoint(user, org, repo, order_id: str, audit_log: bool):
    if audit_log:
        require_admin(user)
    return perform_payout_action(user, org, repo, order_id)
''',
    })
    assert scan_guard_bypass(archive) == []


def test_boolean_helper_without_raise_is_not_treated_as_standalone_guard() -> None:
    archive = _make_zip({
        "app/security/helpers.py": '''
def _org_matches_quietly(user, org) -> bool:
    return user.org_id == org.id
''',
        "app/routes/projects.py": '''
from app.security.helpers import _org_matches_quietly

def remove_project(user, org, repo, legacy: bool):
    if legacy:
        _org_matches_quietly(user, org)
    else:
        require_admin(user)
    return repo.delete_project(org.id)
''',
    })
    hits = scan_guard_bypass(archive)
    assert len(hits) == 1
    assert hits[0].file == "app/routes/projects.py"


def test_interproc_taint_detects_three_hop_cross_file_flow_and_grants_crc_bonus() -> None:
    archive = _make_zip({
        "app/http/extractors.py": '''
def read_filter_expr(request):
    return request.query_params.get("where_clause").strip()
''',
        "app/services/reporting.py": '''
from app.db.runner import execute_raw_report

def generate_report(db, filter_sql: str):
    return execute_raw_report(db, filter_sql)
''',
        "app/db/runner.py": '''
def execute_raw_report(db, clause: str):
    query = f"SELECT * FROM invoices WHERE {clause}"
    return db.execute(query)
''',
        "app/routes/invoices.py": '''
from fastapi import APIRouter, Request
from app.http.extractors import read_filter_expr
from app.services.reporting import generate_report

router = APIRouter()

@router.get("/invoices")
def list_invoices(request: Request, db):
    expr = read_filter_expr(request)
    return generate_report(db, expr)
''',
    })
    hits = scan_interproc_taint(archive)
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == "python-interprocedural-taint-flow"
    assert hit.file == "app/db/runner.py"
    assert hit.claim_evidence["call_chain"] == [
        "list_invoices",
        "read_filter_expr",
        "generate_report",
        "execute_raw_report",
    ]
    assert hit.claim_evidence["hop_count"] == 3
    assert finding_nonconformity(hit) < 0.10
