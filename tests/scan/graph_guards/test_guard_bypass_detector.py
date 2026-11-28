"""Behavioral tests for intra-procedural Partial Guard Bypass detection."""

from __future__ import annotations

import io
import zipfile

from app.scan.detectors_app.graph_guards import RULE_ID, scan_guard_bypass


def _zip_py(files: dict[str, str]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, body in files.items():
            zf.writestr(name, body)
    buf.seek(0)
    return buf


def test_partial_webhook_signature_bypass_in_fallback_branch_is_caught() -> None:
    code = """
def handle_payment_webhook(payload: bytes, sig: str | None, legacy_mode: bool, db):
    if not legacy_mode:
        if not verify_signature(payload, sig):
            raise ValueError("bad signature")
        db.execute("UPDATE orders SET status = 'paid' WHERE id = 1")
        return {"ok": True}
    # Forgotten signature verification on legacy fallback path!
    db.execute("UPDATE orders SET status = 'paid' WHERE id = 1")
    return {"ok": True}
"""
    hits = scan_guard_bypass(_zip_py({"app/webhooks.py": code}))
    assert len(hits) == 1
    hit = hits[0]
    assert hit.rule_id == RULE_ID
    assert hit.file == "app/webhooks.py"
    assert hit.claim_evidence["guard_class"] == "signature"
    assert hit.claim_evidence["optimal_cut_lines"]


def test_exception_handler_fallthrough_bypassing_auth_guard_is_caught() -> None:
    code = """
def delete_project_endpoint(user, project_id: int, repo):
    try:
        if not check_admin(user):
            return {"error": "forbidden"}
    except RuntimeError:
        pass
    repo.delete_project(project_id)
"""
    hits = scan_guard_bypass(_zip_py({"app/routes.py": code}))
    assert len(hits) == 1
    assert hits[0].claim_evidence["guard_class"] == "authz"
    assert hits[0].claim_evidence["sink"] == "delete_project"


def test_fully_dominated_early_exit_guard_stays_silent() -> None:
    code = """
def refund_endpoint(user, order_id: int, service):
    if not verify_signature(order_id, user.token):
        raise PermissionError("denied")
    service.issue_refund(order_id)
"""
    assert scan_guard_bypass(_zip_py({"app/payments.py": code})) == []


def test_both_branches_guarded_independently_stays_silent() -> None:
    code = """
def remove_user_endpoint(actor, target_id: int, is_self: bool, repo):
    if is_self:
        if actor.account_id != target_id:
            raise PermissionError("not owner")
        repo.delete_user(target_id)
    else:
        require_admin(actor)
        repo.delete_user(target_id)
"""
    assert scan_guard_bypass(_zip_py({"app/users.py": code})) == []


def test_function_without_any_guard_intent_does_not_speculate() -> None:
    code = """
def internal_migration_helper(cur):
    cur.execute("DELETE FROM stale_sessions")
"""
    assert scan_guard_bypass(_zip_py({"app/tasks.py": code})) == []
