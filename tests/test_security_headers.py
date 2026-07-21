"""Tests for the global security-headers middleware and the per-route CSP
on the HTML audit report (Hermes MEDIUM finding 5)."""

import uuid

from fastapi.testclient import TestClient

from app.main import app, get_audit_repo

client = TestClient(app)


class FakeAuditRepo:
    """Minimal repo returning one row with a well-formed score_json so the
    report route renders. Mirrors the DI pattern in test_persistence_wiring."""

    def __init__(self, row):
        self.row = row

    async def get_authorized(self, audit_id, access_token):
        if audit_id != self.row["id"] or access_token != self.row["access_token"]:
            return None
        return {k: v for k, v in self.row.items() if k != "access_token"}


def test_json_response_carries_baseline_security_headers():
    resp = client.get("/healthz")
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
    assert "max-age=63072000" in resp.headers["Strict-Transport-Security"]
    assert resp.headers["Referrer-Policy"] == "no-referrer"


def test_json_response_has_no_report_csp():
    # CSP is scoped to the HTML report only, so JSON endpoints (and /docs)
    # never carry it.
    resp = client.get("/healthz")
    assert "Content-Security-Policy" not in resp.headers


def test_report_carries_tight_csp_and_baseline_headers():
    audit_id = str(uuid.uuid4())
    row = {
        "id": audit_id,
        "access_token": "tok",
        "score_json": {
            "total": 6.4,
            "categories": {"Security": 5.0, "Auth": 10.0},
        },
        "findings_json": [],
    }
    app.dependency_overrides[get_audit_repo] = lambda: FakeAuditRepo(row)
    try:
        resp = client.get(f"/v1/audits/{audit_id}/report?token=tok")
    finally:
        app.dependency_overrides.pop(get_audit_repo, None)

    assert resp.status_code == 200
    csp = resp.headers["Content-Security-Policy"]
    assert "default-src 'none'" in csp
    assert "style-src 'unsafe-inline'" in csp
    assert "frame-ancestors 'none'" in csp
    # Baseline headers still apply on the report too.
    assert resp.headers["X-Content-Type-Options"] == "nosniff"
    assert resp.headers["X-Frame-Options"] == "DENY"
