"""Tests for stack detection and the intake endpoint."""

import io
import json
import zipfile

from fastapi.testclient import TestClient

from app.ingest.stack_detect import Stack, detect_stack
from app.main import app

client = TestClient(app)


def make_zip(entries: dict[str, bytes]) -> io.BytesIO:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    buf.seek(0)
    return buf


NEXT_PKG = json.dumps({"dependencies": {"next": "15.0.0", "react": "19.0.0"}}).encode()


def test_detect_nextjs_by_dependency():
    buf = make_zip({"package.json": NEXT_PKG, "app/page.tsx": b"export default ..."})
    assert detect_stack(buf) is Stack.NEXTJS


def test_detect_nextjs_inside_export_root_folder():
    # Lovable/Bolt exports wrap the project in a single top-level folder.
    buf = make_zip({"my-app/package.json": NEXT_PKG, "my-app/next.config.mjs": b""})
    assert detect_stack(buf) is Stack.NEXTJS


def test_detect_fastapi():
    buf = make_zip({
        "requirements.txt": b"fastapi\nuvicorn\n",
        "app/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
    })
    assert detect_stack(buf) is Stack.FASTAPI


def test_python_without_fastapi_import_is_unsupported():
    buf = make_zip({
        "requirements.txt": b"flask\n",
        "app/main.py": b"from flask import Flask\n",
    })
    assert detect_stack(buf) is Stack.UNSUPPORTED


def test_unknown_project_is_unsupported():
    buf = make_zip({"index.html": b"<html></html>"})
    assert detect_stack(buf) is Stack.UNSUPPORTED


# --- API surface ---

def test_healthz():
    assert client.get("/healthz").json() == {"status": "ok"}


def test_audit_intake_accepts_nextjs_zip():
    buf = make_zip({"package.json": NEXT_PKG})
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["stack"] == "nextjs"
    assert body["file_count"] == 1
    # static scan is wired in: clean-ish project still gets presence findings
    assert "score" in body and 0 <= body["score"]["total"] <= 10
    assert any(f["rule_id"] == "no-tests" for f in body["findings"])


def test_audit_intake_rejects_traversal_zip_with_reason():
    buf = make_zip({"../../etc/evil": b"x"})
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "unsafe_path"


def test_audit_intake_rejects_unsupported_stack():
    buf = make_zip({"index.html": b"<html></html>"})
    resp = client.post(
        "/v1/audits", files={"archive": ("app.zip", buf, "application/zip")}
    )
    assert resp.status_code == 422
    assert resp.json()["detail"]["reason"] == "unsupported_stack"


def test_detect_vite_react_lovable_export():
    pkg = json.dumps({
        "dependencies": {"react": "18.3.1"},
        "devDependencies": {"vite": "5.4.1", "lovable-tagger": "1.0.0"},
    }).encode()
    buf = make_zip({"proj/package.json": pkg, "proj/vite.config.ts": b""})
    assert detect_stack(buf) is Stack.VITE_REACT


def test_next_takes_priority_over_vite():
    pkg = json.dumps({
        "dependencies": {"next": "15.0.0", "react": "19.0.0", "vite": "5.0.0"}
    }).encode()
    buf = make_zip({"package.json": pkg})
    assert detect_stack(buf) is Stack.NEXTJS
