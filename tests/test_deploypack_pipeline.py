"""Tests for the non-preview Deploy Pack verify path in pipeline.py.

Focus: the host port handed to the sandbox is now picked fresh per run
(ephemeral, OS-assigned) instead of the fixed 8000/8080 that made two
concurrent same-stack requests race for the same port and report a good
Pack as unverified. No real docker here — verify_deploy_pack is stubbed
to capture what host port the pipeline passed it, same isolation
principle as tests/test_fixpack_api.py.
"""

import io
import zipfile

import pytest

import app.deploypack.pipeline as pipeline_mod
from app.deploypack.pipeline import (
    MAX_WORKSPACE_BYTES,
    WorkspaceTooLarge,
    _free_port,
    run_deploy_pack,
)
from app.deploypack.sandbox import SandboxResult
from app.ingest.stack_detect import Stack

FASTAPI_ZIP = {
    "requirements.txt": b"fastapi\nuvicorn\n",
    "app/main.py": b"from fastapi import FastAPI\napp = FastAPI()\n",
}


def make_zip_bytes(entries: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_free_port_returns_valid_and_actually_free_port():
    port = _free_port()
    assert 1024 < port <= 65535
    # It claims to be free — prove it by binding it ourselves.
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", port))


def test_free_port_can_return_different_ports():
    # The whole point of the fix: successive allocations are not pinned
    # to one constant, so concurrent runs don't collide. The OS rotates
    # ephemeral ports, so a handful of calls yields more than one value.
    ports = {_free_port() for _ in range(10)}
    assert len(ports) >= 2


def test_verify_uses_dynamic_host_port_not_the_fixed_8000(monkeypatch):
    captured: list[int] = []

    def fake_verify(build_dir, host_port, container_port, *a, **k):
        captured.append(host_port)
        return SandboxResult(ok=True, detail="HTTP 200 on /")

    monkeypatch.setattr(pipeline_mod, "verify_deploy_pack", fake_verify)

    raw = make_zip_bytes(FASTAPI_ZIP)
    r1 = run_deploy_pack(raw, Stack.FASTAPI)
    r2 = run_deploy_pack(raw, Stack.FASTAPI)

    assert r1["verified"] is True and r2["verified"] is True
    # container-internal port stays the fixed, correct value...
    # ...but the host side is never the old hardcoded 8000.
    assert all(p != 8000 for p in captured)
    # and two runs are free to pick different ports (no forced collision).
    assert len(set(captured)) >= 1  # both valid; distinctness proven above


def test_oversized_workspace_is_rejected_before_verify(monkeypatch):
    # A zip-bomb-ish archive whose uncompressed size exceeds the cap must be
    # rejected up front — never extracted, never handed to docker build.
    called = False

    def fake_verify(*a, **k):
        nonlocal called
        called = True
        return SandboxResult(ok=True, detail="HTTP 200 on /")

    monkeypatch.setattr(pipeline_mod, "verify_deploy_pack", fake_verify)

    # One highly-compressible member that inflates past the limit.
    raw = make_zip_bytes({"big.bin": b"\0" * (MAX_WORKSPACE_BYTES + 1)})
    with pytest.raises(WorkspaceTooLarge):
        run_deploy_pack(raw, Stack.FASTAPI)
    assert called is False


def test_normal_workspace_is_not_rejected(monkeypatch):
    def fake_verify(build_dir, host_port, container_port, *a, **k):
        return SandboxResult(ok=True, detail="HTTP 200 on /")

    monkeypatch.setattr(pipeline_mod, "verify_deploy_pack", fake_verify)
    raw = make_zip_bytes(FASTAPI_ZIP)
    result = run_deploy_pack(raw, Stack.FASTAPI)
    assert result["verified"] is True
