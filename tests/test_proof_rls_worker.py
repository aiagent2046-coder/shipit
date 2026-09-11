"""Exercise the actual worker process without contacting a cloud project."""
from __future__ import annotations

import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from app.proof import rls_probe as probe

KEY = "synthetic-public-key-private-pipe-only"
PUBLISHABLE_KEY = "sb_publishable_syntheticWorkerTestKey_12345678"


@pytest.fixture
def loopback_server(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    responses = {"status": 200, "body": b"[]", "headers": {}}
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            self.send_response(responses["status"])
            for key, value in responses["headers"].items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(responses["body"])

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", responses, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def run(base, *, anon_key=KEY, **kwargs):
    return probe.run_rls_probe(
        project_url=base, anon_key=anon_key, table="users", consent=True,
        allow_loopback=True, **kwargs,
    )


@pytest.mark.parametrize("key", [KEY, PUBLISHABLE_KEY])
def test_shipping_worker_reads_rows_and_returns_only_sanitized_verdict(
    loopback_server, monkeypatch, key,
):
    base, response, requests = loopback_server
    value = "synthetic-private-database-value"
    response["body"] = json.dumps([{"email": value}]).encode()
    outputs = []
    commands = []
    real_popen = subprocess.Popen

    class ObservedProcess(real_popen):
        def __init__(self, args, **kwargs):
            commands.append(args)
            super().__init__(args, **kwargs)

        def communicate(self, *args, **kwargs):
            output = super().communicate(*args, **kwargs)
            outputs.append(output[0])
            return output

    monkeypatch.setattr(probe.subprocess, "Popen", ObservedProcess)
    result = run(base, anon_key=key)
    assert result.status == "success"
    assert result.evidence["rows_read"] == 1
    assert result.evidence["columns"] == ["email"]
    assert key not in repr(result)
    assert value not in repr(result)
    assert key not in repr(commands)
    assert key.encode() not in b"".join(outputs)
    assert value.encode() not in b"".join(outputs)
    assert requests[0][0] == "/rest/v1/users?select=%2A&limit=3"
    headers = {name.lower(): value for name, value in requests[0][1].items()}
    assert headers["apikey"] == key
    if key == PUBLISHABLE_KEY:
        assert "authorization" not in headers
    else:
        assert headers["authorization"] == f"Bearer {key}"


@pytest.mark.parametrize(("status", "body", "headers", "reason"), [
    (403, b'{"code":"42501","message":"synthetic-private-error"}', {}, "permission_denied"),
    (200, b"synthetic-private-error", {}, "invalid_response"),
    (200, b"not read", {"content-encoding": "gzip"}, "unsupported_encoding"),
    (200, b"not read", {"content-length": str(probe.MAX_RESPONSE_BYTES + 1)}, "response_too_large"),
])
def test_shipping_worker_delivers_controlled_results(
    loopback_server, status, body, headers, reason,
):
    base, response, _ = loopback_server
    response.update(status=status, body=body, headers=headers)
    result = run(base)
    assert result.evidence["reason"] == reason
    assert result.status == ("failure" if reason == "permission_denied" else "error")
    assert "synthetic-private-error" not in repr(result)


def test_deadline_kills_and_reaps_worker_that_is_already_resolving_dns(
    tmp_path, monkeypatch,
):
    # Only this child environment installs a slow system resolver. Recording
    # its PID proves the deadline reached DNS, rather than merely slow imports.
    marker = tmp_path / "dns-started"
    completed = tmp_path / "dns-completed"
    startup = tmp_path / "sitecustomize.py"
    startup.write_text(
        "import os, socket, time\n"
        "from pathlib import Path\n"
        "def slow_dns(*args, **kwargs):\n"
        f"    Path({str(marker)!r}).write_text(str(os.getpid()))\n"
        "    time.sleep(10)\n"
        f"    Path({str(completed)!r}).write_text('completed')\n"
        "    raise socket.gaierror('synthetic slow DNS failure')\n"
        "socket.getaddrinfo = slow_dns\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    monkeypatch.setenv("NO_PROXY", "*")
    monkeypatch.setenv("no_proxy", "*")
    started = time.monotonic()
    result = probe.run_rls_probe(
        project_url="https://abcdefghijklmnopqrst.supabase.co",
        anon_key=KEY, table="users", consent=True, timeout_s=2,
    )
    elapsed = time.monotonic() - started
    assert marker.exists(), "worker must enter real HTTP client's DNS resolution"
    assert result.evidence["reason"] == "request_timeout"
    assert result.status == "error"
    assert elapsed < 5, "parent must not wait for resolver's 10-second sleep"
    assert not completed.exists()
    pid = int(marker.read_text())
    with pytest.raises(ChildProcessError):
        os.waitpid(pid, os.WNOHANG)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_worker_startup_is_charged_to_the_same_deadline(tmp_path, monkeypatch):
    marker = tmp_path / "startup-started"
    (tmp_path / "sitecustomize.py").write_text(
        "import os, time\n"
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text(str(os.getpid()))\n"
        "time.sleep(10)\n"
    )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    result = run("http://127.0.0.1:54321", timeout_s=1)
    assert result.evidence["reason"] == "request_timeout"
    assert marker.exists()
    with pytest.raises(ChildProcessError):
        os.waitpid(int(marker.read_text()), os.WNOHANG)
