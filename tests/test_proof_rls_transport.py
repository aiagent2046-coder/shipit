"""Exercise the shipping streaming client over a synthetic HTTP transport.

No project credentials, DNS, or live database are used. Timeout tests cancel a
slow stream and check its cleanup, rather than merely faking a TimeoutError.
"""
from __future__ import annotations

import asyncio
import gzip
import json

import httpx
import pytest

from app.proof import rls_probe as probe

PROJECT = "https://abcdefghijklmnopqrst.supabase.co"
KEY = "synthetic-public-test-key"


class Stream(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0):
        self.chunks = chunks
        self.delay = delay
        self.closed = False
        self.yielded = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            self.yielded += 1
            yield chunk

    async def aclose(self):
        self.closed = True


def use_response(monkeypatch, stream, *, status=200, headers=None):
    requests = []

    async def handle(request):
        requests.append(request)
        return httpx.Response(status, headers=headers, stream=stream)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(
        **kw, transport=httpx.MockTransport(handle), trust_env=False))
    return requests


def run(**kwargs):
    return probe.run_rls_probe(
        project_url=PROJECT, anon_key=KEY, table="users", consent=True, **kwargs)


def test_actual_client_sends_read_only_bounded_request_and_sanitizes_rows(monkeypatch):
    value = "synthetic-private-row-value"
    stream = Stream([json.dumps([{"email": value}]).encode()])
    requests = use_response(monkeypatch, stream)
    result = run(limit=500)
    assert result.status == "success"
    assert result.evidence["rows_read"] == 1
    assert value not in repr(result)
    assert KEY not in repr(result)
    assert stream.closed
    assert len(requests) == 1
    request = requests[0]
    assert request.method == "GET"
    assert request.url == f"{PROJECT}/rest/v1/users?select=%2A&limit=3"
    assert request.headers["apikey"] == KEY
    assert request.headers["Authorization"] == f"Bearer {KEY}"
    assert request.headers["Accept-Encoding"] == "identity"


@pytest.mark.parametrize("headers", [None, {"content-length": "2"}])
def test_stream_size_limit_does_not_trust_content_length(monkeypatch, headers):
    stream = Stream([b" " * 4096] * (probe.MAX_RESPONSE_BYTES // 4096 + 10))
    use_response(monkeypatch, stream, headers=headers)
    result = run()
    assert result.status == "error"
    assert result.evidence["reason"] == "response_too_large"
    assert stream.closed
    assert stream.yielded == probe.MAX_RESPONSE_BYTES // 4096 + 1


def test_oversized_declared_length_is_rejected_before_body_is_read(monkeypatch):
    stream = Stream([b"not read"])
    use_response(monkeypatch, stream, headers={"content-length": str(probe.MAX_RESPONSE_BYTES + 1)})
    assert run().evidence["reason"] == "response_too_large"
    assert stream.yielded == 0
    assert stream.closed


def test_compressed_response_is_rejected_before_decompression(monkeypatch):
    stream = Stream([gzip.compress(b" " * (probe.MAX_RESPONSE_BYTES * 10))])
    use_response(monkeypatch, stream, headers={"content-encoding": "gzip"})
    assert run().evidence["reason"] == "unsupported_encoding"
    assert stream.yielded == 0
    assert stream.closed


@pytest.mark.parametrize("body", [
    b"<html>synthetic-private-error</html>",
    b"[null]", b'[{}, "synthetic-private-error"]', b"[{}, {}, {}, {}]",
    b"[" * 2000 + b"]" * 2000,
])
def test_malformed_or_excess_rows_are_inconclusive_and_never_leak(monkeypatch, body):
    stream = Stream([body])
    use_response(monkeypatch, stream)
    result = run()
    assert result.status == "error"
    assert result.evidence["reason"] == "invalid_response"
    assert "synthetic-private-error" not in repr(result)
    assert stream.closed


def test_small_valid_body_at_the_byte_limit_is_evaluated(monkeypatch):
    stream = Stream([b"[]" + b" " * (probe.MAX_RESPONSE_BYTES - 2)])
    use_response(monkeypatch, stream)
    result = run()
    assert result.status == "failure"
    assert result.evidence["alone_proves_nothing"] is True
    assert stream.closed


def test_redirect_is_not_followed_with_credentials(monkeypatch):
    stream = Stream([b"{}"])
    requests = use_response(monkeypatch, stream, status=302,
                            headers={"location": "http://169.254.169.254/"})
    result = run()
    assert len(requests) == 1
    assert result.status == "error"
    assert stream.closed


def test_slow_drip_is_cancelled_despite_regular_chunks(monkeypatch):
    stream = Stream([b" "] * 1000, delay=0.005)
    use_response(monkeypatch, stream)
    result = run(timeout_s=0.08)
    assert result.evidence["reason"] == "request_timeout"
    assert result.status == "error"
    assert stream.yielded < 1000
    assert stream.closed


def test_deadline_also_cancels_waiting_for_response_headers(monkeypatch):
    cancelled = []

    async def never_answers(request):
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.append(True)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(
        **kw, transport=httpx.MockTransport(never_answers), trust_env=False))
    assert run(timeout_s=0.02).evidence["reason"] == "request_timeout"
    assert cancelled == [True]


def test_transport_exception_never_exposes_a_key_or_error_text(monkeypatch):
    def fail(**kwargs):
        raise httpx.ConnectError(f"synthetic-private-error {KEY}")

    monkeypatch.setattr(httpx, "AsyncClient", fail)
    result = run()
    assert result.evidence["reason"] == "request_failed"
    assert KEY not in repr(result)
    assert "synthetic-private-error" not in repr(result)


def test_shared_budget_cancels_native_request_and_preserves_partial_run(monkeypatch):
    import base64
    import io
    import zipfile
    from app.proof import rls_live_check as live

    def segment(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    key = ".".join([
        segment({"alg": "HS256", "typ": "JWT"}),
        segment({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "anon"}),
        "syntheticSignatureForLocalTestOnly1234567890",
    ])
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("repo/.env", f"KEY={key}\n")
        zf.writestr("repo/src/db.ts", "".join(
            f"supabase.from('t{i}').select('*');" for i in range(3)))
    calls = []
    streams = []

    async def respond(request):
        calls.append(request)
        stream = Stream([b"[]"] if len(calls) == 1 else [b" "] * 1000, delay=0.005)
        streams.append(stream)
        return httpx.Response(200, stream=stream)

    real_client = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: real_client(
        **kw, transport=httpx.MockTransport(respond), trust_env=False))
    monkeypatch.setattr(live, "MAX_CHECK_SECONDS", 0.1)
    result = live.run_live_rls_check(archive.getvalue(), consent=True)
    assert len(calls) == 2
    assert result.checked == ["t0", "t1"]
    assert result.not_checked == ["t2"]
    assert result.empty_but_unproven == 1
    assert result.inconclusive == 1
    assert result.attempts[1].evidence["reason"] == "request_timeout"
    assert result.stop_reason == "time_budget_exceeded"
    assert all(stream.closed for stream in streams)
