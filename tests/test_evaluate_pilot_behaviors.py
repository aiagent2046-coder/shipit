"""Prove pilot mutations change behavior, without a database or network."""
from __future__ import annotations

import ast
import io
import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
import zipfile

import httpx
import pytest
from fastapi import BackgroundTasks
from starlette.requests import Request

from app.billing import grant_fixpack, yookassa
from app.ingest import validators
from scripts.evaluate_pilot_models import mutate

ROOT = Path(__file__).resolve().parents[1]


def _function(source, name, namespace):
    """Execute just the trusted repository function; never register app routes."""
    node = next(n for n in ast.parse(source).body
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name)
    node.decorator_list = []
    node.args.defaults = []  # Dependency injection defaults are unused in direct calls.
    module = ast.Module(body=[ast.ImportFrom(module="__future__", names=[
        ast.alias(name="annotations")], level=0), node], type_ignores=[])
    ast.fix_missing_locations(module)
    exec(compile(module, "<pilot-behavior>", "exec"), namespace)
    return namespace[name]


def test_archive_seed_bypasses_aggregate_expansion_limit():
    name = "app/ingest/validators.py"
    original = {name: (ROOT / name).read_text()}
    seeded = mutate(original, "files")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("a.txt", b"a" * 1800)
        archive.writestr("b.txt", b"b" * 1800)
    raw = buffer.getvalue()
    for source, should_reject in ((original[name], True), (seeded[name], False)):
        namespace = {**vars(validators), "MAX_UNCOMPRESSED_BYTES": 3000,
                     "MAX_UNCOMPRESSED_ENTRY_BYTES": 2000}
        validate = _function(source, "validate_zip", namespace)
        if should_reject:
            with pytest.raises(validators.ArchiveValidationError) as error:
                validate(io.BytesIO(raw), len(raw))
            assert error.value.reason == "zip_bomb"
        else:
            report = validate(io.BytesIO(raw), len(raw))
            assert report.file_count == 2
            assert report.total_uncompressed_bytes < 3000


@pytest.mark.asyncio
async def test_payment_seed_grants_forged_notification_without_provider_verification(monkeypatch):
    name = "app/routes/yookassa.py"
    original = {name: (ROOT / name).read_text()}
    seeded = mutate(original, "payments")
    monkeypatch.setenv("YOOKASSA_SHOP_ID", "pilot-test-shop")
    monkeypatch.setenv("YOOKASSA_SECRET_KEY", "test_pilot_secret")

    @asynccontextmanager
    async def lock(*args):
        yield  # Only synchronization is replaced; provider and grant logic stay real.

    async def notify(*args, **kwargs):
        raise AssertionError("Background notification must not run in this test")

    for source, should_grant in ((original[name], False), (seeded[name], True)):
        row = {"id": "test-order", "status": "pending", "amount": 990,
               "currency": "RUB", "audit_id": "test-audit"}
        jobs = []
        provider_calls = []

        async def get_order(provider, reference):
            assert (provider, reference) == ("yookassa", "DRY-PILOT")
            return row

        async def complete(payment_id, *, external_ref, fixpack_job_id):
            assert payment_id == row["id"]
            row.update(status="completed", fixpack_job_id=fixpack_job_id)
            return row

        async def get_audit(audit_id):
            assert audit_id == "test-audit"
            return {"id": audit_id, "stack": "fastapi"}

        async def create_paid(**kwargs):
            job = {"id": "test-job", **kwargs}
            jobs.append(job)
            return job

        obj = {"id": "pilot-payment", "status": "succeeded", "paid": True,
               "amount": {"value": "990.00", "currency": "RUB"},
               "metadata": {"reference": "DRY-PILOT"}}
        payload = json.dumps({"event": "payment.succeeded", "object": obj}).encode()

        async def receive():
            return {"type": "http.request", "body": payload, "more_body": False}

        request = Request({"type": "http", "method": "POST", "path": "/",
                           "headers": [(b"x-forwarded-for", b"185.71.76.5")],
                           "client": ("10.0.0.1", 1234)}, receive)

        def provider_response(request):
            provider_calls.append(request)
            return httpx.Response(200, json={**obj, "status": "pending", "paid": False})

        namespace = {"yookassa": yookassa, "grant_fixpack": grant_fixpack,
                     "payment_confirmation_lock": lock,
                     "PaymentConfirmationBusy": type("PaymentConfirmationBusy", (Exception,), {}),
                     "logger": logging.getLogger(__name__),
                     "_tell_the_payer_after_answering": notify}
        handler = _function(source, "receive_notification", namespace)
        background = BackgroundTasks()
        result = await handler(
            request=request, background=background,
            payment_repo=SimpleNamespace(get_by_external_ref=get_order,
                                         mark_completed_fixpack=complete),
            fixpack_repo=SimpleNamespace(create_paid=create_paid),
            audit_repo=SimpleNamespace(get=get_audit),
            transport=httpx.MockTransport(provider_response),
        )
        assert result == {"ok": True}
        assert bool(jobs) is should_grant
        assert row["status"] == ("completed" if should_grant else "pending")
        assert len(provider_calls) == (0 if should_grant else 1)
        assert len(background.tasks) == (1 if should_grant else 0)
