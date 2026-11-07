"""Delivery tests: queue and quotas from the registry, fail-closed without config.

ARCHITECTURE.md phase 2: automatic delivery with quotas. Sending is an
explicit operator command; the tests pin the quota math and the refusal
paths (unemailable contact, missing letter, spent quota, failed SMTP).
"""
from __future__ import annotations

import smtplib
import ssl
from typing import ClassVar

import pytest

from scout import delivery, registry


@pytest.fixture
def sent_path(tmp_path, monkeypatch):
    path = tmp_path / "sent.jsonl"
    monkeypatch.setattr(registry, "SENT_REGISTRY", path)
    return path


@pytest.fixture
def letter(tmp_path):
    def make(name: str = "letter.md") -> str:
        path = tmp_path / name
        path.write_text("To: sec@example.test\n"
                        "Subject: Security finding in o/r - coordinated disclosure\n"
                        "\nbody\n")
        return str(path)
    return make


def test_plan_queues_drafts_oldest_first_within_run_limit(sent_path, letter):
    reg = registry.SentRegistry()
    for i in range(3):
        reg.record(f"fp-{i}", target=f"t{i}", contact=f"mailto:c{i}@example.test",
                   findings=0, kev_listed=0, letter_path=letter(f"l{i}.md"))
    rows = delivery.plan(reg, limit=2)
    assert [r["fingerprint"] for r in rows] == ["fp-0", "fp-1"]
    assert rows[0]["deliver_to"] == "c0@example.test"


def test_plan_skips_unemailable_and_missing_letters(sent_path, letter, tmp_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t1", contact="https://example.test/security",
               findings=0, kev_listed=0, letter_path=letter())  # contact form, not mail
    reg.record("fp-2", target="t2", contact="mailto:c@example.test",
               findings=0, kev_listed=0)  # no letter recorded
    reg.record("fp-3", target="t3", contact="mailto:c@example.test",
               findings=0, kev_listed=0, letter_path=str(tmp_path / "gone.md"))
    assert delivery.plan(reg) == []


def test_plan_respects_daily_quota(sent_path, letter):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t1", contact="mailto:a@example.test",
               findings=0, kev_listed=0, letter_path=letter("l1.md"))
    reg.mark("fp-1", "sent")  # spends today's quota
    reg.record("fp-2", target="t2", contact="mailto:b@example.test",
               findings=0, kev_listed=0, letter_path=letter("l2.md"))
    assert delivery.plan(reg, daily_limit=1) == []
    assert [r["fingerprint"] for r in delivery.plan(reg, daily_limit=2)] == ["fp-2"]


def test_plan_one_letter_per_contact_per_day(sent_path, letter):
    reg = registry.SentRegistry()
    for i in range(2):
        reg.record(f"fp-{i}", target=f"t{i}", contact="mailto:same@example.test",
                   findings=0, kev_listed=0, letter_path=letter(f"l{i}.md"))
    rows = delivery.plan(reg, daily_limit=5)
    assert [r["fingerprint"] for r in rows] == ["fp-0"]


def test_plan_skips_non_draft_statuses(sent_path, letter):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact="mailto:a@example.test",
               findings=0, kev_listed=0, letter_path=letter())
    reg.mark("fp-1", "read")
    assert delivery.plan(reg) == []


def test_delivery_address_variants():
    assert delivery.delivery_address("mailto:sec@example.test") == "sec@example.test"
    assert delivery.delivery_address("sec@example.test") == "sec@example.test"
    assert delivery.delivery_address("https://example.test/security") is None
    assert delivery.delivery_address(None) is None


def test_mail_fields_reads_letter_headers():
    to, subject = delivery.mail_fields(
        "To: a@b.test\nSubject: Security finding in o/r\n\nbody")
    assert to == "a@b.test"
    assert subject == "Security finding in o/r"
    assert delivery.mail_fields("no headers here")[1] == "Security assessment"


def test_smtp_sender_failure_is_delivery_error(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError("connection refused")
    monkeypatch.setattr(smtplib, "SMTP", boom)
    sender = delivery.SmtpSender("smtp.example.test", 587, "u", "p", "me@example.test")
    with pytest.raises(delivery.DeliveryError):
        sender.send(to="you@example.test", subject="s", body="b")


def test_smtp_sender_from_env_is_fail_closed(monkeypatch):
    for name in ("SCOUT_SMTP_HOST", "SCOUT_SMTP_PORT", "SCOUT_SMTP_FROM",
                 "SCOUT_SMTP_USER", "SCOUT_SMTP_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
    assert delivery.smtp_sender_from_env() is None
    monkeypatch.setenv("SCOUT_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SCOUT_SMTP_FROM", "me@example.test")
    sender = delivery.smtp_sender_from_env()
    assert sender is not None
    assert sender.host == "smtp.example.test" and sender.port == 587


class FakeSMTP:
    """Records the TLS context each smtplib entry point was handed."""
    captured: ClassVar[dict] = {}

    def __init__(self, host, port, timeout=None, context=None):
        FakeSMTP.captured["init_context"] = context

    def starttls(self, *, context=None):
        FakeSMTP.captured["starttls_context"] = context

    def login(self, user, password):
        pass

    def send_message(self, msg):
        FakeSMTP.captured["msg"] = msg

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def verified(context) -> bool:
    return (context is not None
            and context.verify_mode == ssl.CERT_REQUIRED
            and context.check_hostname)


def test_smtp_sender_upgrades_starttls_with_verified_context(monkeypatch):
    FakeSMTP.captured = {}
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    delivery.SmtpSender("smtp.example.test", 587, "", "",
                        "me@example.test").send(
        to="you@example.test", subject="s", body="b")
    assert verified(FakeSMTP.captured["starttls_context"])


def test_smtp_sender_ssl_port_uses_verified_context(monkeypatch):
    FakeSMTP.captured = {}
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    delivery.SmtpSender("smtp.example.test", 465, "", "",
                        "me@example.test").send(
        to="you@example.test", subject="s", body="b")
    assert verified(FakeSMTP.captured["init_context"])


def test_smtp_sender_from_env_invalid_port_is_fail_closed(monkeypatch):
    monkeypatch.setenv("SCOUT_SMTP_HOST", "smtp.example.test")
    monkeypatch.setenv("SCOUT_SMTP_PORT", "not-a-port")
    monkeypatch.setenv("SCOUT_SMTP_FROM", "me@example.test")
    assert delivery.smtp_sender_from_env() is None


def test_plan_contact_quota_counts_mailbox_not_spelling(sent_path, letter):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t1", contact="mailto:same@example.test",
               findings=0, kev_listed=0, letter_path=letter("l1.md"))
    reg.record("fp-2", target="t2", contact="same@example.test",
               findings=0, kev_listed=0, letter_path=letter("l2.md"))
    rows = delivery.plan(reg, daily_limit=5)
    assert [r["fingerprint"] for r in rows] == ["fp-1"]  # one mailbox, one letter
