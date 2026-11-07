"""Outreach delivery: queue from the registry, quotas from the registry.

Sending is explicitly operator-initiated (`scout outreach send`); scanning
never sends anything. Fail-closed without SMTP config: nothing is sent and
nothing is marked. Quotas are computed from the append-only registry, so
they survive restarts with no separate state file:

  - one letter per artifact set, ever (the drafted-status gate),
  - at most DAILY_LIMIT deliveries per UTC day,
  - at most CONTACT_DAILY_LIMIT deliveries per contact per UTC day.

The letter carries its own To:/Subject: headers (see report.render_outreach),
so delivery reads them from the letter instead of inventing its own.
"""
from __future__ import annotations

import os
import smtplib
import ssl
import time
from collections import Counter
from email.message import EmailMessage
from pathlib import Path

DAILY_LIMIT = 5
CONTACT_DAILY_LIMIT = 1


class DeliveryError(RuntimeError):
    pass


def delivery_address(contact: str | None) -> str | None:
    """Bare email address for a security.txt contact. None = not emailable."""
    if not contact:
        return None
    value = contact.strip()
    if value.lower().startswith("mailto:"):
        value = value[len("mailto:"):]
    return value if "@" in value else None


def mail_fields(body: str) -> tuple[str | None, str]:
    """Recipient and subject from the letter's own To:/Subject: lines."""
    to = subject = None
    for line in body.splitlines()[:5]:
        if line.startswith("To: ") and to is None:
            to = line[4:].strip()
        elif line.startswith("Subject: ") and subject is None:
            subject = line[9:].strip()
    return to, subject or "Security assessment"


def plan(reg, limit: int | None = None,
         daily_limit: int = DAILY_LIMIT,
         contact_daily_limit: int = CONTACT_DAILY_LIMIT,
         today: str | None = None) -> list[dict]:
    """Deliverable drafts within quota, oldest first. Skips silently are
    visible in the counts: nothing without a contact, a letter file or a
    fresh 'drafted' status can ever be queued."""
    today = today or time.strftime("%Y-%m-%d", time.gmtime())
    sent_today = [e for e in reg.all_events()
                  if e.get("status") == "sent"
                  and str(e.get("recorded_at", "")).startswith(today)]
    quota_left = daily_limit - len(sent_today)
    if quota_left <= 0:
        return []
    run_cap = quota_left if limit is None else min(limit, quota_left)
    # quota counts mailboxes, not spellings: "mailto:a@b" and "a@b" are one contact
    by_contact = Counter(delivery_address(e.get("contact")) for e in sent_today)
    rows: list[dict] = []
    for row in sorted(reg.entries(), key=lambda r: r["recorded_at"] or ""):
        if len(rows) >= run_cap:
            break
        if row["status"] != "drafted":
            continue  # one letter per artifact set, ever
        address = delivery_address(row.get("contact"))
        if not address:
            continue  # nobody to deliver to
        if not row.get("letter_path") or not Path(row["letter_path"]).is_file():
            continue  # nothing to deliver
        if by_contact[address] >= contact_daily_limit:
            continue  # one letter per contact per day
        by_contact[address] += 1
        row["deliver_to"] = address
        rows.append(row)
    return rows


class SmtpSender:
    """Minimal SMTP delivery; port 465 = implicit TLS, else STARTTLS."""

    def __init__(self, host: str, port: int, user: str, password: str,
                 sender: str) -> None:
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.sender = sender

    def send(self, to: str, subject: str, body: str) -> None:
        msg = EmailMessage()
        msg["From"] = self.sender
        msg["To"] = to
        msg["Subject"] = subject
        msg.set_content(body)
        # verified TLS: smtplib's default context accepts ANY certificate,
        # and a disclosure letter is worth MITMing
        context = ssl.create_default_context()
        try:
            if self.port == 465:
                smtp = smtplib.SMTP_SSL(self.host, self.port, timeout=30,
                                        context=context)
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=30)
            with smtp:
                if self.port != 465:
                    smtp.starttls(context=context)
                if self.user:
                    smtp.login(self.user, self.password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise DeliveryError(f"SMTP delivery to {to} failed: {exc}") from exc


def smtp_sender_from_env() -> SmtpSender | None:
    """Sender from SCOUT_SMTP_* env vars; None = not configured (fail-closed)."""
    host = os.environ.get("SCOUT_SMTP_HOST", "")
    port = os.environ.get("SCOUT_SMTP_PORT", "587")
    sender = os.environ.get("SCOUT_SMTP_FROM", "")
    if not (host and port and sender):
        return None
    try:
        port_number = int(port)
    except ValueError:
        return None  # broken config is not a config
    return SmtpSender(host, port_number, os.environ.get("SCOUT_SMTP_USER", ""),
                      os.environ.get("SCOUT_SMTP_PASSWORD", ""), sender)
