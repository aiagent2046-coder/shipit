"""Registry of generated outreach: one draft per artifact set, ever.

Append-only JSONL keyed by artifact_fingerprint - the anti-spam key from
ARCHITECTURE.md so one project is never drafted twice for the same analyzed
artifacts. Phase 2 adds the status lifecycle: each status change (drafted ->
sent -> read -> fixed) is a new event on the same fingerprint, so the history
is preserved and the file stays append-only. A torn append is skipped on
load, never fatal: the registry must survive a crash mid-write.

Status moves forward only; the operator records what they know (a reply
proves "read"), and an out-of-order claim is refused instead of laundered.
"""
from __future__ import annotations

import json
import time
from pathlib import Path

SENT_REGISTRY = Path.home() / ".agent-scout" / "sent.jsonl"

STATUS_ORDER = ("drafted", "sent", "read", "fixed")
DRAFT_FIELDS = ("target", "contact", "findings", "kev_listed", "letter_path",
                "advisories", "sources")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _last_with(events: list[dict], field: str) -> dict | None:
    """Most recent event that carries this field (re-record events lack status)."""
    for event in reversed(events):
        if field in event:
            return event
    return None


class RegistryError(RuntimeError):
    """The registry cannot be read. An unreadable registry is NOT an empty
    one: treating it as empty would lose the dedup key and zero the quotas."""


class SentRegistry:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else SENT_REGISTRY
        self._events: dict[str, list[dict]] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.is_file():
            return
        try:
            text = self.path.read_text()
        except OSError as exc:
            raise RegistryError(f"registry unreadable: {self.path}: {exc}") from exc
        for line in text.splitlines():
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue  # a torn append must not poison the registry
            if isinstance(entry, dict) and isinstance(entry.get("fingerprint"), str):
                self._events.setdefault(entry["fingerprint"], []).append(entry)

    def _append(self, entry: dict) -> dict:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a") as fh:
            fh.write(json.dumps(entry, sort_keys=True) + "\n")
        self._events.setdefault(entry["fingerprint"], []).append(entry)
        return entry

    def seen(self, fingerprint: str) -> dict | None:
        """Last recorded event for this artifact set, or None."""
        events = self._events.get(fingerprint)
        return events[-1] if events else None

    def history(self, fingerprint: str) -> list[dict]:
        """All recorded events for this artifact set, oldest first."""
        return list(self._events.get(fingerprint, []))

    def all_events(self) -> list[dict]:
        """Every recorded event across fingerprints (for quota accounting)."""
        return [e for events in self._events.values() for e in events]

    def entries(self) -> list[dict]:
        """One summary row per fingerprint: draft facts + current status.

        Status comes from the last event that carries one (re-record events
        carry none); draft facts come from the first event, with later
        backfills (re_record) filling the gaps - a recorded fact never moves.
        """
        out = []
        for fingerprint, events in self._events.items():
            first = events[0]
            status_event = _last_with(events, "status") or first
            row = {"fingerprint": fingerprint,
                   "status": status_event.get("status", "drafted"),
                   "updated_at": status_event.get("recorded_at")}
            for field in DRAFT_FIELDS:
                row[field] = first.get(field)
            for event in events[1:]:
                for field in DRAFT_FIELDS:
                    if row.get(field) is None and field in event:
                        row[field] = event[field]
            row["recorded_at"] = first.get("recorded_at")
            out.append(row)
        return out

    def record(self, fingerprint: str, target: str, contact: str | None,
               findings: int, kev_listed: int,
               letter_path: str | None = None,
               advisories: list[str] | None = None,
               sources: list[str] | None = None) -> dict:
        entry = {
            "recorded_at": _now(),
            "fingerprint": fingerprint,
            "target": target,
            "contact": contact,
            "findings": findings,
            "kev_listed": kev_listed,
            "status": "drafted",
        }
        if letter_path:
            entry["letter_path"] = str(letter_path)
        if advisories:
            entry["advisories"] = list(advisories)
        if sources:
            entry["sources"] = list(sources)
        return self._append(entry)

    def mark(self, fingerprint: str, status: str, note: str | None = None) -> dict:
        """Record a status change; only forward moves along STATUS_ORDER."""
        if status not in STATUS_ORDER:
            raise ValueError(
                f"unknown status {status!r} (expected one of: {', '.join(STATUS_ORDER)})")
        events = self._events.get(fingerprint)
        if not events:
            raise ValueError(f"unknown fingerprint {fingerprint!r}")
        status_event = _last_with(events, "status")
        current = status_event["status"] if status_event else "drafted"
        if STATUS_ORDER.index(status) <= STATUS_ORDER.index(current):
            raise ValueError(
                f"status must move forward: current {current!r}, got {status!r}")
        anchor = _last_with(events, "target") or events[-1]
        entry = {
            "recorded_at": _now(),
            "fingerprint": fingerprint,
            "target": anchor.get("target"),
            "contact": anchor.get("contact"),
            "status": status,
        }
        if note:
            entry["note"] = note
        return self._append(entry)

    def re_record(self, fingerprint: str, advisories: list[str] | None = None,
                  contact: str | None = None, sources: list[str] | None = None,
                  note: str | None = None) -> dict:
        """Backfill facts a draft lacked (advisory baseline, contact).

        Append-only: a backfill is a new event that carries no status.
        Each fact fills a gap only - the advisory baseline is immutable
        once set and a recorded contact never moves, so neither the
        comparison anchor nor the recipient can change silently."""
        events = self._events.get(fingerprint)
        if not events:
            raise ValueError(f"unknown fingerprint {fingerprint!r}")
        facts: dict = {}
        if advisories is not None:
            if not advisories:
                raise ValueError("re-record needs a non-empty advisory list")
            if any("advisories" in event for event in events):
                raise ValueError("advisory baseline already recorded")
            facts["advisories"] = list(advisories)
        if contact is not None:
            if not contact.strip():
                raise ValueError("re-record needs a non-empty contact")
            if any(event.get("contact") for event in events):
                raise ValueError("contact already recorded")
            facts["contact"] = contact
        if not facts:
            raise ValueError("re-record needs a fact to backfill")
        anchor = _last_with(events, "target") or events[-1]
        entry = {
            "recorded_at": _now(),
            "fingerprint": fingerprint,
            "target": anchor.get("target"),
            "contact": facts.get("contact", anchor.get("contact")),
            **facts,
        }
        if sources:
            entry["sources"] = list(sources)
        if note:
            entry["note"] = note
        return self._append(entry)
