"""Sent-registry tests: one outreach per artifact set, ever.

The registry is the anti-spam key from ARCHITECTURE.md: artifact_fingerprint
dedup so one project is never drafted twice for the same analyzed artifacts.
Phase 1 records drafts; delivery statuses and automation are Phase 2.
"""
from __future__ import annotations

import pytest

from scout import registry


@pytest.fixture
def sent_path(tmp_path, monkeypatch):
    path = tmp_path / "sent.jsonl"
    monkeypatch.setattr(registry, "SENT_REGISTRY", path)
    return path


def test_registry_records_and_returns_entry(sent_path):
    reg = registry.SentRegistry()
    entry = reg.record("fp-1", target="github.com/o/r",
                       contact="mailto:sec@example.test",
                       findings=3, kev_listed=1)
    assert entry["fingerprint"] == "fp-1"
    assert entry["status"] == "drafted"
    assert reg.seen("fp-1") == entry
    assert reg.seen("fp-2") is None


def test_registry_survives_reload(sent_path):
    registry.SentRegistry().record("fp-1", target="github.com/o/r",
                                   contact=None, findings=0, kev_listed=0)
    fresh = registry.SentRegistry()
    assert fresh.seen("fp-1")["target"] == "github.com/o/r"


def test_registry_ignores_torn_lines(sent_path):
    # a torn append (crash mid-write) must not poison the registry
    sent_path.write_text('{"fingerprint": "fp-1", "target": "t"}\nnot json at all\n')
    reg = registry.SentRegistry()
    assert reg.seen("fp-1")["target"] == "t"
    reg.record("fp-2", target="u", contact=None, findings=0, kev_listed=0)
    assert registry.SentRegistry().seen("fp-2")["target"] == "u"


def test_registry_requires_fingerprint_field(sent_path):
    sent_path.write_text('{"target": "no-fingerprint"}\n[]\n')
    reg = registry.SentRegistry()
    assert reg.seen("anything") is None


def test_mark_records_forward_event_with_note(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="github.com/o/r", contact="mailto:sec@example.test",
               findings=3, kev_listed=1)
    entry = reg.mark("fp-1", "sent", note="delivered by hand")
    assert entry["status"] == "sent"
    fresh = registry.SentRegistry()
    assert fresh.seen("fp-1")["status"] == "sent"
    assert fresh.seen("fp-1")["note"] == "delivered by hand"
    assert [e["status"] for e in fresh.history("fp-1")] == ["drafted", "sent"]


def test_mark_allows_skipping_stages_forward(sent_path):
    # operator ground truth wins: a reply proves "read" even if "sent" was never logged
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    reg.mark("fp-1", "read")
    assert reg.seen("fp-1")["status"] == "read"


def test_mark_rejects_backward_and_same_status(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    reg.mark("fp-1", "read")
    for bad in ("drafted", "sent", "read"):
        with pytest.raises(ValueError, match="forward"):
            reg.mark("fp-1", bad)
    assert len(reg.history("fp-1")) == 2  # refusals leave no trace


def test_mark_rejects_unknown_status(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    with pytest.raises(ValueError, match="unknown status"):
        reg.mark("fp-1", "bounced")


def test_mark_rejects_unknown_fingerprint(sent_path):
    reg = registry.SentRegistry()
    with pytest.raises(ValueError, match="unknown fingerprint"):
        reg.mark("nope", "sent")


def test_entries_merge_draft_facts_with_current_status(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact="mailto:a@b.test", findings=3, kev_listed=1,
               letter_path="/tmp/letter.md")
    reg.mark("fp-1", "fixed")
    row = reg.entries()[0]
    assert row["status"] == "fixed"
    assert row["findings"] == 3 and row["kev_listed"] == 1
    assert row["letter_path"] == "/tmp/letter.md"
    assert row["contact"] == "mailto:a@b.test"


def test_re_record_backfills_advisory_baseline(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact="mailto:a@b.test", findings=3, kev_listed=1)
    entry = reg.re_record("fp-1", ["GHSA-1", "GHSA-2"], sources=["repo:o/r"],
                          note="baseline re-recorded")
    assert entry["advisories"] == ["GHSA-1", "GHSA-2"]
    assert "status" not in entry  # a backfill is not a status change
    row = registry.SentRegistry().entries()[0]
    assert row["advisories"] == ["GHSA-1", "GHSA-2"]
    assert row["sources"] == ["repo:o/r"]
    assert row["status"] == "drafted"


def test_re_record_keeps_current_status_and_forward_rule(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    reg.mark("fp-1", "read")
    reg.re_record("fp-1", ["GHSA-1"])
    assert reg.entries()[0]["status"] == "read"
    with pytest.raises(ValueError, match="forward"):
        reg.mark("fp-1", "sent")  # the backfill must not reset the status ladder
    reg.mark("fp-1", "fixed")  # forward still works
    assert reg.entries()[0]["status"] == "fixed"


def test_re_record_refuses_existing_baseline(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0,
               advisories=["GHSA-1"])
    with pytest.raises(ValueError, match="already recorded"):
        reg.re_record("fp-1", ["GHSA-2"])


def test_re_record_refuses_empty_list_and_unknown_fingerprint(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    with pytest.raises(ValueError, match="non-empty"):
        reg.re_record("fp-1", [])
    with pytest.raises(ValueError, match="unknown fingerprint"):
        reg.re_record("nope", ["GHSA-1"])


def test_unreadable_registry_fails_closed(sent_path, monkeypatch):
    # an unreadable registry is NOT an empty one: it must refuse, not forget
    sent_path.write_text('{"fingerprint": "fp-1", "target": "t"}\n')

    def boom(self, *args, **kwargs):
        raise PermissionError("denied")
    monkeypatch.setattr(type(sent_path), "read_text", boom)
    with pytest.raises(registry.RegistryError, match="unreadable"):
        registry.SentRegistry()


def test_re_record_backfills_contact(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="https://t", contact=None, findings=1, kev_listed=0)
    entry = reg.re_record("fp-1", contact="mailto:sec@example.test",
                          note="contact backfilled from security.txt")
    assert entry["contact"] == "mailto:sec@example.test"
    assert "status" not in entry  # a backfill is not a status change
    assert registry.SentRegistry().entries()[0]["contact"] == "mailto:sec@example.test"


def test_re_record_refuses_contact_when_recorded(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact="mailto:a@b.test", findings=0, kev_listed=0)
    with pytest.raises(ValueError, match="contact already recorded"):
        reg.re_record("fp-1", contact="mailto:c@d.test")
    with pytest.raises(ValueError, match="non-empty contact"):
        reg.re_record("fp-1", contact="   ")


def test_re_record_refuses_factless_call(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    with pytest.raises(ValueError, match="fact to backfill"):
        reg.re_record("fp-1")
