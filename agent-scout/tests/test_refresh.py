"""Refresh tests: 'fixed' means the recorded advisories no longer match.

The verdicts are pinned as a refusal ladder: nothing marks 'fixed' without
a positive re-scan signal (recorded advisories gone), no artifacts means
'unverifiable' (absence of evidence is not evidence of safety), and
entries without a recorded advisory list are skipped, not guessed.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from scout import engine as engine_mod
from scout import refresh, registry


@pytest.fixture
def sent_path(tmp_path, monkeypatch):
    path = tmp_path / "sent.jsonl"
    monkeypatch.setattr(registry, "SENT_REGISTRY", path)
    return path


def langflow_files() -> dict[str, bytes]:
    return {"requirements.txt": b"langflow==1.2.0\n"}


def langflow_advisories() -> list[str]:
    result = engine_mod.Engine().scan_files(langflow_files(), target="t")
    return sorted(refresh.advisory_ids(result))


def test_advisory_ids_prefers_claim_evidence():
    result = SimpleNamespace(findings=[
        {"title": "fallback title", "claim_evidence": {"advisory_id": "GHSA-1"}},
        {"title": "second"},
        {"title": ""},
    ])
    assert refresh.advisory_ids(result) == {"GHSA-1", "second"}


def test_sources_for_target_fallback():
    assert refresh.sources_for_target("github.com/o/r") == ["repo:o/r"]
    assert refresh.sources_for_target("https://site.test") == ["url:https://site.test"]
    assert refresh.sources_for_target("something else") == []


def test_refetch_replays_repo_and_url_recipes(monkeypatch):
    monkeypatch.setattr(refresh.recon, "github_manifests",
                        lambda o, r: {"package-lock.json": b"{}"})
    monkeypatch.setattr(refresh.recon, "manifests_from_site",
                        lambda u: {"sourcemap-pins/package-lock.json": b"{}"})
    files = refresh.refetch(["repo:o/r", "url:https://site.test"])
    assert set(files) == {"package-lock.json", "sourcemap-pins/package-lock.json"}
    assert refresh.refetch(["repo:o/r", "url:https://site.test"]) == files  # replayable
    assert refresh.refetch([]) == {}


def test_verify_marks_fixed_when_recorded_advisories_gone(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=1,
               advisories=langflow_advisories())
    row = reg.entries()[0]
    verdict, note = refresh.verify(row, {"requirements.txt": b"flask==99.0.0\n"})
    assert verdict == "fixed"
    assert "recorded advisories" in note


def test_verify_open_when_advisory_still_matches(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=1,
               advisories=langflow_advisories() + ["GHSA-gone"])
    row = reg.entries()[0]
    verdict, note = refresh.verify(row, langflow_files())
    assert verdict == "open"
    assert "still matching" in note


def test_verify_unverifiable_without_artifacts(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=1,
               advisories=langflow_advisories())
    verdict, note = refresh.verify(reg.entries()[0], {})
    assert verdict == "unverifiable"
    assert "absence of evidence" in note


def test_verify_skips_entries_without_advisory_list(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=3, kev_listed=1)
    verdict, note = refresh.verify(reg.entries()[0], langflow_files())
    assert verdict == "skipped"
    assert "mark fixed manually" in note


def test_assess_rerecord_sets_baseline(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=0)
    verdict, note, baseline = refresh.assess(reg.entries()[0], langflow_files(),
                                             re_record=True)
    assert verdict == "re-recorded"
    assert baseline == langflow_advisories()
    assert "baseline set from current scan" in note


def test_assess_rerecord_needs_artifacts(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=0)
    verdict, _, baseline = refresh.assess(reg.entries()[0], {}, re_record=True)
    assert verdict == "unverifiable"
    assert baseline is None


def test_assess_rerecord_clean_scan_stays_skipped(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=0)
    verdict, note, baseline = refresh.assess(
        reg.entries()[0], {"requirements.txt": b"flask==99.0.0\n"}, re_record=True)
    assert verdict == "skipped"
    assert "mark fixed manually" in note
    assert baseline is None  # an empty baseline must never be recorded


def test_assess_without_flag_keeps_verify_path(sent_path):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=1, kev_listed=0)
    verdict, _, baseline = refresh.assess(reg.entries()[0], langflow_files())
    assert verdict == "skipped"  # verify's honest refusal, no baseline invented
    assert baseline is None


def test_discover_contact_prefers_sources_then_target(monkeypatch):
    calls = []

    def fake_fetch(url):
        calls.append(url)
        return ("txt", None)  # nothing published
    monkeypatch.setattr(refresh.recon, "fetch_security_txt", fake_fetch)
    row = {"target": "https://site.test", "sources": ["repo:o/r", "url:https://a.test"]}
    assert refresh.discover_contact(row) is None
    assert calls == ["https://a.test"]  # the target is not probed when url sources exist
    calls.clear()
    assert refresh.discover_contact({"target": "https://site.test", "sources": None}) is None
    assert calls == ["https://site.test"]  # target fallback for old records
    assert refresh.discover_contact({"target": "github.com/o/r"}) is None  # no surface


def test_discover_contact_survives_probe_failures(monkeypatch):
    def boom(url):
        raise refresh.recon.ReconError("down")
    monkeypatch.setattr(refresh.recon, "fetch_security_txt", boom)
    assert refresh.discover_contact({"target": "https://site.test"}) is None

    def found(url):
        return ("txt", "mailto:sec@example.test")
    monkeypatch.setattr(refresh.recon, "fetch_security_txt", found)
    assert refresh.discover_contact(
        {"target": "https://site.test"}) == "mailto:sec@example.test"
