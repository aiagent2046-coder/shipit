"""The operator-side locks on the site-structure scan script.

`run_web_structure_scan` has its own consent gate, its own SSRF guard and its
own honest statuses, tested in tests/test_web_scan.py. These are the locks in
front of it: the ones a person trips over at 1am with a terminal open.

Every refusal here must happen BEFORE any request. A guard that fires after the
read has already happened is decoration.
"""

from __future__ import annotations

import json

import pytest

import scripts.scan_site as scan_site
from app.proof.web_scan import WebFinding, WebScanResult

URL = "https://example.com"


@pytest.fixture(autouse=True)
def no_env_consent(monkeypatch):
    monkeypatch.delenv("SITE_SCAN_CONSENT", raising=False)


@pytest.fixture
def no_scan(monkeypatch):
    """Fail loudly if anything tries to scan during a refusal path."""
    def _boom(**_kw):
        raise AssertionError("a scan was attempted after a refusal")

    monkeypatch.setattr(scan_site, "run_web_structure_scan", _boom)
    return _boom


def test_without_the_consent_phrase_nothing_runs(no_scan):
    assert scan_site.main([URL]) == 2


def test_a_near_miss_phrase_is_not_accepted(monkeypatch, no_scan):
    """The phrase is exact on purpose. `true`, `yes`, `1` are what someone
    types when they are guessing at a flag rather than confirming ownership of
    a site. Surrounding whitespace IS forgiven (a copied value), the words are
    not."""
    for wrong in ("true", "yes", "1", "i own this site", "I-OWN-THIS-PROJECT",
                  "i-own-this-project!"):
        monkeypatch.setenv("SITE_SCAN_CONSENT", wrong)
        assert scan_site.main([URL]) == 2, wrong


def test_the_exact_phrase_runs_the_scan(monkeypatch, capsys):
    seen = {}

    def fake_scan(**kwargs):
        seen.update(kwargs)
        return WebScanResult(status="checked", detail="ок")

    monkeypatch.setenv("SITE_SCAN_CONSENT", "i-own-this-project")
    monkeypatch.setattr(scan_site, "run_web_structure_scan", fake_scan)
    assert scan_site.main([URL, "--allow-loopback", "--delay", "0"]) == 0
    assert seen["url"] == URL
    assert seen["consent"] is True
    assert seen["allow_loopback"] is True
    assert seen["delay_s"] == 0
    assert "ок" in capsys.readouterr().out


def test_findings_at_or_above_fail_on_exit_1(monkeypatch):
    result = WebScanResult(
        status="checked", detail="находок: 1",
        findings=[WebFinding("web-exposed-files", "high", "t", "d", "r")])

    def fake_scan(**kwargs):
        return result

    monkeypatch.setenv("SITE_SCAN_CONSENT", "i-own-this-project")
    monkeypatch.setattr(scan_site, "run_web_structure_scan", fake_scan)
    assert scan_site.main([URL, "--fail-on", "high"]) == 1
    assert scan_site.main([URL, "--fail-on", "critical"]) == 0
    assert scan_site.main([URL]) == 0


def test_a_refused_or_failed_scan_exits_2_never_1(monkeypatch):
    """`skipped` is not a finding and not a success; 2 is "did not run"."""
    result = WebScanResult(status="skipped", detail="no consent",
                           findings=[WebFinding("x", "critical", "t", "d", "r")])

    def fake_scan(**kwargs):
        return result

    monkeypatch.setenv("SITE_SCAN_CONSENT", "i-own-this-project")
    monkeypatch.setattr(scan_site, "run_web_structure_scan", fake_scan)
    assert scan_site.main([URL, "--fail-on", "low"]) == 2


def test_json_flag_prints_a_machine_readable_report(monkeypatch, capsys):
    def fake_scan(**kwargs):
        return WebScanResult(status="checked", detail="ок",
                             findings=[WebFinding("web-cors", "high", "t", "d", "r",
                                                  evidence={"allow_origin": "x"})],
                             limitations=["тестовое ограничение"])

    monkeypatch.setenv("SITE_SCAN_CONSENT", "i-own-this-project")
    monkeypatch.setattr(scan_site, "run_web_structure_scan", fake_scan)
    assert scan_site.main([URL, "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "checked"
    assert payload["findings"][0]["check_id"] == "web-cors"
    assert payload["limitations"], "the honest limits travel with --json"
