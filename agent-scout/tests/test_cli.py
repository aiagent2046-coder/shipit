"""CLI tests: command contracts, exit codes, and written artifacts.

Network and repository boundaries are faked; the drydock engine and the
report pipeline run for real. Exit-code contract under test:
0 = scanned, 1 = nothing to scan / recon error, 2 = usage, 3 = refused.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import ClassVar

import pytest

from scout import cli, delivery, guard, recon, refresh, registry
from scout.recon import SiteProfile


def npm_lockfile(deps):
    packages = {"": {"name": "demo", "dependencies": dict(deps)}}
    for name, version in deps.items():
        packages[f"node_modules/{name}"] = {"version": version}
    return json.dumps(
        {"name": "demo", "lockfileVersion": 3, "packages": packages}).encode()


@pytest.fixture(autouse=True)
def quiet_network(monkeypatch):
    monkeypatch.setattr(recon, "REQUEST_INTERVAL_S", 0.0)


@pytest.fixture(autouse=True)
def sent_registry_isolated(tmp_path, monkeypatch):
    """Keep test scans out of the operator's real ~/.agent-scout registry."""
    monkeypatch.setattr(registry, "SENT_REGISTRY", tmp_path / "sent.jsonl")


@pytest.fixture
def auth_dir(monkeypatch, tmp_path):
    path = tmp_path / "authorizations"
    monkeypatch.setattr(guard, "AUTH_DIR", path)
    return path


def test_scan_repo_writes_report_and_outreach(tmp_path, monkeypatch):
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"package-lock.json": npm_lockfile({"lodash": "4.17.15"})})
    rc = cli.main(["scan", "--repo", "o/r", "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "github.com_o_r-report.md").read_text()
    assert "External security assessment: github.com/o/r" in report
    assert "lodash 4.17.15" in report
    assert "Limitations (carried from the engine, unchanged)" in report
    assert (tmp_path / "github.com_o_r-outreach.md").is_file()


def test_scan_url_without_manifests_writes_profile_report(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(recon, "profile_site", lambda url: SiteProfile(
        base_url=url, server_headers={"Server": "nginx"}, contact="mailto:sec@example.test"))
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {})
    monkeypatch.setattr(recon, "manifests_from_site", lambda url: {})
    rc = cli.main(["scan", "--url", "https://example.test", "--out", str(tmp_path)])
    assert rc == 1
    report = (tmp_path / "example.test-report.md").read_text()
    assert "proves nothing about dependency safety" in report
    assert "mailto:sec@example.test" in capsys.readouterr().out


def test_scan_url_scans_source_map_manifests(tmp_path, monkeypatch):
    monkeypatch.setattr(recon, "profile_site", lambda url: SiteProfile(
        base_url=url, contact="mailto:sec@example.test"))
    monkeypatch.setattr(recon, "manifests_from_site", lambda url: {
        "sourcemap-pins/package-lock.json": npm_lockfile({"lodash": "4.17.15"})})
    rc = cli.main(["scan", "--url", "https://example.test", "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "example.test-report.md").read_text()
    assert "lodash 4.17.15" in report                    # engine matched the pins
    assert "sourcemap-pins/package-lock.json" in report  # provenance names the origin


def test_scan_url_and_repo_combines_contact(tmp_path, monkeypatch):
    monkeypatch.setattr(recon, "profile_site", lambda url: SiteProfile(
        base_url=url, contact="mailto:sec@example.test"))
    monkeypatch.setattr(recon, "manifests_from_site", lambda url: {})
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"package-lock.json": npm_lockfile({"lodash": "4.17.15"})})
    rc = cli.main(["scan", "--url", "https://example.test", "--repo", "o/r",
                   "--out", str(tmp_path)])
    assert rc == 0
    outreach = (tmp_path / "github.com_o_r-outreach.md").read_text()
    assert outreach.startswith("To: mailto:sec@example.test")


def test_scan_without_lockfiles_is_honest(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {})
    rc = cli.main(["scan", "--repo", "o/r", "--out", str(tmp_path)])
    assert rc == 1
    assert "absence of evidence is not evidence of safety" in capsys.readouterr().err


def test_scan_dedups_outreach_by_fingerprint(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"package-lock.json": npm_lockfile({"lodash": "4.17.15"})})
    out = tmp_path / "out"
    assert cli.main(["scan", "--repo", "o/r", "--out", str(out)]) == 0
    letter = out / "github.com_o_r-outreach.md"
    assert letter.is_file()
    letter.unlink()  # if dedup fails, the letter comes back
    assert cli.main(["scan", "--repo", "o/r", "--out", str(out)]) == 0
    assert not letter.exists()
    assert "already recorded" in capsys.readouterr().out
    assert (out / "github.com_o_r-report.md").is_file()  # assessment stays current
    lines = (tmp_path / "sent.jsonl").read_text().splitlines()
    assert len(lines) == 1


def test_scan_repo_requires_owner_name():
    assert cli.main(["scan", "--repo", "bad-shape"]) == 2


def test_recon_error_maps_to_exit_1(monkeypatch):
    def boom(url):
        raise recon.ReconError("down")
    monkeypatch.setattr(recon, "profile_site", boom)
    assert cli.main(["scan", "--url", "https://down.test"]) == 1


def test_auth_add_list_rm(auth_dir, capsys):
    rc = cli.main(["auth", "add", "--contract", "c-1", "--scope", "db.example.test",
                   "--hours", "1"])
    assert rc == 0
    record = auth_dir / "c-1.json"
    assert json.loads(record.read_text())["scope"] == ["db.example.test"]
    assert "authorization recorded" in capsys.readouterr().out
    assert cli.main(["auth", "list"]) == 0
    assert "c-1" in capsys.readouterr().out
    assert cli.main(["auth", "rm", "--contract", "c-1"]) == 0
    assert not record.exists()


def test_auth_add_requires_scope(auth_dir):
    assert cli.main(["auth", "add", "--contract", "c-2"]) == 3


def test_auth_rm_refuses_path_traversal_and_leaves_files_intact(auth_dir, tmp_path, capsys):
    victim = tmp_path / "victim.json"
    victim.write_text('{"keep": true}')
    assert cli.main(["auth", "rm", "--contract", "../victim"]) == 3
    assert "refused" in capsys.readouterr().err
    assert victim.is_file()


def test_hunt_kev_targets_ranked_and_clean_skipped(tmp_path, monkeypatch):
    search = {"items": [
        {"full_name": "o/kev", "html_url": "https://github.com/o/kev"},
        {"full_name": "o/clean", "html_url": "https://github.com/o/clean"},
    ]}

    class SearchResponse:
        status = 200
        headers: ClassVar[dict] = {}
        def read(self):
            return json.dumps(search).encode()
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: SearchResponse())
    manifests = {
        "o/kev": {"requirements.txt": b"langflow==1.2.0\n"},
        "o/clean": {"package-lock.json": npm_lockfile({"left-pad": "1.3.0"})},
    }
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: manifests[f"{o}/{r}"])
    rc = cli.main(["hunt", "--query", "demo", "--limit", "5", "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "hunt-report.md").read_text()
    assert "o/kev" in report          # KEV findings -> reported
    assert "o/clean" not in report    # no findings -> not noise


def search_response(body):
    class Response:
        status = 200
        headers: ClassVar[dict] = {}
        def read(self):
            return body
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False
    return Response()


def test_hunt_search_rate_limit_is_honest(tmp_path, monkeypatch, capsys):
    def blocked(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "rate limited", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    rc = cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "HTTP 403" in err and "rate" in err.lower()
    assert not (tmp_path / "hunt-report.md").exists()


def test_hunt_search_server_error_is_honest(tmp_path, monkeypatch, capsys):
    def broken(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 502, "bad gateway", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", broken)
    assert cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)]) == 1
    assert "HTTP 502" in capsys.readouterr().err


def test_hunt_search_network_failure_maps_to_exit_1(tmp_path, monkeypatch, capsys):
    def down(req, timeout=None):
        raise urllib.error.URLError("search endpoint down")
    monkeypatch.setattr(urllib.request, "urlopen", down)
    assert cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)]) == 1
    assert "recon error" in capsys.readouterr().err


def test_hunt_search_unexpected_body_is_honest(tmp_path, monkeypatch, capsys):
    for body in (b"<html>oops</html>", b'{"message": "no items here"}'):
        monkeypatch.setattr(urllib.request, "urlopen",
                            lambda req, timeout=None, _body=body: search_response(_body))
        assert cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)]) == 1
        assert "search error" in capsys.readouterr().err


def gitlab_response(projects):
    return search_response(json.dumps(projects).encode())


def test_hunt_gitlab_source_scans_projects(tmp_path, monkeypatch):
    def wrong_source(o, r):
        raise AssertionError("github manifests must not be fetched for --source gitlab")
    monkeypatch.setattr(recon, "github_manifests", wrong_source)
    monkeypatch.setattr(recon, "gitlab_manifests",
                        lambda p: {"requirements.txt": b"langflow==1.2.0\n"})
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: gitlab_response(
        [{"path_with_namespace": "o/kev", "web_url": "https://gitlab.com/o/kev"}]))
    rc = cli.main(["hunt", "--query", "demo", "--source", "gitlab",
                   "--limit", "5", "--out", str(tmp_path)])
    assert rc == 0
    report = (tmp_path / "hunt-report.md").read_text()
    assert "o/kev" in report


def test_hunt_gitlab_search_errors_are_honest(tmp_path, monkeypatch, capsys):
    def blocked(req, timeout=None):
        raise urllib.error.HTTPError(req.full_url, 403, "rate limited", {}, None)
    monkeypatch.setattr(urllib.request, "urlopen", blocked)
    rc = cli.main(["hunt", "--query", "demo", "--source", "gitlab", "--out", str(tmp_path)])
    assert rc == 1
    err = capsys.readouterr().err
    assert "HTTP 403" in err and "rate" in err.lower()


def test_hunt_gitlab_unexpected_body_is_honest(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=None: search_response(b'{"message": "not a list"}'))
    assert cli.main(["hunt", "--query", "demo", "--source", "gitlab",
                     "--out", str(tmp_path)]) == 1
    assert "search error" in capsys.readouterr().err


def test_hunt_report_counts_candidates_when_nothing_listed(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=None: search_response(json.dumps({"items": [
                            {"full_name": "o/one", "html_url": "https://github.com/o/one"},
                            {"full_name": "o/two", "html_url": "https://github.com/o/two"},
                        ]}).encode()))
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {})
    assert cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)]) == 0
    report = (tmp_path / "hunt-report.md").read_text()
    assert "Candidates scanned: 2" in report
    assert "with public manifests: 0" in report
    assert "listed below: 0" in report
    assert "absence of evidence is not evidence of safety" in report


def test_hunt_report_coverage_counts_manifests_and_listed(tmp_path, monkeypatch):
    monkeypatch.setattr(urllib.request, "urlopen",
                        lambda req, timeout=None: search_response(json.dumps({"items": [
                            {"full_name": "o/bare", "html_url": "https://github.com/o/bare"},
                            {"full_name": "o/clean", "html_url": "https://github.com/o/clean"},
                            {"full_name": "o/kev", "html_url": "https://github.com/o/kev"},
                        ]}).encode()))
    manifests = {
        "o/bare": {},
        "o/clean": {"package-lock.json": npm_lockfile({"left-pad": "1.3.0"})},
        "o/kev": {"requirements.txt": b"langflow==1.2.0\n"},
    }
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: manifests[f"{o}/{r}"])
    assert cli.main(["hunt", "--query", "demo", "--out", str(tmp_path)]) == 0
    report = (tmp_path / "hunt-report.md").read_text()
    assert "Candidates scanned: 3" in report
    assert "with public manifests: 2" in report
    assert "listed below: 1" in report
    assert "o/kev" in report
    assert "o/clean" not in report


def test_scan_records_letter_path_for_delivery(tmp_path, monkeypatch):
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"package-lock.json": npm_lockfile({"lodash": "4.17.15"})})
    out = tmp_path / "out"
    assert cli.main(["scan", "--repo", "o/r", "--out", str(out)]) == 0
    row = registry.SentRegistry().entries()[0]
    assert row["letter_path"] == str(out / "github.com_o_r-outreach.md")


def test_registry_list_shows_status_and_counts(capsys):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="github.com/o/r", contact=None, findings=3, kev_listed=1)
    reg.mark("fp-1", "sent")
    assert cli.main(["registry", "list"]) == 0
    out = capsys.readouterr().out
    assert "fp-1" in out and "sent" in out
    assert "findings=3" in out and "kev=1" in out


def test_registry_list_empty_is_honest(capsys):
    assert cli.main(["registry", "list"]) == 0
    assert "registry is empty" in capsys.readouterr().out


def test_registry_mark_resolves_target_and_moves_forward(capsys):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="github.com/o/r", contact=None, findings=0, kev_listed=0)
    assert cli.main(["registry", "mark", "github.com/o/r", "sent",
                     "--note", "by hand"]) == 0
    assert "fp-1" in capsys.readouterr().out
    fresh = registry.SentRegistry()
    assert fresh.seen("fp-1")["status"] == "sent"
    assert fresh.seen("fp-1")["note"] == "by hand"


def test_registry_mark_accepts_fingerprint_prefix(capsys):
    reg = registry.SentRegistry()
    reg.record("abcdef1234567890", target="t", contact=None, findings=0, kev_listed=0)
    assert cli.main(["registry", "mark", "abcdef", "read"]) == 0
    assert registry.SentRegistry().seen("abcdef1234567890")["status"] == "read"


def test_registry_mark_backward_is_refused(capsys):
    reg = registry.SentRegistry()
    reg.record("fp-1", target="t", contact=None, findings=0, kev_listed=0)
    reg.mark("fp-1", "read")
    assert cli.main(["registry", "mark", "fp-1", "sent"]) == 3
    assert "forward" in capsys.readouterr().err


def test_registry_mark_unknown_target_exits_2(capsys):
    assert cli.main(["registry", "mark", "ghost", "sent"]) == 2
    assert "no unique registry entry" in capsys.readouterr().err


def test_registry_mark_requires_arguments(capsys):
    assert cli.main(["registry", "mark"]) == 2
    assert "usage" in capsys.readouterr().err


class FakeSender:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[tuple[str, str]] = []
        self.fail = fail

    def send(self, to: str, subject: str, body: str) -> None:
        if self.fail:
            raise delivery.DeliveryError("boom")
        self.sent.append((to, subject))


def make_draft(tmp_path, fingerprint="fp-1", contact: str | None = "mailto:sec@example.test",
               name="letter-1.md", advisories=None, sources=None):
    letter = tmp_path / name
    letter.write_text(f"To: {contact}\n"
                      "Subject: Security finding in o/r - coordinated disclosure\n"
                      "\nbody\n")
    registry.SentRegistry().record(fingerprint, target="github.com/o/r",
                                   contact=contact, findings=1, kev_listed=0,
                                   letter_path=str(letter),
                                   advisories=advisories, sources=sources)
    return letter


def test_outreach_dry_run_reports_plan_and_sends_nothing(tmp_path, capsys):
    make_draft(tmp_path)
    assert cli.main(["outreach", "send", "--dry-run"]) == 0
    out = capsys.readouterr().out
    assert "would send -> sec@example.test" in out
    assert "nothing sent" in out
    assert registry.SentRegistry().seen("fp-1")["status"] == "drafted"


def test_outreach_without_smtp_config_fails_closed(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path)
    for name in ("SCOUT_SMTP_HOST", "SCOUT_SMTP_FROM"):
        monkeypatch.delenv(name, raising=False)
    assert cli.main(["outreach", "send"]) == 1
    assert "nothing sent" in capsys.readouterr().err
    assert registry.SentRegistry().seen("fp-1")["status"] == "drafted"


def test_outreach_send_marks_sent_on_success(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path)
    fake = FakeSender()
    monkeypatch.setattr(delivery, "smtp_sender_from_env", lambda: fake)
    assert cli.main(["outreach", "send"]) == 0
    assert "sent -> sec@example.test" in capsys.readouterr().out
    assert fake.sent == [("sec@example.test", "Security finding in o/r - coordinated disclosure")]
    assert registry.SentRegistry().seen("fp-1")["status"] == "sent"


def test_outreach_send_failure_keeps_draft(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path)
    monkeypatch.setattr(delivery, "smtp_sender_from_env", lambda: FakeSender(fail=True))
    assert cli.main(["outreach", "send"]) == 1
    err = capsys.readouterr().err
    assert "delivery failed" in err and "left drafted" in err
    assert registry.SentRegistry().seen("fp-1")["status"] == "drafted"


def test_outreach_nothing_to_deliver_is_honest(capsys):
    assert cli.main(["outreach", "send", "--dry-run"]) == 0
    assert "nothing to deliver" in capsys.readouterr().out


def test_scan_records_advisories_and_sources(tmp_path, monkeypatch):
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"langflow==1.2.0\n"})
    out = tmp_path / "out"
    assert cli.main(["scan", "--repo", "o/r", "--out", str(out)]) == 0
    row = registry.SentRegistry().entries()[0]
    assert row["advisories"]  # what was reported is recorded for later comparison
    assert row["sources"] == ["repo:o/r"]


def test_registry_refresh_marks_fixed_and_reports(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path, advisories=["GHSA-old-1", "GHSA-old-2"], sources=["repo:o/r"])
    monkeypatch.setattr(cli.refresh, "advisory_ids",
                        lambda result: {"GHSA-new"})  # current: none of the recorded
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"flask==99.0.0\n"})
    assert cli.main(["registry", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "fixed -" in out and "1 fixed" in out
    assert registry.SentRegistry().seen("fp-1")["status"] == "fixed"


def test_registry_refresh_leaves_open_entries_alone(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path, advisories=["GHSA-still-here", "GHSA-old"],
               sources=["repo:o/r"])
    registry.SentRegistry().mark("fp-1", "read")  # must survive refresh untouched
    monkeypatch.setattr(cli.refresh, "advisory_ids",
                        lambda result: {"GHSA-still-here"})  # one recorded still matches
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"langflow==1.2.0\n"})
    assert cli.main(["registry", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "open -" in out and "1 open" in out
    assert registry.SentRegistry().seen("fp-1")["status"] == "read"


def test_registry_refresh_falls_back_to_target_recipe(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path, advisories=["GHSA-x"])  # recorded without sources
    monkeypatch.setattr(cli.refresh, "advisory_ids", lambda result: {"GHSA-x"})
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"langflow==1.2.0\n"})
    assert cli.main(["registry", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "open -" in out  # verified via the target fallback recipe
    assert ": unverifiable -" not in out  # no entry fell through to unverifiable


def test_registry_refresh_without_artifacts_is_unverifiable(tmp_path, monkeypatch,
                                                             capsys):
    make_draft(tmp_path, advisories=["GHSA-x"], sources=["repo:o/r"])
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {})
    assert cli.main(["registry", "refresh"]) == 0
    out = capsys.readouterr().out
    assert ": unverifiable -" in out  # the entry's verdict line, not the summary
    assert registry.SentRegistry().seen("fp-1")["status"] == "drafted"


def test_registry_refresh_rerecord_backfills_baseline(tmp_path, monkeypatch, capsys):
    make_draft(tmp_path)  # recorded without an advisory list
    monkeypatch.setattr(cli.refresh, "current_advisories",
                        lambda files, target="": {"GHSA-a", "GHSA-b"})
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {"requirements.txt": b"x"})
    assert cli.main(["registry", "refresh", "--re-record"]) == 0
    out = capsys.readouterr().out
    assert "re-recorded -" in out and "1 re-recorded" in out
    row = registry.SentRegistry().entries()[0]
    assert row["advisories"] == ["GHSA-a", "GHSA-b"]
    assert row["status"] == "drafted"  # a backfill is not a status change
    # second run: the baseline exists now -> plain verification path,
    # and the baseline must NOT move
    monkeypatch.setattr(cli.refresh, "current_advisories",
                        lambda files, target="": {"GHSA-a"})
    assert cli.main(["registry", "refresh", "--re-record"]) == 0
    out = capsys.readouterr().out
    assert "open -" in out
    row = registry.SentRegistry().entries()[0]
    assert row["advisories"] == ["GHSA-a", "GHSA-b"]


def test_registry_refresh_rerecord_clean_scan_and_no_artifacts(tmp_path, monkeypatch,
                                                               capsys):
    make_draft(tmp_path)
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {})
    assert cli.main(["registry", "refresh", "--re-record"]) == 0
    assert ": unverifiable -" in capsys.readouterr().out
    monkeypatch.setattr(recon, "github_manifests", lambda o, r: {"requirements.txt": b"x"})
    monkeypatch.setattr(cli.refresh, "current_advisories",
                        lambda files, target="": set())
    assert cli.main(["registry", "refresh", "--re-record"]) == 0
    out = capsys.readouterr().out
    assert ": skipped -" in out and "mark fixed manually" in out
    assert registry.SentRegistry().entries()[0]["advisories"] is None


def test_registry_refresh_backfills_contact_from_security_txt(tmp_path, monkeypatch,
                                                              capsys):
    make_draft(tmp_path, contact=None, advisories=["GHSA-x"],
               sources=["url:https://site.test"])
    monkeypatch.setattr(cli.refresh, "advisory_ids", lambda result: {"GHSA-x"})
    monkeypatch.setattr(refresh.recon, "fetch_security_txt",
                        lambda url: ("txt", "mailto:sec@example.test"))
    monkeypatch.setattr(refresh.recon, "manifests_from_site",
                        lambda u: {"package-lock.json": b"{}"})
    assert cli.main(["registry", "refresh"]) == 0
    out = capsys.readouterr().out
    assert "contact backfilled -> mailto:sec@example.test" in out
    assert "1 contacts backfilled" in out
    row = registry.SentRegistry().entries()[0]
    assert row["contact"] == "mailto:sec@example.test"
    # second run: the contact is recorded now -> no second backfill
    assert cli.main(["registry", "refresh"]) == 0
    assert "contact backfilled" not in capsys.readouterr().out


def test_unreadable_registry_maps_to_clean_error(monkeypatch, capsys):
    def boom():
        raise registry.RegistryError("registry unreadable: /x: denied")
    monkeypatch.setattr(registry, "SentRegistry", boom)
    assert cli.main(["registry", "list"]) == 1
    err = capsys.readouterr().err
    assert "registry error" in err and "unreadable" in err


def test_audit_refuses_before_any_fetch(auth_dir, monkeypatch, capsys):
    def boom(*args, **kwargs):
        raise AssertionError("fetch must not happen before the authorization gate")
    monkeypatch.setattr(recon, "github_manifests", boom)
    monkeypatch.setattr(recon, "manifests_from_site", boom)
    assert cli.main(["audit", "--contract", "nope", "--repo", "o/r"]) == 3
    assert "refused" in capsys.readouterr().err


def test_audit_writes_result_json_and_reports_llm_status(auth_dir, tmp_path,
                                                        monkeypatch, capsys):
    guard.activate("c-1", scope=["db.example"], hours=24)
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"langflow==1.2.0\n"})

    def fake_run_audit(contract_id, files, **kwargs):
        return {"contract_id": contract_id, "target": kwargs.get("target"),
                "engine_commit": "abc123",
                "result": {"findings": [{"title": "x"}], "score": {"total": 4.2},
                           "llm": {"skipped_reason": "no_providers_configured",
                                   "calls": 0},
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "llm:      skipped (no_providers_configured)" in out
    assert "findings: 1 (score 4.2)" in out
    saved = json.loads((tmp_path / "github.com_o_r-audit.json").read_text())
    assert saved["contract_id"] == "c-1" and saved["engine_commit"] == "abc123"


def test_audit_reports_failed_llm_honestly(auth_dir, tmp_path, monkeypatch,
                                           capsys):
    guard.activate("c-1", scope=["db.example"], hours=24)
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"x\n"})

    def fake_run_audit(contract_id, files, **kwargs):
        return {"contract_id": contract_id, "target": "t", "engine_commit": "x",
                "result": {"findings": [], "score": {}, "llm": "failed: 402",
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--out", str(tmp_path)]) == 0
    assert "llm:      failed: 402" in capsys.readouterr().out


def test_audit_reports_partial_llm_failure_honestly(auth_dir, tmp_path,
                                                    monkeypatch, capsys):
    guard.activate("c-1", scope=["db.example"], hours=24)
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"x\n"})

    def fake_run_audit(contract_id, files, **kwargs):
        return {"contract_id": contract_id, "target": "t", "engine_commit": "x",
                "result": {"findings": [], "score": {},
                           "llm": {"failure": "cost_cap_exceeded", "prompts": 2},
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--out", str(tmp_path)]) == 0
    assert "llm:      partial - cost_cap_exceeded" in capsys.readouterr().out


def test_audit_writes_deep_report(auth_dir, tmp_path, monkeypatch, capsys):
    guard.activate("c-1", scope=["db.example"], hours=24)
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"x\n"})

    def fake_run_audit(contract_id, files, **kwargs):
        return {"contract_id": contract_id, "target": "github.com/o/r",
                "engine_commit": "abc",
                "result": {"findings": [], "score": {"basis": "static_only"},
                           "llm": {"skipped_reason": "no_providers_configured"},
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    evidence = tmp_path / "db-evidence.json"
    evidence.write_text('[{"label": "tables", "observation": "42 tables"}]')
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--db-evidence", str(evidence),
                     "--out", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "deep:" in out
    deep = (tmp_path / "github.com_o_r-deep-report.md").read_text()
    assert "Deep security assessment: github.com/o/r" in deep
    assert "table inventory" not in deep and "42 tables" in deep


def test_audit_accepts_customer_archive(auth_dir, tmp_path, monkeypatch, capsys):
    import zipfile
    guard.activate("c-1", scope=["customer"], hours=24)
    archive = tmp_path / "customer-repo.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("app/main.py", "print('hello')\n")
        zf.writestr("app/", "")
    seen = {}

    def fake_run_audit(contract_id, files, **kwargs):
        seen.update(files)
        seen["_target"] = kwargs.get("target")
        return {"contract_id": contract_id, "target": kwargs.get("target"),
                "engine_commit": "x",
                "result": {"findings": [], "score": {},
                           "llm": {"skipped_reason": "no_providers_configured"},
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(archive),
                     "--out", str(tmp_path)]) == 0
    assert seen["app/main.py"] == b"print('hello')\n"
    assert "app/" not in seen  # directory entries are not artifacts
    assert seen["_target"] == "customer-repo"


def test_audit_archive_and_repo_merges_files(auth_dir, tmp_path, monkeypatch):
    import zipfile
    guard.activate("c-1", scope=["customer"], hours=24)
    archive = tmp_path / "customer-repo.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("app/main.py", "print('hello')\n")
    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"flask==3.0.0\n"})
    seen = {}

    def fake_run_audit(contract_id, files, **kwargs):
        seen.update(files)
        return {"contract_id": contract_id, "target": kwargs.get("target"),
                "engine_commit": "x",
                "result": {"findings": [], "score": {},
                           "llm": {"skipped_reason": "no_providers_configured"},
                           "llm_usage": None, "sca": {}}}
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", fake_run_audit)
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(archive),
                     "--repo", "o/r", "--out", str(tmp_path)]) == 0
    assert "app/main.py" in seen
    assert "requirements.txt" in seen


def test_audit_unreadable_archive_and_db_evidence_fail_cleanly(auth_dir, tmp_path,
                                                               monkeypatch, capsys):
    guard.activate("c-1", scope=["customer"], hours=24)
    missing = tmp_path / "missing.zip"
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(missing),
                     "--out", str(tmp_path)]) == 1
    assert "unreadable archive" in capsys.readouterr().err

    corrupt = tmp_path / "corrupt.zip"
    corrupt.write_bytes(b"not a zip archive")
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(corrupt),
                     "--out", str(tmp_path)]) == 1
    assert "unreadable archive" in capsys.readouterr().err

    monkeypatch.setattr(recon, "github_manifests",
                        lambda o, r: {"requirements.txt": b"x\n"})
    import scout.audit as audit_mod
    monkeypatch.setattr(audit_mod, "run_audit", lambda cid, files, **kw: {
        "contract_id": cid, "target": "t", "engine_commit": "x",
        "result": {"findings": [], "score": {},
                   "llm": {"skipped_reason": "no_providers_configured"},
                   "llm_usage": None, "sca": {}}})
    bad_ev = tmp_path / "bad.json"
    bad_ev.write_text("{broken")
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--db-evidence", str(bad_ev), "--out", str(tmp_path)]) == 1
    assert "unreadable --db-evidence" in capsys.readouterr().err

    dict_ev = tmp_path / "dict.json"
    dict_ev.write_text('{"not": "a list"}')
    assert cli.main(["audit", "--contract", "c-1", "--repo", "o/r",
                     "--db-evidence", str(dict_ev), "--out", str(tmp_path)]) == 1
    assert "must be a JSON list" in capsys.readouterr().err


def test_audit_refuses_oversized_archive(auth_dir, tmp_path, monkeypatch, capsys):
    import zipfile
    guard.activate("c-1", scope=["customer"], hours=24)
    archive = tmp_path / "big.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("a.py", "x = 1\n")
        zf.writestr("b.py", "y = 2\n")
    monkeypatch.setattr(cli, "MAX_ARCHIVE_BYTES", 5)  # pretend the bound is tiny
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(archive),
                     "--out", str(tmp_path)]) == 1
    assert "exceeds the audit bound" in capsys.readouterr().err
    monkeypatch.setattr(cli, "MAX_ARCHIVE_MEMBERS", 1)  # same for member count
    monkeypatch.setattr(cli, "MAX_ARCHIVE_BYTES", 200 * 1024 * 1024)
    assert cli.main(["audit", "--contract", "c-1", "--archive", str(archive),
                     "--out", str(tmp_path)]) == 1


def test_db_query_refuses_out_of_scope_before_any_connection(auth_dir, monkeypatch,
                                                            capsys):
    import scout.db as db_mod
    guard.activate("c-2", scope=["db.in-scope.example"], hours=24)

    def boom(dsn):
        raise AssertionError("connection must not be attempted out of scope")
    monkeypatch.setattr(db_mod, "postgres_connect", boom)
    assert cli.main(["db", "query", "--contract", "c-2",
                     "--target", "db.out-of-scope.example", "SELECT 1"]) == 3
    assert "refused" in capsys.readouterr().err


def test_db_query_requires_dsn_env(auth_dir, monkeypatch, capsys):
    import scout.db as db_mod
    guard.activate("c-3", scope=["db.example"], hours=24)
    monkeypatch.delenv(db_mod.DSN_ENV, raising=False)
    assert cli.main(["db", "query", "--contract", "c-3",
                     "--target", "db.example", "SELECT 1"]) == 2
    err = capsys.readouterr().err
    assert db_mod.DSN_ENV in err and "credential" in err


def test_db_query_runs_and_audits(auth_dir, tmp_path, monkeypatch, capsys):
    import scout.active as active_mod
    import scout.db as db_mod
    guard.activate("c-4", scope=["db.example"], hours=24)
    monkeypatch.setenv(db_mod.DSN_ENV, "postgresql://host/db")
    monkeypatch.setattr(active_mod, "AUDIT_LOG_DIR", tmp_path / "audit-log")

    class Cursor:
        def execute(self, sql, params=None):
            pass
        def fetchall(self):
            return [(1, "row-a"), (2, "row-b")]
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    class Conn:
        def cursor(self):
            return Cursor()
        def close(self):
            pass
    monkeypatch.setattr(db_mod, "postgres_connect", lambda dsn: lambda: Conn())
    assert cli.main(["db", "query", "--contract", "  c-4  ",
                     "--target", "db.example", "SELECT 1"]) == 0
    out = capsys.readouterr().out
    assert "(1, 'row-a')" in out and "(2, 'row-b')" in out
    lines = (tmp_path / "audit-log" / "c-4.jsonl").read_text().splitlines()
    assert json.loads(lines[0])["contract_id"] == "c-4"
