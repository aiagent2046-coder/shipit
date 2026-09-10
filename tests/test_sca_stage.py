"""The SCA stage, driven by a transport that never opens a socket.

Every test here replaces the transport, so the suite proves what the stage does
with an answer and what it does WITHOUT one. The offline cases are the point:
an audit that cannot reach the database must not report a clean repository, and
must not fail the audit either.
"""
from __future__ import annotations

import io
import json
import zipfile

import httpx
import pytest

from app.sca import osv as osv_module
from app.sca.lockfiles import Dependency
from app.sca.osv import OsvClient, OsvUnavailable
from app.sca.stage import CHECKS_RUN_KEY, RULE_ID, run_sca_stage

LODASH_ADVISORY = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "summary": "Command Injection in lodash",
    "details": "`lodash` versions prior to 4.17.21 are vulnerable.",
    "aliases": ["CVE-2021-23337"],
    "published": "2021-05-06T16:05:51Z",
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]},
    "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                  "ranges": [{"type": "SEMVER",
                              "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}]}],
    "references": [{"type": "ADVISORY",
                    "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
}


class FakeResponse:
    def __init__(self, status_code: int, payload: object):
        self.status_code = status_code
        self._payload = payload

    def json(self) -> object:
        return self._payload


class FakeTransport:
    """Answers the two documented shapes; records what was asked.

    `batches` is one `results` ARRAY per POST -- the shape /v1/querybatch
    returns -- not a single result object. Getting that wrong makes every
    response look malformed, which is exactly what happened the first time this
    fixture was written.
    """

    def __init__(self, batches: list[list[dict]], details: dict[str, dict],
                 status: int = 200, raw: object = None):
        self.batches = batches
        self.details = details
        self.status = status
        self.raw = raw
        self.posts: list[dict] = []
        self.gets: list[str] = []

    def post(self, url: str, *, json: dict | None = None) -> FakeResponse:
        self.posts.append(json or {})
        if self.status != 200:
            return FakeResponse(self.status, {})
        if self.raw is not None:
            return FakeResponse(200, self.raw)
        index = min(len(self.posts) - 1, len(self.batches) - 1)
        return FakeResponse(200, {"results": self.batches[index]})

    def get(self, url: str) -> FakeResponse:
        self.gets.append(url)
        record = self.details.get(url.rsplit("/", 1)[-1])
        if record is None:
            return FakeResponse(404, {})
        return FakeResponse(200, record)


def make_zip(entries: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, text in entries.items():
            zf.writestr(name, text)
    return buf.getvalue()


def repo_with(version: str = "4.17.4") -> bytes:
    return make_zip({
        "package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
        "package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "node_modules/lodash": {"version": version}}}),
    })


def client_for(transport: FakeTransport) -> OsvClient:
    return OsvClient(transport=transport)


def one_advisory(record: dict | None = None) -> FakeTransport:
    return FakeTransport([[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]],
                         {"GHSA-35jh-r3h4-6jhm": record or LODASH_ADVISORY})


def test_a_vulnerable_pinned_version_is_reported():
    findings, stats = run_sca_stage(repo_with(), client_for(one_advisory()))

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == RULE_ID
    assert finding.severity == "high"
    assert finding.file == "package-lock.json"
    assert "CVE-2021-23337" in finding.title, "the searchable identifier wins"
    assert "lodash 4.17.4" in finding.title
    assert "4.17.21" in finding.fix_hint
    assert finding.confidence == 0.9
    assert stats["checks_run"] == [CHECKS_RUN_KEY]
    assert stats["dependencies"] == 1 and stats["advisories"] == 1
    assert stats["dependencies_found"] == 1
    assert stats["findings"] == 1 and stats["skipped_reason"] is None
    assert stats["asked_at"], "an answer that is true only of today must say when"


def test_the_finding_does_not_claim_the_code_is_exploitable():
    findings, _ = run_sca_stage(repo_with(), client_for(one_advisory()))
    assert "was NOT checked" in findings[0].explanation, (
        "a database match is not a reachability proof; the wording must say so")


def test_a_patched_version_is_silent():
    transport = FakeTransport([[]], {})
    findings, stats = run_sca_stage(repo_with("4.17.21"), client_for(transport))
    assert findings == []
    assert stats["dependencies"] == 1
    assert stats["skipped_reason"] is None, "the database was asked and had nothing"
    assert transport.gets == [], "no advisory means no detail lookup"


def test_no_lockfile_asks_nothing_and_says_so():
    transport = FakeTransport([[]], {})
    findings, stats = run_sca_stage(make_zip({"src/app.py": "print(1)\n"}),
                                   client_for(transport))
    assert findings == []
    assert stats["skipped_reason"] == "no_lockfile"
    assert stats["asked_at"] is None, "nobody was asked, so there is no date"
    assert transport.posts == [], "nothing to look up means no request"


def test_no_client_records_that_nobody_asked():
    findings, stats = run_sca_stage(repo_with(), None)
    assert findings == []
    assert stats["skipped_reason"] == "no_client"
    assert stats["dependencies"] == 1, "the dependencies were found, not absent"


def test_an_unreachable_database_skips_the_stage_instead_of_failing_it():
    class DeadTransport:
        def post(self, url, *, json=None):
            raise httpx.ConnectError("no route to host")

        def get(self, url):
            raise httpx.ConnectError("no route to host")

    findings, stats = run_sca_stage(repo_with(), OsvClient(transport=DeadTransport()))
    assert findings == []
    assert str(stats["skipped_reason"]).startswith("osv_unavailable")
    assert "ConnectError" in str(stats["skipped_reason"])


@pytest.mark.parametrize("status", [500, 429, 404])
def test_an_error_status_skips_the_stage(status):
    transport = FakeTransport([[]], {}, status=status)
    findings, stats = run_sca_stage(repo_with(), client_for(transport))
    assert findings == []
    assert str(stats["skipped_reason"]).startswith("osv_unavailable")
    assert f"HTTP {status}" in str(stats["skipped_reason"])


def test_low_severity_advisories_are_filtered_and_counted():
    record = {**LODASH_ADVISORY, "database_specific": {"severity": "LOW"}}
    findings, stats = run_sca_stage(repo_with(), client_for(one_advisory(record)))
    assert findings == []
    assert stats["below_severity_floor"] == 1
    assert stats["advisories"] == 1


def test_an_advisory_without_a_declared_rating_is_reported_weaker():
    silent = {k: v for k, v in LODASH_ADVISORY.items() if k != "database_specific"}
    findings, _ = run_sca_stage(repo_with(), client_for(one_advisory(silent)))
    assert findings[0].severity == "medium"
    assert findings[0].confidence == 0.6, (
        "an assumed rating is weaker evidence than a declared one")


def test_an_unreadable_advisory_does_not_discard_the_readable_one():
    transport = FakeTransport(
        [[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}, {"id": "GHSA-gone-0000-0000"}]}]],
        {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY})
    findings, stats = run_sca_stage(repo_with(), client_for(transport))
    assert [f.severity for f in findings] == ["high"], (
        "the second ID has no detail to serve; only the readable one is reported")
    assert stats["unreadable_advisories"] == 1


def test_a_confirmed_match_survives_a_failed_detail_fetch():
    """Reproduced end to end: an HTTP 503 on a detail lookup used to delete a
    confirmed vulnerability from the report and RAISE the score (1 finding ->
    0, 9.3 -> 9.6). A failure must never move the report in the good direction.

    Two packages: one advisory loads, one does not. The loaded match keeps its
    rating; the unloaded one is reported as a match whose details are unknown --
    at the floor severity, with a confidence that says so.
    """
    class OneDetailDown(FakeTransport):
        def __init__(self):
            super().__init__(
                [[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]},
                  {"vulns": [{"id": "GHSA-gone-0000-0000"}]}]],
                {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY})

        def get(self, url):
            record = self.details.get(url.rsplit("/", 1)[-1])
            return FakeResponse(200, record) if record else FakeResponse(503, {})

    repo = make_zip({"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.4"},
        "node_modules/other": {"version": "1.0.0"}}})})
    findings, stats = run_sca_stage(repo, OsvClient(transport=OneDetailDown()))

    by_name = {f.title.split()[-2]: f for f in findings}
    assert set(by_name) == {"lodash", "other"}, "both confirmed matches survive"
    assert by_name["lodash"].severity == "high"
    assert by_name["lodash"].confidence == 0.9, "its record loaded"
    assert by_name["other"].severity == "medium", (
        "an unknown rating is reported at the floor, never invented upward")
    assert by_name["other"].confidence == 0.4
    assert "details could not be fetched" in by_name["other"].explanation
    assert stats["asked_at"], "the batch did answer"
    assert stats["unreadable_advisories"] == 1


def test_when_no_detail_could_be_fetched_nothing_is_claimed():
    class AllDetailsDown(FakeTransport):
        def __init__(self):
            super().__init__([[{"vulns": [{"id": "GHSA-aaaa-0000-0000"}]},
                              {"vulns": [{"id": "GHSA-bbbb-0000-0000"}]}]], {})

        def get(self, url):
            return FakeResponse(503, {})

    findings, stats = run_sca_stage(repo_with(), OsvClient(transport=AllDetailsDown()))
    assert findings == []
    assert str(stats["skipped_reason"]).startswith("osv_unavailable"), (
        "a database that answered nothing is not a clean dependency report")
    assert stats["asked_at"] is None, "nothing was established, so nothing is dated"


def test_the_upgrade_advice_names_one_target_and_flags_the_earlier_fix():
    """Fixes on two branches used to be offered as equals -- "upgrade to 2.0.0,
    or 1.5.0 or later" -- and taking 1.5.0 leaves the advisory that needed
    2.0.0. Advice that undoes itself."""
    records = {
        "GHSA-aaaa-0000-0000": {**LODASH_ADVISORY, "id": "GHSA-aaaa-0000-0000",
                                "aliases": ["CVE-2020-0001"],
                                "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                              "ranges": [{"events": [{"fixed": "1.5.0"}]}]}]},
        "GHSA-bbbb-0000-0000": {**LODASH_ADVISORY, "id": "GHSA-bbbb-0000-0000",
                                "aliases": ["CVE-2020-0002"],
                                "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                                              "ranges": [{"events": [{"fixed": "2.0.0"}]}]}]},
    }
    transport = FakeTransport([[{"vulns": [{"id": k} for k in records]}]], records)
    findings, _stats = run_sca_stage(repo_with(), client_for(transport))

    fix = findings[0].fix_hint
    assert "Upgrade to 2.0.0 or later" in fix
    assert "or 1.5.0 or later" not in fix, "an earlier fix is not an equal option"
    assert "1.5.0" in fix and "do not clear every advisory" in fix, (
        "the earlier fix is named, and named as insufficient")


def test_batches_are_split_and_results_line_up_with_dependencies():
    packages = {f"node_modules/pkg{i}": {"version": "1.0.0"} for i in range(3)}
    advisory = {**LODASH_ADVISORY, "affected": []}
    transport = FakeTransport(
        [[], [{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}], []],
        {"GHSA-35jh-r3h4-6jhm": advisory})
    client = OsvClient(transport=transport, batch_size=1)
    findings, stats = run_sca_stage(
        make_zip({"package-lock.json": json.dumps({"lockfileVersion": 3,
                                                   "packages": packages})}), client)
    assert len(transport.posts) == 3, "one request per batch"
    assert len(findings) == 1, "the advisory belongs to the middle dependency"
    assert findings[0].title.endswith("pkg1 1.0.0")
    assert stats["requests"] == 4, "three batches and one detail lookup"


def test_two_packages_are_ordered_by_severity_and_the_order_is_stable():
    repo = make_zip({"package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/aaa-high": {"version": "1.0.0"},
        "node_modules/zzz-critical": {"version": "1.0.0"}}})})
    critical = {**LODASH_ADVISORY, "id": "GHSA-crit-0000-0000",
                "aliases": ["CVE-2020-9999"], "affected": [],
                "database_specific": {"severity": "CRITICAL"}}
    transport = FakeTransport(
        [[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}, {"vulns": [{"id": "GHSA-crit-0000-0000"}]}]],
        {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY, "GHSA-crit-0000-0000": critical})
    findings, _ = run_sca_stage(repo, client_for(transport))
    assert [f.severity for f in findings] == ["critical", "high"]
    assert "zzz-critical" in findings[0].title
    again, _ = run_sca_stage(repo, client_for(transport))
    assert [f.title for f in again] == [f.title for f in findings]


def test_two_records_for_one_cve_become_one_finding_with_the_furthest_fix():
    """Measured against the live API: lodash 4.17.21 matched two entries that
    both resolve to CVE-2025-13465, and reporting them separately printed the
    same CVE twice with two different upgrade targets."""
    first = {**LODASH_ADVISORY, "id": "GHSA-aaaa-0000-0000",
             "aliases": ["CVE-2025-13465"], "summary": "Prototype pollution",
             "database_specific": {"severity": "MODERATE"},
             "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                           "ranges": [{"events": [{"fixed": "4.17.23"}]}]}]}
    second = {**LODASH_ADVISORY, "id": "GHSA-bbbb-0000-0000",
              "aliases": ["CVE-2025-13465"], "summary": "Prototype pollution",
              "database_specific": {"severity": "HIGH"},
              "affected": [{"package": {"ecosystem": "npm", "name": "lodash"},
                            "ranges": [{"events": [{"fixed": "4.18.0"}]}]}]}
    transport = FakeTransport(
        [[{"vulns": [{"id": "GHSA-aaaa-0000-0000"}, {"id": "GHSA-bbbb-0000-0000"}]}]],
        {"GHSA-aaaa-0000-0000": first, "GHSA-bbbb-0000-0000": second})
    findings, stats = run_sca_stage(repo_with("4.17.21"), client_for(transport))

    assert len(findings) == 1, "one CVE is one row"
    assert findings[0].severity == "high", "the higher of the merged ratings"
    assert "4.18.0" in findings[0].fix_hint, "the furthest fix satisfies both"
    assert stats["advisories"] == 2


def test_a_package_with_many_advisories_is_one_row_that_names_the_worst():
    """Measured live: django==2.0.0 matches 24 advisories whose fix is one
    action. Twenty-four rows bury that action, so the unit is the package."""
    records = {}
    ids = []
    for index, (alias, severity) in enumerate(
            [("CVE-2020-0001", "MODERATE"), ("CVE-2020-0002", "CRITICAL"),
             ("CVE-2020-0003", "LOW")]):
        advisory_id = f"GHSA-{index:04d}-0000-0000"
        ids.append(advisory_id)
        records[advisory_id] = {**LODASH_ADVISORY, "id": advisory_id,
                                "aliases": [alias],
                                "database_specific": {"severity": severity}}
    transport = FakeTransport([[{"vulns": [{"id": i} for i in ids]}]], records)
    findings, stats = run_sca_stage(repo_with(), client_for(transport))

    assert len(findings) == 1, "one package is one row"
    finding = findings[0]
    assert finding.severity == "critical", "the worst advisory sets the row"
    assert "3 known vulnerabilities" in finding.title
    for alias in ("CVE-2020-0001", "CVE-2020-0002", "CVE-2020-0003"):
        assert alias in finding.explanation, "every advisory is still named"
    assert stats["reported_advisories"] == 3
    assert stats["below_severity_floor"] == 0, (
        "the floor is about the package's worst rating, not its mildest")


def test_a_package_whose_worst_advisory_is_low_is_still_filtered():
    low = {**LODASH_ADVISORY, "database_specific": {"severity": "LOW"}}
    transport = FakeTransport([[{"vulns": [{"id": "GHSA-35jh-r3h4-6jhm"}]}]],
                              {"GHSA-35jh-r3h4-6jhm": low})
    findings, stats = run_sca_stage(repo_with(), client_for(transport))
    assert findings == []
    assert stats["below_severity_floor"] == 1


def test_at_most_four_advisories_are_named_and_the_rest_are_counted():
    records = {}
    ids = []
    for index in range(6):
        advisory_id = f"GHSA-{index:04d}-0000-0000"
        ids.append(advisory_id)
        records[advisory_id] = {**LODASH_ADVISORY, "id": advisory_id,
                                "aliases": [f"CVE-2020-000{index}"],
                                "database_specific": {"severity": "HIGH"}}
    transport = FakeTransport([[{"vulns": [{"id": i} for i in ids]}]], records)
    findings, _ = run_sca_stage(repo_with(), client_for(transport))
    assert len(findings) == 1
    assert "6 known vulnerabilities" in findings[0].title
    assert "and 2 more" in findings[0].explanation, (
        "a cap on what is named must say how much was not")


@pytest.mark.parametrize("development,expected", [
    (True, "installed for development only"),
    (False, "lists this dependency directly"),
])
def test_the_row_says_where_the_package_came_from(development, expected):
    lock = json.dumps({"lockfileVersion": 3, "packages": {
        "node_modules/lodash": {"version": "4.17.4", "dev": development}}})
    repo = make_zip({"package.json": json.dumps({"dependencies": {"lodash": "^4.17.0"}}),
                     "package-lock.json": lock})
    findings, _ = run_sca_stage(repo, client_for(one_advisory()))
    assert expected in findings[0].explanation


def test_a_lockfile_that_cannot_be_parsed_does_not_abort_the_audit(monkeypatch):
    """The stage promises the audit never fails because of it, and that promise
    has to cover parsing too: a lockfile is input, and no input may take an
    audit down. Whatever the shape turns out to be, the reason is recorded."""
    def exploding(_data):
        raise RecursionError("nested deeper than this parser can walk")

    monkeypatch.setattr("app.sca.stage.collect_dependencies", exploding)
    findings, stats = run_sca_stage(repo_with(), client_for(one_advisory()))
    assert findings == []
    assert stats["skipped_reason"] == "lockfile_unreadable: RecursionError"


def test_an_archive_with_only_go_sum_says_why_nothing_was_asked():
    gosum = make_zip({"go.sum": "github.com/example/retired v1.0.0 h1:aaa=\n"})
    findings, stats = run_sca_stage(gosum, client_for(one_advisory()))
    assert findings == []
    assert stats["skipped_reason"] == "no_resolvable_lockfile"
    assert stats["unusable_lockfiles"] == ["go.sum"]


def test_query_raises_unavailable_when_the_body_is_not_the_documented_shape():
    transport = FakeTransport([], {}, raw={"unexpected": "shape"})
    with pytest.raises(OsvUnavailable):
        OsvClient(transport=transport).query(
            [Dependency("npm", "lodash", "4.17.4", "package-lock.json")])


def test_a_non_dict_body_is_rejected_rather_than_iterated():
    transport = FakeTransport([], {}, raw=[])
    with pytest.raises(OsvUnavailable):
        OsvClient(transport=transport).query(
            [Dependency("npm", "lodash", "4.17.4", "package-lock.json")])


def test_the_default_transport_is_httpx_and_the_base_url_is_the_documented_one():
    assert osv_module.OSV_BASE == "https://api.osv.dev"
    assert OsvClient().base_url == "https://api.osv.dev"
    assert OsvClient().transport is None


def test_a_failed_detail_lookup_does_not_lose_the_advisories_that_loaded():
    transport = FakeTransport([[]], {"GHSA-35jh-r3h4-6jhm": LODASH_ADVISORY})
    client = OsvClient(transport=transport)
    records = client.details(["GHSA-35jh-r3h4-6jhm", "GHSA-gone-0000-0000"])
    assert list(records) == ["GHSA-35jh-r3h4-6jhm"]
    assert client.requests_made == 2
