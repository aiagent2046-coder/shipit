"""CVE enrichment must remain bounded and never manufacture database evidence."""
from copy import deepcopy
import json

import httpx
import pytest

from app.sca.cve import CveClient, empty_cve_summary, normalize_cve_summary

FIRST = "CVE-2021-23337"
SECOND = "CVE-2024-7033"
THIRD = "CVE-2021-44228"


def published(cve_id=FIRST, version="5.1"):
    return {
        "dataType": "CVE_RECORD", "dataVersion": version,
        "cveMetadata": {"cveId": cve_id, "state": "PUBLISHED",
                        "datePublished": "2021-02-15T12:15:14.715Z",
                        "dateUpdated": "2024-09-16T19:15:17.074Z"},
        "containers": {"cna": {
            "providerMetadata": {"shortName": "example-cna"}, "title": "Example vulnerability",
            "descriptions": [{"lang": "fr", "value": "Description française"},
                             {"lang": "en-US", "value": "CNA English description"}],
            "problemTypes": [{"descriptions": [{"cweId": "CWE-78"}, {"cweId": "CWE-78"},
                                                {"description": "Other issue"}]}],
        }},
    }


def client_for(record, **kwargs):
    return CveClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=record)), **kwargs)


def assert_accounting(result):
    assert result["attempted"] == result["resolved"] + result["unavailable"]
    assert result["requested"] == result["attempted"] + result["not_requested"]
    assert result["resolved"] == len(result["records"])
    assert result["unavailable"] == len(result["errors"])
    assert normalize_cve_summary(result) == result


@pytest.mark.parametrize("version", ["5.0", "5.0.0", "5.1", "5.1.0", "5.1.1", "5.2", "5.2.0"])
def test_known_record_versions_and_cna_attribution(version):
    record = published(version=version)
    record["containers"]["adp"] = [{"providerMetadata": {"shortName": "another-source"},
                                     "descriptions": [{"lang": "en", "value": "Different assessment"}],
                                     "metrics": [{"cvssV3_1": {"baseScore": 10}}]}]
    result = client_for(record).lookup([FIRST])
    assert result["status"] == "complete"
    assert result["records"][0] == {
        "id": FIRST, "state": "PUBLISHED", "title": "Example vulnerability",
        "description": "CNA English description", "provider": "example-cna", "data_version": version,
        "published_at": "2021-02-15T12:15:14.715Z", "updated_at": "2024-09-16T19:15:17.074Z",
        "cwes": ["CWE-78"], "url": f"https://www.cve.org/CVERecord?id={FIRST}",
        "record_url": f"https://cveawg.mitre.org/api/cve/{FIRST}",
    }
    assert_accounting(result)


def test_only_unique_strict_ids_reach_fixed_host_without_credentials():
    seen = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json=published(request.url.path.rsplit("/", 1)[1]))

    client = CveClient(transport=httpx.MockTransport(handler))
    result = client.lookup([FIRST, FIRST, "cve-2021-23337", FIRST + "\n", FIRST + "/../../metadata",
                            "https://evil.test/", "CVE-2021-123", "CVE-2021-" + "1" * 20,
                            None, 1, SECOND])
    assert result["requested"] == result["attempted"] == 2
    assert [str(r.url) for r in seen] == [f"https://cveawg.mitre.org/api/cve/{FIRST}",
                                        f"https://cveawg.mitre.org/api/cve/{SECOND}"]
    assert all(r.method == "GET" and "authorization" not in r.headers for r in seen)
    assert_accounting(result)


def test_rejected_record_preserves_rejection_without_old_vulnerability_description():
    record = published(SECOND, "5.2")
    record["cveMetadata"]["state"] = "REJECTED"
    record["containers"]["cna"]["rejectedReasons"] = [{"lang": "en", "value": "Duplicate CVE ID."}]
    result = client_for(record).lookup([SECOND])
    assert result["status"] == "complete" and result["rejected"] == 1
    normalized = result["records"][0]
    assert normalized["description"] == "Duplicate CVE ID."
    assert normalized["title"] == "" and normalized["cwes"] == []
    assert_accounting(result)


@pytest.mark.parametrize("mutate", [
    lambda r: r.update(dataType="UNKNOWN"),
    lambda r: r["cveMetadata"].update(cveId=SECOND),
    lambda r: r["cveMetadata"].update(state="RESERVED"),
    lambda r: r["cveMetadata"].update(datePublished="2024-02-30T00:00:00Z"),
    lambda r: r.update(containers=[]),
    lambda r: r["containers"]["cna"].update(providerMetadata="CNA"),
    lambda r: r["containers"]["cna"].update(title={"unsafe": "html"}),
    lambda r: r["containers"]["cna"].update(descriptions=[{"lang": "fr", "value": "French only"}]),
    lambda r: r["containers"]["cna"].update(descriptions=[{"lang": "en", "value": []}]),
    lambda r: r["containers"]["cna"].update(problemTypes=[{"descriptions": [42]}]),
])
def test_malformed_consumed_fields_cannot_become_resolved_evidence(mutate):
    record = published()
    mutate(record)
    result = client_for(record).lookup([FIRST])
    assert result["status"] == "unavailable" and result["records"] == []
    assert result["errors"] == [{"id": FIRST, "reason": "invalid_record"}]
    assert_accounting(result)


@pytest.mark.parametrize("version", [None, 5.1, "4.0", "6.0", "5.3", "5.01", "5.2.00", "5.2\n"])
def test_unknown_versions_are_explicitly_unavailable(version):
    result = client_for(published(version=version)).lookup([FIRST])
    assert result["errors"] == [{"id": FIRST, "reason": "unsupported_schema"}]
    assert_accounting(result)


def test_record_budget_preserves_partial_evidence_and_accounts_for_unrequested_ids():
    requests = []

    def handler(request):
        cve_id = request.url.path.rsplit("/", 1)[1]
        requests.append(cve_id)
        return httpx.Response(200, json=published(cve_id))

    result = CveClient(transport=httpx.MockTransport(handler), max_records=1).lookup([FIRST, SECOND])
    assert requests == [FIRST]
    assert result["status"] == "partial" and result["not_requested"] == 1
    assert_accounting(result)


@pytest.mark.parametrize("bounds", [{"max_records": 0}, {"time_budget": 0}])
def test_zero_budget_does_not_send_a_request(bounds):
    def forbidden(_):
        pytest.fail("No request is allowed with zero budget")
    client = CveClient(transport=httpx.MockTransport(forbidden), **bounds)
    result = client.lookup([FIRST])
    assert result["status"] == "unavailable" and result["checked_at"] is None
    assert result["not_requested"] == 1
    assert_accounting(result)


def test_rate_limit_stops_later_ids_without_retry_and_keeps_successes():
    seen = []

    def handler(request):
        seen.append(request.url.path)
        return (httpx.Response(200, json=published()) if len(seen) == 1
                else httpx.Response(429, headers={"Retry-After": "60"}, text="PRIVATE SERVER DETAIL"))

    result = CveClient(transport=httpx.MockTransport(handler)).lookup([FIRST, SECOND, THIRD])
    assert len(seen) == 2 and result["not_requested"] == 1 and result["status"] == "partial"
    assert result["errors"] == [{"id": SECOND, "reason": "rate_limited"}]
    assert "PRIVATE" not in json.dumps(result)
    assert_accounting(result)


@pytest.mark.parametrize(("status", "reason"), [(302, "http_error"), (404, "not_found"), (503, "http_error")])
def test_redirects_and_http_failures_never_follow_response_links(status, reason):
    seen = []

    def handler(request):
        seen.append(request.url.host)
        return httpx.Response(status, headers={"Location": "http://169.254.169.254/credentials"})

    result = CveClient(transport=httpx.MockTransport(handler)).lookup([FIRST])
    assert seen == ["cveawg.mitre.org"]
    assert result["errors"] == [{"id": FIRST, "reason": reason}]
    assert_accounting(result)


@pytest.mark.parametrize(("error", "reason"), [
    (httpx.ReadTimeout("private URL / secret"), "timeout"),
    (httpx.ConnectError("private URL / secret"), "network_error"),
    (ConnectionError("private URL / secret"), "network_error"),
])
def test_transport_failures_have_fixed_public_reasons(error, reason):
    def handler(_):
        raise error
    result = CveClient(transport=httpx.MockTransport(handler)).lookup([FIRST])
    assert result["errors"] == [{"id": FIRST, "reason": reason}]
    assert "secret" not in json.dumps(result)
    assert_accounting(result)


class Chunks(httpx.SyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False

    def __iter__(self):
        yield from self.chunks

    def close(self):
        self.closed = True


def test_oversized_stream_is_stopped_and_closed():
    def chunks():
        yield b"x" * 16_384
        yield b"y" * 16_384
        pytest.fail("Client must stop before the third chunk")
    stream = Chunks(chunks())
    client = CveClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, stream=stream)),
                       max_response_bytes=20_000)
    result = client.lookup([FIRST])
    assert result["errors"] == [{"id": FIRST, "reason": "response_too_large"}]
    assert stream.closed
    assert_accounting(result)


def test_unsolicited_compression_is_rejected_without_decompressing():
    def chunks():
        pytest.fail("Compressed stream must not be consumed")
        yield b""
    stream = Chunks(chunks())
    client = CveClient(transport=httpx.MockTransport(
        lambda _: httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)))
    result = client.lookup([FIRST])
    assert result["errors"] == [{"id": FIRST, "reason": "invalid_record"}]
    assert stream.closed


@pytest.mark.parametrize("body", [b"<html>proxy error</html>", b"[]", b"null", b"\xff", b"{" * 2000])
def test_invalid_response_bodies_are_unavailable(body):
    client = CveClient(transport=httpx.MockTransport(lambda _: httpx.Response(200, content=body)))
    result = client.lookup([FIRST])
    assert result["errors"] == [{"id": FIRST, "reason": "invalid_record"}]
    assert_accounting(result)


def test_wall_clock_budget_is_checked_between_stream_chunks(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("app.sca.cve.time.monotonic", lambda: clock[0])
    seen = []

    def chunks():
        clock[0] = 11
        yield b"x"
        pytest.fail("Time budget must stop further reads")

    def handler(request):
        seen.append(request)
        return httpx.Response(200, stream=Chunks(chunks()))

    result = CveClient(transport=httpx.MockTransport(handler)).lookup([FIRST, SECOND])
    assert len(seen) == 1 and result["not_requested"] == 1
    assert result["errors"] == [{"id": FIRST, "reason": "time_budget"}]
    assert_accounting(result)


def test_request_timeout_is_capped_by_remaining_total_budget(monkeypatch):
    clock = [0.0]
    monkeypatch.setattr("app.sca.cve.time.monotonic", lambda: clock[0])
    timeouts = []

    def handler(request):
        timeouts.append(request.extensions["timeout"])
        clock[0] += 2
        return httpx.Response(200, json=published(request.url.path.rsplit("/", 1)[1]))

    result = CveClient(transport=httpx.MockTransport(handler), time_budget=3).lookup([FIRST, SECOND])
    assert timeouts == [dict.fromkeys(("connect", "read", "write", "pool"), 3),
                        dict.fromkeys(("connect", "read", "write", "pool"), 1)]
    assert result["status"] == "partial"
    assert result["errors"] == [{"id": SECOND, "reason": "time_budget"}]
    assert_accounting(result)


def test_description_cwes_and_other_public_fields_are_bounded():
    record = published()
    cna = record["containers"]["cna"]
    cna.update(title="t" * 1000, descriptions=[{"lang": "en", "value": "d" * 10000}])
    cna["providerMetadata"]["shortName"] = "p" * 1000
    cna["problemTypes"] = [{"descriptions": [{"cweId": f"CWE-{i}"} for i in range(1, 40)]}]
    result = client_for(record).lookup([FIRST])
    normalized = result["records"][0]
    assert len(normalized["title"]) == 256 and len(normalized["description"]) == 4096
    assert len(normalized["provider"]) == 32 and len(normalized["cwes"]) == 20
    assert_accounting(result)


@pytest.mark.parametrize("status", ["disabled", "not_run", "not_applicable"])
def test_empty_modes_and_invalid_input_are_network_free(status):
    summary = empty_cve_summary(status)
    assert normalize_cve_summary(summary) == summary
    result = client_for(None).lookup(["GHSA-example", "malformed", None])
    assert result == empty_cve_summary()


@pytest.mark.parametrize("mutate", [
    lambda s: s.update(attempted=True),
    lambda s: s.update(resolved=2),
    lambda s: s.update(status="disabled"),
    lambda s: s.update(checked_at=None),
    lambda s: s.update(rejected=1),
    lambda s: s["records"][0].update(url="https://evil.test"),
    lambda s: s["records"][0].update(record_url="http://169.254.169.254"),
    lambda s: s["records"][0].update(cwes=["javascript:alert(1)"]),
    lambda s: s["records"][0].update(description=None),
    lambda s: s["records"][0].update(data_version="6.0"),
])
def test_public_normalizer_rejects_forged_coverage_or_links(mutate):
    result = client_for(published()).lookup([FIRST])
    mutate(result)
    assert normalize_cve_summary(result) is None


def test_public_normalizer_strips_unknown_raw_data_without_mutating_input():
    result = client_for(published()).lookup([FIRST])
    result["raw_body"] = "not public"
    result["records"][0]["metrics"] = {"unvalidated": "data"}
    before = deepcopy(result)
    normalized = normalize_cve_summary(result)
    assert "raw_body" not in normalized and "metrics" not in normalized["records"][0]
    assert result == before
