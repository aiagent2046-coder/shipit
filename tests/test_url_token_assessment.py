"""A header guard must not hide a related page's URL token origin."""

import hashlib
import json

import pytest

from app.scan.auth_source_assessment import AuthSourceVerifier
from app.scan.claim_evidence import unsupported_transport
from tests.test_auth_source_assessment import archive, raw

API_PATH = "app/api/lab/stats/route.ts"
PAGE_PATH = "app/lab/page.tsx"
API = """export async function GET(req) {
  const token = req.headers.get('x-lab-token');
  if (!process.env.LAB_TOKEN || token !== process.env.LAB_TOKEN) return forbidden();
  const rows = await loadRecords();
  return rows.filter(row => row.enabled);
}
"""
PAGE = """import { useState, useEffect, useCallback } from 'react';
export default function Dashboard() {
  const [token, setToken] = useState(null);
  useEffect(() => {
    const t = new URLSearchParams(window.location.search).get('token');
    setToken(t);
  }, []);
  const load = useCallback(async () => {
    if (!token) return;
    const res = await fetch('/api/lab/stats', {headers: {'x-lab-token': token}});
    show(await res.json());
  }, [token]);
  return render(load);
}
"""


def check(api=API, page=PAGE, files=None):
    f = raw(
        api,
        needle="rows.filter",
        title="Lab dashboard token validation insufficient",
        path=API_PATH,
        explanation="The page token is passed as a URL query parameter, exposing data if guessed.",
    )
    return AuthSourceVerifier(archive({API_PATH: api, PAGE_PATH: page, **(files or {})})).checks_for(f)


def test_page_url_state_is_bound_to_api_header_guard_and_not_dismissed():
    (record,) = check()
    assert record["kind"] == "url_token_header_transport"
    assert record["result"] == "observed" and not record["whole_finding"]
    assert "narrative_review" not in record
    binding = record["source_binding"]
    assert binding["request_header"] == "x-lab-token"
    assert binding["query_parameter"] == "token"
    assert binding["page_url_read"]["file"] == PAGE_PATH
    assert binding["page_request"]["source_sha256"] == hashlib.sha256(PAGE.encode()).hexdigest()
    assert binding["page_request"]["line_start"] == 10
    assert not unsupported_transport({"version": 1, "source_assessments": [record]})
    assert "LAB_TOKEN" not in json.dumps(record)
    assert "window.location.search" in record["detail"]


@pytest.mark.parametrize(
    "old,new",
    [
        ("fetch('/api/lab/stats'", "fetch('/api/other/stats'"),
        ("'x-lab-token': token", "'x-other-token': token"),
        ("'x-lab-token': token", "'x-lab-token': otherToken"),
        ("'x-lab-token': token", "'x-lab-token': token, ...extra"),
        ("'x-lab-token': token", "'x-lab-token': token, 'x-lab-token': other"),
        ("setToken(t);", "setToken(other);"),
        ("setToken(t);", "setToken(t); setToken(other);"),
        ("setToken(t);", "const alias = setToken; alias(t);"),
        ("window.location.search", "window.location.hash"),
        ("new URLSearchParams(window.location.search)", "customParser(window.location.search)"),
        ("from 'react'", "from './hooks'"),
        ("useState(null)", "useState('default-secret')"),
        ("}, [token]);", "}, []);"),
        ("}, []);", "}, [other]);"),
        ("const res = await fetch", "const token = other; const res = await fetch"),
        ("const res = await fetch", "token = other; const res = await fetch"),
        ("const res = await fetch", "const fetch = fake; const res = await fetch"),
        ("const t = new URLSearchParams", "const URLSearchParams = fake; const t = new URLSearchParams"),
        ("const t = new URLSearchParams", "const window = fake; const t = new URLSearchParams"),
    ],
)
def test_wrong_destination_state_setter_header_shadowing_or_url_source_abstains(old, new):
    assert old in PAGE
    assert check(page=PAGE.replace(old, new)) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("get('x-lab-token')", "get('other-token')"),
        ("token !== process.env.LAB_TOKEN", "token === process.env.LAB_TOKEN"),
        ("return forbidden();", "log();"),
        ("const token =", "let token ="),
        ("const rows =", "token = forged; const rows ="),
        ("export async function GET(req)", "export async function GET(req, process)"),
        ("export async function GET(req)", "export async function POST(req)"),
    ],
)
def test_api_binding_requires_exact_header_read_and_guard(old, new):
    assert old in API
    assert check(api=API.replace(old, new)) == []


def test_unrelated_page_or_multiple_candidates_do_not_create_cross_file_claim():
    assert check(files={"app/other/page.tsx": PAGE}) == []
    assert check(page="export default function Page() { return null; }") == []


def test_entire_archive_path_prefix_is_preserved_without_cross_project_binding():
    prefix = "project-abc/"
    f = raw(API, needle="rows.filter", title="URL token validation", path=prefix + API_PATH)
    verifier = AuthSourceVerifier(
        archive({prefix + API_PATH: API, prefix + PAGE_PATH: PAGE, "other/" + PAGE_PATH: PAGE})
    )
    (record,) = verifier.checks_for(f)
    assert record["source_binding"]["page_request"]["file"] == prefix + PAGE_PATH


@pytest.mark.parametrize("method", ["'POST'", "'DELETE'", "requestMethod"])
def test_request_to_different_http_method_does_not_bind_get_guard(method):
    page = PAGE.replace(
        "{headers: {'x-lab-token': token}}", "{method: " + method + ", headers: {'x-lab-token': token}}"
    )
    assert check(page=page) == []


def test_explicit_get_matches_but_option_override_abstains():
    page = PAGE.replace("{headers: {'x-lab-token': token}}", "{method: 'GET', headers: {'x-lab-token': token}}")
    assert check(page=page)
    assert not check(page=page.replace("method: 'GET',", "method: 'GET', ...extra,"))


@pytest.mark.parametrize(
    "mutation",
    [
        "const headers = req.headers; headers.get = fake;",
        "Object.assign(req.headers, {get: fake});",
        "req.headers = forged;",
        "const get = req.headers.get; get.patch = fake;",
    ],
)
def test_header_receiver_aliases_and_mutation_abstain(mutation):
    assert check(api=API.replace("  const token =", "  " + mutation + "\n  const token =")) == []


@pytest.mark.parametrize(
    "pattern",
    [
        "[token,,setToken]",
        "[,token,setToken]",
        "[token, [setToken]]",
        "[token, ...setToken]",
        "[token = fallback, setToken]",
    ],
)
def test_state_tuple_elision_or_nested_pattern_is_not_a_setter_binding(pattern):
    assert check(page=PAGE.replace("[token, setToken]", pattern)) == []
