"""Tests for PR delivery, with httpx.MockTransport — same pattern as
LLMClient's fallback-chain test. No real GitHub calls."""

import json

import httpx

from app.deploypack.delivery import (
    DeliveryError,
    PullRequestResult,
    open_pull_request,
    render_pr_body,
)

FILES = {"Dockerfile": "FROM python:3.12-slim\n", "docker-compose.yml": "services: {}\n"}


def make_handler(fail_at: str | None = None):
    """Scripts a full, successful Git-Data-API + PR flow. `fail_at` lets
    a test make one specific step return a 4xx instead."""

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method

        if fail_at and path.endswith(fail_at):
            return httpx.Response(404, json={"message": "not found"})

        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "basesha123"}})
        if method == "GET" and path.endswith("/git/commits/basesha123"):
            return httpx.Response(200, json={"tree": {"sha": "treesha123"}})
        if method == "POST" and path.endswith("/git/blobs"):
            body = json.loads(request.content)
            return httpx.Response(201, json={"sha": f"blob-{hash(body['content']) & 0xff}"})
        if method == "POST" and path.endswith("/git/trees"):
            return httpx.Response(201, json={"sha": "newtreesha"})
        if method == "POST" and path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "commitsha12345678"})
        if method == "POST" and path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": "refs/heads/shipit/deploy-pack-commitsh"})
        if method == "POST" and path.endswith("/pulls"):
            return httpx.Response(
                201, json={"html_url": "https://github.com/acme/app/pull/42"}
            )
        raise AssertionError(f"unscripted request: {method} {path}")

    return handler


def test_open_pull_request_full_flow():
    transport = httpx.MockTransport(make_handler())
    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake", transport=transport,
    )
    assert isinstance(result, PullRequestResult)
    assert result.html_url == "https://github.com/acme/app/pull/42"
    assert result.branch == "shipit/deploy-pack-commitsh"  # branch_prefix + commit_sha[:8]


def test_missing_token_raises_without_any_http_call():
    called = []
    transport = httpx.MockTransport(lambda r: called.append(1) or httpx.Response(200))
    try:
        open_pull_request("acme", "app", FILES, token=None, transport=transport)
        assert False, "expected DeliveryError"
    except DeliveryError as exc:
        assert "no GitHub token" in str(exc)
    assert called == []


def test_failed_base_branch_lookup_raises_clear_error():
    transport = httpx.MockTransport(make_handler(fail_at="git/ref/heads/main"))
    try:
        open_pull_request("acme", "app", FILES, token="ghp_fake", transport=transport)
        assert False, "expected DeliveryError"
    except DeliveryError as exc:
        assert "resolve base branch" in str(exc)


def test_pr_body_lists_every_file_and_the_verification_result():
    body = render_pr_body("deploy", FILES, "HTTP 200 on /")
    assert "Dockerfile" in body
    assert "docker-compose.yml" in body
    assert "HTTP 200 on /" in body


# --- Idempotent delivery (job_id-keyed branch + pre-flight lookup) ---

JOB_ID = "job-1234"


def make_idempotent_handler(
    *, existing_prs=None, ref_conflict=False, pr_conflict=False, calls=None
):
    """Scripts the flow with a job_id-keyed branch. `existing_prs` is the JSON
    array the `GET /pulls` pre-flight returns; `ref_conflict`/`pr_conflict`
    make those POSTs return a 422 "already exists". Every request is appended
    to `calls` as (method, path) so a test can assert what was (not) created."""
    existing_prs = existing_prs if existing_prs is not None else []

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if calls is not None:
            calls.append((method, path))

        if method == "GET" and path.endswith("/pulls"):
            return httpx.Response(200, json=existing_prs)
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "basesha123"}})
        if method == "GET" and path.endswith("/git/commits/basesha123"):
            return httpx.Response(200, json={"tree": {"sha": "treesha123"}})
        if method == "POST" and path.endswith("/git/blobs"):
            body = json.loads(request.content)
            return httpx.Response(201, json={"sha": f"blob-{hash(body['content']) & 0xff}"})
        if method == "POST" and path.endswith("/git/trees"):
            return httpx.Response(201, json={"sha": "newtreesha"})
        if method == "POST" and path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "commitsha12345678"})
        if method == "POST" and path.endswith("/git/refs"):
            if ref_conflict:
                return httpx.Response(422, json={"message": "Reference already exists"})
            return httpx.Response(201, json={"ref": "refs/heads/x"})
        if method == "POST" and path.endswith("/pulls"):
            if pr_conflict:
                return httpx.Response(
                    422, json={"message": "A pull request already exists for acme:x"}
                )
            return httpx.Response(
                201, json={"html_url": "https://github.com/acme/app/pull/99"}
            )
        raise AssertionError(f"unscripted request: {method} {path}")

    return handler


def _create_calls(calls):
    return [
        (m, p) for (m, p) in calls
        if m == "POST" and (
            p.endswith(("/git/blobs", "/git/trees", "/git/commits", "/git/refs", "/pulls"))
        )
    ]


def test_existing_pr_is_returned_without_creating_anything():
    # (a) A PR already exists for the job's branch -> return it, create nothing.
    calls = []
    existing = [{"html_url": "https://github.com/acme/app/pull/7"}]
    transport = httpx.MockTransport(
        make_idempotent_handler(existing_prs=existing, calls=calls)
    )
    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake", job_id=JOB_ID, transport=transport,
    )
    assert result.html_url == "https://github.com/acme/app/pull/7"
    assert result.branch == f"shipit/deploy-pack-{JOB_ID}"
    assert _create_calls(calls) == []  # nothing was created


def test_branch_exists_but_no_pr_opens_pr_without_failing():
    # (b) Branch left over from a crashed attempt (422 on git/refs), no PR yet
    #     -> tolerate the 422 and open the PR to the existing branch.
    calls = []
    transport = httpx.MockTransport(
        make_idempotent_handler(ref_conflict=True, calls=calls)
    )
    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake", job_id=JOB_ID, transport=transport,
    )
    assert result.html_url == "https://github.com/acme/app/pull/99"
    assert result.branch == f"shipit/deploy-pack-{JOB_ID}"
    # commit/tree/blob still built (can't know branch is current otherwise).
    assert any(p.endswith("/git/commits") for (_, p) in calls)


def test_happy_path_with_job_id_creates_everything():
    # (c) Nothing exists -> full create sequence, branch keyed on job_id.
    calls = []
    transport = httpx.MockTransport(make_idempotent_handler(calls=calls))
    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake", job_id=JOB_ID, transport=transport,
    )
    assert result.html_url == "https://github.com/acme/app/pull/99"
    assert result.branch == f"shipit/deploy-pack-{JOB_ID}"
    created = {p.rsplit("/", 1)[-1] for (m, p) in _create_calls(calls)}
    assert {"blobs", "trees", "commits", "refs", "pulls"} <= created


def test_concurrent_racer_pr_conflict_returns_existing():
    # (d) A racer opens the PR between our pre-flight and our POST /pulls:
    #     422 on create -> re-lookup and return the racer's PR.
    lookups = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        method = request.method
        if method == "GET" and path.endswith("/pulls"):
            lookups["n"] += 1
            # First pre-flight: empty. Second (after 422): the racer's PR.
            if lookups["n"] == 1:
                return httpx.Response(200, json=[])
            return httpx.Response(
                200, json=[{"html_url": "https://github.com/acme/app/pull/55"}]
            )
        if method == "GET" and path.endswith("/git/ref/heads/main"):
            return httpx.Response(200, json={"object": {"sha": "basesha123"}})
        if method == "GET" and path.endswith("/git/commits/basesha123"):
            return httpx.Response(200, json={"tree": {"sha": "treesha123"}})
        if method == "POST" and path.endswith("/git/blobs"):
            return httpx.Response(201, json={"sha": "blobsha"})
        if method == "POST" and path.endswith("/git/trees"):
            return httpx.Response(201, json={"sha": "newtreesha"})
        if method == "POST" and path.endswith("/git/commits"):
            return httpx.Response(201, json={"sha": "commitsha12345678"})
        if method == "POST" and path.endswith("/git/refs"):
            return httpx.Response(201, json={"ref": "refs/heads/x"})
        if method == "POST" and path.endswith("/pulls"):
            return httpx.Response(
                422, json={"message": "A pull request already exists for acme:x"}
            )
        raise AssertionError(f"unscripted request: {method} {path}")

    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake", job_id=JOB_ID,
        transport=httpx.MockTransport(handler),
    )
    assert result.html_url == "https://github.com/acme/app/pull/55"


def test_fixpack_prefix_and_job_id_shape_the_branch():
    # (f) A Fix-Pack-shaped call names the branch from prefix + job_id.
    transport = httpx.MockTransport(make_idempotent_handler())
    result = open_pull_request(
        "acme", "app", FILES, token="ghp_fake",
        branch_prefix="drydock/fix-pack", job_id="abc-987", transport=transport,
    )
    assert result.branch == "drydock/fix-pack-abc-987"
