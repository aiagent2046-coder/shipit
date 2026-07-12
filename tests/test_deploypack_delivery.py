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
