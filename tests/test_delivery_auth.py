"""Caller GitHub authority cannot be replaced by the service's App/PAT."""
import json
import httpx
import pytest

from app.deploypack.delivery_auth import (
    DeliveryAuthorizationError, authorize_repository_delivery, validate_delivery_token,
)

TOKEN = "fixture-request-only-token"


def test_preflight_checks_exact_repository_with_caller_token():
    seen = []
    def handler(request):
        seen.append((request.method, str(request.url)))
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        return httpx.Response(200, json={"full_name": "Acme/App", "permissions": {"push": True}})
    authorize_repository_delivery("acme", "app", TOKEN, transport=httpx.MockTransport(handler))
    assert seen == [("GET", "https://api.github.com/repos/acme/app")]


@pytest.mark.parametrize("data", [
    {"full_name": "acme/app", "permissions": {"push": False}},
    {"full_name": "acme/app", "permissions": {"push": "true"}},
    {"full_name": "acme/app", "permissions": {"push": 1}},
    {"full_name": "other/app", "permissions": {"push": True}},
    {"full_name": "acme/app"}, [], None,
])
def test_public_read_access_and_mismatched_targets_do_not_authorize_delivery(data):
    transport = httpx.MockTransport(lambda request: httpx.Response(200, content=json.dumps(data)))
    with pytest.raises(DeliveryAuthorizationError) as caught:
        authorize_repository_delivery("acme", "app", TOKEN, transport=transport)
    assert caught.value.status_code == 403


@pytest.mark.parametrize("upstream,expected", [(401, 401), (403, 403), (404, 403), (429, 502), (500, 502)])
def test_error_bodies_never_become_public_diagnostics(upstream, expected):
    transport = httpx.MockTransport(lambda request: httpx.Response(upstream, text=TOKEN))
    with pytest.raises(DeliveryAuthorizationError) as caught:
        authorize_repository_delivery("acme", "app", TOKEN, transport=transport)
    assert caught.value.status_code == expected
    assert TOKEN not in str(caught.value)


def test_redirect_never_forwards_caller_token_to_another_host():
    requests = []
    def handler(request):
        requests.append(str(request.url))
        return httpx.Response(302, headers={"Location": "https://outside.example/collect"})
    with pytest.raises(DeliveryAuthorizationError) as caught:
        authorize_repository_delivery("acme", "app", TOKEN, transport=httpx.MockTransport(handler))
    assert caught.value.status_code == 403
    assert requests == ["https://api.github.com/repos/acme/app"]


@pytest.mark.parametrize("failure", ["invalid_json", "timeout"])
def test_unavailable_preflight_fails_closed(failure):
    def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout(TOKEN, request=request)
        return httpx.Response(200, text=TOKEN)
    with pytest.raises(DeliveryAuthorizationError) as caught:
        authorize_repository_delivery("acme", "app", TOKEN, transport=httpx.MockTransport(handler))
    assert caught.value.status_code == 502
    assert TOKEN not in str(caught.value)


@pytest.mark.parametrize("token", [None, "", "a b", "a\nb", "é", "a" * 4097])
def test_missing_or_invalid_tokens_are_rejected_without_network(token):
    with pytest.raises(DeliveryAuthorizationError) as caught:
        validate_delivery_token(token)
    assert caught.value.status_code == 401


@pytest.mark.parametrize("headers,body", [
    ({"X-RateLimit-Remaining": "0"}, {}),
    ({"Retry-After": "60"}, {}),
    ({}, {"message": "You have exceeded a secondary rate limit."}),
])
def test_github_rate_limit_403_is_unavailable_not_revoked(headers, body):
    from app.deploypack.delivery import _check, DeliveryError
    response = httpx.Response(403, headers=headers, json=body)
    with pytest.raises(DeliveryAuthorizationError) as error:
        authorize_repository_delivery("acme", "app", TOKEN, transport=httpx.MockTransport(
            lambda request: response))
    assert error.value.status_code == 502
    with pytest.raises(DeliveryError) as delivery:
        _check(response, "create branch")
    assert delivery.value.retryable is True
    assert delivery.value.status_code == 403
