"""The X channel, and the several ordinary ways it does not work.

This is the weakest of the three transports and the tests are shaped by that.
A DM needs a paid API tier, a user-context token with `dm.write`, a handle
resolved to a numeric id, and a recipient who accepts messages from accounts
they do not follow. Any one of those missing means the message does not
arrive — and the only unacceptable outcome is reporting that it did, because
the router writes that down and stops looking for another way.

NOT EXERCISED AGAINST THE LIVE API. This deployment holds no X credentials. The
request shapes are from the documented v2 endpoints; what these tests prove is
the behaviour around them, which is where the damage would be.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.notify import x


def _api(handler) -> httpx.MockTransport:
    return httpx.MockTransport(handler)


def _working(seen: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if "/users/by/username/" in request.url.path:
            return httpx.Response(200, json={"data": {"id": "1234567890"}})
        return httpx.Response(201, json={"data": {"dm_event_id": "99"}})
    return _api(handler)


# --- handles ---------------------------------------------------------------

@pytest.mark.parametrize("written,expected", [
    ("@drydock", "drydock"),
    ("drydock", "drydock"),
    ("  @drydock  ", "drydock"),
    ("a", "a"),
    ("_" * 15, "_" * 15),
])
def test_a_handle_is_read_the_way_people_write_one(written, expected) -> None:
    assert x.normalize_handle(written) == expected


@pytest.mark.parametrize("written", [
    "https://x.com/drydock",     # the URL, which is what people copy
    "buyer@example.invalid",     # the wrong field on the form
    "_" * 16,                    # one over the limit
    "with space",
    "@",
    "",
    None,
])
def test_anything_else_is_not_a_handle(written) -> None:
    """A free-text field on a checkout form collects all of these. Returning
    None rather than trying means a confused entry does not become a
    guaranteed failed send that then pages the operator."""
    assert x.normalize_handle(written) is None


# --- it sends --------------------------------------------------------------

@pytest.mark.anyio
async def test_a_dm_resolves_the_handle_then_posts_to_that_id() -> None:
    """A handle is not an id: the messages endpoint is keyed by the numeric
    user id, so a handle costs a lookup first."""
    seen: list[httpx.Request] = []

    assert await x.send_dm(
        "@buyer", "We returned 10.79 USD.",
        token="t", transport=_working(seen),
    ) is True

    assert len(seen) == 2
    assert seen[0].url.path == "/2/users/by/username/buyer"
    assert seen[1].url.path == "/2/dm_conversations/with/1234567890/messages"
    assert json.loads(seen[1].content) == {"text": "We returned 10.79 USD."}
    for request in seen:
        assert request.headers["authorization"] == "Bearer t"


# --- it fails quietly, and says so -----------------------------------------

@pytest.mark.anyio
async def test_no_token_is_a_quiet_false(monkeypatch) -> None:
    monkeypatch.delenv("X_DM_TOKEN", raising=False)
    assert await x.send_dm("@buyer", "hi") is False


@pytest.mark.anyio
async def test_a_recipient_who_does_not_take_dms_is_a_false_not_a_raise() -> None:
    """The common and expected refusal: 403 because the recipient does not
    accept messages from accounts they do not follow. That is their setting,
    not a bug, and it is invisible until we try."""
    def handler(request: httpx.Request) -> httpx.Response:
        if "/users/by/username/" in request.url.path:
            return httpx.Response(200, json={"data": {"id": "1234567890"}})
        return httpx.Response(403, json={"title": "Forbidden"})

    assert await x.send_dm(
        "@buyer", "hi", token="t", transport=_api(handler)) is False


@pytest.mark.anyio
async def test_an_unpaid_api_tier_is_a_false() -> None:
    """Write access to the X API is a paid tier, and a deployment without one
    gets 403s on the lookup itself. Reported as not-delivered, which is what it
    is."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"title": "Unsupported Authentication"})

    assert await x.send_dm(
        "@buyer", "hi", token="t", transport=_api(handler)) is False


@pytest.mark.anyio
async def test_a_handle_that_does_not_exist_does_not_post_anything() -> None:
    """No id means no conversation to post into. Asserted on the REQUESTS
    rather than the return value: posting to a made-up id is the shape of
    sending a stranger somebody else's refund notice."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(404, json={"title": "Not Found Error"})

    assert await x.send_dm(
        "@nobody", "hi", token="t", transport=_api(handler)) is False
    assert len(seen) == 1
    assert "/dm_conversations/" not in seen[0].url.path


@pytest.mark.anyio
async def test_a_lookup_that_answers_200_with_no_id_still_posts_nothing() -> None:
    """X answers some lookups 200 with an `errors` array and no `data`. Reading
    the status code alone would take that for success and then build a URL with
    `None` in it."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"errors": [{"title": "Not Found"}]})

    assert await x.send_dm(
        "@nobody", "hi", token="t", transport=_api(handler)) is False
    assert len(seen) == 1


@pytest.mark.anyio
async def test_a_network_failure_is_a_false() -> None:
    """Never raises: the caller is announcing something that already happened,
    and an exception here would report a completed refund as a failed
    request."""
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route to host")

    assert await x.send_dm(
        "@buyer", "hi", token="t", transport=_api(handler)) is False


@pytest.mark.anyio
async def test_a_non_handle_never_reaches_the_network() -> None:
    """The URL is built from this string. A value that is not a handle must be
    refused before it becomes a path segment."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"data": {"id": "1"}})

    assert await x.send_dm(
        "../../admin", "hi", token="t", transport=_api(handler)) is False
    assert seen == []
