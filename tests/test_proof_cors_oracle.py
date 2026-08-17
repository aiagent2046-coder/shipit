"""Table tests for the runtime CORS oracle (P0, PROOF_RUNTIME_CORS_PLAN).

Pure function, no docker and no runner — which is the point of doing P0
first: the decision that separates "confirmed exploit" from "misconfigured
but not exploitable" is settled and pinned before an hour goes into booting
containers.

The case that matters most is `*` + credentials. The plan called it an
exploit; the Fetch standard says a browser rejects `Access-Control-Allow-
Origin: *` outright when the request's credentials mode is `include`, so no
page ever reads a private response that way. Reporting it as confirmed would
print "атака сработала" over an attack that cannot happen — the overstatement
the release before this one removed from the static templates.
"""

from __future__ import annotations

import pytest

from app.proof.cors_oracle import PROBE_ORIGIN, evaluate_cors_response

_OTHER = "https://app.customer.example"


def _headers(origin: str | None = None, credentials: str | None = None,
             **extra: str) -> dict[str, str]:
    out: dict[str, str] = {"Content-Type": "application/json", **extra}
    if origin is not None:
        out["Access-Control-Allow-Origin"] = origin
    if credentials is not None:
        out["Access-Control-Allow-Credentials"] = credentials
    return out


# (label, headers, expected exploitable, expected reason)
_CASES = [
    (
        "reflection + credentials — the finding",
        _headers(PROBE_ORIGIN, "true"),
        True,
        "credentialed_reflection",
    ),
    (
        "reflection, credentials absent",
        _headers(PROBE_ORIGIN),
        False,
        "reflection_without_credentials",
    ),
    (
        "reflection, credentials explicitly false",
        _headers(PROBE_ORIGIN, "false"),
        False,
        "reflection_without_credentials",
    ),
    (
        "wildcard + credentials — browser blocks it, so not confirmed",
        _headers("*", "true"),
        False,
        "wildcard_with_credentials_blocked_by_browser",
    ),
    (
        "wildcard alone — a public API, not a finding",
        _headers("*"),
        False,
        "wildcard_without_credentials",
    ),
    (
        "pinned to someone else's origin",
        _headers(_OTHER, "true"),
        False,
        "allowed_other_origin",
    ),
    (
        "no CORS headers at all",
        _headers(),
        False,
        "no_cors_headers",
    ),
]


@pytest.mark.parametrize(
    "headers,expected_exploitable,expected_reason",
    [(h, e, r) for _label, h, e, r in _CASES],
    ids=[label for label, *_ in _CASES],
)
def test_oracle_table(headers, expected_exploitable, expected_reason) -> None:
    verdict = evaluate_cors_response(headers)
    assert verdict.exploitable is expected_exploitable
    assert verdict.reason == expected_reason
    # Every verdict has to be explainable to a customer, not just to a switch.
    assert verdict.detail.strip()


def test_only_one_case_in_the_whole_table_is_exploitable() -> None:
    """Guards the shape of the judgement, not one branch of it.

    A later edit that widens `exploitable` — most plausibly by folding the
    wildcard cases back in, as the plan originally had it — flips this
    count and fails here even if every individual case above was updated to
    match the new behaviour.
    """
    exploitable = [
        label for label, headers, _e, _r in _CASES
        if evaluate_cors_response(headers).exploitable
    ]
    assert exploitable == ["reflection + credentials — the finding"]


def test_header_casing_and_padding_do_not_change_the_verdict() -> None:
    """Starlette lowercases its headers, Express title-cases them, and real
    servers pad values. The oracle judges the app, not its formatting."""
    verdict = evaluate_cors_response({
        "ACCESS-CONTROL-ALLOW-ORIGIN": PROBE_ORIGIN,
        "access-control-allow-credentials": "  True  ",
    })
    assert verdict.exploitable is True
    assert verdict.reason == "credentialed_reflection"


def test_a_trailing_slash_is_still_a_reflection() -> None:
    """Servers that build the header by concatenation sometimes append one.
    A reflection is a reflection."""
    verdict = evaluate_cors_response({
        "Access-Control-Allow-Origin": PROBE_ORIGIN + "/",
        "Access-Control-Allow-Credentials": "true",
    })
    assert verdict.exploitable is True


def test_credentials_must_be_the_literal_true() -> None:
    """Browsers honour only `true`. Accepting `1` or `yes` would report an
    exploit that no browser performs."""
    for value in ("1", "yes", "TRUE!", ""):
        verdict = evaluate_cors_response(_headers(PROBE_ORIGIN, value))
        assert verdict.exploitable is False, value
        assert verdict.reason == "reflection_without_credentials", value


def test_evidence_carries_what_the_pr_will_print() -> None:
    """The PR shows the two header values verbatim; they have to survive the
    verdict. Response bodies deliberately do not — a body from a customer's
    app can contain their data."""
    verdict = evaluate_cors_response(_headers(PROBE_ORIGIN, "true"))
    assert verdict.evidence["allow_origin"] == PROBE_ORIGIN
    assert verdict.evidence["allow_credentials"] == "true"
    assert verdict.evidence["probe_origin"] == PROBE_ORIGIN
    assert "body" not in verdict.evidence


def test_probe_origin_is_unresolvable_by_construction() -> None:
    """RFC 2606 reserves `.invalid`. If this ever became a resolvable domain,
    a reflection of it could be a legitimate allowlist entry and the oracle's
    central inference would quietly stop holding."""
    assert PROBE_ORIGIN.endswith(".invalid")
    assert PROBE_ORIGIN.startswith("https://")
