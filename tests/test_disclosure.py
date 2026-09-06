"""Disclosure is unconditional; the probe is consent-gated. Both, as tests.

The point of app/proof/disclosure.py is that the ethics are structural, not a
matter of intent — so the invariants get tests, not comments:

  * a secret finding ALWAYS yields a disclosure, for every ownership;
  * a publishable finding yields none (it is designed to ship);
  * the live probe is refused on third-party / unknown targets, in code;
  * a stored disclosure cannot be hand-edited to grant probe rights ownership
    never implied;
  * and the served-bundle fetch wires all of this together — findings become
    disclosures always, and a probe plan only when ownership permits.
"""

from __future__ import annotations

import pytest

from app.proof.disclosure import (
    COORDINATED_WINDOW_DAYS,
    ProbeNotPermitted,
    assert_probe_allowed,
    build_coordinated_disclosure,
    disclosure_from_json,
    disclosure_to_json,
    plan_disclosure,
)
from app.proof.secret_registry import Finding
from app.proof.served_bundle import fetch_served_bundle

RAW = "sk_live_" + "C" * 24


def _secret() -> Finding:
    return Finding(pattern_id="stripe_secret_key",
                   name="Stripe secret / restricted key",
                   kind="secret", severity="critical", tier="A",
                   redacted="sk_live_••••CCCC", secret=RAW)


def _publishable() -> Finding:
    return Finding(pattern_id="stripe_publishable_key",
                   name="Stripe publishable key",
                   kind="publishable", severity="info", tier="C",
                   redacted="pk_live_••••DDDD", secret="pk_live_" + "D" * 24)


# --- the core invariant: a secret is ALWAYS disclosed --------------------- #

@pytest.mark.parametrize("ownership", ["own", "consented", "third_party", "unknown"])
def test_a_secret_finding_always_produces_a_disclosure(ownership) -> None:
    d = plan_disclosure(_secret(), ownership=ownership, location="/assets/x.js")
    assert d is not None
    assert d.finding_id == "stripe_secret_key"
    assert d.redacted == "sk_live_••••CCCC"


def test_a_publishable_finding_is_not_disclosed() -> None:
    """anon keys and pk_ keys are designed to ship — disclosing them is the
    false alarm the whole registry exists to avoid."""
    assert plan_disclosure(_publishable(), ownership="own", location="x") is None


# --- channel + probe gate follow ownership, never intent ------------------ #

@pytest.mark.parametrize("ownership,channel,may_probe", [
    ("own", "report", True),
    ("consented", "report", True),
    ("third_party", "coordinated", False),
    ("unknown", "coordinated", False),
])
def test_channel_and_probe_gate_are_derived_from_ownership(
        ownership, channel, may_probe) -> None:
    d = plan_disclosure(_secret(), ownership=ownership, location="x")
    assert d.channel == channel
    assert d.may_probe is may_probe


def test_probe_is_allowed_on_owned_and_consented() -> None:
    for ownership in ("own", "consented"):
        d = plan_disclosure(_secret(), ownership=ownership, location="x")
        assert_probe_allowed(d)  # does not raise


@pytest.mark.parametrize("ownership", ["third_party", "unknown"])
def test_probe_is_refused_on_third_party_and_unknown(ownership) -> None:
    d = plan_disclosure(_secret(), ownership=ownership, location="x")
    with pytest.raises(ProbeNotPermitted):
        assert_probe_allowed(d)


# --- coordinated notice for someone else's product ------------------------ #

def test_coordinated_notice_carries_the_mask_not_the_secret() -> None:
    d = plan_disclosure(_secret(), ownership="third_party", location="/assets/x.js")
    notice = build_coordinated_disclosure(d, product="acme.app")
    assert RAW not in notice
    assert "sk_live_••••CCCC" in notice
    assert "acme.app" in notice
    assert str(COORDINATED_WINDOW_DAYS) in notice
    # it must state we did NOT use the key
    assert "did NOT use" in notice or "not use" in notice.lower()


def test_coordinated_notice_refuses_an_owned_disclosure() -> None:
    """A report-channel disclosure must not be dressed up as an external notice
    — the channels are distinct and must not be confused."""
    d = plan_disclosure(_secret(), ownership="own", location="x")
    with pytest.raises(ValueError):
        build_coordinated_disclosure(d, product="mine.app")


# --- storage round-trip cannot smuggle probe rights ----------------------- #

def test_disclosure_survives_a_json_round_trip() -> None:
    d = plan_disclosure(_secret(), ownership="third_party", location="/x.js")
    assert disclosure_from_json(disclosure_to_json(d)) == d


def test_a_hand_edited_row_cannot_grant_probe_rights() -> None:
    """third_party with may_probe flipped to True must be rejected, or a stored
    row could authorise a probe ownership never allowed."""
    j = disclosure_to_json(plan_disclosure(_secret(), ownership="third_party",
                                           location="/x.js"))
    j["may_probe"] = True
    with pytest.raises(ValueError):
        disclosure_from_json(j)


def test_a_hand_edited_channel_must_agree_with_ownership() -> None:
    j = disclosure_to_json(plan_disclosure(_secret(), ownership="third_party",
                                           location="/x.js"))
    j["channel"] = "report"
    with pytest.raises(ValueError):
        disclosure_from_json(j)


# --- integration: served_bundle wires findings -> (disclosures, probe_plan) - #

HOST = "app.example.test"
URL = f"https://{HOST}/"


def _resolver(mapping):
    def resolve(host, port):
        if host not in mapping:
            raise OSError("nx")
        return [(0, 0, 0, "", (ip, port)) for ip in mapping[host]]
    return resolve


_PUBLIC = _resolver({HOST: ["93.184.216.34"]})


def _serve(js: str):
    def _fn(url, host, port, max_bytes):
        if url.endswith((".js", ".mjs")) or "/assets/" in url:
            return 200, js
        return 200, '<script src="/assets/app.js"></script>'
    return _fn


def test_served_bundle_discloses_every_owner_but_only_probes_the_consented() -> None:
    js = f'const k="{RAW}";'  # a stripe secret in the served JS
    for ownership, expect_probe in [("own", True), ("consented", True),
                                    ("third_party", False), ("unknown", False)]:
        res = fetch_served_bundle(url=URL, consent=True, ownership=ownership,
                                  resolver=_PUBLIC, fetch=_serve(js))
        assert res.status == "checked"
        assert res.leaked is True
        # disclosure happens regardless of ownership
        assert len(res.disclosures) == 1
        assert res.disclosures[0].finding_id == "stripe_secret_key"
        # probe plan only when ownership permits
        assert bool(res.probe_plan) is expect_probe
        if expect_probe:
            assert res.probe_plan[0].probe_family == "key"
            assert res.probe_plan[0].probe.plan["read_only"] is True


def test_served_bundle_never_puts_the_raw_secret_in_evidence() -> None:
    js = f'const k="{RAW}";'
    res = fetch_served_bundle(url=URL, consent=True, ownership="own",
                              resolver=_PUBLIC, fetch=_serve(js))
    assert RAW not in repr(res.evidence)
    # but the raw token is available in-process for the permitted probe
    assert res.probe_plan and res.leaked


def test_served_bundle_surfaces_publishable_without_alarming() -> None:
    anon_pub = "pk_live_" + "D" * 24
    js = f'const p="{anon_pub}";'
    res = fetch_served_bundle(url=URL, consent=True, ownership="own",
                              resolver=_PUBLIC, fetch=_serve(js))
    assert res.leaked is False              # not a leak
    assert res.disclosures == []            # nothing to disclose
    assert any(bf.finding.pattern_id == "stripe_publishable_key"
               for bf in res.publishable)  # but recognised, surfaced
