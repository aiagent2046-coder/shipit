"""Disclosure is unconditional. Proof is consent-gated. They are not the same act.

A leaked secret found in a served bundle is a fact about a real person's
exposure. Withholding it once found — to gate it behind payment, or because the
deployment is not ours — leaves the owner and their users under a live threat we
know about. So this module encodes one invariant: **a secret finding always
produces a Disclosure.** There is no code path from "found a secret" to silence.

What consent DOES gate is the live probe — the active request that uses the
leaked credential against a real system to prove it works. Reading a public
bundle is reading a public file; firing the key at someone's Stripe or database
is access. So `Disclosure.may_probe` is the single gate both paths read:

  * the report path shows the finding either way;
  * the proof path (rls_probe, the Tier A key probes) may run ONLY when
    may_probe is True — own or consented deployments.

This makes the ethical question structural rather than a matter of intent: the
system cannot stay silent about what it found, and cannot probe a stranger's
system to confirm it.

THE THIRD-PARTY CASE. When Drydock finds a leak in a product that is not the
user's and has no consent, the answer is not silence and not exploitation — it
is coordinated disclosure: notify the rightful owner, do not publish, do not
probe, and give a reasonable window to rotate. `build_coordinated_disclosure`
produces that notice, carrying only the redacted finding. Done consistently,
this is also what earns Drydock a reputation as a responsible partner rather
than a tool that rattles doorknobs.

NEVER THE RAW SECRET. A Disclosure carries only what a `secret_registry.Finding`
already redacted. The raw token stays in-process for a permitted probe and never
reaches a Disclosure, a notice, or stored json.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Literal

from app.proof.secret_registry import Finding, Severity

# Who the audited deployment belongs to. This is an input the caller must
# establish (ownership check / consent record) — it is never inferred from the
# target, because guessing "probably theirs" is exactly the wrong default.
Ownership = Literal["own", "consented", "third_party", "unknown"]

# How the finding is communicated, derived from ownership — never set by hand.
#   report      -> full report to the user + fix via PR (own / consented)
#   coordinated -> responsible disclosure to the rightful owner (third_party / unknown)
DisclosureChannel = Literal["report", "coordinated"]

# Coordinated-disclosure window before any escalation, in days. 90 is the
# widely-used norm; it is long enough to rotate and short enough not to sit on
# an active exposure.
COORDINATED_WINDOW_DAYS = 90


@dataclass(frozen=True)
class Disclosure:
    """An obligation to tell the rightful owner about one secret finding.

    Produced for every `secret` finding, regardless of ownership or payment.
    `may_probe` is the consent gate the live probe reads; `channel` is how the
    finding is delivered.
    """

    finding_id: str            # secret_registry pattern id, e.g. "stripe_secret_key"
    name: str
    severity: Severity
    redacted: str              # from Finding.redacted — never the raw token
    location: str              # where it was seen (asset url / "served bundle")
    ownership: Ownership
    channel: DisclosureChannel
    may_probe: bool            # True iff ownership in {own, consented}
    detail: str

    def evidence(self) -> dict[str, Any]:
        """Safe to store or render — redaction and metadata, never a token."""
        return {
            "finding": self.finding_id, "name": self.name,
            "severity": self.severity, "redacted": self.redacted,
            "location": self.location, "ownership": self.ownership,
            "channel": self.channel, "may_probe": self.may_probe,
        }


def _channel_for(ownership: Ownership) -> DisclosureChannel:
    return "report" if ownership in ("own", "consented") else "coordinated"


def plan_disclosure(
    finding: Finding, *, ownership: Ownership, location: str,
) -> Disclosure | None:
    """Turn a secret finding into a disclosure obligation.

    Returns a Disclosure for every `secret` finding — this is the "cannot stay
    silent" invariant; there is no argument that suppresses it. Returns None
    only for `publishable` findings, which are designed to ship and are not a
    leak to disclose.
    """
    if finding.kind != "secret":
        return None  # publishable — nothing to disclose

    channel = _channel_for(ownership)
    may_probe = ownership in ("own", "consented")
    if channel == "report":
        detail = ("disclosed to the deployment owner; live confirmation "
                  "permitted on this owned/consented target")
    else:
        detail = (f"coordinated disclosure to the rightful owner; no probe, no "
                  f"publication, {COORDINATED_WINDOW_DAYS}-day window to rotate")

    return Disclosure(
        finding_id=finding.pattern_id, name=finding.name,
        severity=finding.severity, redacted=finding.redacted,
        location=location, ownership=ownership, channel=channel,
        may_probe=may_probe, detail=detail)


class ProbeNotPermitted(PermissionError):
    """Raised when a live probe is attempted against a non-consented target."""


def assert_probe_allowed(disclosure: Disclosure) -> None:
    """Hard gate for the live-probe path. A caller about to fire a leaked key at
    a real system must pass the disclosure here first; a third-party or unknown
    target raises rather than proceeds. This is the code-level twin of the
    read-only assert in secret_registry — a rule enforced, not documented."""
    if not disclosure.may_probe:
        raise ProbeNotPermitted(
            f"live probe refused: ownership is {disclosure.ownership!r}; "
            f"only own/consented deployments may be probed")


# --------------------------------------------------------------------------- #
# coordinated disclosure notice (the third-party case)
# --------------------------------------------------------------------------- #

def build_coordinated_disclosure(
    disclosure: Disclosure, *, product: str, finder: str = "Drydock",
) -> str:
    """A responsible-disclosure notice for a leak found in someone else's
    product. Carries the redacted finding and a rotation recommendation — never
    the raw secret, never a probe result (there is none; we did not probe)."""
    if disclosure.channel != "coordinated":
        raise ValueError(
            "coordinated notice is only for third_party/unknown ownership; "
            f"this disclosure is {disclosure.channel!r}")

    return (
        f"Subject: Security disclosure — exposed credential in {product}\n"
        f"\n"
        f"Hello,\n"
        f"\n"
        f"While reviewing publicly served assets of {product}, {finder} "
        f"identified a credential that appears to be exposed to every visitor "
        f"in the browser bundle:\n"
        f"\n"
        f"  Type:     {disclosure.name}\n"
        f"  Severity: {disclosure.severity}\n"
        f"  Value:    {disclosure.redacted}  (redacted)\n"
        f"  Location: {disclosure.location}\n"
        f"\n"
        f"We found this by reading the JavaScript your site serves publicly. "
        f"We did NOT use the credential, access your systems, or retain the raw "
        f"value, and we have not published or shared this information.\n"
        f"\n"
        f"Recommended action: rotate this credential and move it server-side so "
        f"it is no longer shipped to the browser. Keys of this kind are commonly "
        f"harvested by automated scanners within minutes of exposure.\n"
        f"\n"
        f"We're following coordinated disclosure and will take no further action "
        f"for {COORDINATED_WINDOW_DAYS} days to give you time to rotate. Reply "
        f"if we can help or clarify.\n"
        f"\n"
        f"— {finder}\n"
    )


# --------------------------------------------------------------------------- #
# storage round-trip (mirrors types.py discipline)
# --------------------------------------------------------------------------- #

_OWNERSHIP: tuple[str, ...] = ("own", "consented", "third_party", "unknown")
_CHANNEL: tuple[str, ...] = ("report", "coordinated")


def disclosure_to_json(disclosure: Disclosure) -> dict[str, Any]:
    return asdict(disclosure)


def disclosure_from_json(value: object) -> Disclosure:
    """Rebuild a Disclosure from stored json. Raises ValueError on junk."""
    if not isinstance(value, dict):
        raise ValueError("disclosure must be an object")

    ownership = value.get("ownership")
    channel = value.get("channel")
    may_probe = value.get("may_probe")
    if ownership not in _OWNERSHIP:
        raise ValueError("disclosure.ownership is invalid")
    if channel not in _CHANNEL:
        raise ValueError("disclosure.channel is invalid")
    if not isinstance(may_probe, bool):
        raise ValueError("disclosure.may_probe must be boolean")
    # Defence in depth: the derived fields must agree, or a hand-edited row
    # could grant probe rights that ownership never implied.
    if may_probe != (ownership in ("own", "consented")):
        raise ValueError("disclosure.may_probe disagrees with ownership")
    if channel != _channel_for(ownership):  # type: ignore[arg-type]
        raise ValueError("disclosure.channel disagrees with ownership")

    for key in ("finding_id", "name", "severity", "redacted", "location", "detail"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise ValueError(f"disclosure.{key} must be a non-empty string")

    return Disclosure(
        finding_id=value["finding_id"], name=value["name"],
        severity=value["severity"], redacted=value["redacted"],
        location=value["location"], ownership=ownership,  # type: ignore[arg-type]
        channel=channel, may_probe=may_probe, detail=value["detail"])  # type: ignore[arg-type]
