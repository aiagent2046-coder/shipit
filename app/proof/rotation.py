"""Did the credential we found in the bundle actually change?

The chain this closes: a bundle check finds a live key, the customer acts, and
a second check says whether anything happened. Four answers, because "did you
fix it" has four honest ones and collapsing them would make the last two look
like the first.

THE NAMING IS THE POINT, AND IT UNDERCLAIMS ON PURPOSE. `gone_from_bundle` says
the credential we saw is no longer shipped to browsers. It does **not** say the
credential was revoked, and the difference is the whole customer risk:

    Removing a key from the build stops NEW visitors from reading it.
    It does nothing about everyone who already read it.

A key that sat in a public bundle was scraped by automated collectors within
minutes. Deleting it from the source and redeploying leaves that key live at
the provider, in the hands of whoever took it. Only rotation at the provider
dashboard ends that, and rotation is something we cannot observe from outside:
we can see what the bundle ships, never what Supabase still accepts. So the
verdict is named for what we measured, and the report has to say the rest.

WHY FINGERPRINTS AND NOT THE TOKEN. app/proof/secret_registry keeps the raw
secret in-process only; nothing persists it, because a stored service_role key
is the same exposure we are reporting, with our name on it. A fingerprint —
HMAC-SHA256 under the deployment's own pepper, the scheme accounts.py already
uses for API keys — is enough to answer "same credential or a different one"
and is useless to anybody who reads the row.

That choice costs one thing, and it is worth naming: we cannot fire the old key
at the provider to prove it now 401s, because we did not keep it. What we can
prove is what the deployment serves, which is where the exposure lives.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

RotationVerdict = Literal[
    # Nothing to compare against: this is the first check of this deployment.
    "no_baseline",
    # The same credential is still being served. Nothing was done, or what was
    # done did not reach the build.
    "unchanged",
    # The credential changed but a credential of that class is still shipped:
    # rotated at the provider and re-baked into the bundle, which fixes the old
    # key and re-creates the exposure with a new one. The most dangerous
    # outcome to report as success, because a naive "it changed!" reads as
    # progress.
    "replaced_still_shipped",
    # What we saw is no longer served. NOT proof of revocation -- see module
    # docstring.
    "gone_from_bundle",
]


@dataclass(frozen=True)
class RotationCheck:
    verdict: RotationVerdict
    detail: str
    # Classes still shipped after the change, so a report can name them.
    still_shipped: tuple[str, ...] = ()

    def evidence(self) -> dict:
        return {"verdict": self.verdict, "detail": self.detail,
                "still_shipped": list(self.still_shipped)}


def _fingerprints(findings: list[dict]) -> set[str]:
    """Fingerprints out of a stored or fresh finding list.

    Reads `evidence()` dicts rather than Finding objects so the same function
    compares a live result against a row that came back from the database —
    those are the two sides of the question, and they are never the same type.
    """
    return {str(f.get("fingerprint")) for f in findings
            if f.get("fingerprint")}


def compare_findings(
    previous: list[dict], current: list[dict],
) -> RotationCheck:
    """Baseline findings vs. this run's, by fingerprint.

    `previous` empty means no baseline — NOT that the deployment was clean
    before. A caller that treats "no earlier row" as "it used to be fine" would
    report a first-ever finding as a regression, so the two are separate
    verdicts and this one refuses to guess.
    """
    before = _fingerprints(previous)
    after = _fingerprints(current)
    classes_now = tuple(sorted({str(f.get("pattern")) for f in current
                                if f.get("pattern")}))

    if not before:
        return RotationCheck(
            "no_baseline",
            "no earlier check of this deployment to compare against; this "
            "result is the baseline, not a verdict on whether anything changed",
            classes_now)

    if before & after:
        return RotationCheck(
            "unchanged",
            "the same credential is still served to every visitor",
            classes_now)

    if after:
        return RotationCheck(
            "replaced_still_shipped",
            "the credential changed, but one of the same kind is still in the "
            "bundle — the old key is no longer the exposure, the new one is",
            classes_now)

    return RotationCheck(
        "gone_from_bundle",
        "the credential we found is no longer served. That stops new readers; "
        "it does not revoke the key, and anyone who copied it while it was "
        "public still holds it — rotate at the provider if that has not been "
        "done",
        ())
