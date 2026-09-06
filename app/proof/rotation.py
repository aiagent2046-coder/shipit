"""Did the credential we found in the bundle actually change?

The chain this closes: a bundle check finds a live key, the customer acts, and
a second check says whether anything happened. Seven answers, because "did you
fix it" has that many honest ones and collapsing them makes the dangerous cases
look like the safe ones.

THREE ABSENCES, NOT ONE, and the first two versions of this conflated a pair of
them each time. An empty baseline finding list arises from three unrelated
situations, and they have three different answers:

  * We never checked this deployment before        -> no_baseline
  * We checked, and it carried no credentials      -> still_clean / newly_exposed
  * We checked, but nothing could be fingerprinted -> not_comparable

Reading the finding list alone cannot tell them apart, which is why `previous`
being empty is NOT the signal for "no baseline" any more: the caller states
`had_baseline` explicitly, because only the caller knows whether a prior
completed check exists. The cost of getting this wrong is not cosmetic — a
credential that APPEARS on a deployment that was clean at the last check is the
most valuable thing this table can say, and under the old rule it was reported
as `no_baseline`, i.e. as a first-ever sighting with nothing to compare to.

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
    # There WAS an earlier check, it found no credentials, and neither does
    # this one. Distinct from `no_baseline`: we are keeping score and the score
    # has not moved. Still not an all-clear about the deployment — it is an
    # all-clear about the classes this checker knows and the assets it read.
    "still_clean",
    # The earlier check found nothing and this one does. A REGRESSION, and the
    # verdict this whole distinction exists for: under the old rule, where an
    # empty baseline meant "no baseline", a credential newly appearing on a
    # deployment that used to be clean was reported as a first-ever sighting.
    "newly_exposed",
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
    # Credentials on one side or both, and no fingerprints to match them by
    # (no pepper configured, so secret_registry.fingerprint returns ""). We
    # cannot say whether it is the same key, and a blank comparing equal to a
    # blank would manufacture `unchanged` out of two absences. Refusing is the
    # only honest answer.
    "not_comparable",
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
    previous: list[dict], current: list[dict], *, had_baseline: bool,
) -> RotationCheck:
    """Baseline findings vs. this run's, by fingerprint.

    `had_baseline` is REQUIRED and has no default, because every default would
    be a guess about the one thing this function cannot see. An empty
    `previous` is produced both by "no earlier check" and by "an earlier check
    that found nothing", and only the caller — which either read a prior row or
    did not — can tell those apart. A keyword with no default is what makes the
    caller say it out loud; see the module docstring for what the old inference
    got wrong.
    """
    before = _fingerprints(previous)
    after = _fingerprints(current)
    classes_now = tuple(sorted({str(f.get("pattern")) for f in current
                                if f.get("pattern")}))

    if not had_baseline:
        return RotationCheck(
            "no_baseline",
            "no earlier check of this deployment to compare against; this "
            "result is the baseline, not a verdict on whether anything changed",
            classes_now)

    if not previous:
        # A real earlier check that found no credentials. The comparison is
        # against a fact, not against a blank.
        if current:
            return RotationCheck(
                "newly_exposed",
                "the previous check of this deployment found no credentials "
                "and this one does — the exposure appeared between the two "
                "checks, so whatever shipped in between is where to look",
                classes_now)
        return RotationCheck(
            "still_clean",
            "no credentials in the previous check of this deployment and none "
            "now, in the assets we were able to read — unchanged, not audited "
            "clean",
            ())

    # The baseline carried findings. From here the comparison is by
    # fingerprint, and a missing fingerprint on EITHER side means there is
    # nothing to compare with rather than something that compares as absent.
    if not before or (current and not after):
        return RotationCheck(
            "not_comparable",
            "credentials on at least one side carry no fingerprint (no pepper "
            "configured), so we cannot say whether this is the same key as "
            "before — this is a gap in our configuration, not a finding about "
            "the deployment",
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
