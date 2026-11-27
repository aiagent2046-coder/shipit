"""Seven answers to "did you fix it", and why none of them may be fewer.

app/proof/rotation.py compares a baseline check against a fresh one by
credential fingerprint. The verdicts are separate because the customer's next
action differs for each, and the pairs that are easiest to collapse are exactly
the ones where collapsing them misleads: "changed" vs "gone", and — the
correction this file grew for — "we never checked" vs "we checked and it was
clean".

THE EMPTY-LIST TRAP HAS ITS OWN GROUP OF TESTS BELOW. Three unrelated
situations produce an empty baseline finding list, and until `had_baseline`
existed they all came out as `no_baseline`, which meant a credential appearing
on a previously clean deployment was reported as a first-ever sighting.
"""

from __future__ import annotations

from app.proof.rotation import compare_findings

KEY_A = {"pattern": "supabase_service_role", "fingerprint": "aaa111"}
KEY_B = {"pattern": "supabase_service_role", "fingerprint": "bbb222"}


def test_no_baseline_is_not_an_all_clear():
    """No earlier check means we never looked -- NOT that the deployment used
    to be clean. A caller that conflated them would report a first-ever finding
    as a regression, and a first-ever clean result as a fix that never
    happened."""
    check = compare_findings([], [KEY_A], had_baseline=False)

    assert check.verdict == "no_baseline"
    assert "baseline" in check.detail
    assert check.still_shipped == ("supabase_service_role",)


def test_a_credential_appearing_since_a_clean_check_is_a_regression():
    """THE VERDICT THIS DISTINCTION EXISTS FOR.

    Same arguments as the test above except that a prior check happened and
    found nothing. That single bit turns "we have nothing to say" into the most
    actionable statement this comparison can make: it was clean, it is not now,
    and the thing that shipped in between is the cause. Under the old rule --
    empty `previous` means no baseline -- this case was indistinguishable from
    a first-ever sighting, on the deployment class most likely to be re-checked
    on a schedule.
    """
    check = compare_findings([], [KEY_A], had_baseline=True)

    assert check.verdict == "newly_exposed"
    assert check.still_shipped == ("supabase_service_role",)
    assert "no credentials" in check.detail
    assert "appeared between" in check.detail


def test_clean_before_and_clean_now_is_not_no_baseline():
    """The other half of the same bit, and the one that governs our own site:
    drydock.co ships an anon key and no secrets, so every re-check compares an
    empty list against an empty list. Reporting `no_baseline` there would say
    "we are not keeping score" about the exact deployment we check most."""
    check = compare_findings([], [], had_baseline=True)

    assert check.verdict == "still_clean"
    assert check.still_shipped == ()
    # And it must not overclaim: we read some assets, not the deployment.
    assert "not audited clean" in check.detail


def test_the_same_credential_is_unchanged():
    check = compare_findings([KEY_A], [KEY_A], had_baseline=True)

    assert check.verdict == "unchanged"
    assert "still served" in check.detail


def test_a_new_key_in_the_bundle_is_not_success():
    """THE VERDICT MOST LIKELY TO BE MISREAD. Rotating at the provider and
    baking the new key back into the bundle changes the fingerprint, so a naive
    "it changed!" reads as progress. The old key is indeed dead; the exposure is
    not -- it is the same hole with a fresh credential in it."""
    check = compare_findings([KEY_A], [KEY_B], had_baseline=True)

    assert check.verdict == "replaced_still_shipped"
    assert check.still_shipped == ("supabase_service_role",)
    assert "still in the bundle" in check.detail


def test_gone_from_the_bundle_never_claims_revocation():
    """The honesty this module exists for.

    Removing a key from the build stops NEW visitors reading it and does
    nothing about everyone who already did. A key that sat in a public bundle
    was scraped within minutes; only rotation at the provider ends that, and we
    cannot see the provider. The verdict is named for what was measured and the
    detail must say the rest -- if this ever reads as "resolved", somebody will
    close a ticket on a live credential.
    """
    check = compare_findings([KEY_A], [], had_baseline=True)

    assert check.verdict == "gone_from_bundle"
    assert check.still_shipped == ()
    assert "does not revoke" in check.detail
    assert "still holds it" in check.detail
    # And it must not say the reassuring thing.
    assert "revoked" not in check.detail.replace("does not revoke", "")


def test_one_key_gone_and_another_still_there_is_not_gone():
    """A partial fix is not a fix. Two keys, one removed: the remaining one is
    still served to every visitor, so the verdict has to be the one that says
    so."""
    other = {"pattern": "openai_api_key", "fingerprint": "ccc333"}
    check = compare_findings([KEY_A, other], [other], had_baseline=True)

    assert check.verdict == "unchanged", (
        "a fingerprint surviving in the new set means that credential is still "
        "shipped, whatever else was removed")
    assert "openai_api_key" in check.still_shipped


def test_findings_without_fingerprints_do_not_fabricate_an_unchanged():
    """No pepper configured -> empty fingerprints (see secret_registry). Those
    must not compare equal to each other and invent an `unchanged`, which would
    be a verdict built from two blanks.

    And the answer is `not_comparable`, not `no_baseline`: there WAS an earlier
    check with credentials in it. Saying "no baseline" would blame the customer
    for a gap in our own configuration."""
    blank = {"pattern": "supabase_service_role", "fingerprint": ""}
    check = compare_findings([blank], [blank], had_baseline=True)

    assert check.verdict == "not_comparable"
    assert "no pepper" in check.detail


def test_an_unfingerprintable_finding_now_is_not_gone_from_the_bundle():
    """The same blank, on the other side, and the dangerous direction.

    The baseline had a fingerprinted key; this run found a credential it could
    not fingerprint. Matching by fingerprint alone would see an empty `after`
    and report `gone_from_bundle` -- "your key is no longer served" -- about a
    bundle that is still serving one."""
    blank = {"pattern": "supabase_service_role", "fingerprint": ""}
    check = compare_findings([KEY_A], [blank], had_baseline=True)

    assert check.verdict == "not_comparable"
    assert check.still_shipped == ("supabase_service_role",)
