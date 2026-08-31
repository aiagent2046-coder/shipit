"""Four answers to "did you fix it", and why none of them may be three.

app/proof/rotation.py compares a baseline check against a fresh one by
credential fingerprint. The verdicts are separate because the customer's next
action differs for each, and the two that are easiest to collapse -- "changed"
and "gone" -- are exactly the two where collapsing them misleads.
"""

from __future__ import annotations

from app.proof.rotation import compare_findings

KEY_A = {"pattern": "supabase_service_role", "fingerprint": "aaa111"}
KEY_B = {"pattern": "supabase_service_role", "fingerprint": "bbb222"}


def test_no_baseline_is_not_an_all_clear():
    """An empty baseline means we never looked before -- NOT that the
    deployment used to be clean. A caller that conflated them would report a
    first-ever finding as a regression, and a first-ever clean result as a fix
    that never happened."""
    check = compare_findings([], [KEY_A])

    assert check.verdict == "no_baseline"
    assert "baseline" in check.detail
    assert check.still_shipped == ("supabase_service_role",)


def test_the_same_credential_is_unchanged():
    check = compare_findings([KEY_A], [KEY_A])

    assert check.verdict == "unchanged"
    assert "still served" in check.detail


def test_a_new_key_in_the_bundle_is_not_success():
    """THE VERDICT MOST LIKELY TO BE MISREAD. Rotating at the provider and
    baking the new key back into the bundle changes the fingerprint, so a naive
    "it changed!" reads as progress. The old key is indeed dead; the exposure is
    not -- it is the same hole with a fresh credential in it."""
    check = compare_findings([KEY_A], [KEY_B])

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
    check = compare_findings([KEY_A], [])

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
    check = compare_findings([KEY_A, other], [other])

    assert check.verdict == "unchanged", (
        "a fingerprint surviving in the new set means that credential is still "
        "shipped, whatever else was removed")
    assert "openai_api_key" in check.still_shipped


def test_findings_without_fingerprints_do_not_fabricate_a_baseline():
    """No pepper configured -> empty fingerprints (see secret_registry). Those
    must not compare equal to each other and invent an `unchanged`, which would
    be a verdict built from two blanks."""
    blank = {"pattern": "supabase_service_role", "fingerprint": ""}
    check = compare_findings([blank], [blank])

    assert check.verdict == "no_baseline"
