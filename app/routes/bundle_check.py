"""The second consented request the product makes, and the first to an
arbitrary address.

`POST /v1/audits/{audit_id}/bundle-check` fetches the JavaScript a customer's
deployment serves to every visitor and reports the credentials it carries. Part
C of SUPABASE_SERVICE_ROLE_BUNDLE_PLAN.md, at the API edge.

WHY THIS CANNOT BE DERIVED FROM THE AUDIT, unlike the RLS check next door. That
one re-fetches the repository the audit already stored and reads the anon key
out of it. A deployment URL is not in the repository: the same source ships to
vercel.app, netlify.app or a custom domain, and Part A measured that 93% of
repos commit no build output at all, so there is nothing to infer it from. The
customer supplies the URL, which is precisely why the guard in
app/proof/served_bundle.py is IP vetting rather than a shape check.

CONSENT IS THE SAME TYPED PHRASE, imported rather than re-spelled. `consent=true`
is what a client library sets by default and what a copied curl carries;
`i-own-this-project` cannot be arrived at without having read what it means. One
phrase, one definition — a second copy here is how the two would drift the day
one of them changed.

DISCLOSURE IS NOT GATED ON CONSENT; THE FETCH IS. That distinction lives in
app/proof/disclosure.py and this route does not soften it: consent is what
permits us to make the request at all, and once a secret is found the finding is
reported. What consent never buys is a live probe against a third party — the
probe plan comes back empty for anything but an owned or consented target, and
this route never fires a key at anything.

WHAT THE RESPONSE MAY SAY. `checked`, `skipped` and `error` are three different
answers and none of them is "your deployment is fine". A refused URL is
`skipped` with the reason; a deployment that would not answer is `error`; only
a bundle we actually read and classified is `checked`. app/proof/served_bundle.py
keeps those apart and this layer does not flatten them.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.concurrency import run_in_threadpool

from app.db import AuditRepository, ServedBundleCheckRepository
from app.log_context import set_log_context
from app.proof.rotation import RotationCheck, compare_findings
from app.proof.served_bundle import (
    ServedBundleResult,
    UnsafeDeploymentUrl,
    fetch_served_bundle,
    validate_deployment_url,
)
from app.ratelimit import RateLimitExceeded, RateLimiter
from app.routes._shared import _client_key
from app.routes.dependencies import (
    get_audit_repo,
    get_bundle_fetch,
    get_rate_limiter,
    get_served_bundle_check_repo,
)
# One definition, imported. See the module docstring.
from app.routes.rls_check import CONSENT_PHRASE

logger = logging.getLogger(__name__)

router = APIRouter()


def payload_findings(result: ServedBundleResult) -> list[dict]:
    """The finding evidence dicts, which is what the rotation comparison and
    the stored row both read. One producer, so the fingerprints compared are
    exactly the fingerprints stored."""
    return [bf.evidence() for bf in result.findings]


def _payload(result: ServedBundleResult,
             rotation: RotationCheck | None = None) -> dict:
    """The storable, renderable form of a check.

    Findings are rendered through `evidence()`, never `Finding.secret`: the raw
    token exists in-process so a probe could consume it and must not leave. The
    disclosures travel with the findings because a secret finding ALWAYS
    produces one, and a response that showed the finding without it would hide
    the obligation.
    """
    return {
        "status": result.status,
        "detail": result.detail,
        "leaked": result.leaked,
        "findings": payload_findings(result),
        # Recognised and deliberately NOT alarmed on. Reported so a reader can
        # see the anon key was identified rather than missed -- the difference
        # between a scanner that is quiet because it looked and one that is
        # quiet because it did not.
        "publishable": [bf.evidence() for bf in result.publishable],
        "disclosures": [d.evidence() for d in result.disclosures],
        # Declared read-only checks for Tier A classes on a consented target.
        # Empty for everything else, which is the ownership gate showing.
        "probe_plan": [
            {"finding": p.finding_id, "name": p.name, "redacted": p.redacted,
             "location": p.location, "probe_family": p.probe_family,
             "probe": None if p.probe is None else {
                 "status": p.probe.status, "detail": p.probe.detail,
                 "plan": p.probe.plan}}
            for p in result.probe_plan
        ],
        "assets_read": result.assets_read,
        "evidence": result.evidence,
        # Absent rather than a fabricated "no_baseline" when the ledger is not
        # configured: on a DB-less deployment there is no baseline to have an
        # opinion about, and a verdict shaped like one would be an answer to a
        # question nobody could ask.
        "rotation": None if rotation is None else rotation.evidence(),
        "duration_ms": result.duration_ms,
    }


@router.post("/v1/audits/{audit_id}/bundle-check", status_code=200)
async def create_bundle_check_for_audit(
    audit_id: str,
    request: Request,
    deployment_url: str = Form(...),
    consent: str = Form(...),
    token: str | None = Form(None),
    limiter: RateLimiter = Depends(get_rate_limiter),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    check_repo: ServedBundleCheckRepository = Depends(
        get_served_bundle_check_repo),
    bundle_fetch=Depends(get_bundle_fetch),
) -> dict:
    """Read what this deployment serves, with the owner's typed consent.

    Ownership is the audit's per-row access token, and a missing or wrong one
    is answered 404 rather than 403 — the same rule as GET /v1/audits/{id}, so
    this never confirms an id exists to somebody who does not hold its token.

    THE RATE LIMIT IS NOT BOILERPLATE HERE. Every other limited endpoint bounds
    work we do for the caller; this one bounds requests we make to a third
    party on the caller's say-so. Without it the endpoint is a fetch proxy with
    our address on the packets, and the fact that it only ever returns the
    SHAPE of a token would be no comfort to whoever received the traffic.
    """
    if consent != CONSENT_PHRASE:
        raise HTTPException(
            status_code=422,
            detail={"reason": "consent_not_given",
                    "detail": f'consent must be exactly "{CONSENT_PHRASE}"'},
        )

    set_log_context(audit_id=audit_id)
    audit = await audit_repo.get_authorized(audit_id, token)
    if audit is None:
        raise HTTPException(
            status_code=404,
            detail={"reason": "not_found",
                    "detail": "no audit with this id and token, or persistence "
                              "isn't configured on this deployment"},
        )

    try:
        limiter.check(_client_key(request))
    except RateLimitExceeded as exc:
        raise HTTPException(
            status_code=429,
            detail={"reason": "rate_limited",
                    "detail": f"max {limiter.limit} per day"},
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc

    # THE LEDGER KEY IS THE NORMALIZED URL, NOT THE TYPED ONE, and the
    # difference is a missed baseline rather than a cosmetic one.
    # validate_deployment_url normalizes an empty path to "/", so a customer
    # who curls `https://app.example` today and `https://app.example/`
    # tomorrow was writing two independent histories: the second run would
    # find no earlier row and report `no_baseline` about a deployment we had
    # already checked. Harmless while every verdict about an empty baseline
    # was `no_baseline` anyway; not harmless now that a missed baseline is the
    # difference between `newly_exposed` and "nothing to compare with".
    #
    # An unsafe URL keeps its typed form: fetch_served_bundle is what refuses
    # it, with a reason, and the ledger should record what was actually asked
    # for rather than a tidied version of a request we declined.
    try:
        ledger_url = validate_deployment_url(deployment_url).url
    except UnsafeDeploymentUrl:
        ledger_url = deployment_url

    # The previous FINISHED check of this same deployment, read before this
    # run opens its own row so it can never compare against itself.
    baseline = await check_repo.latest_completed_for(
        audit_id=audit_id, deployment_url=ledger_url)

    # Written before the request goes out, so a crash mid-fetch leaves a row
    # with a NULL outcome rather than no row at all.
    ledger_row = await check_repo.start(
        audit_id=audit_id,
        client_key=_client_key(request),
        consent_phrase=consent,
    )

    # `ownership="consented"`: the caller holds this audit's access token AND
    # typed the phrase. That is what the disclosure layer means by consented,
    # and it is passed explicitly rather than defaulted -- fetch_served_bundle's
    # own default is "unknown", which discloses and never probes.
    result = await run_in_threadpool(
        lambda: fetch_served_bundle(
            url=deployment_url, consent=True, ownership="consented",
            fetch=bundle_fetch),
    )

    # Read AFTER the fetch and BEFORE this run is stored, so the baseline is
    # the previous check rather than this one. Reading it earlier would work
    # too; doing it here keeps the ordering obvious next to the write below.
    # THREE DIFFERENT ABSENCES, and each earlier version of this conflated a
    # different pair of them.
    #
    #   * No ledger at all (DB-less deployment): nothing was ever recorded and
    #     nothing can be, so there is no question to answer -- rotation is None.
    #   * A ledger, but no earlier CHECKED row for this deployment: that IS an
    #     answer, and it is `no_baseline`. Reporting None here would look
    #     identical to the case above and hide that we are now keeping score.
    #   * An earlier checked row that found no credentials: also an answer, and
    #     NOT `no_baseline` -- it is the baseline, and it was clean. Passing an
    #     empty finding list and letting rotation.py infer from it is how this
    #     used to report a newly appeared credential as a first-ever sighting,
    #     so what we can and cannot compare is stated here instead of guessed
    #     there.
    #
    # `ledger_row` is the discriminator for the first case: it exists exactly
    # when the ledger is live. `previous_findings is not None` is the
    # discriminator for the second -- we have a baseline exactly when we could
    # read a finding LIST out of it, so a row with a null or malformed
    # result_json falls back to `no_baseline` rather than passing for clean.
    rotation: RotationCheck | None = None
    if ledger_row is not None:
        baseline_result = (baseline or {}).get("result_json")
        previous_findings = (baseline_result.get("findings")
                             if isinstance(baseline_result, dict) else None)
        rotation = compare_findings(
            previous_findings if isinstance(previous_findings, list) else [],
            payload_findings(result),
            had_baseline=isinstance(previous_findings, list),
        )

    payload = _payload(result, rotation)

    if ledger_row:
        await check_repo.complete(
            str(ledger_row["id"]),
            # The same key the lookup above used, so this row is findable as a
            # baseline by the next check. Storing the typed form here while
            # looking up the normalized one would guarantee a miss.
            deployment_url=ledger_url,
            outcome=result.status,
            assets_read=result.assets_read,
            result=payload,
        )
    payload["persisted"] = ledger_row is not None

    if result.leaked:
        # Logged at warning because somebody has a live credential in a public
        # file right now. The classes, never the token, never the mask.
        logger.warning(
            "served bundle check found %d secret(s): %s",
            len(result.findings),
            ", ".join(sorted({bf.finding.pattern_id for bf in result.findings})),
            extra={"step": "bundle_check"},
        )
    return payload
