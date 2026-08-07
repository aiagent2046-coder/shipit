"""Request/response helpers shared by more than one route module.

Extracted from app/main.py verbatim. Everything here is used by at least two
endpoint groups -- that shared use is the reason it lives in its own module
rather than beside a single router.

Names keep their leading underscore. They were private to main.py and are
still not part of any public surface; the underscore records that, and keeping
it means the move is a pure relocation with no rename to chase through
callers.
"""

from __future__ import annotations

import json

from fastapi import HTTPException, Request

from app.fixpack.generate import has_auto_fixable_findings


async def _json_object_body(request: Request) -> dict:
    """The request body as a JSON object, or 422.

    `await request.json()` raises on a malformed body, and every endpoint that
    called it bare turned a typo into a 500 -- which the global handler logs
    with a traceback AND pages the operator for. A client sending broken JSON
    is not an incident; it is the client's mistake, and the response should
    say which.

    Non-objects are refused for the same reason one level down. A body of `[]`
    or `"hi"` parses fine, and the next line is always `body.get(...)`, so it
    became AttributeError -- a 500 by a slightly longer route.

    422 rather than 400 to match every other body-shape refusal in this API,
    including the one place that already guarded this (the service-flags
    endpoint). Webhook senders retry on any non-2xx, so this does not stop
    Telegram or PayPal re-delivering an unparseable payload -- but a retry that
    fails identically is cheap, while a 500 also wakes someone up.
    """
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        body = None

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=422,
            detail={"reason": "invalid_json",
                    "detail": "request body must be a JSON object"},
        )
    return body


def _reject_if_nothing_to_fix(audit: dict) -> None:
    """409 when this audit has no finding a Fix Pack could ever rewrite.

    Every rule the Fix Pack knows is fixed; every other finding is advice. An
    audit whose findings contain none of them has an empty plan before a
    customer pays, and no amount of running the job changes that.

    Audit 05fa18f5 was sold one anyway: zero eligible findings, job ran, payer
    got "Nothing to auto-fix" and was charged for it. The check needs no
    network and no LLM -- only the findings already stored on the audit.

    Deliberately one-directional. It proves "definitely nothing to fix" and
    never claims the opposite: a finding eligible here can still fall away
    when the repository is re-fetched, because the code may have moved since
    the audit. Refusing on the certain case is worth doing; promising a pull
    request is not something this can honestly do.
    """
    if not has_auto_fixable_findings(audit.get("findings_json") or []):
        raise HTTPException(
            status_code=409,
            detail={"reason": "no_auto_fixable_findings",
                    "detail": "This audit has no findings a Fix Pack can fix "
                              "automatically \u2014 the ones it found are "
                              "recommendations, or live in comments, docs or "
                              "tests. Buying one would produce an empty pull "
                              "request, so it isn't offered."},
        )


async def _reject_if_fixpack_already_live(fixpack_repo, audit_id: str) -> None:
    """409 when this audit already has a Fix Pack job that is paid or running.

    Selling one is the last moment refusing costs nothing. After the payment,
    every layer below reports success and none of them can undo it:
    create_paid is idempotent per audit, so a second confirmed payment joins
    the existing job instead of opening a second fix PR, and the buyer is told
    "completed" for work that was already bought and paid for once.

    The condition mirrors the ON CONFLICT predicate in create_paid --
    status in ('paid', 'running') -- and must keep mirroring it. A stricter
    check here would refuse sales the database would have happily served:
    re-buying after a 'failed' job is a supported flow, and so is buying again
    once a previous Fix Pack was delivered and the audit re-run.

    get_by_audit returns the newest job, which is enough: migration 0025's
    partial unique index allows only one live job per audit, so a newer
    terminal row can only exist if no live one does.

    No-op when persistence isn't configured (get_by_audit returns None), same
    contract as every other repository call on this path.
    """
    job = await fixpack_repo.get_by_audit(audit_id)
    if job is None or job.get("status") not in ("paid", "running"):
        return
    raise HTTPException(
        status_code=409,
        detail={
            "reason": "fixpack_already_in_progress",
            "detail": "a Fix Pack for this audit has already been paid for "
                      "and is being generated. Watch this audit's page for "
                      "the pull request — buying a second one would fund no "
                      "extra work.",
        },
    )
