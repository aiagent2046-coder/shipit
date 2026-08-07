"""The GitHub App webhook, and the monitoring baseline it can trigger.

Extracted from app/main.py verbatim -- handler bodies are unchanged, only the
decorator moved from ``@app.post`` to ``@router.post``.

Signature verification is deliberately strict: HMAC-SHA256 over the raw body,
compared with a constant-time helper, and a sha1 signature header is ignored
rather than accepted. An unset webhook secret makes the endpoint 503 instead of
skipping the check.

``monitor.MONITORING_FOR_SALE`` is read through the module, not imported by
name, so the test suite's single patch target keeps working from here.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os

from fastapi import APIRouter, Depends, HTTPException, Request

from app import monitor
from app.db import (
    FixOutcomeRepository,
    MonitoringRunRepository,
    SubscriptionRepository,
)
from app.monitor import normalize_repo_full_name
from app.routes._shared import _secret_equals
from app.routes.dependencies import (
    get_fix_outcome_repo,
    get_monitoring_repo,
    get_subscription_repo,
)

router = APIRouter()


def _github_webhook_secret() -> str | None:
    """The GitHub App's configured webhook secret, or None if unset. Used to
    verify X-Hub-Signature-256 on incoming deliveries. Must equal the secret
    set in the App's webhook settings on GitHub."""
    return os.environ.get("GITHUB_APP_WEBHOOK_SECRET") or None


def _verify_github_signature(secret: str, body: bytes, header: str) -> bool:
    """Verify a GitHub webhook delivery: header is X-Hub-Signature-256, of the
    form 'sha256=<hex>', where <hex> = HMAC-SHA256(secret, raw_body). Compared
    constant-time. GitHub also sends the older 'sha1' X-Hub-Signature, which we
    deliberately ignore -- sha256 is required and sha1 is deprecated."""
    if not header.startswith("sha256="):
        return False
    expected = hmac.new(
        secret.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    provided = header.split("=", 1)[1]
    return _secret_equals(provided, expected)


async def _handle_monitoring_push(
    payload: dict, *, subscription_repo: SubscriptionRepository,
    monitoring_repo: MonitoringRunRepository,
) -> dict:
    """Fast half of continuous monitoring (see MONITORING_ASYNC_PLAN.md): decide
    whether a push warrants a monitoring run and, if so, ENQUEUE it and ACK 200
    immediately -- the real work (audit + diff + notify) runs later in
    POST /internal/monitoring/process-pending. Doing the audit inline used to
    make GitHub mark the delivery "timed out" (its webhook-response timeout is
    shorter than a ~10s-2min audit) even when the work succeeded.

    Only a push to the repo's OWN default branch counts -- a push to a feature
    branch isn't what ships, and re-auditing every branch push would burn the LLM
    budget for noise.

    The 24h cost cap and the enqueue-dedup are one and the same atomic write:
    claim_for_monitoring stamps last_monitored_at up front, iff the repo hasn't
    been monitored in the last 24h, and reports whether THIS call won the claim.
    Two near-simultaneous default-branch pushes race on that single UPDATE;
    exactly one wins and enqueues a run, the other is a no-op -- so a subscriber
    is neither double-audited nor double-notified. Stamping at enqueue (not after
    the audit) is also what makes a dead/private repo stop re-enqueuing on every
    push."""
    repository = payload.get("repository") or {}
    default_branch = repository.get("default_branch")
    ref = payload.get("ref") or ""
    if not default_branch or ref != f"refs/heads/{default_branch}":
        return {"ignored": True, "reason": "not_default_branch"}

    repo_full_name = normalize_repo_full_name(
        repository.get("full_name") or repository.get("html_url")
    )
    if repo_full_name is None:
        return {"ignored": True, "reason": "unparseable_repo"}

    # Checked BEFORE the subscription lookup, deliberately: an already-active
    # row must not drive spend either, and this is the single place a push
    # turns into an audit. See MONITORING_FOR_SALE.
    if not monitor.MONITORING_FOR_SALE:
        return {"ignored": True, "reason": "monitoring_not_for_sale"}

    subs = await subscription_repo.list_active_for_repo(repo_full_name)
    if not subs:
        return {"ignored": True, "reason": "no_active_subscription"}

    now = datetime.datetime.now(datetime.timezone.utc)
    if not await subscription_repo.claim_for_monitoring(repo_full_name, now):
        # Within 24h of the last run, or lost the race to a concurrent push.
        return {"ignored": True, "reason": "within_interval"}

    # Won the claim: enqueue a durable 'pending' run and ACK immediately. The
    # processor drains it off the HTTP path.
    run = await monitoring_repo.enqueue(repo_full_name)
    return {
        "queued": True, "repo_full_name": repo_full_name,
        "run_id": run["id"] if run else None,
    }


@router.post("/v1/webhooks/github")
async def github_webhook(
    request: Request,
    fix_outcome_repo: FixOutcomeRepository = Depends(get_fix_outcome_repo),
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    monitoring_repo: MonitoringRunRepository = Depends(get_monitoring_repo),
) -> dict:
    """GitHub App webhook. Two independent jobs, dispatched by X-GitHub-Event:

      * pull_request: when a Fix Pack PR is closed, record whether it was
        merged (fix_outcomes.pr_merged) -- the real-world signal for whether
        our fix shipped. Collection only (see PHASE_B_KNOWLEDGE_BASE_PLAN.md).
      * push: continuous monitoring (Phase C). A push to a repo's default
        branch ENQUEUES a monitoring run (at most once per 24h per repo) and
        ACKs immediately; the re-audit + diff + DM run later on the
        /internal/monitoring/process-pending processor (see
        MONITORING_ASYNC_PLAN.md).

    Authenticity is the standard GitHub scheme: X-Hub-Signature-256 =
    'sha256=' + HMAC-SHA256(GITHUB_APP_WEBHOOK_SECRET, raw body), compared
    constant-time over the *raw* bytes (not re-serialized JSON). 503 if the
    secret isn't configured -- an unconfigured webhook is an operational gap to
    notice, same posture as the Telegram webhook. 401 on a missing/invalid
    signature.

    Everything other than the two handled events is a 200 ack so GitHub stops
    retrying.

    NOTE: the App must be subscribed to BOTH the 'Pull request' AND 'Push'
    events in its GitHub settings for these deliveries to arrive at all -- a
    manual, one-time UI step (see README)."""
    secret = _github_webhook_secret()
    if not secret:
        raise HTTPException(
            status_code=503,
            detail={"reason": "github_webhook_not_configured",
                    "detail": "GITHUB_APP_WEBHOOK_SECRET is not set on this "
                              "deployment"},
        )
    body = await request.body()
    signature = request.headers.get("x-hub-signature-256", "")
    if not _verify_github_signature(secret, body, signature):
        raise HTTPException(status_code=401, detail={"reason": "unauthorized"})

    event = request.headers.get("x-github-event", "")
    payload = json.loads(body) if body else {}

    if event == "pull_request":
        if payload.get("action") != "closed":
            return {"ignored": True, "reason": "action_not_handled"}
        pr = payload.get("pull_request") or {}
        pr_url = pr.get("html_url")
        if not pr_url:
            return {"ignored": True, "reason": "no_pull_request_url"}
        merged = bool(pr.get("merged"))
        updated = await fix_outcome_repo.set_pr_merged_by_pr_url(pr_url, merged)
        return {"updated": updated, "merged": merged}

    if event == "push":
        return await _handle_monitoring_push(
            payload, subscription_repo=subscription_repo,
            monitoring_repo=monitoring_repo,
        )

    return {"ignored": True, "reason": "event_not_handled"}
