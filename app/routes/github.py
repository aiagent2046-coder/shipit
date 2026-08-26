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
from starlette.concurrency import run_in_threadpool

from app import monitor
from app.deploypack import github_app
from app.deploypack.github_app import GitHubAppError
from app.db import (
    FixOutcomeRepository,
    MonitoringRunRepository,
    SubscriptionRepository,
)
from app.monitor import normalize_repo_full_name
from app.routes._shared import _VALID_OWNER_REPO_SEGMENT, _secret_equals
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


@router.get("/v1/github/installation-status")
async def github_installation_status(owner: str, repo: str) -> dict:
    """Is the Drydock GitHub App installed on owner/repo? The audit results
    page checks this before offering a Fix Pack: a Fix Pack opens a real PR,
    which needs the App installed on the target repo (see
    app/deploypack/github_app.py). Audit intake itself is public-only and
    needs no App — this gate is Fix-Pack-specific.

    Reuses the same per-repo installation lookup the PR-delivery path uses
    (github_app.installation_exists_for_repo -> GET /repos/{owner}/{repo}/installation),
    so there is one source of truth for "installed on this repo" and no
    stored installation_id to drift.

    Shape:
      - app_configured=false: the App isn't set up on this deployment at all
        (PR delivery falls back to the operator PAT), so `installed` is null
        and the frontend should not gate on it.
      - app_configured=true, installed=true: good to go, install_url null.
      - app_configured=true, installed=false, suspended=false: install_url
        points the repo owner at the App's public install page, carrying
        state=owner/repo.
      - app_configured=true, installed=false, suspended=true: the App IS
        installed and has been suspended, so no pull request can be opened.
        install_url is null ON PURPOSE — the install page is the wrong
        destination for somebody who has already installed it, and a button
        that does not fix the problem is worse than a sentence that names it.
        The page tells them to unsuspend it instead.

    `installed` is false in the suspended case, and that is the point rather
    than a rounding: on 2026-08-25 this endpoint's lookup answered True for a
    suspended installation one second before delivery got a 403, which on the
    money path means selling a Fix Pack that cannot be delivered.
    """
    if not (_VALID_OWNER_REPO_SEGMENT.match(owner)
            and _VALID_OWNER_REPO_SEGMENT.match(repo)):
        raise HTTPException(
            status_code=422,
            detail={"reason": "bad_owner_repo",
                    "detail": "owner and repo must each match ^[A-Za-z0-9._-]+$"},
        )

    app_creds = github_app.app_credentials_from_env()
    if app_creds is None:
        return {"owner": owner, "repo": repo, "app_configured": False,
                "installed": None, "suspended": None, "install_url": None}

    app_id, private_key = app_creds
    try:
        # Off the event loop: the lookup does blocking network I/O, same as
        # the token resolution the delivery path runs.
        state = await run_in_threadpool(
            github_app.installation_state_for_repo, owner, repo,
            app_id=app_id, private_key=private_key,
        )
    except GitHubAppError as exc:
        # The App IS configured but the check itself failed (bad key, GitHub
        # down). Surface as an upstream error rather than a misleading
        # "not installed" — same fault/caller split create_audit draws.
        raise HTTPException(
            status_code=502,
            detail={"reason": "installation_check_failed", "detail": str(exc)},
        ) from exc

    installed = state == github_app.INSTALLATION_ACTIVE
    suspended = state == github_app.INSTALLATION_SUSPENDED
    install_url = (None if installed or suspended
                   else github_app.build_install_url(f"{owner}/{repo}"))
    return {"owner": owner, "repo": repo, "app_configured": True,
            "installed": installed, "suspended": suspended,
            "install_url": install_url}
