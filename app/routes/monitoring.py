"""Operational continuous-monitoring backlog drain and per-run processor."""
from __future__ import annotations

import logging
import sys

from fastapi import APIRouter, Depends, HTTPException, Request

from app import alerts, monitor
from app.billing import telegram_stars
from app.db import (
    AuditRepository,
    LlmUsageRepository,
    MonitoringRunRepository,
    ProcessorLockBusy,
    ServiceFlagsRepository,
    SubscriptionRepository,
    monitoring_processor_lock,
)
from app.ingest.github_fetch import RepoFetchError
from app.llm.client import LLMClient
from app.log_context import set_log_context
from app.monitor import repo_url_from_full_name
from app.monitor.diff import new_high_severity_findings
from app.routes._shared import _require_bearer_token
from app.routes.dependencies import (
    get_audit_repo,
    get_billing_transport,
    get_llm_client,
    get_llm_usage_repo,
    get_monitoring_repo,
    get_repo_fetcher,
    get_service_flags_repo,
    get_subscription_repo,
)
from app.scan_pipeline import BASIS_FULL

logger = logging.getLogger("app.main")
router = APIRouter()
_MISSING = object()


def _main_attr(name: str, default=_MISSING):
    mod = sys.modules.get("app.main")
    if mod is not None and hasattr(mod, name):
        return getattr(mod, name)
    if default is not _MISSING:
        return default
    raise RuntimeError(f"app.main.{name} is not initialized")


async def _process_one_monitoring_run(
    run: dict, *, monitoring_repo: MonitoringRunRepository,
    subscription_repo: SubscriptionRepository, audit_repo: AuditRepository,
    llm_client: LLMClient, repo_fetcher, transport,
    llm_usage_repo: LlmUsageRepository,
) -> str:
    """Do the real monitoring work for one claimed run: re-audit the repo, diff
    against its previous audit, and DM every active subscriber the NEW
    critical/high findings. Returns the outcome ('notified', 'no_new',
    'unfetchable', 'unauditable', 'no_subscription', or 'failed') and advances
    the run to a terminal state so a re-run of the processor doesn't pick it up
    again.

    This is the slow half lifted verbatim from the old synchronous
    _handle_monitoring_push, now off the HTTP path. The diff is taken against
    the latest completed audit of the SAME repo captured BEFORE run_repo_audit
    persists this run's audit, so a subscriber is told only about findings that
    are newly present (new_high_severity_findings, keyed on rule_id+file).

    Every failure is made visible (mark_failed with a diagnosable error + a
    logged traceback), the same hardening as _process_one_paid_job -- a 'failed'
    run must never be silent. A caught failure is terminal; only a true crash
    (the run left stuck 'running') is recovered by the stale-lease reaper."""
    run_id = run["id"]
    repo_full_name = run["repo_full_name"]
    # Same ambient-context binding _process_one_paid_job does, for the same
    # reason: this is the other durable queue, and its drain loop is the only
    # place that knows which run the lines below belong to. Bare set (not
    # log_context()) matches that function -- the loop is sequential, so each
    # claimed run overwrites the previous one's ids rather than nesting.
    set_log_context(job_id=str(run_id))
    try:
        subs = await subscription_repo.list_active_for_repo(repo_full_name)
        if not subs:
            # Every subscription lapsed between enqueue and now -- nothing to
            # notify. Benign; close the run out.
            await monitoring_repo.mark_done(run_id)
            return "no_subscription"

        # Baseline BEFORE the new audit persists, so the diff reflects only what
        # this push introduced.
        # BASIS_FULL: this path re-audits at full depth, so only full prior
        # audits are a comparable baseline. A free static-only row in the
        # baseline would make every LLM finding look newly appeared.
        #
        # The UNION of prior audits, not the latest one. A single-pass scan is
        # a sample: measured on four same-engine runs of unchanged code
        # (2026-08-18), high-severity keys reproduce at ~65-84% and one real
        # critical showed in 2 of 4 -- against a latest-only baseline, about
        # every third high on a re-audit would DM the subscriber as "new"
        # with nothing pushed. Seen in ANY prior audit means not news.
        prior = await audit_repo.list_findings_by_repo_url(
            repo_full_name, BASIS_FULL)
        previous_findings = [f for findings in prior for f in findings]

        try:
            result = await _main_attr("run_repo_audit")(
                repo_url_from_full_name(repo_full_name), llm_client=llm_client,
                audit_repo=audit_repo, repo_fetcher=repo_fetcher,
                llm_usage_repo=llm_usage_repo, job_type="monitoring",
            )
        except RepoFetchError:
            # Repo went private/was deleted (404, indistinguishable by design).
            # Benign terminal state; the interval claim already stopped
            # re-enqueues.
            await monitoring_repo.mark_done(run_id)
            return "unfetchable"

        if result is None:
            await monitoring_repo.mark_done(run_id)
            return "unauditable"

        # The audit this run produced (or reused from the content-hash cache).
        # run_repo_audit doesn't bind it, so without this the notify half of the
        # run can't be joined to the audit it is diffing.
        set_log_context(audit_id=str(result["audit_id"]))

        new_findings = new_high_severity_findings(
            previous_findings, result["findings"]
        )
        notified = 0
        if new_findings:
            token = telegram_stars.bot_token_from_env()
            text = _monitoring_alert_text(repo_full_name, new_findings)
            for sub in subs:
                chat_id = sub.get("telegram_chat_id") or sub.get("telegram_user_id")
                if not (chat_id and token):
                    continue
                try:
                    await telegram_stars.send_message(
                        str(chat_id), text, token=token, transport=transport
                    )
                    notified += 1
                except Exception:  # noqa: BLE001 -- one bad DM must not abort the rest
                    logger.warning("monitoring alert send failed", exc_info=True)

        await monitoring_repo.mark_done(run_id)
        return "notified" if new_findings else "no_new"
    except Exception as exc:  # noqa: BLE001 -- every failure must be recorded
        # Fetch/audit/persist/notify errors land here. Log the full traceback
        # and persist a short reason so the failure is diagnosable from both the
        # logs and a `select ... from monitoring_runs` query -- never silent.
        logger.exception("monitoring run %s failed during processing", run_id)
        await monitoring_repo.mark_failed(run_id, _main_attr("_failure_detail")(exc))
        return "failed"


def _monitoring_alert_text(repo_full_name: str, new_findings: list[dict]) -> str:
    """One DM summarizing the new critical/high findings from a monitored push.
    Lists up to a handful by rule/file so the subscriber knows what changed
    without us dumping an unbounded wall of text."""
    n = len(new_findings)
    lines = [
        f"⚠️ Continuous monitoring: {n} new "
        f"critical/high finding{'s' if n != 1 else ''} in {repo_full_name}",
        "",
    ]
    shown = new_findings[:10]
    for f in shown:
        sev = (f.get("severity") or "").upper()
        rule = f.get("rule_id") or "?"
        path = f.get("file") or "?"
        lines.append(f"• [{sev}] {rule} — {path}")
    if n > len(shown):
        lines.append(f"… and {n - len(shown)} more")
    return "\n".join(lines)


@router.post("/internal/monitoring/process-pending")
async def process_pending_monitoring(
    request: Request,
    subscription_repo: SubscriptionRepository = Depends(get_subscription_repo),
    monitoring_repo: MonitoringRunRepository = Depends(get_monitoring_repo),
    audit_repo: AuditRepository = Depends(get_audit_repo),
    llm_client: LLMClient = Depends(get_llm_client),
    repo_fetcher=Depends(get_repo_fetcher),
    transport=Depends(get_billing_transport),
    llm_usage_repo: LlmUsageRepository = Depends(get_llm_usage_repo),
    service_flags_repo: ServiceFlagsRepository = Depends(get_service_flags_repo),
) -> dict:
    """Operational endpoint: drain the pending continuous-monitoring backlog.
    The GitHub push webhook enqueues one 'pending' run per eligible push and
    ACKs immediately (see MONITORING_ASYNC_PLAN.md); this drains those runs off
    the HTTP path -- re-audit the repo, diff against its previous audit, and DM
    subscribers the new critical/high findings. Meant for a scheduled caller (a
    systemd timer, same as the Fix Pack processor and the reaper -- this repo
    ships no unit file).

    Mirrors POST /internal/fixpack/process-paid exactly: a session advisory lock
    so two overlapping timer firings don't stampede; a stale-lease reap first (a
    crashed worker's run back to 'pending', bounded by attempts, else 'failed');
    then claim runs one at a time, each atomically leased 'pending' -> 'running'
    so a single run can never be processed by two passes at once.

    Requires `Authorization: Bearer <MONITORING_PROCESS_TOKEN>`, constant-time
    compared. 503 if the token isn't configured on this deployment -- an
    unconfigured processor is an operational gap to notice, not a silent no-op.

    Returns a summary the scheduler can log. If another run already holds the
    lock, returns {"skipped_locked": true} instead."""
    token = _main_attr("_monitoring_process_token")()
    if not token:
        raise HTTPException(
            status_code=503,
            detail={"reason": "monitoring_process_not_configured",
                    "detail": "MONITORING_PROCESS_TOKEN is not set on this deployment"},
        )
    _require_bearer_token(request, token)

    # Emergency stop applies to monitoring too (each run is an LLM-spending
    # re-audit). A background drain has no user to 503, so it soft-degrades:
    # leave the backlog 'pending' and return without claiming anything. The
    # stop's operator alert has already fired inside _emergency_stop_active.
    paused, _note = await _main_attr("_emergency_stop_active")(service_flags_repo)
    if paused:
        return {"skipped_paused": True}

    # Monitoring is withdrawn from sale (#184). Gating only the webhook closed
    # the entrance and left this drain able to process whatever was already
    # queued. Production's queue happened to be empty when that shipped, but
    # "happened to be" is not a guarantee, and every run here is an
    # LLM-spending re-audit of a product nobody can buy.
    #
    # Soft-degrade like the emergency stop above: a background drain has no
    # user to 503, so leave the backlog untouched and say so. Unlike the
    # emergency stop, ALERT -- a pending run existing at all while the product
    # is withdrawn means something got past the webhook gate or predates it,
    # and the operator needs the row id to find out which.
    if not monitor.MONITORING_FOR_SALE:
        queued = await monitoring_repo.pending_summary()
        total = (queued or {}).get("total", 0)
        if total:
            listed = ", ".join(
                f"{r['id']} ({r['repo_full_name']})"
                for r in (queued or {}).get("runs", [])
            )
            await alerts.notify_operator(
                f"Drydock: {total} monitoring run(s) are queued while "
                f"monitoring is WITHDRAWN from sale. Nothing was processed and "
                f"nothing was charged, but a push got past the webhook gate or "
                f"these rows predate it \u2014 worth finding out which.\n\n"
                f"Oldest first: {listed}\n\n"
                f"Inspect: select * from monitoring_runs where id in (...);"
            )
        return {"skipped_not_for_sale": True, "pending": total}

    summary = {"processed": 0, "notified": 0, "no_new": 0, "unfetchable": 0,
               "unauditable": 0, "no_subscription": 0, "failed": 0, "requeued": 0}
    try:
        async with _main_attr("monitoring_processor_lock", monitoring_processor_lock)():
            reaped = await monitoring_repo.reap_stale_running(
                max_age_minutes=_main_attr("STALE_LEASE_MINUTES"),
                max_attempts=_main_attr("MAX_JOB_ATTEMPTS"),
            )
            summary["requeued"] = reaped["requeued"]
            summary["failed"] += reaped["failed"]

            while True:
                run = await monitoring_repo.claim_one_pending()
                if run is None:
                    break
                summary["processed"] += 1
                outcome = await _process_one_monitoring_run(
                    run, monitoring_repo=monitoring_repo,
                    subscription_repo=subscription_repo, audit_repo=audit_repo,
                    llm_client=llm_client, repo_fetcher=repo_fetcher,
                    transport=transport, llm_usage_repo=llm_usage_repo,
                )
                if outcome in summary:
                    summary[outcome] += 1
                else:
                    summary["failed"] += 1
    except ProcessorLockBusy:
        # Another run holds the lock — benign. The scheduler logs and moves on.
        return {"skipped_locked": True}
    return summary
