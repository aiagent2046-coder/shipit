"""FastAPI dependency providers, extracted from app/main.py.

Every function here is an indirection that exists so tests can override it
through ``app.dependency_overrides``. That mechanism keys on **object
identity**, so these must be defined exactly once and imported everywhere
else -- never re-defined or wrapped. ``app/main.py`` re-exports them for
backwards compatibility (38 test modules import them from there), and the
re-export preserves identity because it binds the same function objects.

The module-level singletons below (``_limiter``, ``_preview_registry``, and the
repository instances) live here for the same reason: one process-wide instance,
created at import time, handed out by reference.
"""

from __future__ import annotations

from app import sandbox_client
from app.db import (
    AccountRepository,
    AuditJobRepository,
    AuditRepository,
    FixOutcomeRepository,
    FixpackJobRepository,
    LlmUsageRepository,
    MonitoringRunRepository,
    PaymentRepository,
    RlsLiveCheckRepository,
    ServiceFlagsRepository,
    SubscriptionRepository,
)
from app.deploypack.delivery import open_pull_request
from app.deploypack.preview import PreviewRegistry
from app.ingest.github_fetch import fetch_repo_zip
from app.llm.client import LLMClient
from app.ratelimit import RateLimiter, limiter_from_env

_limiter = limiter_from_env()


def get_rate_limiter() -> RateLimiter:
    """FastAPI dependency indirection — overridable in tests."""
    return _limiter


def get_llm_client() -> LLMClient:
    """FastAPI dependency indirection — overridable in tests."""
    return LLMClient()


def get_pr_opener():
    """FastAPI dependency indirection — overridable in tests."""
    return open_pull_request


def get_repo_fetcher():
    """FastAPI dependency indirection — overridable in tests so the URL
    intake path never makes a real network call under pytest."""
    return fetch_repo_zip


_preview_registry = PreviewRegistry()


def get_preview_registry() -> PreviewRegistry:
    """FastAPI dependency indirection — overridable in tests. In-memory,
    single-process, same caveat as get_rate_limiter."""
    return _preview_registry


def get_preview_reconciler():
    """FastAPI dependency indirection — overridable in tests so the reap
    endpoint never shells out to a real `docker ps`. Routes through the
    sandbox-runner client (Variant A): the backend never execs docker itself.

    Resolved through the ``sandbox_client`` module attribute on every call, not
    captured at import time, because tests patch
    ``sandbox_client.reconcile_previews`` on the module object.
    """
    return sandbox_client.reconcile_previews


_audit_repo = AuditRepository()
_audit_job_repo = AuditJobRepository()
_fixpack_repo = FixpackJobRepository()
_fix_outcome_repo = FixOutcomeRepository()
_rls_live_check_repo = RlsLiveCheckRepository()
_account_repo = AccountRepository()
_payment_repo = PaymentRepository()
_subscription_repo = SubscriptionRepository()
_monitoring_repo = MonitoringRunRepository()
_llm_usage_repo = LlmUsageRepository()
_service_flags_repo = ServiceFlagsRepository()


def get_payment_repo() -> PaymentRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None/[]) when DATABASE_URL isn't set — see app/db.py."""
    return _payment_repo


def get_billing_transport():
    """Outbound HTTP transport for the billing providers (Telegram Bot
    API, TronGrid). None -> httpx's real transport in production;
    overridden in tests with an httpx.MockTransport so the suite never
    touches the network, same idea as get_repo_fetcher."""
    return None


def get_paypal_transport():
    """Outbound HTTP transport for the PayPal REST calls (OAuth token, orders,
    subscriptions, webhook-signature verify). None -> httpx's real transport in
    production; overridden in tests with an httpx.MockTransport so the suite
    never touches PayPal, same idea as get_billing_transport."""
    return None


def get_account_repo() -> AccountRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None) when DATABASE_URL isn't set, so a request carrying an
    API key on an unconfigured deployment falls back to anonymous/free —
    see app/db.py and app/accounts.py."""
    return _account_repo


def get_audit_repo() -> AuditRepository:
    """FastAPI dependency indirection — overridable in tests. No-ops
    (returns None from create/get) when DATABASE_URL isn't set — see
    app/db.py."""
    return _audit_repo


def get_audit_job_repo() -> AuditJobRepository:
    """Same as get_audit_repo, for the durable audit queue (migration 0022).

    Registered here so the queue has one canonical, test-overridable instance
    from the moment the schema lands. Nothing depends on it yet -- the endpoints
    that will (enqueue + poll) arrive in PR2."""
    return _audit_job_repo


def get_fixpack_repo() -> FixpackJobRepository:
    """Same as get_audit_repo, for fixpack_jobs."""
    return _fixpack_repo


def get_fix_outcome_repo() -> FixOutcomeRepository:
    """Same as get_audit_repo, for the fix_outcomes knowledge base."""
    return _fix_outcome_repo


def get_rls_live_check_repo() -> RlsLiveCheckRepository:
    """Same as get_audit_repo, for the live-RLS-check consent ledger."""
    return _rls_live_check_repo


def get_rls_fetch():
    """Outbound transport for the live RLS check. None -> the probe's own
    httpx call in production; overridden in tests so the suite never sends a
    request to a real Supabase project. Same idea as get_billing_transport,
    and load-bearing for a different reason: a test that forgot to override
    this would probe somebody's database."""
    return None


def get_subscription_repo() -> SubscriptionRepository:
    """Same as get_audit_repo, for recurring Stars subscriptions."""
    return _subscription_repo


def get_monitoring_repo() -> MonitoringRunRepository:
    """Same as get_audit_repo, for the async continuous-monitoring queue."""
    return _monitoring_repo


def get_llm_usage_repo() -> LlmUsageRepository:
    """Same as get_audit_repo, for the llm_usage cost journal."""
    return _llm_usage_repo


def get_service_flags_repo() -> ServiceFlagsRepository:
    """Same as get_audit_repo, for the service_flags kill switches."""
    return _service_flags_repo
