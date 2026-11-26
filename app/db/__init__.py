"""Postgres persistence for audits and fixpack_jobs. Minimal scope --
see migrations/0001_audits_and_fixpack_jobs.sql for what was trimmed
from shipit-architecture.md 2.5's full schema and why.

Optional, not required: `DatabaseNotConfigured` is raised by `get_pool`
when `DATABASE_URL` isn't set, and both repositories below catch it and
return `None` from `create`/`get` instead of failing the request --
same pattern as GITHUB_PR_TOKEN, GITHUB_APP_ID, PREVIEW_REAP_TOKEN
elsewhere in this codebase. app/main.py surfaces whether persistence
actually happened (`"persisted": true/false`) rather than hiding it.

Driver: psycopg3, not asyncpg. Tried asyncpg first -- schema and SQL
were verified for real against a real Supabase Postgres 17 project via
the Supabase migration tool, but asyncpg itself hung indefinitely (no
error) on the very first parameterized query through Supabase's
Supavisor pooler, in BOTH session (5432) and transaction (6543) modes,
confirmed by hand across two networks. That's a documented, open
Supabase-side bug (github.com/supabase/supabase/issues/39227), not a
Drydock bug or a network issue -- `psql`'s \\bind (same wire-level
extended protocol, different client implementation) worked fine over
the identical connection, which is what pointed at the client library
rather than the network. `prepare_threshold=None` below disables
psycopg's server-side statement preparation, matching the workaround
that avoids the class of pooler incompatibility entirely (psycopg
wraps real libpq, the same library psql uses).

What is NOT proven from this sandbox: this exact driver code
connecting over the wire to the real project (DATABASE_URL contains a
password and is a raw Postgres-protocol secret, not something safe to
proxy into this sandbox). See scripts/verify_db_locally.py -- run by
the user, with their own DATABASE_URL, never sent here. It DID get run
by hand against the real project during this migration and confirmed
working end to end.
"""

from __future__ import annotations

from __future__ import annotations

from psycopg_pool import AsyncConnectionPool

from app.db._audits import (
    REAL_PR_URL,
    AuditRepository,
    FixOutcomeRepository,
    MonitoringRunRepository,
)
from app.db._billing import (
    PaymentRepository,
    SubscriptionRepository,
)
from app.db._core import (
    DATABASE_URL_ENV,
    GRANT_LOCK_TIMEOUT_MS,
    STALE_LEASE_DETAIL_PREFIX,
    AuditJobIdempotencyConflict,
    DatabaseNotConfigured,
    PaymentConfirmationBusy,
    ProcessorLockBusy,
    ProGrantConflict,
    _AMOUNT_LOCK_ATTEMPTS,
    _AMOUNT_LOCK_DELAY_SECONDS,
    _BANK_TRANSFER_AMOUNT_LOCK_KEY,
    _DEPENDENCY_REFRESH_LOCK_KEY,
    _FIXPACK_PROCESSOR_LOCK_KEY,
    _GRANT_LOCK_NAMESPACE,
    _LLM_ONLY_BEFORE_UNEXAMINED_WAS_STORED,
    _MONITORING_PROCESSOR_LOCK_KEY,
    _advisory_processor_lock,
    _backfill_unexamined,
    _confirmation_slots,
    _expires_at_to_timestamptz,
    _grant_lock_key,
    _json_field,
    _locked_payment_confirmation,
    _pool_lock,
    _row_to_account,
    _row_to_audit,
    _row_to_audit_job,
    _row_to_fix_outcome,
    _row_to_fixpack_job,
    _row_to_mcp_key,
    _row_to_monitoring_run,
    _row_to_payment,
    _row_to_subscription,
    _seconds_to_ms,
    _uuid_or_none,
    bank_transfer_amount_lock,
    close_pool,
    database_url_from_env,
    dependency_refresh_lock,
    fixpack_processor_lock,
    get_pool,
    monitoring_processor_lock,
    payment_confirmation_lock,
)
from app.db._jobs import (
    _AUDIT_JOB_COLUMN_NAMES,
    _AUDIT_JOB_COLUMNS,
    _AUDIT_JOB_COLUMNS_QUALIFIED,
    AuditJobRepository,
    FixpackJobRepository,
)
from app.db._platform import (
    AccountRepository,
    LlmUsageRepository,
    McpKeyRepository,
    RlsLiveCheckRepository,
    ServedBundleCheckRepository,
    ServiceFlagsRepository,
)

_pool: AsyncConnectionPool | None = None

__all__ = [
    "AsyncConnectionPool",
    "DATABASE_URL_ENV",
    "GRANT_LOCK_TIMEOUT_MS",
    "REAL_PR_URL",
    "STALE_LEASE_DETAIL_PREFIX",
    "AccountRepository",
    "AuditJobIdempotencyConflict",
    "AuditJobRepository",
    "AuditRepository",
    "DatabaseNotConfigured",
    "FixOutcomeRepository",
    "FixpackJobRepository",
    "LlmUsageRepository",
    "McpKeyRepository",
    "MonitoringRunRepository",
    "PaymentConfirmationBusy",
    "PaymentRepository",
    "ProcessorLockBusy",
    "ProGrantConflict",
    "RlsLiveCheckRepository",
    "ServedBundleCheckRepository",
    "ServiceFlagsRepository",
    "SubscriptionRepository",
    "_AMOUNT_LOCK_ATTEMPTS",
    "_AMOUNT_LOCK_DELAY_SECONDS",
    "_AUDIT_JOB_COLUMNS",
    "_AUDIT_JOB_COLUMNS_QUALIFIED",
    "_AUDIT_JOB_COLUMN_NAMES",
    "_BANK_TRANSFER_AMOUNT_LOCK_KEY",
    "_DEPENDENCY_REFRESH_LOCK_KEY",
    "_FIXPACK_PROCESSOR_LOCK_KEY",
    "_GRANT_LOCK_NAMESPACE",
    "_LLM_ONLY_BEFORE_UNEXAMINED_WAS_STORED",
    "_MONITORING_PROCESSOR_LOCK_KEY",
    "_advisory_processor_lock",
    "_backfill_unexamined",
    "_confirmation_slots",
    "_expires_at_to_timestamptz",
    "_grant_lock_key",
    "_json_field",
    "_locked_payment_confirmation",
    "_pool",
    "_pool_lock",
    "_row_to_account",
    "_row_to_audit",
    "_row_to_audit_job",
    "_row_to_fix_outcome",
    "_row_to_fixpack_job",
    "_row_to_mcp_key",
    "_row_to_monitoring_run",
    "_row_to_payment",
    "_row_to_subscription",
    "_seconds_to_ms",
    "_uuid_or_none",
    "bank_transfer_amount_lock",
    "close_pool",
    "database_url_from_env",
    "dependency_refresh_lock",
    "fixpack_processor_lock",
    "get_pool",
    "monitoring_processor_lock",
    "payment_confirmation_lock",
]
