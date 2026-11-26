from __future__ import annotations

import json
import uuid
from decimal import Decimal
from typing import Any

from app.accounts import api_key_prefix, generate_api_key, hash_api_key
from app.db._core import (
    DatabaseNotConfigured,
    _resolve_get_pool,
    _row_to_account,
    _row_to_mcp_key,
    _uuid_or_none,
)


class AccountRepository:
    """Accounts for the paywall foundation (see app/accounts.py). Same
    real/fake split and not-configured contract as AuditRepository: when
    DATABASE_URL isn't set, create/get_by_key_hash/rotate_key return None
    instead of failing, so a request carrying an API key on an unconfigured
    deployment simply falls back to anonymous/free.

    No public create-account endpoint exists (that would be an abuse
    hole) -- create() is used by Stage 2's payment flow and by tests."""

    async def create(self, *, api_key: str, tier: str) -> dict[str, Any] | None:
        """Mint an account for a freshly generated `api_key`. Stores only
        the safe prefix and the HMAC hash -- NEVER the plaintext key -- so a
        DB leak yields no usable keys. The plaintext is returned in the
        result dict for one-time delivery to the buyer (it can never be
        recovered afterward; there is no plaintext at rest to re-send)."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        # Compute only once the DB is actually configured, so the
        # not-configured contract (return None) doesn't require a pepper.
        # hash_api_key raises loudly if the pepper is missing on a DB-backed
        # deployment -- never a silent empty-pepper hash.
        key_prefix = api_key_prefix(api_key)
        key_hash = hash_api_key(api_key)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into accounts (key_prefix, key_hash, tier)
                values (%s, %s, %s)
                returning id, key_prefix, key_hash, tier, created_at
                """,
                (key_prefix, key_hash, tier),
            )
            row = await cur.fetchone()
        account = _row_to_account(row)
        # api_key is never persisted. Surface the plaintext in-memory so the
        # caller can deliver it exactly once (it cannot be recovered later).
        account["api_key"] = api_key
        return account

    async def get_by_key_hash(self, key_hash: str) -> dict[str, Any] | None:
        """Primary (and only) authenticated lookup: match the HMAC hash of
        the presented key. See app/accounts.resolve_account."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, key_prefix, key_hash, tier, created_at
                from accounts where key_hash = %s
                """,
                (key_hash,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None

    async def rotate_key(self, account_id: str) -> dict[str, Any] | None:
        """Issue a NEW key for an existing account, invalidating the old one.

        Overwrites key_prefix/key_hash with a freshly generated key: the old
        key's hash is gone, so it stops resolving immediately. The new
        plaintext is returned in-memory for one-time delivery, exactly like
        create() -- it is never persisted and cannot be recovered later.
        Returns None if the DB isn't configured or no such account exists.

        This is the recovery path for a lost key (there is no plaintext at
        rest to re-send) and the response to a suspected leak."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(account_id)
        except ValueError:
            return None
        new_key = generate_api_key()
        key_prefix = api_key_prefix(new_key)
        key_hash = hash_api_key(new_key)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update accounts
                set key_prefix = %s, key_hash = %s
                where id = %s
                returning id, key_prefix, key_hash, tier, created_at
                """,
                (key_prefix, key_hash, parsed_id),
            )
            row = await cur.fetchone()
        if row is None:
            return None
        account = _row_to_account(row)
        account["api_key"] = new_key
        return account

    async def get_by_id(self, account_id: str) -> dict[str, Any] | None:
        """Look up an account by its uuid. Used by the billing flow to
        re-fetch the just-granted account -- e.g. on a duplicate Telegram
        webhook, or the bank-transfer invoice-status endpoint. The plaintext key is
        never stored, so this cannot re-deliver the key text -- the key is
        shown once at creation; a lost key is replaced via rotate_key, not
        recovered. Only key_prefix is available here for identification."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(account_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, key_prefix, key_hash, tier, created_at
                from accounts where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_account(row) if row else None


class LlmUsageRepository:
    """The single journal of what each LLM-backed job cost (migration
    0020_llm_usage.sql). Same real/fake split and not-configured contract as
    AuditRepository: when DATABASE_URL isn't set, create() returns None instead
    of failing, so a scan on an unconfigured deployment still runs -- it just
    doesn't record usage (there is nowhere to record it).

    Write-only in this step: nothing reads it to block a request yet. The
    per-account daily-spend aggregate a follow-up step will add is a single
    SUM(cost_usd) over this table (see the account/created_at index), so no read
    method is added here until that enforcement work lands and can be tested
    against real behavior."""

    async def create(
        self, *, job_type: str, job_id: str | None,
        account_id: str | None, model: str, calls: int,
        input_tokens: int, output_tokens: int, cost_usd: Any,
        audit_job_id: str | None = None,
        provider_usage: dict | None = None,
    ) -> dict[str, Any] | None:
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        # Both foreign-keyish columns are nullable uuids: a scan with no
        # persisted audit row (job_id) or an anonymous/system job (account_id)
        # must still record its cost, not be dropped. An unparseable id is
        # treated as absent rather than raising -- the cost fact matters more
        # than the linkage.
        parsed_job_id = _uuid_or_none(job_id)
        parsed_account_id = _uuid_or_none(account_id)
        # audit_jobs.id, when this spend happened inside a queued job. One row
        # per ATTEMPT, so a job retried three times leaves three rows sharing
        # this id and the true cost of the job is their sum -- see
        # sum_by_audit_job. Null for the monitoring re-audit path, which has no
        # queue row.
        parsed_audit_job_id = _uuid_or_none(audit_job_id)
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into llm_usage
                    (job_type, job_id, account_id, model, calls,
                     input_tokens, output_tokens, cost_usd, audit_job_id, provider_usage)
                values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                returning id, job_type, job_id, account_id, model, calls,
                          input_tokens, output_tokens, cost_usd, created_at,
                          audit_job_id, provider_usage
                """,
                (job_type, parsed_job_id, parsed_account_id, model,
                 int(calls), int(input_tokens), int(output_tokens), cost_usd,
                 parsed_audit_job_id,
                 json.dumps(provider_usage, allow_nan=False) if provider_usage is not None else None),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def sum_by_audit_job(self, audit_job_id: str) -> dict[str, Any]:
        """What one queued job actually cost, summed over EVERY attempt.

        A job is allowed max_attempts tries and each one re-runs the scan, so
        the cost of the job is the sum of its rows, not the cost of the attempt
        that happened to succeed. `attempts` comes from the queue job: a paid
        attempt can now write two model-stage rows. It includes attempts that
        failed before spending; an entirely unspent job still returns zero.

        Zeros (not None) for an unknown or unspent job: "this job cost nothing"
        is the truthful answer for a job whose scans never reached the LLM, and
        a caller adding this into a total should not have to special-case it."""
        empty = {"calls": 0, "input_tokens": 0, "output_tokens": 0,
                 "cost_usd": Decimal(0), "attempts": 0}
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return empty
        parsed = _uuid_or_none(audit_job_id)
        if parsed is None:
            return empty
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select coalesce(sum(calls), 0) as calls,
                       coalesce(sum(input_tokens), 0) as input_tokens,
                       coalesce(sum(output_tokens), 0) as output_tokens,
                       coalesce(sum(cost_usd), 0) as cost_usd,
                       coalesce(max(j.attempts), 0) as attempts
                from llm_usage u
                left join audit_jobs j on j.id = u.audit_job_id
                where u.audit_job_id = %s
                """,
                (parsed,),
            )
            row = await cur.fetchone()
        if row is None:
            return empty
        return {
            "calls": int(row["calls"]),
            "input_tokens": int(row["input_tokens"]),
            "output_tokens": int(row["output_tokens"]),
            "cost_usd": Decimal(row["cost_usd"]),
            "attempts": int(row["attempts"]),
        }

    async def spend_since(self, *, window_seconds: int) -> dict[str, Any] | None:
        """Provider spend and call count over a trailing window, all accounts.

        The operational view of the same journal sum_anon_spend_today reads for
        enforcement: that one gates a request, this one answers "did our LLM
        bill just change shape" from a stats endpoint. Whole-fleet, so no
        account filter -- a per-account breakdown belongs with the billing
        views, not in an ops aggregate.

        cost_usd stays a Decimal so nothing rounds before the caller decides
        it has to; the column is numeric(12,6) and this sum is a spend figure,
        not a display string.

        Zeros for an empty window (nothing spent IS the answer), None only when
        DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select coalesce(sum(calls), 0) as calls,
                       coalesce(sum(cost_usd), 0) as cost_usd
                  from llm_usage
                 where created_at >= now()
                       - make_interval(secs => %s::double precision)
                """,
                (float(window_seconds),),
            )
            row = await cur.fetchone()
        return {
            "window_seconds": window_seconds,
            "calls": int(row["calls"]),
            "cost_usd": Decimal(row["cost_usd"]),
        }

    async def sum_anon_spend_today(self) -> Decimal | None:
        """Total USD spent today (UTC) by anonymous/free traffic -- every
        llm_usage row with account_id IS NULL since UTC midnight. This is a
        GLOBAL backstop over all anonymous callers, not a per-IP figure
        (account_id IS NULL can't tell two anon callers apart; per-IP is the
        request-count rate limiter's job). The daily-spend cap in app/main.py
        reads this before running a scan. Returns None when DATABASE_URL isn't
        set -- an unconfigured deployment has no journal to cap against and the
        caller treats None as "no data, don't degrade"."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select coalesce(sum(cost_usd), 0) as spend
                from llm_usage
                where account_id is null
                  and created_at >= date_trunc('day', now() at time zone 'UTC')
                """,
            )
            row = await cur.fetchone()
        return Decimal(row["spend"]) if row else Decimal(0)


class ServiceFlagsRepository:
    """Operator-controlled kill switches (migration 0021_service_flags.sql).
    One row per flag; the only one used today is key='llm_paid_ops', the
    emergency stop for all LLM-spending work. Same not-configured contract as
    the other repositories: with no DATABASE_URL, get() returns None and the
    caller treats "no flag store" as "not paused" -- an unconfigured dev box
    must still run scans."""

    async def get(self, key: str) -> dict[str, Any] | None:
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select key, enabled, note, updated_at
                from service_flags where key = %s
                """,
                (key,),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def set(self, key: str, *, enabled: bool,
                  note: str | None = None) -> dict[str, Any] | None:
        """Upsert a flag (used by the internal toggle endpoint). Returns the
        stored row, or None when DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into service_flags (key, enabled, note, updated_at)
                values (%s, %s, %s, now())
                on conflict (key) do update
                   set enabled = excluded.enabled,
                       note = excluded.note,
                       updated_at = now()
                returning key, enabled, note, updated_at
                """,
                (key, enabled, note),
            )
            row = await cur.fetchone()
        return dict(row) if row else None



class RlsLiveCheckRepository:
    """The consent ledger for the live RLS check (migration 0031).

    Every other stage of an audit reads a copy of the customer's code. This one
    sends a request to a database that belongs to somebody. If it is ever
    questioned, the answer has to be a row rather than a log line that rotated
    out.

    It was the ONLY path out to a third party's system until the served-bundle
    check (migration 0037, ServedBundleCheckRepository below) added a second.
    That sentence is corrected here rather than left standing, because a
    docstring asserting uniqueness is exactly the kind of claim someone later
    reasons from.

    THE ROW IS WRITTEN BEFORE THE REQUESTS GO OUT. A ledger that only records
    completed checks cannot show the one that crashed halfway, which is exactly
    the case somebody would ask about. `outcome` and `result_json` stay NULL
    until `complete()` — and a NULL pair is itself the record that something
    was started and did not finish.

    Same not-configured contract as every other repository here: with no
    DATABASE_URL these no-op and return None rather than failing, so a missing
    analytics store never breaks the check itself.

    THE ANON KEY IS NEVER PASSED TO THIS CLASS. It has no parameter for one.
    """

    async def start(
        self, *, audit_id: str | None, client_key: str, consent_phrase: str,
    ) -> dict[str, Any] | None:
        """Record the intent to check, before anything is sent.

        `consent_phrase` is what the caller actually typed, not a boolean. A
        boolean stores our interpretation of their act; the phrase stores the
        act, and the two differ exactly when someone asks which happened.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into rls_live_checks
                    (audit_id, client_key, consent_phrase)
                values (%s, %s, %s)
                returning id, audit_id, client_key, project_ref,
                          consent_phrase, tables_asked, outcome, result_json,
                          created_at, completed_at
                """,
                (parsed_audit_id, client_key, consent_phrase),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def complete(
        self, check_id: str, *, project_ref: str, outcome: str,
        tables_asked: list[str], result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Close the row out with what actually happened."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update rls_live_checks
                   set project_ref  = %s,
                       outcome      = %s,
                       tables_asked = %s::jsonb,
                       result_json  = %s::jsonb,
                       completed_at = now()
                 where id = %s
                returning id, audit_id, client_key, project_ref,
                          consent_phrase, tables_asked, outcome, result_json,
                          created_at, completed_at
                """,
                (project_ref or None, outcome, json.dumps(tables_asked),
                 json.dumps(result), uuid.UUID(str(check_id))),
            )
            row = await cur.fetchone()
        return dict(row) if row else None


class ServedBundleCheckRepository:
    """The consent ledger for the served-bundle check (migration 0037).

    The second path this product has out to somebody else's system, and the
    first that fetches an ARBITRARY customer-supplied URL rather than a
    shape-constrained one. Same accounting as RlsLiveCheckRepository above and
    for the same reason: if it is ever questioned, the answer has to be a row.

    THE ROW IS WRITTEN BEFORE THE REQUEST GOES OUT, so a check that crashed
    halfway is visible as a NULL outcome rather than absent — the case somebody
    would actually ask about.

    NO TOKEN AND NO FETCHED BYTES REACH THIS CLASS. It has no parameter for
    either. What `complete()` stores is the redacted evidence the registry
    already produced plus the asset URLs read; a leaked service_role key is
    abused within minutes, so keeping one to prove we found it would repeat the
    defect being reported.
    """

    async def start(
        self, *, audit_id: str | None, client_key: str, consent_phrase: str,
    ) -> dict[str, Any] | None:
        """Record the intent to fetch, before anything leaves the process."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into served_bundle_checks
                    (audit_id, client_key, consent_phrase)
                values (%s, %s, %s)
                returning id, audit_id, client_key, deployment_url,
                          consent_phrase, assets_read, outcome, result_json,
                          created_at, completed_at
                """,
                (parsed_audit_id, client_key, consent_phrase),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def latest_completed_for(
        self, *, audit_id: str, deployment_url: str,
    ) -> dict[str, Any] | None:
        """The most recent SUCCESSFUL check of this deployment, or None.

        The baseline a rotation verdict compares against. Three filters carry
        the meaning:

        * `completed_at is not null` — an open row is a check that started and
          may never have read anything. Comparing against one would produce
          "the credential is gone" from a run that simply crashed, which is the
          worst possible direction for this verdict to be wrong in.
        * `outcome = 'checked'` — a row that finished as 'skipped' (URL
          refused) or 'error' (the deployment would not answer) also carries an
          empty finding list, and it means we never looked. Since an empty
          baseline now reads as "this deployment was clean at the last check",
          admitting those rows would turn a failed fetch into evidence of
          cleanliness. The literal matches ServedBundleResult.status in
          app/proof/served_bundle.py, spelled out rather than imported so this
          module keeps no dependency on the fetch layer.
        * the SAME deployment_url — a customer with a staging and a production
          URL under one audit gets two independent baselines, because they are
          two different exposures. The caller passes the NORMALIZED url
          (app/proof/served_bundle.validate_deployment_url), so that split
          happens on genuinely different deployments and not on whether
          somebody typed a trailing slash. Migration 0037 already describes
          this column as "the URL as validated, not as typed"; that was the
          intent and it only became true in the route on 2026-09-01 — the
          comment is left alone because the file is checksummed in the
          migration ledger, and the correction lives here instead.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, audit_id, client_key, deployment_url,
                       consent_phrase, assets_read, outcome, result_json,
                       created_at, completed_at
                from served_bundle_checks
                where audit_id = %s
                  and deployment_url = %s
                  and completed_at is not null
                  and outcome = 'checked'
                order by completed_at desc
                limit 1
                """,
                (uuid.UUID(audit_id), deployment_url),
            )
            row = await cur.fetchone()
        return dict(row) if row else None

    async def complete(
        self, check_id: str, *, deployment_url: str, outcome: str,
        assets_read: list[str], result: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Close the row out with what actually happened."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update served_bundle_checks
                   set deployment_url = %s,
                       outcome        = %s,
                       assets_read    = %s::jsonb,
                       result_json    = %s::jsonb,
                       completed_at   = now()
                 where id = %s
                returning id, audit_id, client_key, deployment_url,
                          consent_phrase, assets_read, outcome, result_json,
                          created_at, completed_at
                """,
                (deployment_url or None, outcome, json.dumps(assets_read),
                 json.dumps(result), uuid.UUID(str(check_id))),
            )
            row = await cur.fetchone()
        return dict(row) if row else None



class McpKeyRepository:
    """The MCP credential and what it may read (migration 0036).

    Separate from AccountRepository on purpose, and the migration header says
    why at length: an MCP key carries no tier, buys nothing, and must not
    start meaning something different the day somebody buys Pro again.
    """

    async def create(self, *, key_hash: str, key_prefix: str,
                     label: str | None = None) -> dict[str, Any] | None:
        """Record a freshly minted key. The plaintext is the caller's to hand
        over and is never passed in here -- only its hash and visible head."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into mcp_api_keys (key_hash, key_prefix, label)
                values (%s, %s, %s)
                returning id, key_prefix, label, created_at, last_used_at,
                          revoked_at
                """,
                (key_hash, key_prefix, label),
            )
            row = await cur.fetchone()
        return _row_to_mcp_key(row) if row else None

    async def get_by_key_hash(self, key_hash: str) -> dict[str, Any] | None:
        """The one authenticated lookup, run on every MCP request.

        A REVOKED KEY RESOLVES TO None, not to a row the caller must remember
        to check. Returning the row and leaving `revoked_at` for each caller
        to test is how one call site eventually forgets, and that call site is
        then a revoked credential that still works. The cost of deciding here
        is that "revoked" and "never existed" are indistinguishable to the
        holder -- which is the right answer to give either way.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, key_prefix, label, created_at, last_used_at,
                       revoked_at
                from mcp_api_keys
                where key_hash = %s and revoked_at is null
                """,
                (key_hash,),
            )
            row = await cur.fetchone()
        return _row_to_mcp_key(row) if row else None

    async def touch(self, key_id: str) -> None:
        """Record that the key was used, for the expiry policy docs/MCP.md
        deliberately leaves open: recorded from the first day so the decision
        can later be made from data rather than guessed now.

        Best-effort and swallowing nothing -- it is a plain UPDATE -- but the
        caller is expected to run it after answering, never before, so a slow
        write cannot delay a reply.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                "update mcp_api_keys set last_used_at = now() where id = %s",
                (uuid.UUID(str(key_id)),),
            )

    async def revoke(self, key_id: str) -> bool:
        """Stop a key working, keeping its row so the audits it reached still
        trace back to it. Returns whether a live key was revoked, so a second
        call is visibly a no-op rather than a silent success."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update mcp_api_keys set revoked_at = now()
                where id = %s and revoked_at is null
                returning id
                """,
                (uuid.UUID(str(key_id)),),
            )
            row = await cur.fetchone()
        return row is not None

    async def link_audit(self, key_id: str, audit_id: str) -> None:
        """Record that this key asked for this audit and may read it.

        IDEMPOTENT, AND THE REASON IS THE CACHE. get_by_content_hash returns a
        previously created audit row whenever byte-identical content was
        audited before, by anyone (app/main.py). So two keys legitimately land
        on one audit, and one key can land on the same audit twice. A join row
        says the true thing in both cases -- this key may read this audit --
        and ON CONFLICT DO NOTHING makes the repeat harmless rather than a
        500 in the middle of an answer.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                insert into mcp_key_audits (mcp_key_id, audit_id)
                values (%s, %s)
                on conflict (mcp_key_id, audit_id) do nothing
                """,
                (uuid.UUID(str(key_id)), uuid.UUID(str(audit_id))),
            )

    async def may_read_audit(self, key_id: str, audit_id: str) -> bool:
        """docs/MCP.md §2, as one question with one answer.

        Every MCP tool that returns audit content asks this first. It is a
        membership test and nothing else: no fallback to "well, the audit
        exists", no widening for a key that happens to have many audits. The
        caller's 'not found' and 'not yours' must be the same reply, so this
        returning False is all the information a handler needs.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return False
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select 1 from mcp_key_audits
                where mcp_key_id = %s and audit_id = %s
                """,
                (uuid.UUID(str(key_id)), uuid.UUID(str(audit_id))),
            )
            row = await cur.fetchone()
        return row is not None

    async def list_audits(self, key_id: str, *,
                          limit: int = 20) -> list[dict[str, Any]]:
        """This key's audits, newest first -- what drydock_list_recent shows.

        Joined rather than selected by id list so the answer cannot include an
        audit that was deleted out from under the link, and bounded because an
        MCP response goes into a context window somebody is paying for.

        `basis` is extracted in SQL rather than by selecting score_json: the
        listing needs one string out of that blob, and shipping every row's
        findings-shaped jsonb into Python to read it would cost the same
        response its bound. The tool used to reach for `score_json` on these
        rows anyway -- a key this query has never returned -- and printed null.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select a.id, a.repo_url, a.stack, a.score_total, a.created_at,
                       a.score_json->>'basis' as basis
                from mcp_key_audits k
                join audits a on a.id = k.audit_id
                where k.mcp_key_id = %s
                order by k.created_at desc
                limit %s
                """,
                (uuid.UUID(str(key_id)), int(limit)),
            )
            rows = await cur.fetchall()
        return [{**dict(r), "id": str(r["id"])} for r in rows]
