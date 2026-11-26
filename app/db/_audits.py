from __future__ import annotations

import json
import uuid
from typing import Any

from app.db._core import (
    DatabaseNotConfigured,
    _json_field,
    _resolve_get_pool,
    _row_to_audit,
    _row_to_fix_outcome,
    _row_to_monitoring_run,
)


class AuditRepository:
    """Real-Postgres-backed by default. Tests use an in-memory fake
    with the same method signatures instead of this class -- see
    tests/test_db.py."""

    async def create(
        self, *, stack: str, file_count: int,
        score_total: float | None, score_json: dict | None,
        findings_json: list | None, repo_url: str | None = None,
        content_hash: str | None = None, engine_version: str | None = None,
        dependency_inventory: dict | None = None,
    ) -> dict[str, Any] | None:
        # access_token is not inserted here: the column default
        # (migration 0010, encode(gen_random_bytes(16),'hex')) mints a
        # per-row token, and RETURNING hands it back so the API can deliver
        # it to the creator exactly once. It is the ownership secret for
        # GET /v1/audits/{id} and /report -- see get_authorized().
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into audits (stack, file_count, score_total, score_json,
                                    findings_json, repo_url, content_hash,
                                    engine_version, dependency_inventory)
                values (%s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s::jsonb)
                returning id, stack, status, file_count, score_total,
                          score_json, findings_json, repo_url, content_hash,
                          engine_version, dependency_inventory, access_token, created_at
                """,
                (
                    stack, file_count, score_total,
                    json.dumps(score_json) if score_json is not None else None,
                    json.dumps(findings_json) if findings_json is not None else None,
                    repo_url, content_hash, engine_version,
                    # Migration 0039. Only the dependency stage's own scan
                    # writes this, and only when it actually asked: the column
                    # is what makes a stale answer refreshable without the
                    # archive bytes, which this deployment does not retain.
                    (json.dumps(dependency_inventory)
                     if dependency_inventory is not None else None),
                ),
            )
            row = await cur.fetchone()
        return _row_to_audit(row)

    async def get_by_content_hash(
        self, content_hash: str, engine_version: str, basis: str
    ) -> dict[str, Any] | None:
        """Most recent completed audit for this exact content, produced by this
        exact engine version AT THIS SCAN DEPTH, or None.

        `basis` has no default, deliberately: every caller must state which
        depth it is entitled to reuse. Without it the cache crossed the pricing
        boundary in both directions -- an anonymous visitor auditing a repo a
        paying account had already scanned would be handed the full paid result,
        and a paying account would be handed a free static-only row. Both were
        silent.

        A row written before `basis` existed in score_json matches neither value
        and therefore falls through to a recompute, which is the safe direction.

        The reproducibility backstop: an identical re-audit reuses this
        row instead of re-running the LLM scan, which returns a different
        findings set -- and thus a different score -- run to run even at
        temperature=0 (see app/scan/llm_scan.py, app/scan/scoring.py).

        The engine_version filter (migration 0013) is what keeps that reuse
        from freezing a stale result across an engine change: a row written
        under an older AUDIT_ENGINE_VERSION no longer matches, so it falls
        through to None -- a cache miss that recomputes under the current
        engine, exactly as if content_hash hadn't matched. Returns None when
        DATABASE_URL isn't set, same not-configured contract as get()."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, content_hash,
                       engine_version, dependency_inventory, access_token, created_at
                from audits
                where content_hash = %s and engine_version = %s
                      and status = 'completed'
                      and score_json->>'basis' = %s
                order by created_at desc
                limit 1
                """,
                (content_hash, engine_version, basis),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

    async def stale_dependency_audits(
        self, *, created_before: Any, limit: int = 20
    ) -> list[dict[str, Any]]:
        """Completed audits whose stored dependency inventory is old enough to
        re-ask about, oldest first.

        `created_before` is the dependency answer's age cutoff. History-only
        snapshots get a new created_at while keeping the original asked_at,
        so the snapshot date cannot decide freshness. The stage records ISO
        UTC timestamps; comparing their seconds prefix avoids casting JSON
        input, and Python still makes the exact freshness check. Ordering by
        the same answer date prevents fresh copies consuming the batch limit
        ahead of genuinely stale answers.

        Only rows WITH an inventory are returned. A row without one was never
        asked (free tier, opt-out, no lockfile), and asking now would be the
        entitlement boundary leaking in the direction this design exists to
        prevent. Returns [] when DATABASE_URL isn't set.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, content_hash,
                       engine_version, dependency_inventory, created_at
                from audits
                where dependency_inventory is not null
                      and status = 'completed'
                      and left(score_json->'scan_manifest'->>'sca_asked_at', 19)
                          <= to_char(%s::timestamptz at time zone 'UTC',
                                     'YYYY-MM-DD"T"HH24:MI:SS')
                      -- A row that has already been superseded by a newer row
                      -- for the same content, engine and basis is not refreshed
                      -- again: the refreshed row is the current answer, and
                      -- re-asking an old one would grow a new row per sweep
                      -- forever. Compared on all three, because a preview row
                      -- must never supersede a full-depth one.
                      and not exists (
                          select 1 from audits newer
                          where newer.content_hash = audits.content_hash
                                and newer.engine_version = audits.engine_version
                                and newer.score_json->>'basis' = audits.score_json->>'basis'
                                and newer.created_at > audits.created_at
                      )
                order by left(score_json->'scan_manifest'->>'sca_asked_at', 19) asc,
                         created_at asc
                limit %s
                """,
                (created_before, limit),
            )
            rows = await cur.fetchall()
        stored = []
        for row in rows:
            audit = _row_to_audit(row)
            audit["dependency_inventory"] = _json_field(
                dict(row).get("dependency_inventory"))
            stored.append(audit)
        return stored

    async def get_latest_by_repo_url(
        self, repo_full_name: str, basis: str
    ) -> dict[str, Any] | None:
        """Most recent completed audit for a repo AT THIS SCAN DEPTH, matched
        by a canonical
        'owner/repo' (Phase C monitoring's diff baseline). audits.repo_url is
        stored as typed at intake (full github URL, 0006); this normalizes it in
        SQL -- extract owner/repo, drop a trailing '.git'/slash, lowercase -- so
        it matches regardless of the casing/suffix the audit was created with.
        The same normalization app/monitor.normalize_repo_full_name does in
        Python, kept in lockstep so a push and a stored audit for the same repo
        always join. Returns None when DATABASE_URL isn't set.

        `basis` has no default, for the same reason get_by_content_hash has none:
        the two scan depths must never be compared with each other. This backs
        the monitoring diff, which always re-audits at full depth. Left
        unfiltered, one anonymous free audit of a watched repository --
        static-only, and anyone holding the URL can run one -- became the
        baseline, and the next monitoring run reported every auth and injection
        finding as newly appeared. That is a DM to a paying subscriber about
        problems that were already there, triggered by a stranger."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, created_at
                from audits
                where repo_url is not null
                      and lower(regexp_replace(
                          repo_url,
                          '^https://github\\.com/(.+?)(\\.git)?/?$',
                          '\\1')) = %s
                      and status = 'completed'
                      and score_json->>'basis' = %s
                order by created_at desc
                limit 1
                """,
                (repo_full_name, basis),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

    async def list_findings_by_repo_url(
        self, repo_full_name: str, basis: str, limit: int = 50
    ) -> list[list[dict[str, Any]]]:
        """findings_json of the last `limit` completed audits of this repo at
        this scan depth, newest first. Same normalization and same
        basis-has-no-default reasoning as get_latest_by_repo_url above.

        This backs the monitoring diff's UNION baseline. Measured on four
        same-engine, same-content runs (2026-08-18): high-severity LLM finding
        keys reproduce in only ~65-84% of runs and one real critical appeared
        in 2 of 4, so a baseline of one prior audit makes roughly every third
        high look "new" on a re-audit of unchanged code -- a DM to a paying
        subscriber about nothing. A finding seen in ANY prior audit is not
        news, whichever run happened to surface it.

        engine_version is deliberately not filtered: an old engine's sighting
        of (rule_id, file) still proves the finding predates this push, which
        is the only question the baseline answers. `limit` bounds a pathological
        history (monitoring audits are capped at one per repo per
        MONITORING_INTERVAL_HOURS, so 50 spans months);
        past it the oldest sightings age out, which can resurface an ancient
        finding as new -- preferred over an unbounded read."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return []
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select findings_json
                from audits
                where repo_url is not null
                      and lower(regexp_replace(
                          repo_url,
                          '^https://github\\.com/(.+?)(\\.git)?/?$',
                          '\\1')) = %s
                      and status = 'completed'
                      and score_json->>'basis' = %s
                order by created_at desc
                limit %s
                """,
                (repo_full_name, basis, limit),
            )
            rows = await cur.fetchall()
        return [row[0] or [] for row in rows]

    async def get(self, audit_id: str) -> dict[str, Any] | None:
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(audit_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, created_at
                from audits where id = %s
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None

    async def get_access_token(self, audit_id: str) -> str | None:
        """The row's own access token, for building a link the buyer can open.

        Deliberately a narrow method rather than a column added to `get()`:
        `get()` feeds request handlers, and widening its select would put the
        token one careless `return audit` away from a response body. The only
        caller is the delivery path, which has just taken money and must not
        send a bare /audit/{id} link -- without the token that URL is a flat
        404 for the person who paid.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(audit_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                "select access_token from audits where id = %s",
                (parsed_id,),
            )
            row = await cur.fetchone()
        if not row:
            return None
        value = row.get("access_token")
        return str(value) if value else None

    async def get_authorized(
        self, audit_id: str, access_token: str | None
    ) -> dict[str, Any] | None:
        """Ownership-checked fetch for the public report endpoints: return
        the audit only if `access_token` matches the row's per-row token
        (migration 0010). A missing/wrong token, an unknown id, a malformed
        id, and an unconfigured DB all return None -- so the endpoint answers
        404 uniformly and never confirms an id's existence to a caller who
        doesn't hold its token. The token is matched in SQL and is NOT in the
        selected columns, so it never rides back out in the response body.

        Distinct from get(), which is the trusted server-side lookup (fixpack
        processing) with no token gate."""
        if not access_token:
            return None
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(audit_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, stack, status, file_count, score_total,
                       score_json, findings_json, repo_url, created_at
                from audits where id = %s and access_token = %s
                """,
                (parsed_id, access_token),
            )
            row = await cur.fetchone()
        return _row_to_audit(row) if row else None



# A verdict is only trustworthy if the webhook set it, and the webhook finds
# its row by the PR's html_url -- which GitHub always spells
# https://github.com/<owner>/<repo>/pull/<number>.
#
# On 2026-08-02 the production table held four rows claiming pr_merged = true
# on URLs like ".../pull/278bcdc68ae9-outcome". A pull request number is an
# integer; no such PR exists and no webhook ever fired for one. They came from
# tests/test_db_postgres_smoke.py, which records an outcome and then calls
# set_pr_merged_by_pr_url on its own fabricated URL -- run four times against
# the PRODUCTION database on 2026-07-22, instead of the throwaway CI container
# it is written for.
#
# Those four rows sat one distinct audit away from declaring SEC001 and CFG002
# ready to learn from, on a fabricated 100% merge rate. Keyed on the shape of
# the URL rather than a list of banned repositories: this also refuses the
# next fabrication, and refuses the rows already present without deleting the
# history that shows they happened.
REAL_PR_URL = r"^https://github\.com/[^/]+/[^/]+/pull/[0-9]+$"


class FixOutcomeRepository:
    """The fix-outcome knowledge base (migration 0014). One row per terminal
    Fix Pack job outcome.

    It was collection-only from 0014 until 2026-08-20 -- the plan said so
    explicitly, and PHASE_B_KNOWLEDGE_BASE_PLAN.md is where. `get_by_job` is
    the first read that DECIDES anything: app/fixpack/merit.py asks it whether
    a Fix Pack did what it was sold as, so a refund is a decision with a record
    behind it rather than a matter of belief.

    Same real/fake split and not-configured contract as the other
    repositories: when DATABASE_URL isn't set, record()/
    set_pr_merged_by_pr_url() no-op instead of failing, so the Fix Pack
    delivery path never breaks over a missing analytics store."""

    async def record(
        self, *, fixpack_job_id: str | None, audit_id: str | None,
        rule_ids: list[str], stack: str, outcome: str,
        is_regression: bool, pr_url: str | None,
    ) -> dict[str, Any] | None:
        """Insert one outcome row. pr_merged is left NULL -- only the
        pull_request.closed webhook sets it, and only for delivered PRs.
        Returns None when DATABASE_URL isn't configured."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        parsed_job_id = uuid.UUID(fixpack_job_id) if fixpack_job_id else None
        parsed_audit_id = uuid.UUID(audit_id) if audit_id else None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into fix_outcomes
                    (fixpack_job_id, audit_id, rule_ids, stack, outcome,
                     is_regression, pr_url)
                values (%s, %s, %s::jsonb, %s, %s, %s, %s)
                returning id, fixpack_job_id, audit_id, rule_ids, stack,
                          outcome, is_regression, pr_url, pr_merged,
                          created_at, updated_at
                """,
                (
                    parsed_job_id, parsed_audit_id, json.dumps(rule_ids),
                    stack, outcome, is_regression, pr_url,
                ),
            )
            row = await cur.fetchone()
        return _row_to_fix_outcome(row)

    async def get_by_job(self, fixpack_job_id: str) -> dict[str, Any] | None:
        """The terminal outcome recorded for one Fix Pack job, or None.

        Written for app/fixpack/merit.py, which is the first thing to READ this
        table for a decision. The class docstring above said "collection only,
        nothing reads it for decisions yet" from migration 0014 until now; the
        rows were always the evidence for "did this Fix Pack do what it was
        sold as", and the only reason nobody asked was that asking meant
        reading four tables by hand.

        Newest first. A job has one terminal outcome, but `record` has no
        uniqueness constraint behind it -- a retried worker could write two --
        and in that case the later one is the one that describes how it ended.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        try:
            parsed_id = uuid.UUID(fixpack_job_id)
        except ValueError:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, fixpack_job_id, audit_id, rule_ids, stack,
                       outcome, is_regression, pr_url, pr_merged,
                       created_at, updated_at
                from fix_outcomes where fixpack_job_id = %s
                order by created_at desc
                limit 1
                """,
                (parsed_id,),
            )
            row = await cur.fetchone()
        return _row_to_fix_outcome(row) if row else None

    async def learning_readiness(
        self, *, min_labelled: int, min_audits: int,
    ) -> dict[str, Any] | None:
        """Per-rule counts of the LABELLED outcomes, and whether each rule has
        enough of them to learn from.

        Nothing has ever read this table (PHASE_B_KNOWLEDGE_BASE_PLAN.md is
        explicit that collection came first), which meant the only way to
        answer "is there enough data yet?" was to guess. This is that question
        as a query.

        `labelled` is the number that matters, and it is narrower than the row
        count: a rule only teaches us something when the Fix Pack was actually
        delivered AND the customer then merged or closed the PR. A row that is
        blocked, failed, or still waiting on a decision carries no verdict, so
        counting it would inflate readiness with rows that cannot be learned
        from. They are reported separately rather than dropped, because
        "delivered but nobody has decided" is itself worth seeing.

        Counts only, never rows -- same contract as the rest of /internal/stats.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None

        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select
                    rule.id as rule_id,
                    count(*) filter (
                        where o.outcome = 'delivered'
                          and o.pr_merged is not null
                          and o.pr_url ~ %(real_pr)s
                    ) as labelled,
                    count(*) filter (
                        where o.pr_merged is true and o.pr_url ~ %(real_pr)s
                    ) as merged,
                    count(*) filter (
                        where o.outcome = 'delivered' and o.pr_merged is null
                    ) as awaiting_verdict,
                    count(distinct o.audit_id) filter (
                        where o.outcome = 'delivered'
                          and o.pr_merged is not null
                          and o.pr_url ~ %(real_pr)s
                    ) as audits,
                    count(*) as rows_total
                from fix_outcomes o
                cross join lateral
                    jsonb_array_elements_text(o.rule_ids) as rule(id)
                group by rule.id
                order by labelled desc, rule.id
                """,
                {"real_pr": REAL_PR_URL},
            )
            rows = await cur.fetchall()

            cur = await conn.execute(
                """
                select outcome, count(*) as n
                from fix_outcomes
                group by outcome
                order by outcome
                """
            )
            outcome_rows = await cur.fetchall()

        rules = []
        for row in rows:
            labelled = int(row["labelled"])
            audits = int(row["audits"])
            rules.append({
                "rule_id": row["rule_id"],
                "labelled": labelled,
                "merged": int(row["merged"]),
                "awaiting_verdict": int(row["awaiting_verdict"]),
                "audits": audits,
                "rows_total": int(row["rows_total"]),
                "ready": labelled >= min_labelled and audits >= min_audits,
            })

        return {
            "thresholds": {
                "min_labelled": min_labelled,
                "min_audits": min_audits,
            },
            "outcomes": {r["outcome"]: int(r["n"]) for r in outcome_rows},
            "rules_ready": sum(1 for r in rules if r["ready"]),
            "rules": rules,
        }

    async def set_pr_merged_by_pr_url(self, pr_url: str, merged: bool) -> int:
        """Backfill pr_merged for the delivered outcome whose PR just closed,
        matched by the PR's html_url (the exact value stored at delivery).
        Returns the number of rows updated so the webhook can distinguish a
        matched PR (1) from an unknown one (0) -- an unknown PR is a benign
        no-op, not an error. Returns 0 when DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return 0
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update fix_outcomes
                   set pr_merged = %s, updated_at = now()
                 where pr_url = %s
                """,
                (merged, pr_url),
            )
            return cur.rowcount



class MonitoringRunRepository:
    """The async continuous-monitoring job queue (migration 0017). Directly
    analogous to FixpackJobRepository's durable-lease model: the push webhook
    enqueues one 'pending' run per won claim, and the processor claims each into
    a 'running' lease, runs the audit+diff+notify, and marks it terminal.

    Same real/fake split and not-configured contract as the other repositories:
    when DATABASE_URL isn't set every method no-ops (returns None / a zero
    result) instead of failing, so an enqueue on a DB-less deployment simply does
    nothing rather than breaking the fast webhook ACK."""

    async def enqueue(self, repo_full_name: str) -> dict[str, Any] | None:
        """Insert one 'pending' monitoring run for a repo whose push just won the
        claim_for_monitoring gate. Fast INSERT (no audit) so the webhook can ACK
        200 immediately. Returns None when DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                insert into monitoring_runs (repo_full_name, status)
                values (%s, 'pending')
                returning id, repo_full_name, status, attempts, started_at,
                          error, created_at, completed_at
                """,
                (repo_full_name,),
            )
            row = await cur.fetchone()
        return _row_to_monitoring_run(row) if row else None

    async def pending_summary(self, limit: int = 5) -> dict[str, Any] | None:
        """How much is queued, and which rows, without claiming anything.

        Exists for the withdrawn-product guard (#184). The drain refuses to
        claim while monitoring is off sale, but a refusal that says nothing
        lets the queue grow unobserved -- and a pending run existing at all,
        while the product cannot be bought, means something got past the
        webhook gate or predates it. Either way a human should look, and they
        need the row id and the repository to find out which.

        Read-only on purpose: the guard must not mutate a backlog it is
        declining to process.
        """
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                select id, repo_full_name, created_at,
                       count(*) over () as total
                  from monitoring_runs
                 where status = 'pending'
                 order by created_at
                 limit %s
                """,
                (limit,),
            )
            rows = await cur.fetchall()
        return {
            "total": int(rows[0]["total"]) if rows else 0,
            "runs": [{"id": str(r["id"]),
                      "repo_full_name": r["repo_full_name"],
                      "created_at": r["created_at"]} for r in rows],
        }

    async def claim_one_pending(self) -> dict[str, Any] | None:
        """Atomically claim the oldest 'pending' monitoring run into a 'running'
        lease, and return it -- or None when there is nothing to claim (or
        DATABASE_URL isn't set).

        Same concurrency guard as FixpackJobRepository.claim_one_paid: the inner
        SELECT ... FOR UPDATE SKIP LOCKED LIMIT 1 row-locks exactly one candidate
        and skips any a concurrent run already locked, and the surrounding UPDATE
        flips it 'pending' -> 'running' in the same statement, so two overlapping
        processor runs can never both claim the same run. started_at stamps the
        lease (the reaper reads it) and attempts is incremented so crash-requeues
        are bounded."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return None
        async with pool.connection() as conn:
            cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'running',
                       started_at = now(),
                       attempts = attempts + 1
                 where id = (
                     select id from monitoring_runs
                      where status = 'pending'
                      order by created_at asc
                      for update skip locked
                      limit 1
                 )
                returning id, repo_full_name, status, attempts, started_at,
                          error, created_at, completed_at
                """,
            )
            row = await cur.fetchone()
        return _row_to_monitoring_run(row) if row else None

    async def mark_done(self, run_id: str) -> None:
        """Advance a run to the terminal 'done' state (audit+diff+notify finished,
        whether or not it found new findings). No-op when DATABASE_URL isn't
        set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update monitoring_runs
                   set status = 'done', completed_at = now()
                 where id = %s
                """,
                (uuid.UUID(run_id),),
            )

    async def mark_failed(self, run_id: str, error: str) -> None:
        """Advance a run to the terminal 'failed' state with a diagnosable
        reason. The `error` is always written so a 'failed' row is never a silent
        failure (same hardening as fixpack_jobs.detail). No-op when DATABASE_URL
        isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return
        async with pool.connection() as conn:
            await conn.execute(
                """
                update monitoring_runs
                   set status = 'failed', error = %s, completed_at = now()
                 where id = %s
                """,
                (error, uuid.UUID(run_id)),
            )

    async def reap_stale_running(
        self, *, max_age_minutes: int, max_attempts: int
    ) -> dict[str, int]:
        """Recover monitoring runs whose worker crashed mid-audit: a 'running'
        lease older than max_age_minutes means no process is still working it.
        Run at the start of each processor pass, before claiming. Identical
        pattern to FixpackJobRepository.reap_stale_running:

          - attempts < max_attempts -> back to 'pending' (started_at cleared) so
            the next claim retries it;
          - attempts >= max_attempts -> 'failed' with a diagnosable error, so a
            poison-pill run that crashes the worker every time stops re-queuing
            forever and stays visible for a human.

        Returns {'requeued': n, 'failed': m}. No-op ({'requeued': 0, 'failed': 0})
        when DATABASE_URL isn't set."""
        try:
            pool = await _resolve_get_pool()()
        except DatabaseNotConfigured:
            return {"requeued": 0, "failed": 0}
        async with pool.connection() as conn:
            requeued_cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'pending', started_at = null
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts < %s
                returning id
                """,
                (max_age_minutes, max_attempts),
            )
            requeued = len(await requeued_cur.fetchall())
            failed_cur = await conn.execute(
                """
                update monitoring_runs
                   set status = 'failed',
                       error = %s,
                       completed_at = now()
                 where status = 'running'
                   and started_at < now() - make_interval(mins => %s)
                   and attempts >= %s
                returning id
                """,
                (
                    f"stale lease reaped: no completion after {max_attempts} "
                    f"attempt(s), last lease older than {max_age_minutes}m",
                    max_age_minutes,
                    max_attempts,
                ),
            )
            failed = len(await failed_cur.fetchall())
        return {"requeued": requeued, "failed": failed}
