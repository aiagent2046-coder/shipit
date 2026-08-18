"""One consented pass: repository bytes in, a checked answer out.

This is the layer that turns three separate pieces — find the project, find
the tables worth asking about, ask — into the thing an audit can offer. The
pieces are tested on their own; what lives here is the policy that governs
making real requests against somebody else's database.

FOUR RULES, ALL ENFORCED HERE RATHER THAN DOCUMENTED ELSEWHERE.

1. CONSENT HAS NO DEFAULT, the same as in rls_probe. A caller that has not
   thought about it cannot start this by omission, and the result is a
   REFUSAL — never a clean bill of health.

2. THE KEY NEVER LEAVES THIS CALL. It is derived from the repository bytes at
   check time, used, and dropped. LiveCheckResult carries the project ref, the
   table names and the verdicts; it does not carry the credential, and nothing
   here writes one to a log or an artifact.

3. THERE IS A CEILING ON REQUESTS. A repository can name three hundred tables
   and each candidate is a real HTTPS request against a real project. The cap
   is small, it is stated in the result, and the ordering that decides who
   makes the cut is the read detector's own — see supabase_tables.

4. NOT ASKED IS NOT SAFE. Tables beyond the ceiling, a project we could not
   identify, a request that failed — all of them come back as counts and
   reasons the caller must render. `failure` in an ExploitAttempt means "we
   asked and no rows came back"; every other outcome is a different sentence
   and this module keeps them apart.

WHAT A PASS CAN AND CANNOT CONCLUDE. `exposed` here is evidence: rows came out
of a live database through the front door with a key that ships to every
visitor. `not exposed` is weaker — RLS filters rather than denies, so a
protected table and an EMPTY table answer identically, which is why the oracle
marks an empty result `alone_proves_nothing` and why this result reports it as
"checked, nothing came back" rather than "safe".
"""

from __future__ import annotations

import io
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.proof.rls_probe import run_rls_probe
from app.proof.supabase_tables import TableCandidate, find_probe_tables
from app.proof.supabase_target import (
    SupabaseTarget,
    TargetRefusal,
    find_supabase_target,
)
from app.proof.types import ExploitAttempt

# Each candidate is one request against a customer's project. Twelve is enough
# to cover every private-shaped table in all but the largest schemas measured
# (median 8 schema files, and far fewer private-shaped tables than that), and
# small enough that a consented check is unmistakably a check rather than a
# scan of their database.
MAX_TABLES = 12


@dataclass(frozen=True)
class LiveCheckResult:
    """What happened, in terms a report can render without interpreting."""

    status: str                       # "checked" | "refused"
    reason: str = ""                  # populated when refused
    project_ref: str = ""
    # "repository" or "supplied" — which act produced the credential.
    key_source: str = ""
    attempts: list[ExploitAttempt] = field(default_factory=list)
    checked: list[str] = field(default_factory=list)
    not_checked: list[str] = field(default_factory=list)

    @property
    def exposed_tables(self) -> list[str]:
        """Tables that returned rows. The only claim this makes on its own."""
        return [str(a.evidence.get("table", ""))
                for a in self.attempts if a.status == "success"]

    @property
    def inconclusive(self) -> int:
        """Requests that ran and settled nothing — a bad key, a 5xx, a table
        PostgREST does not expose. Counted separately from `failure` because
        "we asked and learned nothing" is not "we asked and it was fine"."""
        return sum(1 for a in self.attempts if a.status == "error")


def run_live_rls_check(
    zip_bytes: bytes,
    *,
    consent: bool,
    anon_key: str | None = None,
    max_tables: int = MAX_TABLES,
    fetch: Callable[..., tuple[int, Any]] | None = None,
) -> LiveCheckResult:
    """Identify the project, pick the tables, ask about each one.

    `fetch` is injectable so the whole pass is testable without a network, the
    same pattern rls_probe and cors_probe already use.
    """
    if not consent:
        # Before anything else, including reading the repository. There is no
        # state to build up for a check that is not going to happen.
        return LiveCheckResult(
            status="refused",
            reason="no confirmed consent from the owner of the project",
        )

    target = find_supabase_target(io.BytesIO(zip_bytes), supplied_key=anon_key)
    if isinstance(target, TargetRefusal):
        return LiveCheckResult(status="refused", reason=target.reason)

    candidates = find_probe_tables(io.BytesIO(zip_bytes))
    if not candidates:
        return LiveCheckResult(
            status="refused",
            project_ref=target.ref,
            reason=(
                "we identified your Supabase project but found no table names "
                "to ask about — neither committed migrations nor a "
                "`supabase.from('…')` call in the source"
            ),
        )

    return _ask(target, candidates, max_tables, fetch)


def _ask(target: SupabaseTarget, candidates: list[TableCandidate],
         max_tables: int,
         fetch: Callable[..., tuple[int, Any]] | None) -> LiveCheckResult:
    chosen = candidates[:max_tables]
    attempts = [
        run_rls_probe(
            project_url=target.project_url,
            anon_key=target.anon_key,
            table=candidate.name,
            consent=True,
            fetch=fetch,
        )
        for candidate in chosen
    ]
    return LiveCheckResult(
        status="checked",
        project_ref=target.ref,
        key_source=target.source,
        attempts=attempts,
        checked=[c.name for c in chosen],
        # Named, not just counted. "We checked 12 of your 40 tables" is a
        # different report from "we checked your tables", and the customer is
        # the one who knows which of the other 28 matter.
        not_checked=[c.name for c in candidates[max_tables:]],
    )
