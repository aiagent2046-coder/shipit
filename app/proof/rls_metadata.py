"""Bounded, owner-supplied configuration evidence; never a database transport.

The collector exports predicate *categories*, not SQL or row values. We only
reason about constants, default-deny and PostgreSQL's policy composition.
Conditional expressions cannot establish ownership or tenant isolation.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.proof.types import ExploitAttempt

MAX_METADATA_BYTES = 256 * 1024
Name = Annotated[str, Field(min_length=1, max_length=63, pattern=r"^[A-Za-z_][A-Za-z0-9_$]*$")]
Role = Literal["anon", "authenticated"]
Predicate = Literal["always", "never", "conditional"]
ReadAccess = Literal["unknown", "public", "public_subset", "owner", "backend_only"]
WriteAccess = Literal["unknown", "public", "owner", "backend_only"]


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class Policy(StrictModel):
    # Names may contain spaces; predicates and role applicability are structural.
    name: Annotated[str, Field(min_length=1, max_length=63)]
    command: Literal["ALL", "SELECT", "INSERT", "UPDATE", "DELETE"]
    permissive: bool
    applies_to: Annotated[list[Role], Field(max_length=2)]
    using: Predicate | None
    with_check: Predicate | None

    @model_validator(mode="after")
    def valid_clauses(self):
        if len(set(self.applies_to)) != len(self.applies_to):
            raise ValueError("duplicate policy roles")
        if self.command == "INSERT" and self.using is not None:
            raise ValueError("INSERT policies cannot have USING")
        if self.command in {"SELECT", "DELETE"} and self.with_check is not None:
            raise ValueError("this command cannot have WITH CHECK")
        return self


class Privileges(StrictModel):
    role: Role
    schema_usage: bool
    rls_bypassed: bool
    select: bool
    select_any_column: bool
    insert: bool
    insert_any_column: bool
    update: bool
    update_any_column: bool
    delete: bool


class Column(StrictModel):
    name: Name
    type: Annotated[str, Field(min_length=1, max_length=128)]
    nullable: bool


class Table(StrictModel):
    name: Name
    object_type: Literal["r", "p", "v", "m", "f"]
    rls_enabled: bool
    rls_forced: bool
    collector_rls_applies: bool
    # Optional independent context, not a live API observation.
    row_count: Annotated[int, Field(ge=0, le=2**63 - 1)] | None = None
    columns: Annotated[list[Column], Field(max_length=1600)]
    privileges: Annotated[list[Privileges], Field(min_length=2, max_length=2)]
    policies: Annotated[list[Policy], Field(max_length=100)]

    @model_validator(mode="after")
    def unique_entries(self):
        if {p.role for p in self.privileges} != {"anon", "authenticated"}:
            raise ValueError("both roles are required")
        for entries in (self.columns, self.policies):
            if len({p.name for p in entries}) != len(entries):
                raise ValueError("duplicate names")
        return self


class Snapshot(StrictModel):
    version: Annotated[int, Field(ge=1, le=1)]
    project_ref: Annotated[str, Field(pattern=r"^[a-z0-9]{16,32}$")]
    captured_at: Annotated[str, Field(max_length=40)]
    collector_role: Name
    schema_name: Literal["public"]
    tables: Annotated[list[Table], Field(min_length=1, max_length=100)]

    @field_validator("captured_at")
    @classmethod
    def timestamp_with_zone(cls, value):
        if datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is None:
            raise ValueError("timestamp requires timezone")
        return value


class Expectation(StrictModel):
    table: Name
    read: ReadAccess = "unknown"
    write: WriteAccess = "unknown"


class AccessReviewInput(StrictModel):
    snapshot: Snapshot
    auth_model: Literal["unknown", "supabase_auth", "backend"] = "unknown"
    expectations: Annotated[list[Expectation], Field(max_length=100)] = Field(default_factory=list)

    @model_validator(mode="after")
    def table_scope(self):
        names = [t.name for t in self.snapshot.tables]
        expected = [e.table for e in self.expectations]
        if len(set(names)) != len(names) or len(set(expected)) != len(expected):
            raise ValueError("duplicate tables")
        if not set(expected) <= set(names):
            raise ValueError("expectations must refer to snapshot tables")
        return self


class MetadataInputError(ValueError):
    """Safe error text; validation errors must not echo submitted values."""


def parse_access_review(raw: str | None) -> AccessReviewInput | None:
    if raw is None:
        return None
    if len(raw.encode("utf-8")) > MAX_METADATA_BYTES:
        raise MetadataInputError("Metadata and expectations exceed 256 KiB.")
    try:
        # Reject duplicate JSON keys instead of silently taking the last value.
        def unique(pairs):
            obj = {}
            for key, value in pairs:
                if key in obj:
                    raise ValueError("duplicate JSON key")
                obj[key] = value
            return obj

        return AccessReviewInput.model_validate(json.loads(raw, object_pairs_hook=unique))
    except (ValueError, RecursionError) as exc:
        raise MetadataInputError(
            "Invalid metadata snapshot or access expectations; use the version 1 collector.") from exc


def _and(values: list[str]) -> str:
    if "never" in values:
        return "never"
    return "conditional" if "conditional" in values else "always"


def _policy_scope(policies: list[Policy], side: str) -> str:
    def predicate(policy: Policy) -> str:
        if side == "with_check":
            return policy.with_check or policy.using or "always"
        return policy.using or "always"

    permissive = [predicate(p) for p in policies if p.permissive]
    restrictive = [predicate(p) for p in policies if not p.permissive]
    # At least one permissive policy must allow the operation, even with
    # restrictive policies present. WITH CHECK inherits USING when omitted.
    allowed = ("always" if "always" in permissive else
               "conditional" if "conditional" in permissive else "never")
    return _and([allowed, *restrictive])


def operation_scope(table: Table, privilege: Privileges, operation: str) -> tuple[str, str]:
    if table.object_type not in {"r", "p"}:
        return "unknown", "unsupported_object"
    if not privilege.schema_usage:
        return "blocked", "schema_usage_missing"
    full_grant = getattr(privilege, operation.lower())
    column_grant = getattr(privilege, f"{operation.lower()}_any_column", False)
    if not full_grant and not column_grant:
        return "blocked", "privilege_missing"
    if not table.rls_enabled or privilege.rls_bypassed:
        return "unrestricted", "rls_bypassed" if privilege.rls_bypassed else "rls_disabled"
    policies = [p for p in table.policies
                if privilege.role in p.applies_to and p.command in {"ALL", operation}]
    sides = ["with_check"] if operation == "INSERT" else ["using"]
    if operation == "UPDATE":
        sides.append("with_check")
    scope = _and([_policy_scope(policies, side) for side in sides])
    return {
        "always": ("unrestricted", "policies_allow_all"),
        "never": ("blocked", "policies_deny_all"),
        "conditional": ("conditional", "predicate_not_evaluated"),
    }[scope]


def _assessment(scope: str, expected: str, role: str) -> str:
    if expected == "unknown":
        return "expectation_missing"
    if scope == "unrestricted" and expected in {"backend_only", "owner", "public_subset"}:
        return "mismatch"
    if scope == "blocked" and (expected == "backend_only" or (expected == "owner" and role == "anon")):
        return "consistent"
    if scope == "unrestricted" and expected == "public":
        return "consistent"
    return "review_needed"


def review_metadata(data: AccessReviewInput, attempts: list[ExploitAttempt]) -> dict:
    """Configuration conclusions and observations retain separate provenance."""
    snapshot = data.snapshot
    expectations = {e.table: e for e in data.expectations}
    observed = {a.evidence.get("table"): a.evidence.get("reason") for a in attempts}
    tables = []
    for table in snapshot.tables:
        expected = expectations.get(table.name, Expectation(table=table.name))
        operations = []
        for privilege in table.privileges:
            for operation in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                scope, reason = operation_scope(table, privilege, operation)
                access = expected.read if operation == "SELECT" else expected.write
                operations.append({
                    "role": privilege.role, "operation": operation, "scope": scope,
                    "reason": reason, "assessment": _assessment(scope, access, privilege.role),
                    "column_limited": (not getattr(privilege, operation.lower())
                                       and getattr(privilege, f"{operation.lower()}_any_column", False)),
                })
        observation = observed.get(table.name, "not_checked")
        if observation == "rows_readable":
            interpretation = {"public": "expected_public_read", "public_subset": "public_subset_unverified",
                              "owner": "unexpected_anonymous_read", "backend_only": "unexpected_anonymous_read"
                              }.get(expected.read, "expectation_missing")
        else:
            interpretation = "no_read_conclusion"
        anon_select = next(o for o in operations if o["role"] == "anon" and o["operation"] == "SELECT")
        tables.append({
            "table": table.name, "expected": expected.model_dump(exclude={"table"}),
            "observation": observation, "interpretation": interpretation,
            "evidence_conflict": observation == "rows_readable" and anon_select["scope"] == "blocked",
            "collector_rls_applies": table.collector_rls_applies, "row_count": table.row_count,
            "policy_summaries": [p.model_dump() for p in table.policies],
            "operations": operations,
        })
    canonical = json.dumps(snapshot.model_dump(), sort_keys=True, separators=(",", ":")).encode()
    return {
        "version": 1, "source": "owner_supplied_metadata", "project_ref": snapshot.project_ref,
        "captured_at": snapshot.captured_at, "snapshot_sha256": hashlib.sha256(canonical).hexdigest(),
        "collector_role": snapshot.collector_role, "auth_model": data.auth_model,
        "tables": tables,
        "limitations": [
            "Snapshot origin, completeness and freshness are not independently verified.",
            "Configuration scope describes grants and RLS, not successful operations or API publication.",
            "Conditional predicates and user isolation are untested, as are triggers, constraints and functions.",
            "Backend authorization is outside this check.",
            "UPDATE and DELETE queries may also need SELECT privileges and policies; writes were not attempted.",
            "Collector visibility does not describe anon or authenticated visibility.",
        ],
    }
