"use client";

import { useRef, useState } from "react";
import type { RlsAccessReview, RlsAccessReviewInput, RlsReadAccess, RlsWriteAccess } from "@/lib/types";

const MAX_BYTES = 256 * 1024;
const accessLabels: Record<RlsReadAccess, string> = {
  unknown: "Not specified",
  public: "Public — all rows",
  public_subset: "Public — published rows only",
  owner: "Each user’s own rows",
  backend_only: "Backend only",
};

export function RlsMetadataInput({ value, onChange, onValidity, disabled }: {
  value: RlsAccessReviewInput | null;
  onChange: (value: RlsAccessReviewInput | null) => void;
  onValidity: (valid: boolean) => void;
  disabled: boolean;
}) {
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);

  async function load(file: File | undefined) {
    const current = ++generation.current;
    onChange(null);
    setError(null);
    onValidity(!file);
    if (!file) return;
    try {
      if (file.size > MAX_BYTES) throw new Error();
      let snapshot = JSON.parse(await file.text());
      // Supabase's SQL editor exports a one-row array; also accept the JSON cell.
      if (Array.isArray(snapshot) && snapshot.length === 1) snapshot = snapshot[0];
      if (snapshot?.metadata_snapshot) snapshot = snapshot.metadata_snapshot;
      if (snapshot?.version !== 1 || !/^[a-z0-9]{16,32}$/.test(snapshot.project_ref) ||
          typeof snapshot.captured_at !== "string" || !Array.isArray(snapshot.tables) ||
          snapshot.tables.length < 1 || snapshot.tables.length > 100 ||
          snapshot.tables.some((t: { name?: unknown } | null) =>
            !t || typeof t.name !== "string" || !/^[A-Za-z_][A-Za-z0-9_$]{0,62}$/.test(t.name)) ||
          new Set(snapshot.tables.map((t: { name: string }) => t.name)).size !== snapshot.tables.length) {
        throw new Error();
      }
      if (current !== generation.current) return;
      onChange({ snapshot, auth_model: "unknown", expectations: snapshot.tables.map((t: { name: string }) =>
        ({ table: t.name, read: "unknown", write: "unknown" })) });
      onValidity(true);
    } catch {
      if (current !== generation.current) return;
      setError("Could not import this snapshot. Use the version 1 collector and a JSON file up to 256 KiB.");
      onValidity(false);
    }
  }

  return <details className="rounded-lg border border-border p-4">
    <summary className="cursor-pointer text-sm font-medium">Add database settings and expected access (optional)</summary>
    <p className="mt-2 text-xs text-muted">
      Run the <a href="/collect-rls-metadata.sql" download className="underline">read-only metadata collector</a>{" "}
      in your project’s SQL editor after replacing its project ref. Export its result as JSON.
      It reads schema settings only; no database password, service key or row values are needed here.
      Importing settings does not add tables to the live requests.
    </p>
    <label className="mt-3 block text-sm">
      Metadata JSON
      <input type="file" accept=".json,application/json" disabled={disabled}
        className="mt-1 block w-full text-xs" onChange={(e) => { void load(e.target.files?.[0]); }} />
    </label>
    {error && <p role="alert" className="mt-2 text-sm text-red-500">{error}</p>}
    {(value || error) && <button type="button" disabled={disabled} className="mt-2 text-xs underline" onClick={() => {
      ++generation.current; onChange(null); onValidity(true); setError(null);
    }}>Remove metadata</button>}
    {value && <div className="mt-3 space-y-3">
      <p className="text-xs text-muted">Snapshot for <code>{value.snapshot.project_ref}</code>, captured {value.snapshot.captured_at}.
        The server validates all fields and checks that the public key belongs to this project.</p>
      <label className="block text-sm">How users sign in
        <select value={value.auth_model} disabled={disabled} className="ml-2 rounded border border-border bg-background p-1"
          onChange={(e) => onChange({ ...value, auth_model: e.target.value as RlsAccessReviewInput["auth_model"] })}>
          <option value="unknown">Not sure</option>
          <option value="supabase_auth">Supabase Auth</option>
          <option value="backend">Own backend sessions</option>
        </select>
      </label>
      <p className="text-xs text-muted">Expected access applies to direct database API clients.
        Choose Backend only for operations authorized by your server. This does not test your server’s authorization.</p>
      {value.expectations.map((expected, index) => <fieldset key={expected.table} className="rounded border border-border p-2">
        <legend className="px-1 font-mono text-xs">{expected.table}</legend>
        {(["read", "write"] as const).map((side) => <label key={side} className="mr-3 inline-block text-xs">
          {side === "read" ? "Read access" : "Write access"}
          <select aria-label={`${expected.table} ${side} access`} disabled={disabled} value={expected[side]}
            className="ml-2 rounded border border-border bg-background p-1"
            onChange={(e) => onChange({ ...value, expectations: value.expectations.map((item, i) => i === index
              ? { ...item, [side]: e.target.value as RlsReadAccess | RlsWriteAccess } : item) })}>
            {Object.entries(accessLabels).filter(([key]) => side === "read" || key !== "public_subset")
              .map(([key, label]) => <option key={key} value={key}>{label}</option>)}
          </select>
        </label>)}
      </fieldset>)}
    </div>}
  </details>;
}

const scopeLabels = {
  blocked: "Denied by grants or RLS",
  unrestricted: "No row restriction in grants/RLS",
  conditional: "Conditional policy — needs review",
  unknown: "Not assessed",
};
const assessmentLabels = {
  mismatch: "Conflicts with expected access",
  consistent: "Consistent with expected access at this layer",
  review_needed: "Needs review against expected access",
  expectation_missing: "Expected access not specified",
};
const reasonLabels: Record<string, string> = {
  unsupported_object: "Views, materialized views and foreign tables require separate analysis.",
  schema_usage_missing: "The role lacks schema USAGE.",
  privilege_missing: "The role lacks the operation privilege, including column grants.",
  rls_bypassed: "This role bypasses RLS.",
  rls_disabled: "RLS is disabled on this table.",
  policies_allow_all: "Applicable policies place no row condition on this operation.",
  policies_deny_all: "No permissive policy allows this operation, or an effective condition is always false.",
  predicate_not_evaluated: "Policy conditions were not evaluated; ownership is unproven.",
};

export function RlsMetadataOutcome({ review }: { review: RlsAccessReview }) {
  return <section className="space-y-3 rounded-lg border border-border p-4" aria-label="Database configuration review">
    <h3 className="font-medium">Database configuration review</h3>
    <p className="text-xs text-muted">Based on owner-supplied metadata for {review.project_ref}, captured {review.captured_at}.
      These are configuration conclusions. Write operations and access between users were not tested.</p>
    <p className="text-xs text-muted">{review.auth_model === "backend"
      ? "Your backend uses its own sessions. Supabase user identity policies are not automatically suitable; backend authorization needs separate review."
      : review.auth_model === "supabase_auth"
        ? "Supabase Auth is declared. Ownership conditions still need verification with prepared users."
        : "The sign-in model is unspecified. No ownership policy can be recommended from column names alone."}</p>
    {review.tables.map((table) => <div key={table.table} className="space-y-2 border-t border-border pt-3">
      <h4 className="font-mono text-sm">{table.table}</h4>
      <p className="text-xs">Expected: read — {accessLabels[table.expected.read]}; write — {accessLabels[table.expected.write]}.</p>
      <p className="text-xs">{table.interpretation === "expected_public_read"
        ? "Observed anonymous reading matches your public-read intention. Write access is assessed separately."
        : table.interpretation === "public_subset_unverified"
          ? "Anonymous rows were readable. Whether only published rows are visible is unverified."
          : table.interpretation === "unexpected_anonymous_read"
            ? "Observed anonymous reading conflicts with your expected access."
            : table.observation === "not_checked"
              ? "This table was not requested in the live check. Only imported settings are reviewed."
              : "The live observation above does not establish protection or user isolation."}</p>
      {table.evidence_conflict && <p className="text-sm text-red-500">The live read conflicts with the snapshot’s denial.
        Check the snapshot’s project, completeness and capture time; protection is not established.</p>}
      {!table.collector_rls_applies && <p className="text-xs text-muted">RLS did not apply to collector role {review.collector_role}.
        This does not mean RLS is disabled for visitors.</p>}
      {table.row_count !== null && <p className="text-xs text-muted">Owner-supplied row count: {table.row_count}.
        This is separate from rows returned to the live request.</p>}
      <div className="overflow-x-auto"><table className="w-full text-left text-xs">
        <thead><tr><th className="p-1">Role / operation</th><th className="p-1">Configuration scope</th><th className="p-1">Expected access</th></tr></thead>
        <tbody>{table.operations.map((op) => <tr key={`${op.role}-${op.operation}`} className="border-t border-border">
          <td className="p-1 font-mono">{op.role} / {op.operation}</td>
          <td className="p-1">{scopeLabels[op.scope]}{op.column_limited && " (column grants only)"}
            <span className="block text-muted">{reasonLabels[op.reason] ?? "Additional review is needed."}</span></td>
          <td className={`p-1 ${op.assessment === "mismatch" ? "text-red-500" : "text-muted"}`}>{assessmentLabels[op.assessment]}</td>
        </tr>)}</tbody>
      </table></div>
      <details className="text-xs text-muted"><summary className="cursor-pointer">Policies in this snapshot</summary>
        {table.policy_summaries.length === 0 ? <p>No policies were supplied.</p> :
          <ul className="mt-2 space-y-1">{table.policy_summaries.map((policy) => <li key={policy.name}>
            <span className="font-medium">{policy.name}</span> — {policy.command}, {policy.permissive ? "permissive (OR)" : "restrictive (AND)"};{" "}
            applies to {policy.applies_to.join(", ") || "neither tested role"};{" "}
            USING: {policy.using ?? "omitted"}; WITH CHECK: {policy.with_check ?? "omitted; inherits USING when applicable"}.
          </li>)}</ul>}
      </details>
    </div>)}
    <details className="text-xs text-muted"><summary className="cursor-pointer">Evidence and limitations</summary>
      <p className="mt-2 break-all">Snapshot SHA-256: {review.snapshot_sha256}</p>
      <ul className="mt-2 list-disc pl-4">{review.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
    </details>
  </section>;
}
