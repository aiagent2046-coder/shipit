# Live database configuration review (snapshot v1)

The optional metadata review joins owner-declared intent, imported PostgreSQL
settings and the existing anonymous read observations. These remain separate
sources of evidence. Public reading does not suppress a write-access finding.

## Use from an audit

1. Open **Check it against your live database → Add database settings and expected access**.
2. Download `collect-rls-metadata.sql`, replace `REPLACE_WITH_PROJECT_REF` with
   the project ref, and run it in that project's SQL editor as its owner.
   An optional `selected_tables` array narrows the snapshot. The default reads
   catalogs for the `public` schema; it does not read application rows.
3. Export the JSON result and import it. Both the JSON cell and the SQL editor's
   single-row `[{"metadata_snapshot": {...}}]` export work in the UI.
4. Declare the sign-in model and expected read/write access for each table.
   “Public — published rows only” differs from “Public — all rows”. Choose
   “Backend only” when your own server authorizes an operation.
5. Supply your public **publishable key** (`sb_publishable_…`) and its **Project
   URL** from Supabase's Connect dialog. A legacy **anon JWT** (`eyJ…`) also
   works and identifies its project without a URL. Leave the key blank only
   when the repository contains a legacy anon JWT to discover automatically.
6. Type the ownership phrase and run. Changing the key or Project URL clears
   that phrase so consent applies to the selected target.

No database credentials, service keys or policy SQL are requested. The collector
exports predicate categories (`always`, `never`, `conditional`, or null when
omitted), column metadata, role applicability, effective table/column grants,
RLS flags, collector role and capture time. It runs in a read-only transaction
with a 5-second statement timeout and a 1-second lock timeout. Names with spaces
or non-ASCII characters in table/column identifiers are outside v1's schema.
Policy names can contain spaces.

## API and evidence contract

Both `POST /v1/rls-check` (ZIP upload) and
`POST /v1/audits/{audit_id}/rls-check` (repository from the audit) accept:

| Multipart field | Meaning |
| --- | --- |
| `anon_key` | Public publishable key or legacy anon JWT; the field name remains compatible with older clients. |
| `project_url` | Required with a publishable key: `https://<project-ref>.supabase.co`. Optional with a legacy JWT; if supplied, it must match that JWT's ref. |
| `consent` | Exact phrase `i-own-this-project`. |

Only the hosted HTTPS origin is accepted, with an optional trailing slash.
Credentials, explicit ports, paths, queries, fragments, custom domains and
local addresses are refused before database requests. The ref is 16–32 ASCII
letters/digits. Publishable keys are opaque, so neither repository URLs nor
metadata silently supply their destination. A key for another project will
be rejected by Supabase; an authentication failure remains `inconclusive`,
never a finding of protection.

Publishable keys use the `apikey` header without `Authorization`; legacy anon
JWTs retain `apikey` and `Authorization: Bearer`. Both `sb_secret_…` and legacy
`service_role` keys are refused. See [Supabase API keys](https://supabase.com/docs/guides/getting-started/api-keys).
Keys are absent from results and ledger JSON, and both opaque prefixes are
covered by log redaction. Request deadlines, response limits and redirect
refusal are unchanged.

The CLI `scripts/probe_supabase_rls_live.py <project-ref> <table>…` accepts
`SUPABASE_PUBLISHABLE_KEY` or the existing `SUPABASE_ANON_KEY` environment
variable. Different values in both variables are refused rather than guessed.

Both existing POST endpoints accept optional multipart field `access_review`:

```json
{
  "snapshot": { "version": 1, "...": "the collector's JSON object" },
  "auth_model": "backend",
  "expectations": [
    { "table": "shared_stacks", "read": "public_subset", "write": "backend_only" }
  ]
}
```

The example abbreviates the snapshot; send the complete collector object.
Omitted expectations mean `unknown`. `auth_model` is `unknown`, `supabase_auth`,
or `backend`. Read modes are `unknown`, `public`, `public_subset`, `owner`,
`backend_only`; write modes omit `public_subset`. These describe direct
`anon`/`authenticated` API access, not a backend's service-role capabilities.

The server strictly validates the import: 256 KiB including expectations,
100 tables, 100 policies per table, both client roles, unique table names, a
timezone-qualified capture time and no unknown fields. Raw SQL is not accepted
or executed. Optional `row_count` is owner-supplied context, never proof of what
the live request could see; the collector does not count rows.

The snapshot's project ref must match the selected Project URL for a
publishable key, or the project derived from a legacy anon JWT.
A mismatch refuses the run before any database request. Imports
cannot supply a URL, change consent, or add live targets: only the repository's
existing candidates are probed within the existing 12-table/45-second limits.
Metadata-only tables are explicitly marked `not_checked`. An audit access token
is required for either endpoint when associating a check with an audit.

`access_review` in the response and existing ledger JSON includes a normalized
snapshot SHA-256, declared auth model/expectations, capture time, policy names
and predicate categories, per-role
SELECT/INSERT/UPDATE/DELETE conclusions, live observations and limitations.
It does not persist the raw imported snapshot or policy text. Existing live
counts and outcomes retain their meanings. No migration is required.

## Meaning and limits

* `unrestricted`: grants and the operation's RLS predicates impose no row
  condition. Column-limited privileges are labelled separately. This is **not**
  proof that an API write succeeds; constraints, triggers and API publication
  are not evaluated. UPDATE/DELETE queries may also require SELECT policies.
* `blocked`: schema/table/column privileges or RLS deny this operation at the
  described layer. An empty HTTP response still does not prove protection.
* `conditional`: at least one effective predicate needs evaluation. Neither
  `is_public = true` nor `auth.uid() = user_id` is treated as an unconditional
  grant or as proof of correct isolation.
* `unknown`: unsupported relation kind (views/materialized views/foreign tables).

Permissive policies combine with OR; restrictive policies combine with AND and
cannot grant access alone. Missing WITH CHECK inherits USING. Owner/BYPASSRLS
visibility is separate from visitor visibility. The relevant semantics are in
[PostgreSQL row security](https://www.postgresql.org/docs/current/ddl-rowsecurity.html)
and [CREATE POLICY](https://www.postgresql.org/docs/current/sql-createpolicy.html).

`consistent` means only that this configuration layer agrees with declared
intent. Conflicting live reads and snapshot denials are surfaced together.
Snapshot origin, completeness and freshness are unverified; the project ref is
owner-declared and matching it does not authenticate the snapshot. Capture time
and digest support review, not attestation. No global security score is produced.

The sign-in model is declarative context. A backend with its own session cookie
and `public.users` must not be given an automatic `auth.uid()` policy. This PR
does not generate fixes, create users, test live writes, retrieve check history,
or claim cross-user isolation. Prepared-user testing and source revision/drift
comparisons remain later stages.
