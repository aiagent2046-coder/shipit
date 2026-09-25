# Database connection posture: the app bypasses RLS

Measured **2026-09-24** against the production Supabase project, by the
operator, with `scripts/verify_db_locally.py` (the connection-role report it
prints; the script itself never leaves the machine running it):

```
role=postgres  rolsuper=False  rolbypassrls=True
-> privileged role: the app BYPASSES RLS on every query;
   row protection then rests on app-layer controls (the
   per-row access_token with 404-on-mismatch, owner
   filters), not on the policies themselves.
```

## What this means

The production DATABASE_URL connects as the `postgres` role with
`rolbypassrls=true`. Row Level Security policies on this database therefore do
**not** constrain the application's own queries: `USING`/`CHECK` clauses are
not evaluated for this role. Every row-level guarantee the product makes rests
on application-layer controls instead:

- the per-row `access_token` capability check with a 404 that is identical to
  a missing resource (pinned by `tests/test_authorization_properties.py`);
- owner/account filters applied in `app/db.py` before any row is returned;
- server-side confirmation of payment state (webhooks are hints only).

This is the standard Supabase server-side posture (a backend service uses a
privileged role; RLS primarily governs anon/authenticated browser clients), and
it is **accepted deliberately**, not discovered as a defect.

## What this does not mean

- It does not weaken the customer-facing audit: uploaded archives and their
  findings are addressed by the token capability above, which runs
  unconditionally in the route layer regardless of RLS.
- It does not make the RLS policies dead code for every caller — they still
  bind any unprivileged role (analytics, replicas, future direct browser
  access). Editing a policy is still a security-relevant change.

## Re-verifying

```bash
export DATABASE_URL='postgresql://...your own, never shared...'
python scripts/verify_db_locally.py   # reads current_user/rolsuper/rolbypassrls
```

If the report ever prints `-> unprivileged role`, this document is stale —
update it together with the connection change.

## Backlog (not accepted, not scheduled)

Moving the application to an unprivileged role with per-table grants and
audited `USING`/`CHECK` policies is real hardening work: it needs a policy per
table matched to that table's access pattern plus a full suite run against a
disposable database. It becomes worth doing if the product ever exposes
Postgres directly to browsers (multi-tenant direct access). Until then the
app-layer boundary above is the contract.
