# Review of four baseline model hypotheses — 2026-10-04

Source reviewed: deployed commit `0fbe8283a080f811a3ed4382f6f3d9dc1a65b2dc`.
Report: audit `b901daab`, archive paths ending in `shipit-0fbe828`.
The report did not record a full Git commit independently. Its free model
retained four hypotheses; the paid model returned eight valid empty responses.
Neither repetition nor absence is an independent consequence check.

## Public API URL

`web/src/lib/api.ts` reads `NEXT_PUBLIC_API_BASE_URL` as the browser's API
destination. The public configuration value is necessary for this client and
does not itself establish credential disclosure. The hypothesis instead depends
on a future change or another CORS error. No repair to this client setting is
justified by the cited source. The existing model instructions already state
that a public API URL or NEXT_PUBLIC prefix alone is not a secret leak.

## Migration diagnostics

The proposed race before redaction is not supported: `run_psql` and
`backup_before_apply` capture subprocess diagnostics and call `redact_dsn`
before constructing `MigrationError`. The pg_restore failure path also redacts.

A different, reproducible gap exists: the old redactor only masks URI userinfo.
Synthetic failed-command output containing a URI query password or libpq
keyword password reaches the exception message unmasked. DATABASE_URL accepts
these nonempty connection strings. The fix extends the shared diagnostic
redactor and tests the actual psql and backup failure paths. This is not
evidence that a real password reached production logs.

Process argument visibility and arbitrary database-returned SQL output are
outside this diagnostic-redaction change.

## Vercel preview CORS

`configure_cors` enables the broad Vercel regex only when
`CORS_ALLOW_VERCEL_PREVIEWS=true`; it defaults off. The regex includes every
Vercel tenant, not just this project. Previously the production validator did
not reject this option. Add a production configuration gate requiring it to be
disabled and directing the operator to explicit `CORS_ALLOWED_ORIGINS`.

No live environment was inspected. Cookie authentication also requires the
web-client header, and session cookies use HttpOnly, Secure and SameSite=Lax;
the optional CORS policy alone does not demonstrate account takeover. This
guard applies to the standard validated production deployment; it does not
change local/staging runtime behavior or prove a manually started service uses
the validator.

## GitHub repository loading

`app/routes/_shared.py::_parse_github_repo_url` requires the HTTPS github.com
origin and restricted owner/repository segments. `app/worker/main.py::_load_payload`
revalidates queued source_ref and passes the parsed segments to
`app/ingest/github_fetch.py::fetch_repo_zip`, which constructs a request under
the fixed `https://api.github.com` base URL.

The hypothesis's missing-helper premise is answered by this call chain. No
arbitrary initial destination was demonstrated. GitHub response redirects are
followed intentionally for zipball downloads; this review does not claim all
redirect or infrastructure behavior is verified. No change to repository
loading or scanner suppression is justified from this hypothesis alone.

## Scanner treatment

Preserve the original hypotheses as unverified review records. Do not add a
repository allowlist or suppress a finding merely because the paid model did
not repeat it. The two concrete changes above are application hardening based
on source inspection and synthetic regression tests, not validation of every
claim made by the free model.

## Validation

- Combined migration, production configuration, CORS, ingestion and worker
  regression run: 193 passed before the final malformed-DSN edge case.
- Final migration suite after adding that edge case: 73 passed.
- Production validator suite: 58 passed; unset/false remain accepted and
  development/staging preview opt-in remains unchanged.
- Ruff and whitespace checks passed. No production credentials or live
  service configuration were read; subprocess diagnostic cases use local fake
  executables and synthetic values without connecting to a database.
