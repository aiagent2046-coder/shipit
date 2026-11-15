# Deploy Pack delivery access

`POST /v1/fixpacks` can still generate a Deploy Pack without GitHub credentials
when `deliver_to` is omitted. Asking it to create a branch and pull request is
a separate authority boundary.

For `deliver_to=owner/repo`, send a caller-owned GitHub credential in the
`X-GitHub-Token` HTTP header. Keep it out of URLs, uploaded archives and command
history. This endpoint checks the target repository with that token before
starting sandbox work. The authenticated principal must have repository push
permission. GitHub additionally enforces the token's own contents/pull-request
write permissions during delivery; a read-only token cannot borrow broader
permissions from the service.

The same supplied token is used for all delivery calls. This endpoint no longer
uses `GITHUB_APP_ID`, the service App private key, or `GITHUB_PR_TOKEN` as a
fallback. Missing/invalid credentials return 401, missing repository authority
returns 403, and an unavailable authorization check returns 502. Repository
redirects are rejected rather than forwarding a credential to a different target.
Unverified builds still cannot open a PR. The token is held only for the request,
is not recorded in jobs, and is not returned in success/error responses.

This is a deliberate compatibility change for API clients that previously set
`deliver_to` without supplying their own authority. Installing the service's
GitHub App alone does not establish the identity of the HTTP caller.

## Paid Fix Pack delivery

Both bank-transfer and YooKassa checkouts require `X-GitHub-Token` before opening
an invoice or contacting the card provider. The browser keeps it only in component
memory and uses a password input. Choose a repository-scoped fine-grained token
with Contents and Pull requests write permission. The read-only preflight verifies
the principal's repository role; it cannot prove every token scope. GitHub enforces
the same token's actual permissions on every subsequent write.

The server encrypts this credential using Fernet and a dedicated
`FIXPACK_DELIVERY_ENCRYPTION_KEY`. The authenticated envelope binds the provider,
order reference, audit ID and exact case-insensitive repository name. An order and
its encrypted grant are inserted in one transaction. The separate
`fixpack_delivery_grants` table has RLS enabled and no public read policy. It never
appears in payment JSON, provider metadata, job responses or logs. Its foreign
key uses ON DELETE CASCADE: deleting a payment also removes its credential
envelope, so an orphan credential cannot outlive its parent order.

The worker reads the original completed funding payment (including its immutable
`funding_key`) before doing expensive work, then reads it again immediately before
opening the PR. Each check decrypts the bound grant and checks GitHub access. A
duplicate payment that happens to point at the same job cannot replace that grant.
Delivery uses the buyer credential, never the service App or operator PAT.

A grant expires after seven days. A revoked, expired or missing grant parks the job
in `awaiting_authorization` without consuming its generation retry budget. It stays
a live paid job, preventing another purchase. The audit owner can enter a new token
and the original order reference in the status panel; the reference is also shown
by the authenticated status endpoint. Renewal requires the audit access token and
fresh GitHub authorization. It atomically updates the funded grant and requeues
only the waiting job, never a completed or already-running job. No new payment is
created. API clients use `POST /v1/audits/{id}/fixpack/delivery-authorization` with
`{reference, audit_token}` and the `X-GitHub-Token` header.

GitHub network failures, rate limits and 5xx responses defer the job for retry
without requesting a new token. Permission refusals during a write also allow
renewal. Other delivery errors remain failures with sanitized diagnostics.
Successful delivery removes retained grants for the job. Seven days is the
**authorization lifetime**, not automatic deletion of every ciphertext row:
unpaid, blocked or failed orders may retain unusable encrypted envelopes. Operators
must include the table in their retention policy and protect its backups and key.
OAuth can replace manual token entry later without changing these funding and
same-credential boundaries; no OAuth flow is claimed in this version.

## Rollout and recovery

1. Stop the old paid worker and pause Fix Pack checkout during rollout. An old
   worker must not process newly authorized orders using its service credentials.
2. Provision one dedicated Fernet key through the deployment secret manager for
   both API and worker. `.env.example` names the setting and generation command;
   do not put the real value in Git, logs, screenshots or this document. Without
   it, new paid checkout refuses before payment and existing jobs defer.
3. Back up the database and apply migration `0041_fixpack_delivery_grants.sql`,
   then deploy matching API, frontend and worker versions. The new live-job state
   makes rollback to old workers unsafe. Keep the key across ordinary deploys.
4. Existing funded orders with no grant park for buyer authorization. Historical
   jobs without an immutable funding key require operator payment reconciliation;
   the system does not guess which old receipt owns them. Rotating or losing the
   encryption key also requires fresh buyer authorization for retained orders.
5. Check checkout refusal without a token, renewed-job resumption, and the
   private-table migration checks before resuming sales and the worker. No live
   payment or production credential is needed for the automated test suite.

References: [GitHub fine-grained token permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
and [personal access token management](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens).
