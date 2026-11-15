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

## Scope and remaining paid-flow work

The asynchronous paid Fix Pack processor is a separate path. Its existing
server App/PAT delivery and installation-status screen are not made into a
GitHub user authorization flow by this change. Possession of an audit link or
payment receipt does not establish write access to that repository.

Before claiming repository ownership enforcement across all delivery paths,
the paid flow needs a verified user-to-repository grant at purchase time and
an authorization check at execution time. A suitable implementation is a
GitHub App user authorization flow with a server-side, repository-bound grant
and revocation checks; the existing frontend-only installation callback is not
such a grant. Do not store a long-lived caller PAT in the job row or silently
reuse service credentials when a caller credential expires.

Tests cover exact-target permission checks, missing/read-only credentials,
redirects, unavailable GitHub, refusal before sandbox work, caller-only writes
with server credentials configured, and omission of upstream secret-bearing
diagnostics. All network interactions in those tests use mocks.
