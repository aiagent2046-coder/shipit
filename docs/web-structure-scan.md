# Web structure scan (site check)

The third consented request the product makes against a customer's own
deployment: after the RLS check (a live database) and the served-bundle check
(the shipped JavaScript), this one reads the deployment's web STRUCTURE —
exposed files, directory listings, transport-security headers, cookie flags,
CORS policy, security.txt. Those live in how the site is served, not in any
single asset, and no static scan of the repository can see them.

Kernel: `app/proof/web_scan.py` (`run_web_structure_scan`).
Operator edge: `scripts/scan_site.py` (consent through the environment, like
`probe_supabase_rls_live.py`). Tests: `tests/test_web_scan.py` (faked network
boundary + a real in-process HTTP stand), `tests/test_scan_site_cli.py`.

## The contract

- **Consent has no default.** `SITE_SCAN_CONSENT` must be exactly
  `i-own-this-project` — the same typed phrase the RLS probe and the bundle
  check use; the kernel takes `consent: bool` and answers `skipped` without it.
- **Read-only GET, fixed probe list.** 16 files, 8 directories, listed as data
  in the kernel. No payloads, no auth attempts, no crawling, no exploitation.
  Requests carry an honest `User-Agent` and a delay between them (0.2 s
  default, `--delay`); a hard request cap (`MAX_REQUESTS`) bounds the target's
  load, and `probes_truncated` keeps a capped answer from reading as a full one.
- **SSRF wall, inherited from `served_bundle.py`.** `validate_deployment_url`
  + `resolve_and_vet` (every address a name resolves to must be public; loopback
  only with `--allow-loopback` for a local stand), and the default fetch pins
  to the vetted IP so the bytes come from the address that passed the guard.
  Redirects are never followed; a root that answers 3xx is an honest `error`.
- **Content-verified positives.** A finding requires the body to carry the
  file's signature (`[core]` for `.git/config`, two KEY=VALUE lines for `.env`,
  the zip magic for a backup) — never status alone, because a SPA answering
  200 with the page shell for every unknown path is the normal modern shape
  and the classic false-positive source. Three or more byte-identical
  catch-all answers set `catch_all_detected` and add the matching limitation.
- **Evidence is masked by construction.** An `.env` finding records key
  NAMES, never values; binary signatures are magic fragments. A real secret
  stays where it was found and is never re-stored by us.
- **Honest statuses.** `checked` / `skipped` / `error` are three different
  answers and none of them is "your site is fine". Every result carries
  `coverage` (requests sent, paths probed, truncation, catch-all) and the
  fixed-list `limitations` verbatim.

## Findings vocabulary

`web-https-redirect`, `web-security-headers`, `web-cookie-flags`,
`web-server-banner`, `web-mixed-content`, `web-cors`, `web-security-txt`,
`web-directory-listing`, `web-exposed-files`.

Hardening observations (missing CSP/nosniff, banner inventory, missing
security.txt) are labelled as hardening/inventory in their details — they are
facts of configuration, not confirmed vulnerabilities.

## Use

    export SITE_SCAN_CONSENT=i-own-this-project
    python scripts/scan_site.py https://example.com
    python scripts/scan_site.py https://example.com --json --fail-on high
    python scripts/scan_site.py http://127.0.0.1:8000 --allow-loopback   # local stand

Exit codes follow `drydock-local`: 0 — ran, nothing at/above `--fail-on`;
1 — findings at/above `--fail-on`; 2 — refused or failed before probing.

## Not checked (stated in every report)

The probe list is fixed and short: a path absent from it is unprobed, and a
clean report is not proof of absence. No authentication is attempted and no
JavaScript executes, so state behind a login or after render is invisible to
this scan. TLS protocols and cipher suites are not audited (only certificate
validity during the request). No exploitation is attempted at any point.

## Roadmap position

A route (`POST /v1/site-check`, rate-limited, ledgered like the RLS check) is
the natural API edge once the kernel has been reviewed in use. The kernel
already keeps the honesty contracts the route will need to preserve.
