# Drydock

**Autonomous rescue for production-bound, AI-generated applications.**

Drydock audits a public GitHub repository or ZIP export, explains concrete
production-readiness risks in product language, builds a narrowly-scoped
**Fix Pack**, verifies it where possible, and delivers the result as a
**GitHub pull request** — never a push to `main`.

Product site: [drydock.co](https://drydock.co).

This repository is the corresponding source for the hosted service (AGPL-3.0).

It is built for the moment after a Lovable, Bolt, Cursor, or hand-built
prototype starts handling real users, credentials, payments, or deployments.

## Why Drydock

Most scanners stop at a list of warnings. Drydock is built around a usable
outcome:

1. Inspect the application (static checks + LLM-assisted review).
2. Explain the risk in product language and point at the relevant files.
3. Generate the smallest safe change for **supported** problem classes.
4. Verify in an isolated sandbox where the pipeline allows it.
5. Open a reviewable pull request; optionally attach **Proof-of-Exploit /
   Proof-of-Fix** evidence for selected finding types (informational / gated
   by configuration, never a silent push).

You pay for the **fix**, not for a PDF of findings.

## Production today

Live on [drydock.co](https://drydock.co) with:

| Area | Status |
|------|--------|
| Public GitHub + ZIP intake | Live (SSRF-safe, hostile-archive checks) |
| Stacks | Next.js, Vite + React, FastAPI |
| Audit | Deterministic rules + LLM review; scores and findings |
| Fix Pack | Secrets / config / selected static security rewrites → PR via GitHub App |
| Card payments | **ЮKassa** (webhook is a hint; status/amount confirmed by server-side API) |
| Manual payments | Bank transfer (operator-confirmed oracle) |
| Customer notify | Email + Telegram (`app/notify/`), channel self-check on a timer |
| Ops | Postgres queues, leases, `/internal/stats`, operator Telegram alerts (including paid backlog not draining) |
| Proof | Registry + templates (e.g. secrets); soft/hard gate modes available |

Release identity for a running host: `GET /version` (commit + `source` tree URL + CalVer tag).

## What Drydock deliberately does not claim

Read this before you pay — same boundaries the product enforces in code:

- **Not a penetration test.** A source-supported finding is not automatically a
  runtime reproduction. Proof stages cover selected classes only.
- **Not every finding is auto-fixed.** Unsupported or unsafe changes stay in the
  report; a Fix Pack is withheld or marked `no_fix_needed` when there is
  nothing safe to ship.
- **Public GitHub (or ZIP) only** on public intake. Private repositories and
  non-GitHub hosts are out of scope for self-serve.
- **Verification can block delivery.** If the sandbox is down or a patch looks
  like a regression, Drydock prefers not to open a PR over shipping an
  unverified change.
- **Payment rails are explicit.** Card = ЮKassa. Bank transfer is manual.
  Historical mentions of other aggregators in old docs are not the live rail.
- **Continuous monitoring is built but not sold.** The GitHub push webhook, the
  durable run queue and the findings diff all exist and are tested;
  `MONITORING_FOR_SALE` is `False`, and the webhook checks it before it looks
  up a subscription, so no push drives spend. Pricing, spend attribution and
  the cap are three decisions that have not been made — code in the tree is
  not a live offer.

## Architecture (short)

```text
public repo or ZIP
  → audit queue → static + LLM scan → findings + score
  → (optional) paid Fix Pack → generate plan → sandbox / proof
  → GitHub App opens PR → customer notification
```

Design and security boundaries: [`docs/shipit-architecture.md`](docs/shipit-architecture.md).
Payment rail note: [`docs/PAYMENT_RAIL.md`](docs/PAYMENT_RAIL.md).
Longer operational history: [`docs/status-active.md`](docs/status-active.md)
(may lag; prefer this README and `PAYMENT_RAIL.md` for current rails).

## Quick start (developers)

```bash
git clone https://github.com/aiagent2046-coder/shipit.git
cd shipit
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The test suite needs no cloud credentials. That is the honest local baseline.

**Audits need a database.** Without `DATABASE_URL`, the API can start, but
`POST /v1/audits` returns `503 {"reason": "queue_unavailable"}` — audits are
queued jobs. Copy [`.env.example`](.env.example), set at least `DATABASE_URL`,
then run migrations as documented in deploy docs.

Optional: LLM keys, GitHub App, sandbox runner, `YOOKASSA_*`, SMTP / Telegram.
Without LLM keys the scan degrades to static-only (`basis: static_only`) rather
than inventing coverage.

## Ownership of results

- Audit report: `GET /v1/audits/{id}?token=…` (per-row `access_token`).
- Fix Pack job: `GET /v1/fixpacks/{id}?token=…` (same model).
- Lightweight poll after purchase: `GET /v1/audits/{id}/fixpack-status`
  (status + `pr_url` only).

A leaked UUID alone is not enough to read a report or job detail.

## Deploy / ops (summary)

- CalVer tags: `vYYYY.MM.DD-N` via `deploy/scripts/tag-release.sh`.
- Production deploy is deliberate (`workflow_dispatch` or
  `deploy/scripts/deploy-production.sh`), not every push to `main`.
- Timers: audit worker, Fix Pack processor, monitoring processor, notify
  channel check, reapers.
- Operator alerts: Telegram (`TELEGRAM_BOT_TOKEN` + `TELEGRAM_ADMIN_CHAT_ID`),
  including failed Fix Packs and a stale **paid** backlog.

## Contributing

Issues and pull requests are welcome. Keep changes small, add a focused test,
and do not include credentials, customer archives, or live secrets.

Commits need a sign-off (`git commit -s`). There is no CLA and no copyright
assignment. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

GNU Affero General Public License v3.0 — see [LICENSE](LICENSE).

The hosted service at drydock.co meets the network-copyleft obligation by
linking this repository from the product UI and by exposing the exact running
tree through `GET /version`:

```json
{
  "release": "5c3efb8…",
  "environment": "production",
  "source": "https://github.com/aiagent2046-coder/shipit/tree/5c3efb8…",
  "version": "v2026.08.28-9"
}
```

The live response also carries `built_at`, the release's build timestamp.
`version` and `built_at` are null on a source checkout rather than guessed —
that is a truthful "this is not a built release", not an error.

If you are served a build whose source is not obtainable from that URL, that is
both a licence problem and a bug — please report it.
