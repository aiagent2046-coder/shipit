# Drydock

**Autonomous rescue for production-bound, AI-generated applications.**

Drydock audits a public GitHub repository or ZIP export, identifies concrete
production-readiness risks, builds a narrowly-scoped Fix Pack, verifies it in
an isolated sandbox, and delivers the result as a pull request.

It is designed for the moment after a Lovable, Bolt, or hand-built prototype
starts handling real users, credentials, payments, or deployments.

## Why Drydock

Most code scanners stop at a list of warnings. Drydock is built around a more
useful outcome:

1. inspect the application;
2. explain the risk in product language and point to the relevant code;
3. generate the smallest safe change for supported problems;
4. compare the original and patched versions in a sandbox; and
5. open a reviewable GitHub pull request — never push to `main`.

## What works today

- Intake from a public GitHub repository or ZIP archive, with hostile-archive
  validation and strict SSRF protection.
- Stack detection for Next.js, Vite + React, and FastAPI.
- Deterministic checks plus LLM-assisted security, auth, payment, data, and
  web-risk reviews; findings are anchored back to real files and lines.
- Fix Packs for safe, deterministic secret and configuration remediation.
- Docker-based build/run verification with resource limits and no network for
  execution stages.
- GitHub App delivery of a verified fix as a pull request.
- Postgres-backed job processing, idempotent billing primitives, structured
  logs, health checks, and production deployment tooling.

## What Drydock deliberately does not claim

- A source-supported finding is not automatically a runtime reproduction.
- A Fix Pack is withheld if verification is unavailable or finds a regression.
- Private repositories and non-GitHub hosts are not supported by public intake
  yet.
- Every payment-provider flow must be proven by a real payment before it is
  presented as production-verified.

## Quick start

```bash
git clone https://github.com/aiagent2046-coder/shipit.git
cd shipit
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
pytest -q
```

The test suite is the part that runs with no configuration at all, and it is
the honest starting point.

**Running an audit needs a database.** `uvicorn app.main:app --reload` will
start without `DATABASE_URL`, but requesting an audit then fails with
`503 {"reason": "queue_unavailable"}`: an audit is a queued job, and with no
database there is no queue to accept it and no worker to run it. The server
says so rather than handing back a job id for a job that does not exist. Set
`DATABASE_URL` (see [`.env.example`](.env.example)) before expecting
`POST /v1/audits` to work.

A static-only audit needs nothing further. LLM providers, GitHub delivery,
sandbox execution and payments each need their own variables from
[`.env.example`](.env.example); without provider keys the scan degrades to
static-only and reports `basis: static_only` instead of pretending it looked.

## Architecture

The technical design, security model, and boundaries are in
[`docs/shipit-architecture.md`](docs/shipit-architecture.md).

```text
repository or ZIP
  -> audit queue -> static + LLM scan -> findings
  -> Fix Pack -> isolated verification -> GitHub pull request
```

## Status: active

The project is actively deployed and developed. The current implementation,
production validation notes, operational runbooks, known gaps, and release
history live in [the active technical status record](docs/status-active.md).

## Contributing

Issues and pull requests are welcome. Please keep changes small, add a focused
test for changed behaviour, and do not include credentials, customer archives,
or generated secrets in a contribution.

Commits need a sign-off (`git commit -s`) certifying you have the right to
submit the work under AGPL-3.0. There is no contributor licence agreement and
no copyright assignment — you keep the copyright in your work, and the project
gives up the ability to relicense it without asking you. See
[CONTRIBUTING.md](CONTRIBUTING.md).

## License

Drydock is licensed under the [GNU Affero General Public License v3.0](LICENSE).
If you run a modified public network service, AGPL-3.0 requires offering its
corresponding source to the users of that service.

That obligation binds the hosted service at drydock.co as much as anyone
else's fork, so here is how it is met. The footer of every page links to this
repository. That is the offer, but it cannot be specific — it is rendered
without knowing which commit is live, so following it a week after a deploy
gives you `main` rather than the code that served you. `GET /version` closes
that gap: it reports the running release's commit and a `source` URL pointing
at exactly that tree.

```json
{ "release": "d6b84bc…", "source": "https://github.com/…/tree/d6b84bc…",
  "version": "v2026.08.12-3" }
```

Releases are tagged, so a running version stays reachable after `main` moves
on. If you are ever served a version whose source you cannot obtain from that
URL, that is a licence violation and a bug — please report it.
