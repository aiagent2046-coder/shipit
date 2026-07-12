# ShipIt

Autonomous rescue for vibe-coded apps: free production-readiness audit,
paid Fix Packs executed by agents and verified in a sandbox, delivered
as a pull request via GitHub sync.

Architecture: see `docs/shipit-architecture.md` (v0.2).

## Status: phase 1 (Audit Engine) done, phase 2 (Deploy Pack) started

Implemented:
- `app/ingest/validators.py` — hostile-archive validation (size, file
  count, symlinks, path traversal, zip bombs by ratio and by total size)
- `app/ingest/stack_detect.py` — Next.js / Vite+React / FastAPI
  detection, honest `unsupported` otherwise
- `app/ratelimit.py` — in-memory fixed-window rate limit per client IP
  (`AUDIT_RATE_LIMIT_PER_DAY`, default 5), enforced before any archive
  bytes are read
- `POST /v1/audits` — intake endpoint (rate limit + validation + stack
  detection + static scan + LLM auth/security scan when providers are
  configured)
- `app/deploypack/generate.py` — Deploy Pack, minimal scope: generates
  Dockerfile / docker-compose.yml / .env.example / CI workflow for
  `fastapi` and `vite-react` only (Next.js deferred — no real Next.js
  export validated yet). Detects poetry vs pip, Postgres usage, and
  Vite build-time `VITE_*` env vars (wired as Docker build args, since
  Vite inlines them at build time, not runtime).
- `app/deploypack/sandbox.py` — real `docker build` + `docker run` +
  `curl` verification, never trusts a generated Pack without booting
  it. **Confirmed end-to-end** on a real GitHub Actions runner (this
  dev sandbox has no `docker` binary itself) — see
  `.github/workflows/smoke-deploy-pack.yml` / `scripts/smoke_verify_deploy_pack.py`.
  Both `fastapi_sample` and `vite_sample` verified=True.
- `app/deploypack/delivery.py` — opens a real PR (branch + commit via
  the Git Data API) for a verified Pack, using a single operator token
  (`GITHUB_PR_TOKEN`) — not a GitHub App yet, so it can only open PRs
  on repos that token has write access to. **Confirmed end-to-end**:
  dogfooded on this repo itself — [PR #1](https://github.com/aiagent2046-coder/shipit/pull/1)
  is a real branch + real commit + real PR opened by this exact code.
  One honest nuance found doing that: `.env.example` didn't show up in
  the PR diff — not a bug, `_merge_env_example` correctly produced
  identical content to what shipit already had (no Postgres, so
  nothing new to add), and git/GitHub correctly show zero diff for an
  unchanged file.
- `POST /v1/fixpacks` — Deploy Pack, free/unpaid preview (no payment
  gate, no persistence yet). Optional `deliver_to="owner/repo"` form
  field opens a real PR once verified; refuses to deliver an unverified
  Pack.

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```
