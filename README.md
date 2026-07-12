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
  it. **Not yet exercised end-to-end** — this dev sandbox has no
  `docker` binary; needs a run on a host that has one before "verified"
  is a signal anyone should trust.
- `POST /v1/fixpacks` — Deploy Pack only, free/unpaid preview (no
  payment gate, no PR delivery, no persistence yet)

## Dev

```bash
pip install -e ".[dev]"
pytest
uvicorn app.main:app --reload
```
