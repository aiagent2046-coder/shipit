# Stage-3 Variant A — process/user separation for docker execution

**Status: IMPLEMENTED in this PR.** Verified by a real end-to-end HTTP run
(`.github/workflows/e2e-sandbox-runner.yml`), not just unit tests with mocks.

Scope: reduce the blast radius of running untrusted client code by moving every
`docker` invocation out of the backend process (which holds all prod secrets)
into a separate, unprivileged **sandbox-runner** process on the **same** VPS,
and putting a **docker-socket-proxy** between that runner and the real docker
socket.

This is **Variant A** (process/user separation on one host). It is explicitly
**not Variant B** (full isolation on a second VPS), which stays out of scope —
Variant B needs a second host and is a hosting/ops project, not a code change.
It is also distinct from `PHASE3_ISOLATION_PLAN.md` (gVisor runtime), which
hardens the *container* boundary; Variant A hardens the *process/privilege*
boundary. The two compose.

---

## Why

Today `shipit.service` runs as **root** with `EnvironmentFile=/opt/shipit/.env`
(DATABASE_URL, billing keys, pepper, Telegram + admin tokens) and shells
`docker` directly (`app/deploypack/sandbox.py`, `app/fixpack/semantic_check.py`).
A container-escape in untrusted client code therefore lands in a process that
can read every prod secret. Variant A does not claim to stop a determined escape
(see the honest limitation), but it removes the "…and now you have all the
secrets" second half: the process that talks to docker holds none of them.

---

## Architecture

```
backend  (root, /opt/shipit, all prod secrets)
   │  app.sandbox_client  — HTTP over a Unix-domain socket
   ▼
sandbox-runner  (user shipit-runner, /opt/shipit-runner, NO prod secrets)
   │  app.runner.main  — FastAPI; calls the UNCHANGED real impl
   │  DOCKER_HOST=tcp://127.0.0.1:2375   (never the real socket)
   ▼
docker-socket-proxy  (Tecnativa; the ONLY container mounting the real socket, ro)
   │  reduced daemon API (allowlist of endpoints)
   ▼
dockerd
```

- The runner imports and runs the **same** `verify_deploy_pack` / `run_suite` /
  `minimal_check` / `reconcile_previews` / preview-stop code the backend used to
  call in-process, so the §5 container hardening (`--cap-drop=ALL`,
  `--pids-limit`, `--network none` on test, egress proxy on install, read-only
  rootfs, non-root uid) is **byte-for-byte identical**. Variant A changes *which
  process/user* runs docker, not *what flags* it runs with.
- `app.sandbox_client` exposes the same function names/signatures/return types as
  the local implementations it replaces, so call sites (`pipeline.py`,
  `preview.py`, the fixpack path in `main.py`) barely changed.

Stateful concerns (PreviewRegistry: TTL, one-preview-per-owner, port
reservation) stay in the **backend** (decision O1); the runner is a stateless
executor.

---

## Decisions (open questions O1–O6)

| # | Question | Decision |
|---|----------|----------|
| **O1** | Where does preview state live? | Runner is a **stateless** docker executor. `PreviewRegistry` (TTL / owner / port state) stays in the backend. |
| **O2** | What does `/healthz` check? | `docker version` through the proxy — a fast daemon-reachability probe. No hello-world container per check. |
| **O3** | Concurrency limit on the runner? | **2** concurrent build/run ops (`SANDBOX_RUNNER_CONCURRENCY`, = prod VPS vCPUs), enforced by an `asyncio.Semaphore` independent of the backend's threadpool. |
| **O4** | Transport for the (multi-MB) workspace? | Raw `application/octet-stream` body for the zip; small control metadata in an `X-Sandbox-Request` JSON header. No multipart, no base64. |
| **O5** | Backend↔runner channel? | **Unix-domain socket** (`/run/shipit-runner/sandbox.sock`) — access gated by the runtime **directory** mode `0710` (owner `shipit-runner` + group only; uvicorn force-chmods the socket file to 0666, so the dir is the real gate). A bearer token is the **second** line of defence. A TCP fallback (`SANDBOX_RUNNER_URL`) exists for hosts without a UDS. The unit sets **no `UMask=`** — a process-global umask breaks the runner's `mkdtemp` build dirs (see the unit comment / `scripts/check_runner_build_dir_perms.py`). |
| **O6** | Code layout? | Separate checkout `/opt/shipit-runner` with its own venv and reduced `.env.runner`; not shared with `/opt/shipit`. |

**Scratch dir must live outside `/tmp` (mount-namespace footgun).** The unit keeps
`PrivateTmp=true`, which gives the runner a *private* `/tmp` in its own mount
namespace that **dockerd cannot see**. The runner extracts each client zip into a
`tempfile.mkdtemp()` dir and bind-mounts it into fixpack containers
(`docker run -v <dir>:/work`); if that dir is under `/tmp` the daemon resolves a
path that doesn't exist in *its* namespace and mounts an **empty** `/work`, so
every install/test fails with the requirements file "missing". Fix: the unit sets
`StateDirectory=shipit-runner` + `Environment=TMPDIR=/var/lib/shipit-runner`, so
mkdtemp builds outside `/tmp` (shared with dockerd). Deploy-pack is immune (it
streams a `docker build` context, never resolving a host path via the daemon).
Regression-guarded by `scripts/check_runner_bindmount_namespace.py` and exercised
by the e2e workflow, which now starts the runner **under `PrivateTmp` via
`systemd-run`** so this class of bug actually reproduces in CI.

---

## docker-socket-proxy — choice and HONEST limitation

We put **Tecnativa/docker-socket-proxy** (HAProxy-based) between the runner and
`/var/run/docker.sock`. The runner reaches dockerd only via the proxy on
loopback TCP; `shipit-runner` is **not** in the `docker` group and never sees the
real socket. Config: `deploy/sandbox-runner/docker-socket-proxy.yml`.

Allowed endpoints (exactly what the code needs): `POST`, `CONTAINERS`, `IMAGES`,
`BUILD`, `NETWORKS`, `VERSION`. Denied (root-equivalent / unused): `EXEC`,
`SECRETS`, `VOLUMES` (API), `SWARM`, `INFO`, `DISTRIBUTION`, `COMMIT`,
`SESSION`, and the rest.

**The limitation, stated plainly (do not overclaim):** this proxy filters at the
**endpoint** level, not the **parameter** level. The runner must be able to
create+run containers (`POST /containers/create`), and the proxy cannot inspect
that request body — so it **cannot** block `--privileged`, `-v /:/host`,
`--pid=host`, etc. A fully-compromised runner process could still craft a
container that escapes to host root. What the proxy genuinely buys: (1) the real
socket is never exposed to the runner's user/group, so a non-code compromise
can't reach dockerd at all; (2) the daemon API surface is cut to a handful of
endpoints (no `exec`, no secrets, no volume API, no swarm…).

**Risk #1 follow-up:** true per-parameter enforcement (reject `--privileged`,
host bind mounts, host namespaces) requires a **Docker AuthZ plugin**
(OPA/Casbin). That is the real fix for the residual escape risk and is the
recommended next step. This proxy is the pragmatic first layer, chosen because
it is the standard, low-effort surface-reduction tool — not a substitute for the
AuthZ plugin.

---

## Degradation contract when the runner is unreachable

- deploy-pack **verify (non-preview)** → `verified=None` ("could not verify" —
  an environment gap, not a verdict), same soft-fail as the old
  "docker binary not found" path.
- deploy-pack **preview** → **503** (a live preview genuinely can't be built).
- fixpack **run_suite / minimal_check** → `RunResult` with `error` set (never
  raises), so `is_regression` treats a runner outage symmetrically as "could not
  verify", never a false regression — identical to the existing "docker CLI not
  available" behaviour.

---

## Verification — real, not mocked

Given the §5 experience (two real bugs that mock-based unit tests missed), the
proof of this change is a **full live run**, not unit tests:

- **Unit tests** (`tests/test_sandbox_client.py`, `tests/test_runner_endpoints.py`,
  plus the rewired preview/pipeline/api suites) cover marshalling, auth, and the
  degradation contract with a fake transport — necessary but **not sufficient**.
- **End-to-end** (`.github/workflows/e2e-sandbox-runner.yml`, `workflow_dispatch`)
  runs the **real** chain on a GitHub-hosted docker host:
  1. real docker-socket-proxy container, and a live assertion that a **denied**
     endpoint (`/info`) actually returns **403** — proving the allowlist is
     enforced, not assumed;
  2. the real sandbox-runner process (uvicorn on a UDS, `DOCKER_HOST`→proxy,
     `DOCKER_BUILDKIT=0`), gated on `/healthz` reporting `docker:true`;
  3. all three deploy-pack stacks (FastAPI, Vite/React, Next.js) **build + run +
     boot-check** through backend→runner→proxy→docker over HTTP;
  4. a fixpack **install + test** suite runs real containers through the chain;
  5. the preview keep-alive + reap path and the backend `/internal/preview/reap`
     endpoint, both over real HTTP.

  No function is called directly and no docker call is mocked in the e2e run.

This workflow **supersedes** the old `smoke-deploy-pack.yml` (whose scripts
assumed the backend ran docker in-process); those scripts are reused here, now
routed through the runner.

**CI limitation to be aware of:** the e2e workflow proves the chain on a
GitHub-hosted docker host, which differs from the prod VPS in two host-provided
pieces (the egress-allowlist Squid and the pre-created `shipit-preview` network).
The workflow reproduces the network with a normal bridge + iptables egress DROP
and clears the build/install proxy URLs, mirroring prod behaviour. It does **not**
exercise the systemd unit or the `shipit-runner` user separation — those are
host-config artifacts verified by the `deploy/sandbox-runner/README.md` checklist
on the VPS itself.

---

## Files

- `app/sandbox_client.py` — backend HTTP client (UDS, result-type parity, `SandboxRunnerUnavailable`).
- `app/runner/` — `main.py` (FastAPI endpoints, concurrency semaphore), `auth.py` (bearer, unset→503, mismatch→401).
- `app/deploypack/pipeline.py`, `app/deploypack/preview.py`, `app/main.py`,
  `app/fixpack/semantic_check.py` — rewired to the client (docker-touching seams only).
- `deploy/sandbox-runner/` — `docker-socket-proxy.yml`, `sandbox-runner.service`,
  `env.runner.example`, `README.md` (deploy checklist + honest posture).
- `.github/workflows/e2e-sandbox-runner.yml`, `scripts/e2e_fixpack_run_suite.py`.
