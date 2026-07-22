# sandbox-runner deploy checklist (Stage-3 Variant A)

This directory wires the **sandbox-runner**: the out-of-process docker executor
that lets the backend stop shelling `docker` itself. Reducing blast radius by
process/user separation on the **same** VPS — NOT full isolation on a second
host (that is Variant B, out of scope here).

```
backend (root, /opt/shipit)                     runner (shipit-runner, /opt/shipit-runner)
  app.sandbox_client ──HTTP over UDS──▶ app.runner.main ──DOCKER_HOST=tcp──▶ docker-socket-proxy ──ro sock──▶ dockerd
  holds all prod secrets                 holds NO prod secrets                only container that
  (DATABASE_URL, billing, pepper…)       (token + runner knobs only)          touches the real socket
```

## What runs where

- **backend** (`shipit.service`, root, `/opt/shipit`) — unchanged app; now calls
  `app.sandbox_client` instead of `app.deploypack.sandbox` / `app.fixpack.semantic_check`
  for every docker-touching step. Connects to the runner over a Unix socket.
- **sandbox-runner** (`sandbox-runner.service`, `shipit-runner`, `/opt/shipit-runner`) —
  a FastAPI app (`app.runner.main`) that reconstructs the build context and runs
  the UNCHANGED real implementation (same §5 container hardening flags).
- **docker-socket-proxy** (`docker-socket-proxy.yml`, its own container) — the
  only thing mounting `/var/run/docker.sock`; exposes a reduced daemon API on
  `127.0.0.1:2375`.

## One-time host setup

1. **Create the runner user, NOT in the docker group:**
   ```
   useradd --system --no-create-home --shell /usr/sbin/nologin shipit-runner
   # verify it is NOT in `docker`:
   id shipit-runner   # groups= must not list docker
   ```

2. **Separate checkout + venv (O6):**
   ```
   git clone <repo> /opt/shipit-runner
   python3 -m venv /opt/shipit-runner/.venv
   /opt/shipit-runner/.venv/bin/pip install --require-hashes -r /opt/shipit-runner/requirements.txt
   /opt/shipit-runner/.venv/bin/pip install -e /opt/shipit-runner --no-deps
   chown -R shipit-runner:shipit-runner /opt/shipit-runner
   ```

3. **Reduced runner env (no prod secrets):**
   ```
   cp deploy/sandbox-runner/env.runner.example /opt/shipit-runner/.env.runner
   # set SANDBOX_RUNNER_TOKEN = `openssl rand -hex 32`
   chown root:shipit-runner /opt/shipit-runner/.env.runner
   chmod 0640 /opt/shipit-runner/.env.runner
   ```

4. **Backend env gets the matching token + socket path** (in `/opt/shipit/.env`):
   ```
   SANDBOX_RUNNER_TOKEN=<same value as the runner>
   SANDBOX_RUNNER_UDS=/run/shipit-runner/sandbox.sock
   ```
   Access to the socket is gated by its parent dir `/run/shipit-runner`
   (`RuntimeDirectoryMode=0710`: only `shipit-runner` and its group may traverse,
   world cannot) — not by the socket file's own mode, which uvicorn sets to 0666.
   The backend runs as root and traverses 0710 regardless; the token is the
   second line of defence.

   > Note: the unit deliberately sets **no** `UMask=`. A process-global umask in
   > systemd applies to every file the runner writes — including the `mkdtemp`
   > build dirs it extracts client zips into — and a value like `0117` strips the
   > directory execute bit (0700 → 0600), breaking every run with EACCES. Tighten
   > the socket via the runtime-dir mode, never via `UMask`.

5. **Pre-create the no-egress preview network** (host admin, not the runner):
   ```
   docker network create shipit-preview
   SUBNET=$(docker network inspect shipit-preview -f '{{(index .IPAM.Config 0).Subnet}}')
   iptables -I DOCKER-USER -s "$SUBNET" ! -d "$SUBNET" -j DROP
   ```

6. **Start the proxy, then the runner:**
   ```
   docker compose -f deploy/sandbox-runner/docker-socket-proxy.yml up -d
   cp deploy/sandbox-runner/sandbox-runner.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now sandbox-runner
   ```

7. **Verify the chain:**
   ```
   # runner is up and can see docker THROUGH the proxy:
   curl --unix-socket /run/shipit-runner/sandbox.sock http://x/healthz
   # → {"ok":true,"docker":true,"docker_version":"..."}
   # proxy really blocks a denied endpoint (exec):
   docker -H tcp://127.0.0.1:2375 ps        # allowed
   docker -H tcp://127.0.0.1:2375 info      # blocked (INFO=0) → 403
   ```

## Security posture — read this, don't overclaim

The socket-proxy filters at the **endpoint** level, not the **parameter** level.
Container create+run is required for the runner to work, so a fully-compromised
runner process could still request `docker run --privileged -v /:/host` and
escape to host root — the proxy cannot see inside the create-request body to
stop that. See the long comment in `docker-socket-proxy.yml`.

What Variant A + the proxy **do** buy, honestly:
- The runner's user/env holds **no prod secrets**, so code that escapes the
  container sandbox still doesn't directly read DATABASE_URL/billing/pepper.
- The real docker socket is **never** exposed to the runner's user or group.
- The daemon API surface is cut to the few endpoints listed in the compose file
  (no exec, secrets, volumes API, swarm, info, distribution, commit…).

The real per-parameter control (block `--privileged`, `-v /:/…`, `--pid=host`)
needs a **Docker AuthZ plugin** (OPA/Casbin). That is tracked as the Risk-#1
follow-up in `STAGE3_VARIANT_A_PLAN.md` — this proxy is the pragmatic first
layer, not a substitute for it.
