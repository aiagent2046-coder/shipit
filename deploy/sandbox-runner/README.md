# sandbox-runner deploy checklist (Stage-3 Variant A)

This directory wires the **sandbox-runner**: the out-of-process docker executor
that lets the backend stop shelling `docker` itself. Reducing blast radius by
process/user separation on the **same** VPS — NOT full isolation on a second
host (that is Variant B, out of scope here).

```
backend (shipit-ops, /opt/shipit)               runner (shipit-runner, /opt/shipit-runner)
  app.sandbox_client ──HTTP over UDS──▶ app.runner.main ──DOCKER_HOST=tcp──▶ docker-socket-proxy ──ro sock──▶ dockerd
  holds all prod secrets                 holds NO prod secrets                only container that
  (DATABASE_URL, billing, pepper…)       (token + runner knobs only)          touches the real socket
```

## What runs where

- **backend** (`shipit.service`, `shipit-ops` + supplementary group
  `shipit-runner`, `/opt/shipit`) — unchanged app; now calls
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
   `shipit.service` runs as `shipit-ops` and reaches the socket through
   `SupplementaryGroups=shipit-runner`
   (`deploy/systemd/shipit.service.d/30-service-user.conf`) — group membership
   is what buys the traverse, so `shipit-ops` must be able to resolve group
   `shipit-runner` or every Deploy Pack / Fix Pack sandbox call fails. The
   token is the second line of defence.

   > Note: the unit deliberately sets **no** `UMask=`. A process-global umask in
   > systemd applies to every file the runner writes — including the `mkdtemp`
   > build dirs it extracts client zips into — and a value like `0117` strips the
   > directory execute bit (0700 → 0600), breaking every run with EACCES. Tighten
   > the socket via the runtime-dir mode, never via `UMask`.

   > Note: the runner's scratch dir lives **outside `/tmp`**. The unit sets
   > `StateDirectory=shipit-runner` (systemd creates `/var/lib/shipit-runner`,
   > owned by `shipit-runner`, on every start — **no manual mkdir/chown**) and
   > `Environment=TMPDIR=/var/lib/shipit-runner`, so `tempfile.mkdtemp()` builds
   > there. This is required because `PrivateTmp=true` gives the runner a private
   > `/tmp` in its own mount namespace that **dockerd cannot see**; a build dir
   > under `/tmp` would bind-mount into fixpack containers as an **empty** `/work`
   > (docker auto-creates the missing source), failing every install/test. Do not
   > repoint `TMPDIR` at `/tmp` while `PrivateTmp` is on. (Deploy-pack is immune —
   > it streams a `docker build` context and never has dockerd resolve a host
   > path.) Guarded by `scripts/check_runner_bindmount_namespace.py`.

5. **Pre-create the no-egress preview network** (host admin, not the runner):
   ```
   docker network create shipit-preview
   SUBNET=$(docker network inspect shipit-preview -f '{{(index .IPAM.Config 0).Subnet}}')
   iptables -I DOCKER-USER -s "$SUBNET" ! -d "$SUBNET" -j DROP
   ```

6. **Install the build-step egress allowlist** (host admin; the Squid that
   `DEPLOYPACK_BUILD_PROXY_URL`/`FIXPACK_INSTALL_PROXY_URL` point at):
   ```
   install -m 0644 deploy/sandbox-runner/squid-build-allowlist.conf \
       /etc/squid/squid-build-allowlist.conf
   # once, in /etc/squid/squid.conf, before any other http_access rule:
   #   acl build_allowlist dstdomain "/etc/squid/squid-build-allowlist.conf"
   #   http_access allow build_allowlist
   #   http_access deny all
   squid -k parse && systemctl reload squid
   ```
   Read that file's header before adding a line: for the **build** step this
   list is a convention, not a boundary (`docker build` gets no `--network`),
   so a domain added here does not widen what a hostile build can reach — it
   only decides whether honest customer code builds at all. Missing entries are
   expensive in a different way: they surface as `docker build failed` with no
   reason, which is what cost a whole detector measurement on 2026-08-17.

7. **Start the proxy, then the runner:**
   ```
   docker compose -f deploy/sandbox-runner/docker-socket-proxy.yml up -d
   cp deploy/sandbox-runner/sandbox-runner.service /etc/systemd/system/
   systemctl daemon-reload && systemctl enable --now sandbox-runner
   ```

8. **Verify the chain:**
   ```
   # runner is up and can see docker THROUGH the proxy:
   curl --unix-socket /run/shipit-runner/sandbox.sock http://x/healthz
   # → {"ok":true,"docker":true,"docker_version":"..."}
   # proxy really blocks a denied endpoint (exec):
   docker -H tcp://127.0.0.1:2375 ps        # allowed
   docker -H tcp://127.0.0.1:2375 info      # blocked (INFO=0) → 403
   # build allowlist actually admits the OS registry that used to 403:
   curl -sI -x http://127.0.0.1:3128 \
       https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/APKINDEX.tar.gz \
       | head -1        # → HTTP/1.1 200 (was: 403 Forbidden)
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
