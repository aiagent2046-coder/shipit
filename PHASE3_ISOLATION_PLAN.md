# Phase 3 — Stronger execution isolation for untrusted client code: reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

Scope note: this is about the **runtime isolation boundary** around the Docker
containers that install and run *client-repo* code during a Fix Pack semantic
check. It is **not** about the dependency-pinning of ShipIt itself (that is
[`PHASE3_SBOM_PLAN.md`](./PHASE3_SBOM_PLAN.md)), and it builds directly on the
container hardening already merged (PR #40): `--cap-drop=ALL`, `--pids-limit`,
`--cpus`, `--security-opt=no-new-privileges`, egress-allowlist proxy on install,
`--network none` on test.

---

## TL;DR — the audit is right, but the answer is a one-line drop-in, not a rebuild

The external audit's Phase-3 (optional, most expensive) item asks us to harden
the boundary **beyond the standard Docker/namespaces/cgroups/seccomp model**,
specifically against *unknown container-escape vulnerabilities in Docker/runc or
the host kernel* — a class of risk the PR #40 hardening reduces but cannot
eliminate, because everything there still runs on the **shared host kernel** via
the default `runc` runtime.

There are two families of answer:

- **microVM isolation (Firecracker / Kata Containers)** — a real guest kernel
  per workload. **Blocked on the current infrastructure**: `/dev/kvm` does not
  exist on the Timeweb VPS (it is itself a guest VM with no nested KVM), so
  these are not runnable *at all* here. They require a hosting migration and are
  documented as such in §7, not designed now.

- **user-space kernel interception (gVisor / `runsc`)** — a sandbox kernel that
  intercepts guest syscalls in user space, **needs no KVM**, and plugs into
  Docker as an **alternative runtime** selected per-container with a single
  `--runtime=runsc` flag. This is the **only** option technically realizable on
  the current VPS without changing providers.

The gVisor integration is genuinely a drop-in: the containers are launched
through two seams in `app/fixpack/semantic_check.py` (`_docker_install_argv`,
`_docker_test_argv`), and adding a runtime is one extra flag on the existing
`docker run` line — **not** an architectural change.

**Recommendation (§3):** wire gVisor in now as an **explicit, reversible,
env-gated opt-in** (`FIXPACK_DOCKER_RUNTIME`, default `runc`) — near-zero code
cost, fully backwards-compatible — but **do not flip it on in production until
there is a reason to**, given **0 real client jobs to date**. The code lands the
capability; enabling it is a one-variable operational decision. This threads the
needle: we neither over-engineer for absent traffic nor leave ourselves a
multi-day scramble the first time an untrusted repo arrives.

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. Where and how client containers are launched today

All client-code execution goes through **`app/fixpack/semantic_check.py`**.
There is exactly one subprocess seam (`_run`, line 233) and two `docker run`
argv builders:

- **`_docker_install_argv(image, workdir, script)`** — `app/fixpack/semantic_check.py:324`
  Step 1, network **on but only via the egress-allowlist proxy**. Builds:

  ```py
  ["docker", "run", "--rm",
   "--memory", MEMORY_LIMIT,
   *_CONTAINER_HARDENING,          # --pids-limit / --cpus / no-new-privileges / --cap-drop=ALL
   *_install_proxy_argv(),         # --add-host + HTTP(S)_PROXY/NO_PROXY env
   "-v", f"{workdir}:/work", "-w", "/work",
   image, "sh", "-c", script]
  ```

- **`_docker_test_argv(image, workdir, script)`** — `app/fixpack/semantic_check.py:337`
  Step 2, network **off** (`--network none`). Builds:

  ```py
  ["docker", "run", "--rm",
   "--network", "none",
   "--memory", MEMORY_LIMIT,
   *_CONTAINER_HARDENING,
   "-v", f"{workdir}:/work", "-w", "/work",
   image, "sh", "-c", script]
  ```

Callers:
- `run_suite()` (`:349`) uses **both** builders (install then test), once per
  version (original + patched) — so a full semantic check is up to 4 containers.
- `minimal_check()` (`:434`) reuses `_docker_test_argv` for the offline
  `node --check` pass — so it inherits any runtime change automatically.

**Runtime in use today:** none specified → Docker's default, **`runc`** (shared
host kernel). Confirmed: `grep` for `runtime`/`runsc`/`gvisor`/`FIXPACK_DOCKER`
in the module returns nothing (the only `runtime` hits are prose in a docstring
and a PR-note string).

**Ease of parameterizing:** trivial. `--runtime=<name>` is a standard
`docker run` flag consumed by the daemon; it needs no change to volumes,
network, proxy, hardening flags, images, or the install/test scripts. Because
both containers are built in these two functions and nowhere else, a single
shared helper that emits `--runtime=<X>` (or nothing) covers the entire
client-execution surface — including `minimal_check`, which routes through
`_docker_test_argv`. gVisor is a **per-container runtime**: `--network none`,
`--memory`, `-v`, `--cap-drop`, the proxy env, etc. all still apply unchanged.

### 2. gVisor (`runsc`) assessment

**Installation / operational complexity — low, one-time, host-side.**
gVisor ships as an `apt` package from Google's repo (or a single release
binary). Registering it as a Docker runtime is the documented flow:

```bash
# 1. install runsc (Google apt repo, or drop the release binary into /usr/bin)
apt-get install -y runsc            # provides /usr/bin/runsc

# 2. register it as a Docker runtime (idempotent; writes daemon.json)
runsc install                        # or hand-edit /etc/docker/daemon.json:
#   { "runtimes": { "runsc": { "path": "/usr/bin/runsc" } } }

# 3. reload the daemon
systemctl restart docker
```

Notes:
- `runc` stays the **default**; `runsc` becomes an *additional, opt-in* runtime.
  Existing containers (and everything else on the host) are unaffected.
- This is a config-management / provisioning step, **not** application code, and
  it is reversible (remove the runtime block, restart docker).
- One caveat worth flagging for the VPS: gVisor's default platform is `ptrace`
  when KVM is unavailable (which is our case — no `/dev/kvm`). `ptrace` mode
  works everywhere but is the slower of gVisor's two platforms; see overhead
  below. No KVM is required for gVisor to run — only for its faster platform.

**Compatibility with our install/test flow — expected to be fine.**
gVisor implements a large subset of the Linux syscall surface in user space.
Our workloads are ordinary and well within that subset:
- **Python `pip install --target` + `pytest`** — file I/O, process spawn,
  sockets to the proxy: all standard, all supported.
- **Node `npm install` + `npm test`** (jest / mocha / `node --test`) — same
  profile; Node and npm are explicitly among gVisor's regularly-tested
  workloads.
- **Egress-allowlist proxy via `host.docker.internal`** — this is plain TCP to a
  host-gateway address plus `HTTP(S)_PROXY` env vars; nothing runtime-specific.
  gVisor's netstack handles outbound TCP normally. (Worth including explicitly
  in the live smoke test, §5, since networking is the most runtime-sensitive
  area.)

Known gVisor limitations and whether they touch us:
- **Unimplemented / differently-emulated syscalls.** A minority of niche
  syscalls return `ENOSYS` or behave slightly differently. Our flow uses none of
  the exotic ones.
- **`ptrace`-heavy tooling** (native debuggers, some profilers, some sandbox-in-
  sandbox tricks) can misbehave under gVisor. **Not relevant** to `pip`/`npm`
  install or to a normal `pytest`/`npm test` run — but note a *client's own test
  suite* could in principle do something exotic. That is exactly why the change
  must be **opt-in and reversible** (§4) and why the decision rule already
  treats a *symmetric* infra failure as "could not verify," not "regression"
  (`run_suite` / `is_regression`): if gVisor broke both original and patched runs
  identically, we do **not** falsely block a Fix Pack.
- **Direct hardware / GPU / low-level `mount` access** — not in our flow.

**Overhead — negligible at our scale.**
Published gVisor overhead is workload-dependent: near-native for CPU-bound work,
higher for syscall/IO-heavy work (network and file syscalls cross the sandbox
boundary), and higher again on the `ptrace` platform we'd be on without KVM.
Realistic figure for `pip`/`npm` install + a test run: a **single-digit to
~20%** wall-clock increase, mostly during dependency install (IO-heavy).

Against our actual constraints this is immaterial:
- **Load:** `fixpack_jobs` shows **4 jobs total in a week (12–18 Jul 2026), all
  our own test runs, 0 real client jobs.** There is no throughput pressure for a
  20% per-job slowdown to matter.
- **Box:** 2 vCPU / 1.9 GB RAM / 2 GB swap. gVisor's `runsc` adds a modest
  resident-memory footprint per sandbox (the sandbox process itself). At our
  concurrency (effectively 1 job at a time) this fits; the existing
  `--memory 512m` cap and `--cpus 1` already bound each container. The Sentry
  runbook note: watch RSS on the first live `runsc` run, but this is not a
  capacity risk at 4 jobs/week.

### 3. Recommendation — land the capability now, gate it off; enable on first real traffic

Both sides, honestly weighed:

**Argument to enable now:** the marginal cost is close to zero. It is one extra
flag, gVisor is the *only* escape-hardening option this infra supports, and the
whole point of defence-in-depth against *unknown* escapes is that you cannot
predict the day you need it. Turning it on before any real client code runs
means the very first untrusted repo is already inside the stronger sandbox.

**Argument to defer:** at **0 real client jobs**, flipping gVisor on in prod
today hardens a threat surface **no attacker is on yet**, while adding a live
dependency (a host package + daemon config) that must stay healthy, plus a real
(if small) per-job overhead — arguably over-engineering ahead of demand.

**Resolution — do both, at the right layers:**
1. **Land the code now** as an **explicit, env-gated, default-off** capability
   (`FIXPACK_DOCKER_RUNTIME`, default `runc`). Merging this is safe and fully
   backwards-compatible: with the default unset, **byte-for-byte identical**
   `docker run` argv to today. Near-zero cost, unit-testable without Docker.
2. **Do the host install of `runsc` on the VPS** as a separate infra step
   (§4), also low-cost and reversible.
3. **Do NOT set `FIXPACK_DOCKER_RUNTIME=runsc` in prod** until the first real
   client Fix Pack is imminent (or immediately, at the operator's discretion —
   it is then a **one-variable flip**, no deploy of new logic).

This avoids the over-engineering trap (nothing forced on at 0 traffic) *and* the
scramble trap (no multi-day integration when traffic appears). The expensive
part was never the flag — it was validating compat and building the seam; we pay
that once, now, cheaply.

### 4. Minimal implementation plan (for Step 2, on approval)

**A. Infra (host, not code) — one-time, reversible:**
- Install `runsc` on the VPS and register the runtime in
  `/etc/docker/daemon.json` (`"runtimes": {"runsc": {"path": "/usr/bin/runsc"}}`),
  `systemctl restart docker`. `runc` remains default.
- No prod behaviour change from this step alone (nothing selects `runsc` yet).

**B. Code — `app/fixpack/semantic_check.py`, small and localized:**
- Add a tunable next to the others (near `MEMORY_LIMIT`, `:53`):
  ```py
  # Docker runtime for client containers. Default "runc" (standard). Set to
  # "runsc" (gVisor) for stronger escape isolation where the host has it
  # installed. Explicit + reversible: unset => identical behaviour to today.
  FIXPACK_DOCKER_RUNTIME = os.environ.get("FIXPACK_DOCKER_RUNTIME", "runc")
  ```
- Add a tiny helper:
  ```py
  def _runtime_argv() -> list[str]:
      rt = FIXPACK_DOCKER_RUNTIME
      # "runc" is Docker's default -> emit nothing, so argv is unchanged when
      # the feature is off (keeps existing tests exact).
      return ["--runtime", rt] if rt and rt != "runc" else []
  ```
- Splice `*_runtime_argv()` into **both** builders, right after `docker run`:
  - `_docker_install_argv` (`:327`) and `_docker_test_argv` (`:339`).
  - `minimal_check` inherits it automatically (it calls `_docker_test_argv`).

**C. Fallback / safety (the "explicit + reversible" requirement):**
- **Default `runc`** means: absent the env var, prod is unchanged and cannot be
  broken by this PR.
- **Explicit opt-in:** only an operator setting `FIXPACK_DOCKER_RUNTIME=runsc`
  activates gVisor — so enabling is a deliberate, logged config act, and
  disabling is deleting one variable.
- **Graceful degradation if `runsc` selected but absent on the host:** if the
  daemon rejects an unknown runtime, `docker run` exits non-zero *before*
  running client code. Because this failure is **symmetric** (it hits the
  original and patched runs identically), the existing `is_regression` logic
  already classifies it as "could not verify," **never** as a false regression —
  so a mis-set variable degrades to today's syntax-only path, it does not block
  legitimate Fix Packs or crash the pipeline. (Optional nicety, decide at Step 2:
  a one-time startup log-warn if `FIXPACK_DOCKER_RUNTIME=runsc` but
  `shutil.which("runsc")` is None — no hard failure.)
- **Env documentation:** add `FIXPACK_DOCKER_RUNTIME` to `.env.example` with the
  default and a one-line note.

**D. Tests (Step 2):** the subprocess seam (`_run`) is already mocked in
`tests/test_fixpack_semantic_check.py`; add cases asserting (a) default →
argv contains **no** `--runtime`, (b) `FIXPACK_DOCKER_RUNTIME=runsc` → argv
contains `--runtime runsc` in both builders. No Docker daemon needed for unit
tests.

### 5. Live testing required before merge/enable

Unit tests prove argv shape; they do **not** prove gVisor actually runs our
workloads. Before setting `FIXPACK_DOCKER_RUNTIME=runsc` in prod, run **on the
VPS** with `runsc` installed:

- [ ] `docker run --runtime=runsc --rm python:3.12-slim python -c "print('ok')"`
      and the Node equivalent — sanity that the runtime is registered and boots.
- [ ] **Install smoke, net-on-via-proxy:** a real install container with
      `--runtime=runsc` **plus** the egress-proxy flags, confirming `pip install`
      / `npm install` still reach the registries **through** the Squid allowlist
      (`host.docker.internal`) and nothing else — this is the most
      runtime-sensitive path.
- [ ] **Test smoke, net-off:** a real `--runtime=runsc --network none` container
      running `pytest` / `npm test` against persisted deps, confirming parsing
      and exit codes are unchanged.
- [ ] **Both existing session smoke scripts under gVisor:** run
      `/tmp/smoke_test.py` (Python) and `/tmp/smoke_test_node.py` (Node) on the
      VPS with the runtime enabled, and confirm identical pass/fail verdicts to
      the `runc` baseline (same jobs, both runtimes, diff the results).
- [ ] **Overhead sanity:** capture wall-clock for one full Python + one Node
      semantic check under `runc` vs `runsc`; confirm the increase is within the
      expected single-digit-to-~20% band and RSS stays under the box's headroom.

Only after all six pass on real Docker should the prod variable be flipped.

---

## 6. What this does and does not buy us (honest boundary)

- **Buys:** a second, independent kernel boundary. A container-escape exploit
  targeting `runc`/host-kernel syscalls hits gVisor's user-space kernel first;
  the attacker must additionally break *out of gVisor itself* to reach the host.
  Directly addresses the audit's "unknown Docker/kernel escape" risk that
  PR #40's in-namespace hardening cannot.
- **Does not buy:** immunity. gVisor has its own (smaller, different) attack
  surface and its own CVE history. It is defence-in-depth, not a guarantee — and
  it does **not** replace the PR #40 hardening or the egress proxy; it stacks on
  top of them.

---

## 7. Firecracker / Kata Containers — BLOCKED by current infrastructure

Documented for completeness; **not designed or planned here.**

**Why blocked now:** both Firecracker and Kata run each workload in a real
**microVM** with its own guest kernel, which requires hardware virtualization
via **KVM**. On the current Timeweb VPS:
- `lscpu` reports `Virtualization type: full` — the VPS is *itself* a guest VM
  at the provider.
- **`/dev/kvm` does not exist** — no nested-virtualization access is granted.

Without `/dev/kvm`, neither Firecracker nor Kata can start a microVM **at all**.
They are therefore **not a "now" option** on this infrastructure — no code or
config change on this box can enable them.

**What it would take to reconsider (future, separate decision):**
- Migrate Fix Pack execution to a host that exposes KVM: a provider offering
  **nested virtualization** (explicit `/dev/kvm` in the guest), or a
  **bare-metal / dedicated** instance.
- Then evaluate **Kata Containers** first (it is an OCI runtime, so it would slot
  into the *same* `--runtime` seam this plan builds for gVisor — `--runtime=kata`
  — making the migration path incremental) vs. **Firecracker** (lighter, but
  needs a jailer/orchestration layer such as firecracker-containerd, i.e. more
  integration work).
- Re-run the same live-smoke matrix (§5) on the new host before enabling.

The `FIXPACK_DOCKER_RUNTIME` seam introduced in §4 is deliberately generic: if a
KVM-capable host arrives later, pointing it at `kata` is the same one-variable
flip, no further code change — so building for gVisor now also de-risks a
possible microVM migration later.

---

## Summary of proposed changes (Step 2, pending approval)

| # | Change | Type | File(s) |
|---|--------|------|---------|
| 1 | `runsc` package + daemon.json runtime on VPS | infra (host) | `/etc/docker/daemon.json` |
| 2 | `FIXPACK_DOCKER_RUNTIME` env tunable (default `runc`) | code | `app/fixpack/semantic_check.py` |
| 3 | `_runtime_argv()` helper spliced into both docker-run builders | code | `app/fixpack/semantic_check.py` |
| 4 | Document env var | docs | `.env.example` |
| 5 | Unit tests for argv shape (on/off) | test | `tests/test_fixpack_semantic_check.py` |

**No implementation in this PR — recon + plan only.**
