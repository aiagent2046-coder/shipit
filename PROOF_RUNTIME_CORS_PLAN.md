# Runtime CORS proof — plan

Status: **proposed, nothing built**. Written 2026-08-17, against `b9531c7`
(`v2026.08.17-8`), the release that shipped the static proof layer.

## What this changes about the claim

The three shipped templates are static scanners. `app/proof/render.py` says so
in every PR section, deliberately: "проверка статическая… атака не
выполняется". That wording is honest and it is also a ceiling — a regex hit is
evidence about the *text*, not about the *behaviour*.

A runtime template lifts that ceiling for one class: boot the customer's app,
send a real cross-origin request, read the real response headers. When the
oracle below fires, "атака сработала до патча и не сработала после" stops being
an overstatement and becomes a literal transcript, printable in the PR.

**Scope: CORS only.** SQLi, BOLA and secrets stay static. See "Not in scope".

## Why CORS is the one to do first

| | CORS | SQLi | BOLA |
|---|---|---|---|
| needs auth session | no | sometimes | **yes** |
| needs seeded data | no | usually | **yes** |
| needs endpoint discovery | no — middleware is global | yes | yes |
| oracle ambiguity | none — two headers | boolean/timing inference | needs two identities |

CORS middleware applies to every route in FastAPI/Express/Flask, so probing
`/` is enough — and `/` is already the path `verify_deploy_pack` polls to
decide the app booted. No discovery, no state, no identity. It is the only
class where the runtime probe is a few lines on top of a stand that exists.

## What already exists (and the one thing that does not)

Reusable as-is:

* `app/deploypack/sandbox.py::verify_deploy_pack(build_dir, host_port,
  container_port, path, …, keep_alive_on_success=True)` — real `docker build`
  + `docker run` + poll to HTTP 200, returns `SandboxResult(ok, detail,
  container, image_tag)`. `keep_alive_on_success=True` is exactly the hook a
  probe needs: it leaves the container up and hands back its name, and the
  caller owns teardown.
* Hardening already applied to that container: published port pinned to
  `127.0.0.1`, no-egress network, `--read-only`, non-root user. We are booting
  hostile code; this is why it must reuse this path rather than shell out
  anywhere else.
* `app/proof/` — registry, routing, gate, storage, render, artifacts all take a
  new template without changes. `ExploitAttempt.status` already distinguishes
  `success / failure / skipped / error`, and `error` is precisely "the stand
  did not come up".
* `app/sandbox_client.py` — the API process never touches docker directly; it
  posts to the runner service over a UDS.

**The gap.** The container publishes to `127.0.0.1` *on the runner host*. The
API process cannot reach it. So the probe cannot live API-side: it needs a new
runner endpoint next to `/deploypack/verify` and `/fixpack/run-suite`, e.g.

```
POST /proof/cors-probe   →  {before: AttemptJSON, after: AttemptJSON}
```

taking two zips (original, patched) and returning two attempts. Everything
docker-touching stays behind the privilege boundary that already exists.

## The oracle

One preflight and one actual request, from a fixed attacker origin:

```http
OPTIONS / HTTP/1.1
Origin: https://drydock-proof.invalid
Access-Control-Request-Method: GET

GET / HTTP/1.1
Origin: https://drydock-proof.invalid
```

`.invalid` is reserved by RFC 2606 and can never be a real customer origin, so
a reflection of it cannot be a legitimate allowlist entry.

**Exploit confirmed (`success`) iff both hold on the same response:**

1. `Access-Control-Allow-Origin` equals `https://drydock-proof.invalid`
   — i.e. the server *reflected* an origin it had never seen; and
2. `Access-Control-Allow-Credentials` is `true`.

Either alone is not a finding: reflection without credentials exposes only
what an anonymous caller could already read, and credentials with a correctly
pinned origin is normal operation.

**Corrected while implementing P0 (2026-08-17).** This section first read
"reflection **or** literally `*`". The `*` half is wrong: per the Fetch
standard a browser rejects `Access-Control-Allow-Origin: *` outright when the
request's credentials mode is `include`, so no page ever reads a private
response that way. Reporting it as a confirmed exploit would have printed
"атака сработала" over an attack that cannot happen — the same overstatement
the preceding release removed from the static templates. `*` with credentials
is now reported as a real misconfiguration that is **not** exploitable
(`wildcard_with_credentials_blocked_by_browser`), and only reflection earns
`exploitable=True`. Implemented and mutation-tested in
`app/proof/cors_oracle.py` / `tests/test_proof_cors_oracle.py`.

Evidence recorded: the two header values verbatim, the status code, and the
request line. No bodies — a body from a customer's app can contain their data.

## Algorithm

```
preflight   is the repo buildable at all?  (Dockerfile or generated Deploy Pack)
            no  → skipped, static template's report stands, PR unchanged
 1 BUILD    original zip   → verify_deploy_pack(keep_alive_on_success=True)
 2 PROBE    OPTIONS + GET  → oracle → attempt_before
 3 TEARDOWN stop container, drop image
 4 PATCH    apply_plan_to_zip(original, plan.files, plan.deletions)   (exists)
 5 BUILD    patched zip    → verify_deploy_pack(keep_alive_on_success=True)
 6 PROBE    identical request → oracle → attempt_after
 7 TEARDOWN
 8 COMPARE  build_proof_report(before, after)                          (exists)
```

Steps 4 and 8 are already written and used by the static path.

## Status mapping — the part that decides whether this is honest

This is where the feature can quietly become the defect the project has fixed
three times (#22, #27, #35). The rule:

| Situation | status | What the PR may say |
|---|---|---|
| oracle fired | `success` | "запрос с чужого origin вернул заголовки, дающие доступ" |
| app booted, oracle did not fire | `failure` | "проба не подтвердила" — **never** "уязвимости нет" |
| build failed / never returned 200 | `error` | "стенд не поднялся, проверка не выполнялась" |
| no Dockerfile, unsupported stack | `skipped` | section falls back to the static template |

`error` and `skipped` **must not** read as safety, and per `app/proof/gate.py`
neither blocks delivery (fail-open) — that is already the gate's behaviour and
must stay.

A runtime `failure` also must not overwrite a static `success`. If the scanner
found an open-CORS pattern and the runtime probe did not reproduce it, both go
in the report: the code says one thing, the running app another, and that
disagreement is information the reader needs — not a reason to publish the
quieter of the two.

## What the PR shows when it fires

Same section, one stronger sentence and a transcript:

```
## Проверка «до / после»
Шаблон: cors_open (runtime)
Вердикт: подтверждён — запрос с постороннего origin получил доступ до
патча и не получает после

| | До патча | После патча |
| Кросс-доменный запрос | ⚠️ доступ разрешён | ✅ отклонён |

До:    Access-Control-Allow-Origin: https://drydock-proof.invalid
       Access-Control-Allow-Credentials: true
После: Access-Control-Allow-Origin: (отсутствует)
```

The `_METHOD_NOTE` in `render.py` is static-specific and must be swapped for a
runtime one on these reports — "приложение поднято в изолированной песочнице,
запрос выполнен реально" — rather than deleted.

## Cost and limits

* Two `docker build` + two boots per proofed job. Minutes and real CPU, against
  seconds today. The runner is shared with Deploy Pack verification and Fix Pack
  suites, so this competes with them — needs a concurrency cap and a per-job
  timeout, not an open queue.
* Only worth attempting when the static `cors_open` template already hit **and**
  the plan touches the file it hit (existing `routing.py` logic). Never a
  blanket runtime pass over every repo.
* Expected yield is the honest unknown: vibe-coded repos frequently do not build
  without `.env`, migrations or seeds. First milestone is a *measurement* — on
  the batch corpus, what share reach step 2 at all.

## Safety

Non-negotiable, all already true of `verify_deploy_pack` and to be asserted by
test rather than assumed: loopback-only publish, no-egress network, read-only
rootfs, non-root user, memory limit, hard timeout, teardown in `finally` on
every path including probe failure. The probe adds one rule of its own: it
sends requests **only** to `127.0.0.1:<published port>`, never to a host the
repository names — otherwise a malicious repo turns the runner into an SSRF
relay.

## Testing

Docker cannot run in unit tests, so:

* oracle logic — pure function over a header dict; table-driven cases (`*` +
  credentials, reflection + credentials, `*` alone, correct origin +
  credentials, missing headers). No docker.
* orchestration — fake runner client returning canned attempts; asserts the
  status mapping table above, especially that "did not boot" is `error` and not
  `failure`.
* one real end-to-end behind the existing docker marker (like
  `scripts/e2e_fixpack_run_suite.py`), run by hand and in the e2e workflow, on
  a fixture app with a deliberately open CORS config.
* a mutation check that the oracle can actually reject: flip it to always return
  `success` and confirm the suite goes red.

## Phasing

1. **P0 — oracle. DONE 2026-08-17.** `app/proof/cors_oracle.py`: pure
   function over response headers, seven-case table, five mutants killed
   (including one that restores this plan's original wildcard bug). Not
   registered in `app/proof/registry.py` — a template id in the registry is a
   capability the product claims, and nothing is behind this one until P1.

   The fixture app that this phase originally carried moved to P1: it exists
   only to be booted, so until the runner endpoint can boot it, it would be
   dead code that rots. Real framework header sets are covered in the table
   instead (Starlette lowercase, Express title-case, padded values).
2. **P1 — runner endpoint. DONE 2026-08-17.** `app/proof/cors_probe.py`
   (boot → probe → judge → teardown, injectable `verify`/`fetch`/`stop`),
   `POST /proof/cors-probe` on the runner, `sandbox_client.run_cors_probe`,
   and `cors_open_runtime` added to the stored template-id contract.
   15 tests, 4 mutants killed: boot-failure downgraded to `failure`, every
   app reported exploitable, teardown removed, probe leaving loopback.

   **Deviation:** one workspace per call, not both zips in one request. Single
   zip body like `/deploypack/verify`, an independent timeout per boot, and
   the comparison stays in `compare.py` where the static path already does it.
   The caller runs it twice.

   Still open before this can run for real: nothing calls it yet (that is P2),
   and the docker end-to-end has not been executed — this environment has no
   docker, so every test here drives injected doubles. The first real boot is
   P2's first task and may well find something these cannot.
3. **P2 — wiring. CODE COMPLETE 2026-08-17, UNVERIFIED AGAINST DOCKER.**
   `app/proof/runtime_cors.py` decides applicability, `stage.py` runs the two
   probes and **appends** the runtime report beside the static one,
   `render.py` gives runtime reports their own verdict wording, row label,
   cells and method note (plus the header transcript in the details), and
   both proof flags are documented in `.env.example`.

   Gated four ways, each a reason not to boot: `PROOF_RUNTIME_CORS` **off by
   default**, the static `cors_open` must have fired (which already implies
   the plan touches its file — see `routing.py`), and the workspace must
   carry a root `Dockerfile`. 20 tests, 4 mutants killed: runtime replacing
   the static report, the flag defaulting on, booting without a Dockerfile,
   booting when the scanner found nothing.

   **First real boot: 2026-08-17, and it falsified an assumption — exactly
   the sentence above, which turned out to be right about the risk and even
   about the example.** Both containers built, answered `HTTP 200 on /`, were
   probed and torn down: the infrastructure works end to end. But the
   deliberately vulnerable app came back **not exploitable**. It answered a
   bare `*`, because Starlette 0.40 (what `fastapi==0.115.0` pulls) reflects
   the caller's Origin only `if self.allow_all_origins and has_cookie` — and
   the probe was sending no Cookie. Starlette 1.6 keys the same branch off
   `allow_credentials`, so two versions of one framework disagree about an
   identical application.

   The oracle was right and the probe was wrong: this template's claim is
   about CREDENTIALED cross-origin reads, and a request carrying no
   credential cannot demonstrate one. Uncorrected it would have
   systematically **under-reported** — an app a real browser session could
   read cross-origin, filed as safe. This plan specified `Cookie:
   session=<любой>` in the oracle section and the implementation dropped it;
   nothing but a real container could have caught that. Fixed via
   `PROBE_COOKIE` in `app/proof/cors_probe.py`, pinned by test.

   Also worth recording, because it is a deploy fact nobody had written down:
   the sandbox runner is a **separate deployment** (`/opt/shipit-runner`, its
   own clone, venv and `sandbox-runner.service`), and
   `deploy/scripts/deploy-production.sh` never touches it. The first attempt
   returned `404 Not Found` from `/proof/cors-probe` because the backend was
   on the new release and the runner was still running August 6th's code.
   Any release that changes runner-side code needs that clone updated and the
   unit restarted, by hand.

   **What remains:**
   * a re-run of `scripts/e2e_proof_cors_probe.py` with the cookie fix, to see
     the vulnerable app come back `success` and the patched one `failure`.
     Until that has been observed, the probe's positive path is still
     unproven — the first boot proved only that the negative paths and the
     infrastructure work.
   * the corpus yield measurement: of repositories where the static scanner
     hits, what share carry a root Dockerfile and actually boot. Until that
     number exists, nothing about "we run the attack" goes into marketing.

## Not in scope

* SQLi and BOLA runtime probes — need endpoint discovery, seeded state and an
  identity model. Different plan.
* "Live" secret validation (calling Stripe with a customer's key to see whether
  it is active). That is a request to a third party using someone else's
  credential, with legal and rate-limit consequences; it is a product decision,
  not a template.
* Any claim in marketing that the product "runs the attack" before P2 has been
  measured on real repositories.
