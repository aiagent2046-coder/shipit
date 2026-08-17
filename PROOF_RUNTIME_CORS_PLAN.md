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
   (reflection) **or** is literally `*`; and
2. `Access-Control-Allow-Credentials` is `true`.

Either alone is not a finding: `*` without credentials is a public API, and
credentials with a correctly pinned origin is normal. It is the pair that lets
a page on any origin read authenticated responses.

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

1. **P0 — oracle + fixture app.** Pure function, table tests, a two-file
   FastAPI fixture with `allow_origins=["*"], allow_credentials=True`. No
   docker, no runner. Proves the decision logic before spending an hour on
   infrastructure.
2. **P1 — runner endpoint.** `/proof/cors-probe`, both boots, teardown,
   `SandboxResult` → `ExploitAttempt` mapping, status table enforced.
3. **P2 — wire into routing.** Runtime attempt tried only when static
   `cors_open` fired and the plan touches its file; on `skipped`/`error` the
   static report stands. Measure yield on the batch corpus before promising
   anything externally.

## Not in scope

* SQLi and BOLA runtime probes — need endpoint discovery, seeded state and an
  identity model. Different plan.
* "Live" secret validation (calling Stripe with a customer's key to see whether
  it is active). That is a request to a third party using someone else's
  credential, with legal and rate-limit consequences; it is a product decision,
  not a template.
* Any claim in marketing that the product "runs the attack" before P2 has been
  measured on real repositories.
