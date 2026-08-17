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

   **VERIFIED 2026-08-17, against real containers.** With the cookie fix on
   the runner, `scripts/e2e_proof_cors_probe.py` passes:

   ```
   [1/2] vulnerable  status: success   reason: credentialed_reflection
         allow_origin: https://drydock-proof.invalid   allow_credentials: true
   [2/2] patched     status: failure   reason: no_cors_headers
         allow_origin: None
   OK: reproduced before the fix, refused after it.
   ```

   That is the whole chain proven end to end: build → boot → real
   cross-origin credentialed request → oracle → teardown, on both
   workspaces, through the runner's socket. For this class the product can
   now say "the attack worked before the patch and does not after" and mean
   it literally.

   It took three runs to get there, and each failure was worth its cost: the
   first 404'd because the runner is a separate deployment, the second
   under-reported because the probe sent no credential, the third passed. Two
   of those three could only ever have been caught by a real boot.

   **Corpus yield, measured 2026-08-17 — and it is the finding that decides
   what this feature is.** `scripts/measure_runtime_cors_yield.py` over nine
   pinned repositories:

   | stage | count |
   |---|---|
   | repositories | 9 |
   | static `cors_open` fired | **1 (11%)** |
   | …and self-buildable | 0 |
   | …and booted | 0 |
   | …runtime reproduced | **0** |

   **End-to-end yield: 0 of 9.**

   The binding constraint is NOT the Dockerfile gate, which is what this plan
   expected. It is the trigger: eight of nine repositories have no
   credentialed-open-CORS shape at all, so the runtime probe would never be
   considered for them. Removing the Dockerfile gate entirely would raise the
   ceiling to 1 in 9.

   And the scanner is not blind — it is right. `blank-slate` ships Supabase
   edge functions answering `Access-Control-Allow-Origin: *`, with no
   credentials; that is a public API, not a hole, and the template correctly
   says nothing. The shape we can prove is genuinely rare in this market:
   these are SPA exports that either carry no server CORS configuration or
   use a platform's default.

   **Conclusion: keep it, leave it off, do not market it.** The capability is
   real and proven end to end, and it applies to approximately none of the
   current customer base. That is worth knowing after a day of work rather
   than after a launch — and it is the second time this measurement habit has
   changed a decision rather than confirming one.

   Explicitly NOT recommended: loosening the Dockerfile gate. Half a day of
   work to move a ceiling from 0/9 to at most 1/9, and it would reintroduce
   the ambiguity between "the customer's app did not come up" and "our
   generated Dockerfile is wrong".

   Caveat on the number: n=9, one market segment, chosen in July for a
   different purpose. It says this corpus, not the universe. A customer base
   with real backends would measure differently — and the script is pinned
   and repeatable, so re-running it against a better corpus is minutes.

### Second corpus, and a correction to the conclusion above

The obvious objection to 0/9 — "that corpus is SPA exports, a real backend
would measure differently" — was tested the same day against ten
server-side applications chosen by structure, not by their CORS config:
`full-stack-fastapi-template`, `LibreChat`, `chainlit`, `Flowise`,
`AgentGPT`, `private-gpt`, `chatbot-ui`, `documenso`, `formbricks`,
`langfuse`. Seven of the ten ship a Dockerfile.

**Static hits: 0 of 10.** Across both corpora: 19 repositories, one hit.

But reading that as "the vulnerability is rare" — which is what the section
above concluded — is only half right, and the other half matters more.
Three of the ten were opened by hand to see WHY they did not match:

* **Flowise** — `cors(getCorsOptions())`, a function returning a runtime
  callback. It also sets `credentials = false` whenever the origin list is
  `*`, i.e. it already defends against precisely the shape we look for.
* **LibreChat** — `app.use(cors())`, bare defaults, no literal anywhere.
* **documenso** — a local helper with an `OriginFn` type and `origin: '*'`
  as its default.

None of those is matchable by a regex over source text, and that is not a
gap in our patterns — it is a property of how real backends configure CORS:
through function calls, env-driven allowlists and per-route logic. On such a
repository `static_hit=False` does not mean "safe". It means **"cannot be
determined statically"** — which is exactly the question a runtime probe
exists to answer.

**So the gate is backwards for the population that needs it most.** The only
method that can judge a dynamically configured application is gated behind a
static hit that structurally cannot happen for one. The measurement was set
up to ask "how often does the runtime probe add proof?" and answered a
better question: "the static trigger and the runtime prover see disjoint
populations."

Two honest options, neither taken here:

1. **Leave it.** Runtime stays a prover for the rare literal case; measured
   yield ~0. Costs nothing, claims nothing.
2. **Let the probe run as a DETECTOR** — on any bootable repository,
   independent of a static hit. It is the only way to judge dynamic
   configuration, and it turns a 0%-yield prover into something that can
   find what the scanner cannot see. Costs two container builds per
   qualifying job, and needs its own measurement first: of repositories that
   ship a Dockerfile, how many actually boot and answer? Seven of the ten
   above are candidates for exactly that experiment, and none of it should be
   built before that number exists.

What must NOT be said either way: that 19 repositories were checked and
found clean. Nineteen were checked by a method that cannot read the
configuration most of them use.
   * the corpus yield measurement: of repositories where the static scanner
     hits, what share carry a root Dockerfile and actually boot. Until that
     number exists, nothing about "we run the attack" goes into marketing.

### Detector-mode boot measurement — and what the zero actually measures

The detector experiment above needed one number before anything is built on
it: of the seven Dockerfile-shipping backends, how many actually **boot** on
our stand. That is the applicability ceiling — the probe can say nothing about
a repository it cannot start.

The first two rows (2026-08-17, `DETECTOR=1`) came back 0-booted, and the
diagnostics channel (`app/proof/cors_probe.py`, added the same day) says why —
which is the whole reason it exists, because "docker build failed" is not a
diagnosis:

* **full-stack-fastapi-template** — no *root* Dockerfile (components only);
  correctly `skipped_no_dockerfile` in 1.1s, never handed to the runner. This
  is the `has_root_dockerfile` wrapper fix doing its job.
* **LibreChat** — root Dockerfile, `EXPOSE 3080`, handed to the runner, build
  failed at **step 2 of 31**: `RUN apk upgrade --no-cache` →
  `HTTP 403: Forbidden` fetching `dl-cdn.alpinelinux.org`.

That 403 is not LibreChat's. It is **our stand's egress-allowlist proxy**
(`DEPLOYPACK_BUILD_PROXY_URL` → host Squid) refusing the Alpine package CDN:
the build container's `HTTP(S)_PROXY` build-args point every fetch at the
allowlist proxy, and `dl-cdn.alpinelinux.org` is not on the allowlist, so
Squid returns 403 and `apk` aborts (`--force-missing-repositories` cannot
help — the repo is reachable, the proxy is refusing it). The earlier
hypothesis was right in shape (a package-install `RUN` hitting the host egress
policy) and wrong in the specific line (`apk upgrade`, step 2, not the first
`pip`/`npm`).

**So the detector `error` rows are currently measuring the Squid allowlist's
coverage, not any application's CORS posture.** 0-booted here does NOT mean
"these apps don't reproduce" and does NOT mean "these apps are safe" — it means
the stand could not build them because their base images upgrade OS packages
against registries the proxy does not permit. The end-to-end yield line stays
honest precisely because it counts `booted` separately: 0 booted ⇒ the runtime
half has said nothing at all.

**The decision this surfaced, and what it turned out to cost.** To make
detector-mode measure applications rather than our proxy, the build allowlist
has to admit the OS registries these Dockerfiles use. That looks like widening
the surface the allowlist exists to bound — so it was written up as the user's
call, and taken deliberately (option A, 2026-08-17).

Reading the code to price it changed the price. `docker build` in
`app/deploypack/sandbox.py` gets **no `--network` flag**: the proxy reaches it
only as `HTTP_PROXY`/`HTTPS_PROXY` build-args, which bind apk/apt/pip/npm/curl
and nothing else. A build step that opens a raw socket, or any tool that
ignores proxy env, already reaches the open internet. So for the build step the
allowlist is a **convention, not a boundary**, and adding domains to it does
not widen what a hostile Dockerfile can reach — it only decides whether honest
customer code builds at all. (The run-time container is genuinely isolated:
`--network shipit-preview` plus a host iptables DROP. Different mechanism,
actually enforced.)

Two things follow, and both are now in the tree:

* `deploy/sandbox-runner/squid-build-allowlist.conf` — the list, in the repo,
  reviewable, with the OS registries added and `files.pythonhosted.org`
  alongside `pypi.org` (pip resolves metadata at the latter and downloads
  wheels from the former; a list with only `pypi.org` fails every pip build at
  the download step — worth checking the host list for exactly that). Guarded
  by `tests/test_build_allowlist.py`, which fails on a bare-TLD entry, on a
  quietly-added `github.com`, and on the loss of the Alpine entry.
* The enforcement gap is written down rather than fixed: real build-step egress
  control needs `docker build --network` on an isolated network, a separate
  change with its own breakage risk. **Nothing may describe this allowlist as
  what contains a malicious Dockerfile.**

Until the measurement is re-run against a host carrying this list, the detector
number remains **not a fact about real backends**, and nothing about
detector-mode reach goes into marketing.

## Not in scope

* SQLi and BOLA runtime probes — need endpoint discovery, seeded state and an
  identity model. Different plan.
* "Live" secret validation (calling Stripe with a customer's key to see whether
  it is active). That is a request to a third party using someone else's
  credential, with legal and rate-limit consequences; it is a product decision,
  not a template.
* Any claim in marketing that the product "runs the attack" before P2 has been
  measured on real repositories.
