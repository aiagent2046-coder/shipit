# Idempotent PR delivery — reconnaissance + plan

**Status: Step 1 (recon + plan) only. No implementation code in this PR.**
Awaiting review/approval before Step 2.

---

## TL;DR — the audit is right, and PR #46 makes it sharper

The external audit flagged: `open_pull_request()` in
`app/deploypack/delivery.py` creates commit → branch → PR with **no check for
an existing branch/PR** for the same job. If a retry re-runs the flow, a paying
client can get a **second PR for one payment.**

After reading the code, the reality is:

- The branch name is derived from **content**, not the job:
  `branch = f"{branch_prefix}-{commit_sha[:8]}"` (`delivery.py:133`). It is
  stable across retries **only** if every byte of every file is byte-identical
  on the re-run (the Git Data API is content-addressed, so identical inputs →
  identical `commit_sha`). Any non-determinism upstream (a regenerated
  timestamp, a reordered dict, an LLM-produced file that differs on retry) →
  **different `commit_sha` → different branch → a brand-new duplicate PR.**
- There is **no pre-flight lookup**: the function never asks GitHub "does a PR
  for this job already exist?" before creating commit/branch/PR.
- The **crash window** is the real hazard: `_process_one_paid_job`
  (`app/main.py:905`) calls the PR opener and only **afterwards**
  (`app/main.py:910`) writes `mark_fixpack_delivered`. If the process dies (or
  the network drops) **after GitHub created the PR but before the DB row flips
  to `delivered`**, the job is left `running`.

**PR #46 (the queue/reaper, in `git log` as the Phase-3 queue work) makes this
strictly more likely, not less.** Before #46 there was no retry at all; now the
reaper re-queues a stale `running` lease back to `paid` up to
`MAX_JOB_ATTEMPTS = 3` times (`app/main.py:269-270`), and the whole pipeline
(fetch → generate → semantic check → **open PR**) re-runs from scratch. If the
first attempt already opened a PR on GitHub, attempt #2 will almost certainly
open a second one. So the durability work we just shipped created a duplicate-PR
path that did not exist before — this plan closes it.

The genuine fix is **surgical**: make the branch name a function of the **job
id** (the only stable identifier across retries), and add a **single idempotent
pre-flight lookup** to `open_pull_request` that returns the existing PR instead
of creating a duplicate. No new tables, no new dependency.

---

## Step 1 — Reconnaissance (answers to the specific questions)

### 1. `open_pull_request()` and all callers

`open_pull_request(owner, repo, files, *, base_branch="main",
branch_prefix="shipit/deploy-pack", title=..., body="", token=None,
deletions=None, transport=None)` (`app/deploypack/delivery.py:62`).

Flow (all via the Git Data API, `httpx.Client`):

1. `GET /git/ref/heads/{base_branch}` → base_sha (`delivery.py:92`)
2. `GET /git/commits/{base_sha}` → base_tree_sha (`delivery.py:96`)
3. `POST /git/blobs` per file (`delivery.py:102`)
4. `POST /git/trees` (base_tree + entries; deletions are `sha: null`)
   (`delivery.py:119`)
5. `POST /git/commits` → `commit_sha` (`delivery.py:125`)
6. `branch = f"{branch_prefix}-{commit_sha[:8]}"` (`delivery.py:133`)
7. `POST /git/refs` creating `refs/heads/{branch}` (`delivery.py:134`)
8. `POST /pulls` head=branch base=base_branch (`delivery.py:140`)
9. returns `PullRequestResult(html_url, branch)`.

`_check()` (`delivery.py:149`) raises `DeliveryError` on any `status_code >= 300`.

**Two callers, both in `app/main.py`:**

- **Fix Pack flow (has retry):** `_process_one_paid_job` (`app/main.py:839`),
  driven by the queue in `process_paid_fixpacks` (`app/main.py:924`). Calls
  `pr_opener(owner, repo, plan.files, title=..., body=...,
  branch_prefix="drydock/fix-pack", deletions=plan.deletions, token=token)`
  (`app/main.py:905`), then `mark_fixpack_delivered(job_id, opened.html_url)`
  (`app/main.py:910`). `job_id = job["id"]` (`app/main.py:857`) — a persisted
  `fixpack_jobs` row (`status='paid'`), so **a stable job id is in hand before
  the PR is opened.**
- **Deploy Pack flow (no retry):** the `/v1/deploy-pack` handler
  (`app/main.py:1332-1355`). Calls `pr_opener(owner, repo, result["files"],
  body=body, token=token)` (default `branch_prefix="shipit/deploy-pack"`), then
  `mark_delivered(job_id, opened.html_url)` (`app/main.py:1355`). `job_id =
  persisted_job["id"]` (`app/main.py:1329`), i.e. also a persisted row — **but
  it is opened synchronously inside the HTTP request and is never retried by any
  reaper.** A client can, however, re-POST `/v1/deploy-pack` with the same repo,
  which today would open another PR. The design below covers it for free.

### 2. Existing DB-level protection against a duplicate call

`claim_one_paid` (`app/db.py:399`) uses `UPDATE ... WHERE id = (SELECT ... FOR
UPDATE SKIP LOCKED LIMIT 1)`, flipping `paid → running` atomically and bumping
`attempts`. This guarantees **exactly one worker processes a given job at one
time** — it defeats *concurrent* double-processing.

It does **not** defend the crash window: `claim → running → [open PR on GitHub]
→ 💥 crash before mark_fixpack_delivered`. The job stays `running`; the reaper
(`reap_stale_running`, `app/db.py:444`) later flips it back to `paid`
(attempts < 3) and the next `process_paid_fixpacks` run re-claims and
re-processes it from the top — including opening a PR again. **Nothing in the DB
records "a PR was already opened on GitHub for this job,"** so the second
attempt has no way to know. That is the gap.

`fixpack_jobs` already has `pr_url text` and `pr_delivered boolean`
(`migrations/0001`, columns confirmed at `app/db.py:352`) but they are only
written *after* success, so they are useless as a pre-open guard.

### 3. GitHub API behaviour on a name collision + what `_check` does today

- **`POST /git/refs` for a ref that already exists → `422 Unprocessable
  Entity`** (`{"message": "Reference already exists"}`). Today `_check(ref,
  "create branch")` turns that into `DeliveryError("create branch failed: 422
  ...")` → the attempt **fails** (does not silently duplicate). So *if the
  commit_sha happens to match* on retry, we currently crash on step 7 rather
  than make a dupe — noisy, but not a double PR.
- **If `commit_sha` differs on retry** (the realistic failure), step 7 gets a
  *new* branch name, `POST /git/refs` succeeds (201), `POST /pulls` succeeds
  (201) → **a second PR.** This is the path the fix must close.
- **`POST /pulls` when an open PR already exists for that head → `422`**
  (`{"message": "A pull request already exists for owner:branch"}`). Useful as a
  backstop, but we should not rely on parsing 422 strings; a positive pre-flight
  lookup is cleaner.

### 4. GitHub lookup primitive we will use

`GET /repos/{owner}/{repo}/pulls?head={owner}:{branch}&state=all` returns a JSON
array of PRs whose head is exactly that branch (empty array if none). It covers
open **and** already-merged/closed PRs (so a retry after a human merged the PR
does not reopen a new one). This is a single, cheap, read-only call and needs no
extra scope beyond what opening a PR already requires. (The Search API variant,
`GET /search/issues?q=...`, is eventually-consistent and rate-limited
separately — rejected in favour of the direct `pulls` list.)

---

## The core design decision: branch name keyed on job id, not content

Change the branch identifier from content-derived to **job-derived**, because
the job id is the *only* value that is provably stable across a retry:

```
branch = f"{branch_prefix}-{job_id}"        # stable across retries
# was: f"{branch_prefix}-{commit_sha[:8]}"  # stable only if bytes identical
```

`open_pull_request` does not currently receive the job id, so we thread it in as
a new optional keyword `job_id: str | None = None`. When provided, it becomes the
branch suffix and the idempotency key; when omitted, we fall back to the current
`commit_sha[:8]` behaviour (keeps any other/ future caller working).

Both existing callers already have a stable `job_id` in scope
(`app/main.py:857` and `app/main.py:1329`), so both get the guarantee.

---

## Idempotent flow inside `open_pull_request` (chosen minimal variant)

Insert **one pre-flight branch** at the top of the client block, only when a
`job_id` (→ deterministic branch name) is available:

```
branch = f"{branch_prefix}-{job_id}"   # deterministic when job_id given

# (A) Is there already a PR for this exact head? -> return it, create nothing.
existing = client.get(f"/repos/{owner}/{repo}/pulls",
                      params={"head": f"{owner}:{branch}", "state": "all"})
_check(existing, "look up existing pull request")
prs = existing.json()
if prs:
    pr = prs[0]
    return PullRequestResult(html_url=pr["html_url"], branch=branch)

# (B) No PR yet. Build commit/tree as before. Then create the ref, but
#     tolerate "already exists" (a prior attempt made the branch, then died
#     before opening the PR): treat 422 "Reference already exists" as OK and
#     continue to open the PR against the existing branch.
... blobs / tree / commit as today ...
ref = client.post(".../git/refs", json={"ref": f"refs/heads/{branch}", "sha": commit_sha})
if not (ref.status_code == 422 and "already exists" in ref.text.lower()):
    _check(ref, "create branch")

# (C) Open the PR against `branch` (head already points at our commit or the
#     prior attempt's commit). If GitHub still races us to a 422 "pull request
#     already exists", fall back to the (A) lookup and return that PR.
pr = client.post(".../pulls", json={...})
if pr.status_code == 422 and "already exists" in pr.text.lower():
    again = client.get(".../pulls", params={"head": f"{owner}:{branch}", "state": "all"})
    _check(again, "look up existing pull request after 422")
    return PullRequestResult(again.json()[0]["html_url"], branch)
_check(pr, "open pull request")
return PullRequestResult(pr.json()["html_url"], branch)
```

This is **Variant B (direct `pulls` lookup)** from the task, combined with the
**job-id branch name** and a small **422-tolerance** on the ref/PR steps to
cover the "branch exists but PR was never opened" sub-case (the crash-between-6-
and-8 window). No DB schema change is required, because the deterministic branch
name *is* the idempotency key and GitHub is the source of truth for "did a PR
already get created."

**Why not Variant A (a DB `opening_pr` intent column)?** It adds a migration and
still cannot be trusted alone: the authoritative fact ("a PR exists on GitHub")
lives on GitHub, and a DB row written *before* the GitHub call has the same
crash-window problem one level up. The GitHub pre-flight is the honest check.
The existing `pr_url`/`pr_delivered`/`mark_fixpack_delivered` write stays exactly
as-is — a fast-path/cache, not the guard.

### Behaviour matrix after the change

| State on retry | Old behaviour | New behaviour |
|---|---|---|
| Nothing exists (happy path) | create commit/branch/PR | identical: create commit/branch/PR |
| PR already open for job's branch | new dup PR (if sha differs) | (A) returns existing PR, **zero writes** |
| PR merged/closed for job's branch | new dup PR | (A) returns that PR, no reopen |
| Branch exists, no PR (crashed 6→8) | 422 on `git/refs`, hard fail | (B) tolerates 422, (C) opens PR to existing branch |
| Concurrent racer opens PR first | second 422 hard fail | (C) catches 422, returns racer's PR |

---

## Scope: both callers covered

- **Fix Pack** (`app/main.py:905`): pass `job_id=job_id`. This is the primary
  target — it is the flow the reaper retries.
- **Deploy Pack** (`app/main.py:1346`): pass `job_id=job_id` too. It has no
  reaper today, but the same call guards against a client re-POSTing
  `/v1/deploy-pack` for the same persisted job, and future-proofs it if a retry
  path is ever added. One-line change, no reason to leave it exposed.

`render_pr_body` and the token-resolution paths are untouched.

---

## Files to change (Step 2)

1. **`app/deploypack/delivery.py`** — add `job_id: str | None = None` kwarg;
   compute `branch` from `job_id` when present (else current `commit_sha[:8]`
   fallback); add the (A) pre-flight lookup, (B) 422-tolerant ref create, and
   (C) 422-tolerant PR open. ~25 lines, no signature break for existing kwargs.
2. **`app/main.py`** — two one-line additions: `job_id=job_id` at the Fix Pack
   call (`:905`) and the Deploy Pack call (`:1346`).
3. **`tests/test_deploypack_delivery.py`** — new tests (below). Existing tests
   keep passing unchanged: they call without `job_id`, exercising the fallback
   branch = `commit_sha[:8]` path (`test_open_pull_request_full_flow` still
   asserts `shipit/deploy-pack-commitsh`).

**No migration.** `fixpack_jobs` already stores `pr_url`; no new column needed.

---

## Test plan (httpx.MockTransport, no real GitHub)

Extend `make_handler` to record which endpoints were hit and to be
parameterisable on the `GET /pulls` lookup response, then add:

- **(a) branch + open PR already exist → returns existing PR, creates nothing.**
  `GET /pulls?head=owner:branch` returns a non-empty array. Assert the result
  `html_url` is the existing PR's, and assert **no** `POST` to `/git/blobs`,
  `/git/trees`, `/git/commits`, `/git/refs`, or `/pulls` was made (record
  method+path in the handler; assert the create endpoints are absent).
- **(b) branch exists but no PR yet → opens PR to existing branch without
  recreating the branch.** `GET /pulls` returns `[]`; `POST /git/refs` returns
  `422 {"message":"Reference already exists"}`; `POST /pulls` returns `201`.
  Assert success, assert the 422 did **not** raise, and assert commit/tree/blob
  were still built once (we can't know the branch is current without a commit).
- **(c) happy path, nothing exists → creates everything as before.** `GET
  /pulls` returns `[]`, all creates 201. Assert full create sequence ran and the
  branch is `f"{branch_prefix}-{job_id}"`.
- **(d) concurrent racer → `POST /pulls` returns `422 "A pull request already
  exists"`, fallback `GET /pulls` returns the racer's PR.** Assert we return the
  racer's `html_url` rather than raising.
- **(e) regression guard:** existing `test_open_pull_request_full_flow`
  (no `job_id`) still returns branch `shipit/deploy-pack-commitsh` — the
  content-hash fallback is untouched.
- **(f)** a Fix-Pack-shaped call (`branch_prefix="drydock/fix-pack",
  job_id="<uuid>"`) produces branch `drydock/fix-pack-<uuid>`.

Full suite (`pytest -q`) must stay green; the `_check` error-path tests are
unaffected (the new lookups reuse `_check`).

---

## Risks / notes

- **`GET /pulls?head=` needs `owner:branch`, not just `branch`** — easy to get
  wrong; the tests pin the exact query param.
- **Branch-name length:** a job UUID (36 chars) + prefix is well under GitHub's
  ref length limit; no truncation needed. (If we ever want it shorter we can use
  the uuid hex without dashes, but there is no need.)
- **422 string-matching** is a backstop only; the positive `GET /pulls`
  pre-flight is the primary guard, so a GitHub wording change degrades to
  "occasionally a hard-fail retry," never "a duplicate PR."
- **No behaviour change when `DATABASE_URL` is unset** — `job_id` still comes
  from the (possibly ephemeral `uuid4`) id the callers already compute; delivery
  itself never touches the DB.

---
🤖 *Generated by Computer*
