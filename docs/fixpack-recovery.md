# Recover a paid Fix Pack or its missing full review

These are two separate operator actions on an existing purchase:

| Current problem | Tool | Effect of `--apply` |
| --- | --- | --- |
| A diagnosed `secrets_leak` hard proof failure blocked an undelivered Fix Pack | `scripts/requeue_blocked_fixpack.py` | Archive the failure and return the same job to `paid` |
| A Fix Pack was delivered, but its PR lacks the full review included in the purchase | `scripts/recover_fixpack_review.py` | Run or reuse the full audit of the original source and save its private ownership link |

Run these commands in a root Bash shell on the production host. Use the active
release's Python and scripts after deploying the reviewed recovery tools. If
running a reviewed copy outside the release, keep both Python scripts together
and set `SHIPIT_TOOLS` to that directory. Application imports still come from
the pinned active release.

Both tools default to diagnosis: they read the database, health endpoints and,
for review recovery, public GitHub data. They make no LLM calls or database
changes without `--apply`. The CLI may create local lock files and a protected
diagnostic log even in this mode.

## Pin the release and identify the existing purchase

Replace every placeholder below. `SHIPIT_REV` is the full lowercase commit SHA
from the successful production deployment you intend to use. It is not a tag,
the current GitHub `main`, or an automatically accepted value from a moving
symlink. The job, audit and payment UUIDs must identify the same purchase.

```bash
SHIPIT_REV='REPLACE_WITH_FULL_DEPLOYED_RELEASE_SHA'
SHIPIT_JOB_ID='REPLACE_WITH_FIXPACK_JOB_UUID'
SHIPIT_AUDIT_ID='REPLACE_WITH_ORIGINAL_AUDIT_UUID'
SHIPIT_PAYMENT_ID='REPLACE_WITH_COMPLETED_PAYMENT_UUID'
SHIPIT_PY='/srv/shipit/current/.venv/bin/python'
SHIPIT_TOOLS='/srv/shipit/current/scripts'

SHIPIT_ORDER_ARGS=(
  --expected-release "$SHIPIT_REV"
  --job-id "$SHIPIT_JOB_ID"
  --audit-id "$SHIPIT_AUDIT_ID"
  --payment-id "$SHIPIT_PAYMENT_ID"
)
```

Every invocation checks `/srv/shipit/current`, local and public `/version`, and
local and public `/readyz`. The APIs must report the pinned production release
and a ready database. The running API's `PROOF_GATE_MODE` must be `hard`.
Credentials come from `/opt/shipit/.env` through the deployment parser; do not
copy its values into commands. The deployment lock prevents a standard deploy
or rollback from switching releases during recovery.

The payment must be completed and unrefunded, with matching `product`,
`fixpack_job_id` and `audit_id`. A refusal is a diagnosis to resolve; neither
tool requires resetting payment state or weakening a verification gate.

## Requeue a blocked secrets proof failure

Use this only after deploying the reviewed correction for the diagnosed
failure. The saved proof must be a non-informational, unverified `secrets_leak`
proof with successful exploit execution before and after the patch, and the
job's detail must record a hard proof gate block. There must be no delivered
PR and no other paid/running job for the audit.

Set `SHIPIT_ATTEMPTS` to the attempt count recorded in that diagnosis. Do not
increase it merely to make a later, different failure pass the guard. The
script preserves the counter; the normal processor increments it when claiming
the queued job.

```bash
SHIPIT_ATTEMPTS='REPLACE_WITH_DIAGNOSED_ATTEMPT_COUNT'
SHIPIT_REQUEUE_ARGS=(
  "${SHIPIT_ORDER_ARGS[@]}"
  --expected-attempts "$SHIPIT_ATTEMPTS"
)

"$SHIPIT_PY" "$SHIPIT_TOOLS/requeue_blocked_fixpack.py" \
  "${SHIPIT_REQUEUE_ARGS[@]}"
```

`state: eligible` with `changed: false` is a successful diagnosis. Apply that
same request with:

```bash
"$SHIPIT_PY" "$SHIPIT_TOOLS/requeue_blocked_fixpack.py" \
  "${SHIPIT_REQUEUE_ARGS[@]}" --apply
```

| Result | Meaning and next action |
| --- | --- |
| `requeued`, `changed: true` | The transaction committed. The normal timer can process the job. |
| `already_processed_or_queued`, `changed: false` | The job is already `paid`, `running` or `delivered`. Inspect its current state; this result does not assert delivery. |
| Processor busy, exit 1 | A normal Fix Pack run owns the processor lock. Let it finish, then retry the same request. |
| Other refusal or error, exit 1 | No success is confirmed. Rerun diagnosis and inspect the reported precondition. |

After `requeued`, an immediate normal processor run can be requested with:

```bash
systemctl start --no-block shipit-fixpack.service
```

The start command is asynchronous and the processor handles the paid queue,
not exclusively this job. Use the job ID to follow its outcome:

```bash
journalctl -u shipit.service --since '30 minutes ago' \
  --no-pager -o cat --grep="$SHIPIT_JOB_ID"
```

The old job and payment evidence is archived under `/root/shipit-recovery/`
before the guarded update. The directory is root-owned mode `0700`; evidence
files are mode `0600`. An archive alone is not proof that the transaction
committed. No payment, new job, funding key or attempt counter is written by
the recovery tool.

## Recover a missing full review for a delivered Fix Pack

The job must already be `delivered`, with a recorded PR in the original
repository and the expected `drydock/fix-pack-<job UUID>` branch. The tool
refuses a PR that already contains the `Your full review` section.

`SHIPIT_SOURCE_REV` is the full SHA of the **original source audited when the
Fix Pack was generated**. It may differ from `SHIPIT_REV`. It is not the Fix
Pack branch's patched head and should not be replaced with the repository's
latest commit. The tool downloads that exact revision, validates the archive,
then matches it against saved proof paths or an incomplete review with the
same content hash and repository created since the job started.

```bash
SHIPIT_SOURCE_REV='REPLACE_WITH_FULL_ORIGINAL_SOURCE_SHA'
SHIPIT_REVIEW_ARGS=(
  "${SHIPIT_ORDER_ARGS[@]}"
  --source-revision "$SHIPIT_SOURCE_REV"
)

"$SHIPIT_PY" "$SHIPIT_TOOLS/recover_fixpack_review.py" \
  "${SHIPIT_REVIEW_ARGS[@]}"
```

After `state: eligible`, run:

```bash
"$SHIPIT_PY" "$SHIPIT_TOOLS/recover_fixpack_review.py" \
  "${SHIPIT_REVIEW_ARGS[@]}" --apply
```

This uses the active engine, LLM configuration and normal usage accounting.
It can incur provider charges. A matching completed full analysis is reused;
an unfinished included free preview is retried without rerunning that full
analysis. A failed or partial analysis may need new LLM work on a later retry.
Same-job recovery is serialized on this production host. There is no promise
of exactly one provider charge across an interruption before audit persistence.

| Result | Meaning and next action |
| --- | --- |
| `full_review_ready`, exit 0 | The saved audit has `basis: static+llm` and the included free baseline is completed. Read its private result file. |
| `review_incomplete`, exit 2 | A result was saved, but full analysis or the included baseline is incomplete. Inspect `basis`, `free_baseline_status` and the private log; resolve the cause before retrying the same request. |
| Refusal or error, exit 1 | Read the reason and rerun diagnosis. The Fix Pack and payment remain unchanged; an interrupted pipeline may already have saved an audit that a retry can reuse. |

`full_review_ready` describes the full analysis and included preview. It does
not assert that every file or optional stage was examined. Read the report's
manifest and limitations. With dependency scanning integrated, this internal
recovery path has no account context and does not initiate a new OSV lookup;
an existing cached dependency inventory is preserved when its analysis is
reused. Production must have the migrations required by its deployed release,
including migration `0039` for the dependency stage.

The summary prints `private_result_file` and `log_file`, but excludes the
ownership token. Files live under `/root/shipit-review-recovery/`, with directory
mode `0700` and file mode `0600`. To retrieve the link in the private operator
terminal after `full_review_ready`:

```bash
"$SHIPIT_PY" - "$SHIPIT_JOB_ID" <<'PY'
import json
from pathlib import Path
import sys
from uuid import UUID

job_id = str(UUID(sys.argv[1]))
path = Path('/root/shipit-review-recovery') / f'{job_id}-review.json'
result = json.loads(path.read_text())
if result.get('state') != 'full_review_ready':
    raise SystemExit('The saved review is not ready.')
print(result['report_url'])
PY
```

Deliver that ownership link to the buyer through the private support channel.
Do not paste it into a public PR, issue or log. The tool does not send a
message, edit the PR, create another Fix Pack or charge the buyer again.
