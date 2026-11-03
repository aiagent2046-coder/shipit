# Known exploitation context in Drydock

Drydock correlates existing dependency findings with a pinned CISA Known Exploited
Vulnerabilities (KEV) snapshot. The result is separate `threat_context` evidence in the
project-check report. It identifies CVEs for expedited remediation review; it does not
create another vulnerability finding or alter severity, confidence, readiness scores,
reachability claims or automatic-patch eligibility.

For example, a resolved package/version can already match CVE-X through CVE/GHSA/OSV.
If CVE-X is in the pinned KEV snapshot, Drydock records the known-exploitation context,
its source and the affected dependency finding references. Multiple references to the
same CVE produce one context row. A package name, advisory title, source comment,
Ghidra symbol or a substring resembling a CVE cannot create a match.

Known exploitation elsewhere does not establish exploitation of the audited project.
An absent KEV entry does not establish safety or prove that exploitation has never occurred.
CISA's required action and due date are labelled source context; the due date is not
automatically assigned as the project's deadline.

## Provenance and deterministic rebuilding

The official input is [`cisagov/kev-data`](https://github.com/cisagov/kev-data), CISA's
public mirror of its KEV data, distributed under CC0. The compiler reads
`known_exploited_vulnerabilities.json` from a pinned regular Git blob, not mutable
worktree bytes. It executes no code, hooks or packages from the upstream checkout.

The committed files are:

- `app/data/kev-catalog.json`: canonical JSON with sorted CVE keys and only the fields
  needed by the priority mechanism.
- `app/data/kev-catalog.json.sha256`: SHA-256 of the exact compiled bytes.

The snapshot retains the official repository URL, full source commit, source commit
timestamp, original upstream blob SHA-256, upstream catalog version and publication time.
It uses no wall-clock build timestamp. The commit timestamp is not described as a fetch
time or a statement that CISA reviewed every entry on that day.

To reproduce a recorded snapshot:

```bash
git clone https://github.com/cisagov/kev-data.git /tmp/kev-source
# Read this exact commit from the recorded snapshot's source.commit.
git -C /tmp/kev-source checkout --detach SOURCE_COMMIT
python scripts/build_kev_catalog.py --source /tmp/kev-source --check
```

`--check` rebuilds and compares both generated files without writing them. Omit it to
replace both files from the selected clean official checkout. Rebuilding twice from
the same commit must produce identical bytes. Full replacement preserves upstream
corrections and removals. An unknown schema, duplicate identifier/key, malformed field,
excessive input or unexpected executable/symlink input stops compilation before output
replacement. A runtime checksum or schema failure becomes `unavailable` context rather
than suppressing the rest of the project audit.

SHA-256 binds the stored data to its receipt; authenticity depends on obtaining the
recorded commit from the official upstream. A self-consistent edited JSON/receipt pair
is not a digital signature by CISA.

## Assessment and freshness

The report records its UTC assessment date in `as_of`; replay with the same snapshot,
finding evidence and date is deterministic. A snapshot older than 30 days by its upstream
catalog publication date (`date_released`) is `stale`; a new repository documentation
commit cannot refresh the age of unchanged threat data. A future publication or source
commit date is unavailable for an earlier assessment.
Bounded or unmappable dependency evidence yields `partial`; the known matches retained
in that result remain visible. `completed` means the bounded correlation completed,
not that the entire project or vulnerability population is safe.

The snapshot fingerprint covers the actual JSON and checksum bytes, including failed
reads. A corrected receipt or changed snapshot therefore invalidates cached context.
The UTC assessment date also participates in freshness checks. Browser continuation
holds the same catalog and date for the session so a single report cannot mix snapshots.
Historical reports describe their recorded assessment date; they are not a claim about
today's threat situation.

Only dependency-stage evidence with exact CVE IDs or successfully resolved advisory
aliases participates. Unreadable advisory identifiers and GHSA-only records without a
confirmed CVE remain unresolved. No fuzzy product matching is performed. Correlation
requires no network request, model call or upload of project source or dependency lists.
Browser and local packages carry the same reviewed KEV bytes.

## Reviewed daily updates

`.github/workflows/update-kev-catalog.yml` checks out the official source separately,
rebuilds the snapshot twice, runs catalog/import/package checks and browser/WASM parity,
then maintains one update branch: `automation/kev-threat-context`.

The workflow stages only the two generated KEV files. An existing open update must be
the bot's single data-only commit; additional human commits or unrelated changes stop
the update. An exact Git lease prevents overwriting a concurrently changed branch.
An already merged branch can be reused; a closed, unmerged proposal is not silently
reopened or overwritten. Identical snapshots produce no mutation. A maintainer must
resolve such blocked branches explicitly before scheduled updates can resume.

After proposing changed bytes, the workflow dispatches the full production, web,
PostgreSQL, browser and local-package checks for that branch. Updates remain subject
to review and merge; this workflow never merges or closes a PR. It does not modify the
separate CVE/GHSA updater or its superseded-snapshot cleanup rules.

## Scope of centre integration

This implementation consumes public CISA KEV data. It does not claim CISA or ACSC
endorsement, connect to ACSC's partner-only CTIS service, submit incident reports or
share customer evidence with a centre. ACSC partnership/access and any future
restricted feed require a separate integration and distribution policy.
