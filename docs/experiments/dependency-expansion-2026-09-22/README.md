# Additional dependency-card project experiments

These experiments extend the two fixed npm/PyPI consumer fixtures with pinned
external project snapshots. They test the existing remediation cards; they do
not enable automatic application of a card or change ordinary scanner verdicts.

## Evidence baseline

- Scanner commit: `0b5c981412ad0a9ab62ad4a7a6da1b90a0acd67b`.
- Catalog SHA-256: `e8cc8c6a60e29331c42f0c50bbdb57484766b947d377afc966c723ec7b3347af`.
- CVE source: `4242683c78e7fbf26a866b87eb2d47c5ac35afba`.
- Reviewed GHSA source: `16adc3ca94f84ac38aa0b847f71eae1cf6d187b9`.

Each case records the original project commit, the candidate actually supplied
by the card, resolved and installed versions, test outcomes, and restoration of
the original manifests. Candidate rejection and remaining affected copies are
results, not successful repairs. A package-level regression is reported
separately from application compatibility and deployed exploit reachability.

## Scope

The npm project is [`isaacs/node-mkdirp`](https://github.com/isaacs/node-mkdirp/tree/b98bedf92798ed73c87413eaf413d01dbe094a09)
at 0.5.0, with an original exact minimist 0.0.8 requirement. See its
[report and reproduction instructions](npm/README.md) and
[recorded evidence](npm/evidence/summary.json).

| npm observation | Before | Candidate | Restored |
| --- | --- | --- | --- |
| Root minimist version | 0.0.8 | 0.2.4 | 0.0.8 |
| Target findings | 2 | 0 | 2 |
| Upstream filesystem assertions | 9 passed | 9 passed | 9 passed |
| Added CLI checks | 5 passed | 5 passed | 5 passed |
| Dependency prototype pollution | Observed | Absent | Observed |

All installed minimist copies are assessed: a second copy at 1.2.8 remains
unchanged and unaffected throughout. After the upgrade every recorded advisory
entry for every target copy is unaffected, with zero unresolved target ranges.
No unrelated package version changes occur. The source has no original lockfile;
the experiment explicitly generates and preserves a baseline lock from the
unchanged source manifest. Restoration matches that baseline, not an invented
upstream lock.

The PyPI project is [`lmeilibr/vtex`](https://github.com/lmeilibr/vtex/tree/c957049c51b7e070e6c91f6212ade5216f7343cb),
with `requests`. See its [report and reproduction instructions](pypi/README.md)
and [recorded evidence](pypi/evidence/evidence.json).

| PyPI observation | Before | Candidate | Restored |
| --- | --- | --- | --- |
| Requests version | 2.31.0 | 2.33.0 | 2.31.0 |
| Target findings | 3 | 0 | 3 |
| Upstream import tests | 2 passed | 2 passed | 2 passed |
| Added client checks | 7 passed | 7 passed | 7 passed |
| Synthetic netrc credential misbinding | Observed | Absent | Observed |

The card supplies 2.33.0; all eight recorded Requests advisory entries are
unaffected after installation. The other eight installed packages retain their
versions. All three environments pass dependency consistency and import-origin
checks. Original and restored manifests, inventory and scan JSON agree.

The scan covers the project's direct requirements, not a complete transitive
audit. The unrelated pytest advisory remains unknown. The client checks use the
real VTEX client and Requests request preparation with an in-memory transport;
the live service and deployed exploit reachability are not tested.

Only disposable local copies are modified. The experiments do not send
findings or patches to the upstream repositories, use a real VTEX account,
or execute requests against a production application. They do not establish
that all dependencies or all application paths are secure.

## An incomplete npm upgrade is retained as evidence

The first npm selection, http-server v14.0.0, retains an affected minimist copy
bundled inside tap after an npm override updates the root copy. Its native tests
could not be run because dependency installation was blocked. The result is
explicitly **unavailable**, with a confirmed lockfile-level incomplete upgrade;
it is not included in the two successful runtime cycles above.
See the [separate report and raw evidence](http-server-unavailable/README.md).

## What this establishes for the cards

The same npm/PyPI recipes work beyond the two original fixed consumer fixtures.
The examples independently connect candidate selection, actual installation,
bounded compatibility checks, a dependency security regression and restoration.
They also demonstrate why every affected installation must be checked: changing
one manifest declaration is insufficient for a bundled copy.

These are reviewed, manually orchestrated experiments. They do not change the
scanner's `automatic_apply: false` or `runtime_verified: false` card fields and
are not a new automatic-repair API. No extra registry-dependent CI job is added.
The existing fixture contracts remain the regular CI controls.

The next planned extension is an LLM reviewer for cases outside proven recipes.
Its proposed changes still need concrete applicability evidence and the same
before / corrected / restored checks before becoming a new trusted card.
