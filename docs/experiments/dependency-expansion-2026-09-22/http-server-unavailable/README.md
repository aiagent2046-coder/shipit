# http-server: incomplete upgrade and unavailable execution

Project: [http-party/http-server v14.0.0](https://github.com/http-party/http-server/tree/967e915f4dc4fd2798e62a370d4e1ac25cc7811d).
The original lock records minimist 1.2.5 both at the root and bundled inside
the development dependency tap. The card proposes minimist 1.2.6.

Changing the direct dependency to 1.2.6, adding `overrides.minimist=$minimist`,
and regenerating the lock through npm updates the root entry. The bundled
`node_modules/tap/node_modules/minimist` entry remains 1.2.5 and affected.
The follow-up scan retains that finding. Restoring both original manifests
restores the original scan. These are lockfile observations, not installation
or runtime verification.

Execution status is **unavailable**. npm 11 rejects the historical original
lock because of a missing optional fsevents entry. npm 8 accepts its structure,
but installation then receives HTTP 403 for camelcase. No successful native
test run or dependency regression is claimed. Partial installation is not
treated as a passing environment.

See [target evidence and hashes](summary.json), the individual installation
logs here, and [complete raw evidence](raw-evidence.tar.xz). The archive contains
the original, npm-regenerated and restored manifests, full scanner results,
the full result record and logs; its hash and member hashes are in the summary.
It contains no installed packages or executable application snapshot.
Trailing whitespace is trimmed in the readable npm 8 log copy; the archive
retains its original bytes and the summary hashes refer to archive members.

The next repair would require reviewing the parent dependency that bundles
minimist. Updating tap across a major version changes the testing dependency
tree and was not combined with this experiment. The existing card already
requires updating every affected installation and reviewing the parent when
necessary; this case demonstrates why those checks cannot be skipped.
