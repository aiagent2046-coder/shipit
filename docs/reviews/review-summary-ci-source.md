# Source review summary and CI source scope

Engine: 2026-10-03-4.

Validated SQL literal-list wording corrections remain in the observation total
and retain their stored model severity and numerical score. The HTML report and
web summary count them separately as source interpretations needing review,
instead of including them in the displayed impact buckets. This does not mark
them safe, confirmed or disproven. Missing/inconsistent source-bound projection
metadata preserves the normal severity display. Test/example observations stay
in their existing category.

The web consumer now validates the SQL source-bound projection and uses the
same active wording as the backend. Original model wording is retained.

CI source mismatch detection inspects selected YAML step bodies rather than
collecting URLs across the entire workflow. Candidates are SSH-action scripts
or Git placement commands naming /srv, /opt or /var/www application paths.
A checkout into a runner-relative data directory does not establish deployment;
workflow/job/step names alone do not establish deployment either. An unrelated
step cannot lend its deployment context to a data checkout. The warning states
source observations and does not assert what was built or is running live.

Limits: shell variable binding is not resolved. Unsupported deployment actions,
custom application directories, reusable workflows and indirect scripts may be
missed. YAML input is limited to 400,000 characters, 100 jobs and 500 steps per
job. Absence of a finding is not deployment verification. No repository URL is
allowlisted as intrinsically safe.

Regression controls include the actual advisory update workflow, mixed data
and deployment steps, a foreign application source, invalid YAML, and matching
Python/TypeScript SQL display cases with missing or modified proof metadata.
