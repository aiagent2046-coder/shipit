# Isolated Luna repository trial

This experiment uses the production pipeline and Luna request/response code
introduced by PR #628. It changes no service configuration and writes no audit
or billing rows. Sonnet is never called. Results and prompts stay in a private
operator directory; do not commit them to GitHub.

## Source and historical comparator

- Repository: `aiagent2046-coder/ai-co-founder-matching`.
- Source revision: `87553a7ab6fcbd2815a2678d6887c0c00ef66829`.
- Historical Sonnet audit: `d8ae8860-3336-48f4-8d45-e9141530a03c`.
- Historical engine: `2026-10-05-1`; this trial uses `2026-10-05-6`.
- Expected content digest:
  `6421f8cc28b90218dda77db60ced5360b5d88eba45159b30f15c4c2c5dd87485`.
- Historical ZIP SHA256:
  `ce08ee771d21ba4ef87d90824cfa036c85acef1b84fff6926207bc2be979525b`.

The saved report's archive root identifies `87553a7`, resolved to the full
revision through GitHub. A locally preserved ZIP also matches both hashes.
The content digest includes member paths, including GitHub's wrapper directory;
do not unpack/repack it or substitute a rootless `git archive`. ZIP compression
metadata may change on a new download, so the content digest is the execution
gate rather than the raw ZIP hash.

The historical report has eight successful answers across four rubrics, which
is consistent with two passes, but it does not explicitly store the pass count.
It also lacks provider billing, token totals and elapsed time. Exact Sonnet
cost/speed comparisons require its usage journal; unrelated dashboard charges
must not be assigned to this audit. Its findings are a comparator, not ground
truth. Source quotes and mechanisms still require review.

Context selection and result processing changed after that Sonnet report.
This is a comparison of two system versions on identical source, not a paired
model experiment using identical prompts. Compare submitted files, partial
files, completed rubrics and rejection reasons before interpreting differences.
The isolated run omits remote OSV, synthetic SQL execution and client runtime
evidence, so its total score is not an exact production-score comparison.

## Bounds and evidence

`scripts/evaluate_luna_repository.py` defaults to a free planning run. Explicit
`--execute` selects Luna alone at the fixed AITunnel endpoint, with medium
reasoning, two passes and 8192 total completion/reasoning tokens per request.
There are no retries or provider fallbacks; the maximum is 16 requests.
On the Linux server an execution has a 20-minute process deadline; each HTTP
read timeout is at most 180 seconds and is capped by the remaining deadline.

Before every request, the runner checks known spend plus a conservative
reservation against `--budget-rub` (default 50). The reservation assumes UTF-8
bytes plus 1024 tokens for the envelope, 25 RUB/MTok input/cache writes and
100 RUB/MTok output. Above 272K estimated input tokens it applies 2x input and
1.5x output rates. These rates were checked against
<https://aitunnel.ru/models/gpt-6-luna> on 2026-10-05.

This is an admission guard based on price/token assumptions, not a
provider-enforced billing ceiling. An unknown charge, error, incomplete or
invalid answer stops further requests. The report retains known spend and
unknown charges separately. Pre-request and post-response checkpoints preserve
evidence if the process is interrupted; a fresh output path is required and
there is no resume mode.

The report records source identity, actual pipeline engine identity, a separate
Luna model-policy identity (no cache is used), prompts and prompt hashes,
answers, provider-attempt metadata, the full pipeline result and coverage.
Review the terminal state and unknown charges even when some findings exist.
Raw response storage is private; stdout shows only progress metadata.

## Invocation

Use the deployed release's Python environment with an isolated checkout of this
experimental branch. Do not source `/opt/shipit/.env`: the runner reads the
AITunnel key through the existing env-file parser only when executing.

```bash
curl --fail --location --max-time 120 --max-filesize 52428800 \
  'https://api.github.com/repos/aiagent2046-coder/ai-co-founder-matching/zipball/87553a7ab6fcbd2815a2678d6887c0c00ef66829' \
  --output source.zip

python scripts/evaluate_luna_repository.py \
  --archive source.zip \
  --repo aiagent2046-coder/ai-co-founder-matching \
  --revision 87553a7ab6fcbd2815a2678d6887c0c00ef66829 \
  --expected-content-hash 6421f8cc28b90218dda77db60ced5360b5d88eba45159b30f15c4c2c5dd87485 \
  --json plan.json
```

After the free plan succeeds, use the same arguments with a new result path
(`--json results-luna-repository.json`), `--budget-rub 50` and `--execute`.
Do not automatically retry a failed or interrupted paid run: inspect its
checkpoint first. The production default model remains Sonnet throughout.
