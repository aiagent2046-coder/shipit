# Bounded production-first LLM context

The 2026-10-05 self-audit spent 1,042.62 RUB on eight Sonnet replies that the
legacy parser counted as empty. Prompt caching worked, but the first pass
still wrote a large cache entry. This change bounds the amount of source sent;
it does not claim to have established the cause of the empty replies.

## Selection policy

- Each rubric receives at most 450,000 source characters (previously 900,000).
  Number gutters, wrappers, system instructions and source facts are additional;
  the existing final request-window check still bounds the complete prompt.
- Application source is selected first. Rubric-matching support files receive
  at most 10% of the budget, and only when a test module name or a static import
  links them to selected production files. Only the support actually selected
  is reserved; unused capacity returns to application code before a final link
  check. Support orphaned by the final application selection is dropped. That
  last check may leave a small amount of capacity unused. The existing path
  classifier keeps migrations and CI in production.
- Exact basenames `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`
  and `packages.lock.json` are excluded before LLM ranking, including nested
  projects. Files ending in `.lock` were already outside the LLM reader.
  Manifests such as `package.json` and `pyproject.toml` remain eligible.
  Original archive bytes and source hashes remain available to other checks.
  This does not assert that every excluded format is supported by dependency
  scanning; consult its separate coverage record.
- A repository containing only tests/examples/docs, plus project metadata,
  receives a bounded nonproduction review. The report explicitly labels this
  scope. Metadata alone does not count as application source for this fallback.
- Existing relevance/breadth ranking and deterministic tie-breaking apply
  within each bucket. Unrelated test fixtures cannot consume the production
  budget. A mixed repository with no rubric-matching application source does
  not produce a review from unrelated tests alone.
- Oversized Python files can use complete relevant top-level functions/classes,
  plus module statements and conservatively resolved local definition
  dependencies. Decorators, imports, defaults and guards inside a retained
  definition remain intact. Comments/docstrings do not make a definition
  relevant; executable string literals do. No source is imported or executed.
- Excerpts preserve original line numbers and explicitly mark omitted ranges.
  Dynamic dispatch and cross-module dependencies are not fully resolved. If
  parsing fails or complete retained definitions exceed the per-file cap, the
  existing marked head truncation remains the fallback. Other languages keep
  the existing head truncation policy.

Source hashes and finding verification continue to use the original files.
The report counts files sent only partially in at least one attempt, including
both excerpts and head truncation. Engine identity is bumped to invalidate old
cached audit results.

## Initial offline measurement (PR #622)

These historical results use the selection implementation at
`fb35b442e59d5743baee7cc5944b2ccf9c31b7e7`, before the lockfile/reserve follow-up.

Archive: commit `e235ee52b2db132d1a525a6a5a7511d56afe4033`, with prefix
`aiagent2046-coder-shipit-e235ee5/`; 1,444 eligible source files. Baseline uses
that commit's selection code. Both measurements use identical archive bytes,
one prompt per rubric and the default content budget. Prompt characters below
include the system prompt, line gutters and wrappers, but exclude the optional
source-facts supplement and model-specific final window trimming. These are
character counts, not billed tokens or a price forecast.

| Rubric | Prompt chars before | After | Reduction | Production files before / after | Support chars before / after | Excerpt files after |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| auth | 1,037,330 | 531,503 | 48.76% | 70 / 61 | 177,270 / 44,696 | 10 |
| security | 1,029,562 | 517,268 | 49.76% | 91 / 78 | 172,729 / 43,341 | 4 |
| money | 1,005,099 | 539,917 | 46.28% | 99 / 76 | 188,650 / 43,443 | 9 |
| web | 1,008,621 | 529,042 | 47.55% | 63 / 62 | 523,319 / 43,694 | 8 |

Total prompt size falls from 4,080,612 to 2,117,730 characters (48.10%).
Production/support counts use `is_non_production_path`, including fixtures and
examples, rather than only checking for a `/tests/` path segment.

This reduces coverage as well as cost exposure: the production file counts
fall in every rubric. New selections are not subsets of old selections and
complete-function excerpts change the lines seen within selected files. Equal
finding recall has **not** been established. No new paid model requests were
made. A subsequent explicitly authorized evaluation should compare known
findings and actual provider charges before treating this as a quality win.

To reproduce without contacting a model, create the pinned archive and run the
following from the baseline and PR #622 checkouts (use the same `/tmp/shipit-context-baseline.zip`):

```sh
git archive --format=zip --prefix=aiagent2046-coder-shipit-e235ee5/ \
  e235ee52b2db132d1a525a6a5a7511d56afe4033 > /tmp/shipit-context-baseline.zip
python - <<'PY'
import json
import zipfile
from app.scan import llm_scan
from app.scan.secrets import is_non_production_path

with zipfile.ZipFile('/tmp/shipit-context-baseline.zip') as archive:
    files = llm_scan._iter_code_files(archive)
for rubric in llm_scan.ALL_RUBRICS:
    selected = llm_scan.select_files(files, rubric)
    print(json.dumps({
        'rubric': rubric,
        'files': len(selected),
        'content_chars': sum(len(text) for _, text in selected),
        'prompt_chars': len(llm_scan.SYSTEM_PROMPT)
                        + len(llm_scan.build_prompt(selected, rubric)),
        'production_files': sum(not is_non_production_path(name) for name, _ in selected),
        'support_chars': sum(len(text) for name, text in selected if is_non_production_path(name)),
        'excerpt_files': sum(hasattr(text, 'omitted_ranges') for _, text in selected),
    }))
PY
```

## Private attempt metadata

The existing usage ledger additionally records prompt character count, selected
file/content counts, support file/content counts, excerpt/head-truncation
counts and selection scope on every provider attempt, including failed attempts.
Response metadata records character/UTF-8 lengths, envelope type and direct
array length; see [empty-response investigation](llm-empty-response-investigation.md).
No raw answer text or source contents are added to the ledger. Public report
manifests expose aggregate partial-file coverage and scope, not provider rows.

Provider choice, pass count, prompt caching and finding admission are unchanged.


## Lockfile and support-reserve follow-up

The archive for `aiagent2046-coder/ai-co-founder-matching` commit
`87553a7ab6fcbd2815a2678d6887c0c00ef66829` has SHA-256
`ce08ee771d21ba4ef87d90824cfa036c85acef1b84fff6926207bc2be979525b`, exactly
matching audit `d8ae8860`. Both sides use the 450K default budget and the same
archive bytes. Unlike the historical table above, these full prompt counts
include the identical 15,717-character `facts_prompt(collect_source_facts(...))`
supplement and final Sonnet request-window fitting. No provider is contacted.

| Rubric | Before follow-up | After | Production files before / after |
| --- | ---: | ---: | ---: |
| auth | 472,568 | 523,500 | 72 / 75 |
| security | 477,590 | 522,227 | 88 / 92 |
| money | 408,021 | 353,544 | 45 / 44 |
| web | 431,549 | 377,072 | 36 / 35 |
| Total prompt characters | 1,789,728 | 1,776,343 | |

The total falls by 0.75%, while auth/security receive more application code.
Money/web lose only `package-lock.json`, whose truncated payload previously
consumed 48,051 characters in each. Overall selection changes from 107 files
(104 non-test, non-lock files; 2 test files; 1 lockfile) to 108 files
(105 non-test, non-lock files; 3 test files). No previously selected application
file is removed from any rubric. The newly covered application file in the
union is `syndi-agents/orchestrator.py`; other gains restore additional thematic
reviews of already selected files.

All 53 accepted source ranges in the saved report remain covered across
rubrics, as do all 16 records with explicit producer-rubric metadata. Auth
recovers six recorded ranges in `app/app/avatar/page.tsx`; security recovers
two in `syndi-agents/experiment_teams.py`. HTML contains the verified quote
ranges, not their text, and does not expose producer metadata for every
ungrouped card. These checks preserve known finding anchors; they do not prove
equal recall, sufficient surrounding context or runtime correctness.

The selection-exclusion ledger adds `dependency_lockfile` as an exclusive
reason for files never submitted. Candidate counts and source hashes retain
the original universe; exclusions still sum to candidates minus submitted
files, including skipped rubrics and provider failures. The report labels the
policy exclusion without claiming that the dependency scan covers that file.
