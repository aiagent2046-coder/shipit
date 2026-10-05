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
  links them to selected production files. Unused support capacity is not
  refilled. The existing path classifier keeps migrations and CI in production.
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

## Offline measurement

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
following from each checkout (use the same `/tmp/shipit-context-baseline.zip`):

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
