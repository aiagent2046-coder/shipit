# LLM stage provider policy (hybrid)

## Decision

Final security verdicts come from a **hosted** model. Cheap assistive LLM work goes
to a **local** model, or is skipped. The split is by who holds the oracle, not by
"a local model is cheaper".

## Context

The LLM stage produces findings -- security verdicts a human reads to judge the
repository. Two routes were open:

1. **Hybrid**: hosted model for the final verdicts, local models for bulk/assistive
   work (and for private-repo customers).
2. **All-local**: curate the rubric prompts down to fit a local 8-9B model and run
   the whole stage on this box.

This records why (1) was chosen.

## Measurements (MEASURED 2026-09-22, on NandhaKishorM/laya and this repo, RTX 4070 Laptop 8 GB)

- **Swapping the local model changed nothing.** `qwen2.5-coder:7b` and `llama3.1:8b`
  (128K window, strong JSON) both returned **4/4 invalid rubric JSON and 0
  findings**, `input_tokens 8200` both. The prompt is truncated to a sliver before
  the model ever sees it, so the model's strength never entered the result.
- **`num_ctx` cannot be raised through the `/v1` payload.** Both `options.num_ctx`
  and a top-level `num_ctx` were measured dead (`input_tokens` stayed 8200). A
  `Modelfile: PARAMETER num_ctx` does work (`input_tokens` 8200 → 32776).
- **A bigger window did not make 8B competent.** At `num_ctx=16K` (the model saw
  ~8K tokens/request instead of ~2K) `llama3.1:8b` still returned 4/4 invalid JSON
  and 0 findings.
- **The full 82K-token rubric prompt does not fit an 8 GB card without spilling.**
  KV cache for an 8B model is ~128 KB/token: 32K → ~9 GB (spilled to RAM, the run
  hit its 290 s limit), 82K → ~15 GB. Local verdicts at full prompt length are
  throughput-bound on this hardware.

## Why hybrid and not all-local

- Final verdicts are the product we sell; a weak judge undercuts the sale. Local
  8-9B measured 4/4 invalid JSON on the rubric task.
- The 82K rubric prompt is already built and working against hosted windows.
  Curating it to fit 8-9B is new work for a strictly weaker result.
- Local verdicts at full prompt length are slow here (KV spill to RAM) -- a batch
  ceiling on one GPU.

## The split (by who holds the oracle)

- **Final security verdicts** (findings, judged by a human) → **hosted** (grok-4.20 /
  claude). This is what production already does; unchanged.
- **Cheap assistive LLM work** (bulk sorting, reformatting, short rubrics where a
  deterministic checker -- not a human -- judges the output) → **local**. This is
  where a local 8B is the right tool: volume, disposability, no privacy cost.
- **Private repos** whose customer forbids sending code to a cloud → **local**,
  honestly labelled a reduced-quality preview rather than passed off as equal.

## Consequences / risks

- The hosted path sends customer code to a third party (grok/claude). This is
  already true of the paid tier today; the policy makes it deliberate rather than
  incidental.
- Local models are kept, not discarded: they carry the bulk and private niches.
  They are explicitly *not* the tool for final security verdicts at this size.
- If a larger-context local model + hardware later changes the measurements
  above, revisit -- the decision is tied to those numbers, not to ideology.

## Related

- [non-llm-agent-chain.md](non-llm-agent-chain.md) -- the deterministic chain where LLM is not used at all.
- [deterministic-security-agent.md](deterministic-security-agent.md) -- the deterministic agent direction.
- [shipit-architecture.md](shipit-architecture.md) -- overall architecture.
