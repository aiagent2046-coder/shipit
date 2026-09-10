import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { FindingsList, PreviewHistory } from "./FindingsList";
import { evidenceLabel, findingCounts } from "@/lib/evidence";
import type { Finding } from "@/lib/types";

afterEach(cleanup);

const partial: Finding = {
  rule_id: "llm-web", source: "llm", title: "save leaves saving stuck on network error",
  severity: "high", confidence: 1, category: "Frontend", file: "app/page.tsx", line: 8,
  explanation: "The fetch is unawaited. HTTP errors also navigate.",
  fix_hint: "Original suggestion <script>notExecutable()</script>",
  claim_evidence: { version: 1, source_check: { kind: "quote_match", line_start: 6, line_end: 10 },
    observation: "The fetch is unawaited", required_conditions: null,
    conditions_status: "not_checked", consequence_status: "not_checked",
    syntax_check: { kind: "react_async_network_reset_absent", result: "not_checked",
      claim: "A network rejection leaves saving true", detail: "Compound finding" },
    premise_checks: [{ kind: "react_async_network_reset_absent", target: "saving", result: "contradicted",
      claim: "A network rejection leaves saving true", detail: "The same handler catches rejection and resets saving." }],
  },
};

it("shows a partial counterexample before the original claim and keeps an independent HTTP issue", () => {
  const http: Finding = { rule_id: "react-unchecked-http-success", source: "static",
    title: "Success navigation without checking HTTP status", file: "app/page.tsx", line: 9,
    category: "Frontend", severity: "medium", confidence: .8 };
  const before = JSON.stringify(partial);
  const { container } = render(<FindingsList findings={[partial, http]} />);
  const card = screen.getByText("Source checks contradict part of this finding").closest("li")!;
  expect(within(card).getByText("Assessment needs review", { selector: "span" })).toBeTruthy();
  expect(within(card).queryByText("Potential high impact")).toBeNull();
  for (const text of [partial.title, partial.explanation!, partial.fix_hint!]) {
    expect(within(card).getByText(text).closest("details")).not.toBeNull();
  }
  expect(card.textContent).toContain("original model severity is retained in the score pending review");
  expect(screen.getAllByRole("listitem")).toHaveLength(2);
  expect(findingCounts([partial, http])).toEqual({ source: 2, examples: 0 });
  expect(container.querySelector("script")).toBeNull();
  expect(JSON.stringify(partial)).toBe(before);
});

it("preserves the original free baseline without applying the current partial headline", () => {
  const before = JSON.stringify(partial);
  render(<PreviewHistory score={{ total: 4, categories: {}, free_baseline: {
    version: 1, origin: "reused", status: "completed", findings: [partial],
    score: { total: 5, categories: {}, basis: "static+preview" },
  } }} />);
  const section = screen.getByRole("region", { name: "Included free audit" });
  expect(within(section).queryByText("Source checks contradict part of this finding")).toBeNull();
  expect(section.textContent).toContain(partial.title);
  expect(within(section).getByText(partial.fix_hint!).closest("details")).not.toBeNull();
  expect(JSON.stringify(partial)).toBe(before);
});

it("does not turn model self-correction into counterevidence or override a whole contradiction", () => {
  const unassessed: Finding = { ...partial, claim_evidence: { ...partial.claim_evidence!,
    premise_checks: [], observation: "Actually this is safe" } };
  expect(evidenceLabel(unassessed)).not.toContain("contradicted");
  const whole: Finding = { ...partial, claim_evidence: { ...partial.claim_evidence!,
    syntax_check: { ...partial.claim_evidence!.syntax_check!, result: "contradicted" } } };
  expect(evidenceLabel(whole)).not.toContain("Part of");
  expect(findingCounts([whole])).toEqual({ source: 0, examples: 0 });
});
