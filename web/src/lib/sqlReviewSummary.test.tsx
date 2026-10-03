import { expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import type { Finding } from "./types";
import sql from "./fixtures/sql_review_summary.json";
import { findingCounts, narrativeProjection, observationSummary, sourceReviewCount, sourceSeverityCounts } from "./evidence";
import { SeveritySummary } from "../components/FindingsList";

it("separates validated SQL review while preserving the stored severity and observation", () => {
  const f = sql as unknown as Finding;
  expect(narrativeProjection(f)).not.toBeNull();
  expect(f.severity).toBe("high");
  expect(findingCounts([f])).toEqual({ source: 1, examples: 0 });
  expect(sourceReviewCount([f])).toBe(1);
  expect(sourceSeverityCounts([f]).high).toBe(0);
  expect(observationSummary([f])).toContain("1 source interpretations need review");
  render(<SeveritySummary findings={[f]} />);
  expect(screen.getByText("1 source interpretations need review")).toBeTruthy();
  expect(screen.queryByText("No source observations recorded")).toBeNull();
  expect(screen.queryByText("1 high")).toBeNull();
});

it("does not separate missing or inconsistent proof, ordinary SQL claims or test examples", () => {
  const f = structuredClone(sql) as unknown as Finding;
  f.claim_evidence!.narrative_projection!.source_hashes = {};
  expect(sourceReviewCount([f])).toBe(0);
  expect(sourceSeverityCounts([f]).high).toBe(1);
  delete f.claim_evidence!.narrative_projection;
  expect(sourceSeverityCounts([f]).high).toBe(1);
  expect(sourceReviewCount([{ ...sql, context: "test_file" } as unknown as Finding])).toBe(0);
});
