import { afterEach, describe, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { AuditCoverage } from "./AuditCoverage";
import { FindingsList } from "./FindingsList";
import type { Finding, Score } from "@/lib/types";

afterEach(cleanup);

const finding: Finding = {
  rule_id: "llm-auth", category: "Auth", title: "Unproven double grant",
  severity: "critical", confidence: 1, source: "llm",
};

describe("audit evidence", () => {
  it.each(["static_only", "static+preview", "static+llm", "static+partial", undefined] as const)(
    "does not publish readiness or confirmation for %s", (basis) => {
      const score: Score = { total: 4.9, categories: { Auth: 8.9 }, basis };
      const { container } = render(<>
        <AuditCoverage score={score} findings={[finding]} />
        <FindingsList findings={[finding]} />
      </>);
      expect(screen.getByText("Model hypothesis — unverified")).toBeTruthy();
      expect(screen.getByText("Potential critical impact")).toBeTruthy();
      expect(container.textContent).not.toContain("4.9");
      expect(container.textContent).not.toContain("8.9");
      expect(container.textContent).not.toContain("nothing serious found");
      expect(container.textContent).not.toContain("Fix before launch");
    },
  );

  it("keeps skipped coverage distinct from partial coverage and findings", () => {
    render(<AuditCoverage score={{ total: 10, categories: {}, basis: "static_only" }}
      findings={[finding]} />);
    expect(screen.getByText("Not surveyed — see findings · 1 unverified finding")).toBeTruthy();
    expect(screen.getByText("Not checked")).toBeTruthy();
    expect(screen.getAllByText("Partly checked")).toHaveLength(4);
  });

  it("does not reassure users when no findings were emitted", () => {
    const { container } = render(<FindingsList findings={[]} />);
    expect(container.textContent).toContain("Absence of findings does not establish safety");
    expect(container.textContent).not.toContain("clean bill");
  });

  it("marks older static findings as having no recorded verification", () => {
    render(<FindingsList findings={[{ ...finding, rule_id: "aws-access-key-id", source: undefined }]} />);
    expect(screen.getByText("Legacy finding — verification not recorded")).toBeTruthy();
  });

  it("separates fixtures without hiding credentials or classifying migrations as examples", () => {
    render(<FindingsList findings={[
      { ...finding, title: "Fixture secret", file: "smoke/sample/key.ts" },
      { ...finding, title: "Migration secret", file: "examples/migrations/0001.sql" },
    ]} />);
    const examples = screen.getByRole("region", { name: "In tests, examples and scaffolding" });
    expect(within(examples).getByText("Fixture secret")).toBeTruthy();
    expect(within(examples).queryByText("Migration secret")).toBeNull();
    expect(screen.getByText("Migration secret")).toBeTruthy();
  });
});
