import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { FindingsList, SeveritySummary } from "./FindingsList";
import { findingCounts } from "@/lib/evidence";
import type { Finding } from "@/lib/types";

afterEach(cleanup);

it("retains alternative deployment inventory without an impact badge or Enterprise offer", () => {
  const finding: Finding = { rule_id: "no-dockerfile", title: "No Dockerfile found in the archive",
    severity: "low", confidence: .9, category: "Deploy", context: "deployment_inventory",
    explanation: "Configuration found: deploy/app.service. Live deployment not checked.",
    fix_hint: "Review existing deployment instructions." };
  render(<><FindingsList findings={[finding]} /><SeveritySummary findings={[finding]} /></>);
  expect(screen.getByRole("region", { name: "Deployment inventory" }).textContent).toContain("deploy/app.service");
  expect(screen.getByText("Informational")).toBeTruthy();
  expect(screen.queryByText("Potential low impact")).toBeNull();
  expect(screen.queryByText("Enterprise")).toBeNull();
  expect(findingCounts([finding])).toEqual({ source: 0, examples: 0 });
});

it("shows a web example's protocol and role without calling it a database", () => {
  const finding: Finding = { rule_id: "connection-string-dev-password", title: "URI example",
    severity: "low", confidence: .3, category: "Security", context: "doc_example",
    file: "scripts/check.py", source: "static",
    claim_evidence: { version: 1, source_check: { kind: "static_rule" }, observation: null,
      required_conditions: null, conditions_status: "not_checked", consequence_status: "not_checked",
      source_context: { kind: "placeholder_uri", uri_scheme: "https", uri_kind: "web" } } };
  const { container } = render(<FindingsList findings={[finding]} />);
  expect(container.textContent).toContain("Example URI");
  expect(container.textContent).toContain("https — web");
  expect(container.textContent?.toLowerCase()).not.toContain("database");
  expect(container.textContent).not.toContain("almost certainly");
  expect(findingCounts([finding])).toEqual({ source: 0, examples: 1 });
});
