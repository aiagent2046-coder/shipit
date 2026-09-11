import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { RlsCheck } from "./RlsCheck";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("preserves hook state across a missing repository URL without querying a live database", () => {
  const fetch = vi.spyOn(globalThis, "fetch");
  const error = vi.spyOn(console, "error");
  const props = { auditId: "synthetic", token: null };
  const { rerender, container } = render(<RlsCheck {...props} repoUrl="https://github.com/example/repo" />);
  const input = screen.getByPlaceholderText("i-own-this-project");
  fireEvent.change(input, { target: { value: "draft consent" } });
  rerender(<RlsCheck {...props} repoUrl={null} />);
  expect(container.textContent).toBe("");
  rerender(<RlsCheck {...props} repoUrl="https://github.com/example/repo" />);
  expect((screen.getByPlaceholderText("i-own-this-project") as HTMLInputElement).value).toBe("draft consent");
  expect(error).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});

async function showResult(overrides: Partial<import("@/lib/types").RlsCheckResult>) {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
    persisted: true, status: "checked", reason: "", project_ref: "synthetic",
    key_source: "repository", checked: [], not_checked: [], exposed_tables: [],
    inconclusive: 0, empty_but_unproven: 0, max_tables: 12, attempts: [],
    ...overrides,
  }), { status: 200, headers: { "content-type": "application/json" } }));
  render(<RlsCheck auditId="synthetic" token={null} repoUrl="https://github.com/example/repo" />);
  fireEvent.change(screen.getByPlaceholderText("i-own-this-project"), {
    target: { value: "i-own-this-project" },
  });
  fireEvent.click(screen.getByRole("button", { name: "Run the check" }));
  await screen.findByText(/We asked about/);
}

it("keeps empty and inconclusive results visible even when another table returns public rows", async () => {
  await showResult({
    checked: ["catalog", "users", "orders"], exposed_tables: ["catalog"],
    empty_but_unproven: 1, inconclusive: 1,
    attempts: [
      { status: "success", detail: "", evidence: { table: "catalog", reason: "rows_readable" } },
      { status: "failure", detail: "", evidence: { table: "users", reason: "empty_result" } },
      { status: "error", detail: "synthetic-private-message", evidence: { table: "orders", reason: "authentication_failed" } },
    ],
  });
  expect(screen.getByText(/This may be intentional for public data/)).toBeTruthy();
  expect(screen.getByText(/An empty answer does not prove protection/)).toBeTruthy();
  expect(screen.getByText(/Key or request authentication rejected/)).toBeTruthy();
  expect(screen.queryByText(/it means they are protected/)).toBeNull();
  expect(screen.queryByText(/synthetic-private-message/)).toBeNull();
});

it("shows an actual database denial separately from an unknown response", async () => {
  await showResult({
    checked: ["users", "orders"], inconclusive: 1,
    attempts: [
      { status: "failure", detail: "", evidence: { table: "users", reason: "permission_denied" } },
      { status: "error", detail: "", evidence: { table: "orders", reason: "unexpected_response" } },
    ],
  });
  expect(screen.getByText(/Database denied this request/)).toBeTruthy();
  expect(screen.getByText(/No interpretable result/)).toBeTruthy();
  expect(screen.getByText(/No readable rows were confirmed/)).toBeTruthy();
  expect(screen.queryByText("No rows came back.")).toBeNull();
});

it.each([
  ["time_budget_exceeded", "The time budget was exhausted."],
  ["table_limit", "The table limit was reached (12)."],
  [undefined, "The check ended before these tables were requested."],
] as const)("explains unasked tables for %s without claiming they were checked", async (reason, text) => {
  await showResult({ not_checked: ["orders"], stop_reason: reason });
  expect(screen.getByText(text, { exact: false })).toBeTruthy();
  expect(screen.getByText(/We asked about 0 tables/)).toBeTruthy();
  expect(screen.getByText("orders")).toBeTruthy();
});

it.each([
  ["table_not_exposed", "Table not found in the published API schema"],
  ["rate_limited", "Request rate limited"],
  ["server_error", "Database service error"],
  ["request_timeout", "Request timed out"],
  ["response_too_large", "Response too large to evaluate"],
  ["invalid_response", "Invalid response format"],
  ["unsupported_encoding", "Response compression is unsupported"],
])("shows the specific limitation for %s", async (reason, text) => {
  await showResult({
    checked: ["users"], inconclusive: 1,
    attempts: [{ status: "error", detail: "", evidence: { table: "users", reason } }],
  });
  expect(screen.getByText(text, { exact: false })).toBeTruthy();
});
