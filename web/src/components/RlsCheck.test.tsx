import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
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

const projectRef = "abcdefghijklmnopqrst";
const projectUrl = `https://${projectRef}.supabase.co`;
const publishableKey = "sb_publishable_synthetic-public-test-key";
const controlProps = { auditId: "synthetic", token: "audit-token", repoUrl: "https://github.com/example/repo" };
const publicKeyInput = () => screen.getByLabelText(/Public key \(optional/);
const projectUrlInput = () => screen.getByLabelText(/^Project URL/);
const consentInput = () => screen.getByPlaceholderText("i-own-this-project");
const runButton = () => screen.getByRole("button", { name: "Run the check" }) as HTMLButtonElement;
function enter(input: HTMLElement, value: string) {
  fireEvent.change(input, { target: { value } });
}
function syntheticJwt(role: string, ref = projectRef) {
  return `eyJhbGciOiJIUzI1NiJ9.${btoa(JSON.stringify({ iss: "supabase", role, ref })).replace(/=+$/, "")}.synthetic`;
}
function refusedResponse() {
  return new Response(JSON.stringify({ status: "refused", reason: "synthetic test", persisted: false }), {
    status: 200, headers: { "content-type": "application/json" },
  });
}

it("requires an explicit project for a publishable key and sends it with typed consent and metadata", async () => {
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(refusedResponse());
  render(<RlsCheck {...controlProps} />);
  enter(publicKeyInput(), ` ${publishableKey} `);
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(true);
  expect(screen.getByText(/Enter the Project URL for this publishable key/)).toBeTruthy();
  fireEvent.click(runButton());
  expect(fetch).not.toHaveBeenCalled();

  const snapshot = { version: 1, project_ref: projectRef, captured_at: "2026-09-11T12:00:00Z", tables: [{ name: "catalog" }] };
  fireEvent.change(screen.getByLabelText("Metadata JSON"), {
    target: { files: [{ size: 200, text: () => Promise.resolve(JSON.stringify({ metadata_snapshot: snapshot })) }] },
  });
  enter(await screen.findByLabelText("catalog read access"), "public");
  enter(projectUrlInput(), ` ${projectUrl}/ `);
  expect((consentInput() as HTMLInputElement).value).toBe("");
  expect(runButton().disabled).toBe(true);
  enter(consentInput(), "I-OWN-THIS-PROJECT");
  expect(runButton().disabled).toBe(true);
  enter(consentInput(), "i-own-this-project");
  fireEvent.click(runButton());
  await screen.findByText("We did not check.");
  const form = fetch.mock.calls[0][1]?.body as FormData;
  expect(form.get("anon_key")).toBe(publishableKey);
  expect(form.get("project_url")).toBe(`${projectUrl}/`);
  expect(form.get("consent")).toBe("i-own-this-project");
  expect(form.get("token")).toBe("audit-token");
  expect(JSON.parse(form.get("access_review") as string).snapshot).toEqual(snapshot);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([
  `http://${projectRef}.supabase.co`,
  `${projectUrl}/rest/v1`,
  `${projectUrl}?select=*`,
  `${projectUrl}#fragment`,
  `${projectUrl}:443`,
  `https://user@${projectRef}.supabase.co`,
  `https://${projectRef}.supabase.co.example.com`,
  "https://localhost",
  "https://short.supabase.co",
])("blocks invalid Project URL %s before a request, even with repository key discovery", (url) => {
  const fetch = vi.spyOn(globalThis, "fetch");
  render(<RlsCheck {...controlProps} />);
  enter(projectUrlInput(), url);
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(true);
  expect(screen.getByRole("alert").textContent).toContain("Use your Supabase Project URL");
  fireEvent.click(runButton());
  expect(fetch).not.toHaveBeenCalled();
});

it.each(["sb_secret_synthetic-secret", syntheticJwt("service_role"), "sb_publishable_", `${publishableKey}.invalid`, "sb_publishable_" + "x".repeat(4096)])(
  "blocks an unsuitable public key without sending it to the API (%#)", (key) => {
    const fetch = vi.spyOn(globalThis, "fetch");
    render(<RlsCheck {...controlProps} />);
    enter(publicKeyInput(), key);
    enter(projectUrlInput(), projectUrl);
    enter(consentInput(), "i-own-this-project");
    expect(runButton().disabled).toBe(true);
    expect(screen.getByRole("alert")).toBeTruthy();
    fireEvent.click(runButton());
    expect(fetch).not.toHaveBeenCalled();
  },
);

it("keeps legacy anon keys usable without a Project URL", async () => {
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(refusedResponse());
  render(<RlsCheck {...controlProps} />);
  const key = syntheticJwt("anon");
  enter(publicKeyInput(), key);
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(false);
  fireEvent.click(runButton());
  await screen.findByText("We did not check.");
  const form = fetch.mock.calls[0][1]?.body as FormData;
  expect(form.get("anon_key")).toBe(key);
  expect(form.has("project_url")).toBe(false);
});

it("requires renewed consent after either target field changes and catches a mismatched legacy project", () => {
  const fetch = vi.spyOn(globalThis, "fetch");
  render(<RlsCheck {...controlProps} />);
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(false);
  enter(publicKeyInput(), syntheticJwt("anon"));
  expect((consentInput() as HTMLInputElement).value).toBe("");
  enter(consentInput(), "i-own-this-project");
  enter(projectUrlInput(), "https://bbbbbbbbbbbbbbbbbbbb.supabase.co");
  expect((consentInput() as HTMLInputElement).value).toBe("");
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(true);
  expect(screen.getByRole("alert").textContent).toContain("different projects");
  enter(projectUrlInput(), projectUrl.toUpperCase() + "/");
  enter(consentInput(), "i-own-this-project");
  expect(runButton().disabled).toBe(false);
  expect(screen.queryByRole("alert")).toBeNull();
  expect(fetch).not.toHaveBeenCalled();
});

it("locks the target, consent and metadata controls during a live request", async () => {
  let resolve!: (response: Response) => void;
  const fetch = vi.spyOn(globalThis, "fetch").mockImplementation(() => new Promise<Response>((done) => { resolve = done; }));
  render(<RlsCheck {...controlProps} />);
  enter(publicKeyInput(), publishableKey);
  enter(projectUrlInput(), projectUrl);
  enter(consentInput(), "i-own-this-project");
  fireEvent.click(runButton());
  await waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
  for (const input of [publicKeyInput(), projectUrlInput(), consentInput(), screen.getByLabelText("Metadata JSON")]) {
    expect((input as HTMLInputElement).disabled).toBe(true);
  }
  resolve(refusedResponse());
  await screen.findByText("We did not check.");
});
