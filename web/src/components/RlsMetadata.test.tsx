import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RlsCheck } from "./RlsCheck";
import { RlsMetadataOutcome } from "./RlsMetadata";
import type { RlsAccessReview } from "@/lib/types";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });
const props = { auditId: "synthetic", token: "audit-token", repoUrl: "https://github.com/example/repo" };
const snapshot = {
  version: 1, project_ref: "abcdefghijklmnopqrst", captured_at: "2026-09-11T12:00:00Z",
  tables: [{ name: "shared_stacks" }],
};
function importFile(text: string, size = text.length) {
  fireEvent.change(screen.getByLabelText("Metadata JSON"), {
    target: { files: [{ size, text: () => Promise.resolve(text) }] },
  });
}

it("imports a SQL-editor export and sends separate read/write intent without manufacturing consent", async () => {
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({
    status: "refused", reason: "fixture", persisted: false,
  }), { status: 200, headers: { "content-type": "application/json" } }));
  render(<RlsCheck {...props} />);
  importFile(JSON.stringify([{ metadata_snapshot: snapshot }]));
  const read = await screen.findByLabelText("shared_stacks read access");
  fireEvent.change(read, { target: { value: "public_subset" } });
  fireEvent.change(screen.getByLabelText("shared_stacks write access"), { target: { value: "backend_only" } });
  fireEvent.change(screen.getByLabelText("How users sign in"), { target: { value: "backend" } });
  const button = screen.getByRole("button", { name: "Run the check" }) as HTMLButtonElement;
  expect(button.disabled).toBe(true);
  expect(fetch).not.toHaveBeenCalled();
  fireEvent.change(screen.getByPlaceholderText("i-own-this-project"), { target: { value: "i-own-this-project" } });
  fireEvent.click(button);
  await screen.findByText("We did not check.");
  const form = fetch.mock.calls[0][1]?.body as FormData;
  expect(JSON.parse(form.get("access_review") as string)).toEqual({
    snapshot, auth_model: "backend", expectations: [{ table: "shared_stacks", read: "public_subset", write: "backend_only" }],
  });
  expect(form.get("consent")).toBe("i-own-this-project");
  expect(form.get("token")).toBe("audit-token");
  fireEvent.click(screen.getByRole("button", { name: "Prepare another check" }));
  expect((screen.getByRole("button", { name: "Run the check" }) as HTMLButtonElement).disabled).toBe(true);
});

it.each(["not-json", JSON.stringify({ ...snapshot, tables: [null] }), JSON.stringify({ ...snapshot, version: 2 })])(
  "blocks a malformed import and allows explicit removal", async (text) => {
    const fetch = vi.spyOn(globalThis, "fetch");
    render(<RlsCheck {...props} />);
    fireEvent.change(screen.getByPlaceholderText("i-own-this-project"), { target: { value: "i-own-this-project" } });
    importFile(text);
    await screen.findByRole("alert");
    expect((screen.getByRole("button", { name: "Run the check" }) as HTMLButtonElement).disabled).toBe(true);
    expect(fetch).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Remove metadata" }));
    expect((screen.getByRole("button", { name: "Run the check" }) as HTMLButtonElement).disabled).toBe(false);
  },
);

it("does not read an oversized file", async () => {
  render(<RlsCheck {...props} />);
  const read = vi.fn();
  fireEvent.change(screen.getByLabelText("Metadata JSON"), { target: { files: [{ size: 262145, text: read }] } });
  await screen.findByRole("alert");
  expect(read).not.toHaveBeenCalled();
});

it("ignores a stale file read after a second import", async () => {
  render(<RlsCheck {...props} />);
  let resolve!: (text: string) => void;
  fireEvent.change(screen.getByLabelText("Metadata JSON"), {
    target: { files: [{ size: 10, text: () => new Promise<string>((done) => { resolve = done; }) }] },
  });
  importFile(JSON.stringify(snapshot));
  await screen.findByLabelText("shared_stacks read access");
  resolve("not-json");
  await waitFor(() => expect(screen.queryByRole("alert")).toBeNull());
});

it("public reading never hides a write mismatch or turns collector bypass into disabled RLS", () => {
  const review: RlsAccessReview = {
    version: 1, source: "owner_supplied_metadata", project_ref: snapshot.project_ref, captured_at: snapshot.captured_at,
    snapshot_sha256: "a".repeat(64), collector_role: "postgres", auth_model: "backend", limitations: [],
    tables: [{ table: "shared_stacks", expected: { read: "public", write: "backend_only" },
      observation: "rows_readable", interpretation: "expected_public_read", evidence_conflict: false,
      collector_rls_applies: false, row_count: 2,
      policy_summaries: [],
      operations: [{ role: "anon", operation: "INSERT", scope: "unrestricted", reason: "policies_allow_all",
        assessment: "mismatch", column_limited: false }] }],
  };
  const { rerender } = render(<RlsMetadataOutcome review={review} />);
  expect(screen.getByText(/matches your public-read intention/)).toBeTruthy();
  expect(screen.getByText("Conflicts with expected access")).toBeTruthy();
  expect(screen.getByText(/does not mean RLS is disabled for visitors/)).toBeTruthy();
  expect(screen.getByText(/Your backend uses its own sessions/)).toBeTruthy();
  rerender(<RlsMetadataOutcome review={{ ...review, tables: [{ ...review.tables[0], evidence_conflict: true }] }} />);
  expect(screen.getByText(/The live read conflicts with the snapshot/)).toBeTruthy();
});
