import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { FixpackPurchase } from "./FixpackPurchase";

// Use the real API client to catch a token lost anywhere in the UI -> request path.
afterEach(() => { cleanup(); vi.unstubAllGlobals(); });

it("passes the audit token to status polling and displays the owner's PR", async () => {
  const urls: string[] = [];
  vi.stubGlobal("fetch", vi.fn(async (input: string) => {
    urls.push(String(input));
    const isStatus = String(input).includes("fixpack-status");
    return new Response(JSON.stringify(isStatus
      ? { status: "delivered", pr_url: "https://github.com/acme/app/pull/1" }
      : {}), { status: isStatus ? 200 : 503 });
  }));
  const { rerender } = render(<FixpackPurchase auditId="audit-owner"
    repoUrl="https://github.com/acme/app" accessToken="owner+/&?" />);
  expect(await screen.findByText("Your fix PR is open.")).toBeTruthy();
  const statusUrl = new URL(urls.find((u) => u.includes("fixpack-status"))!);
  expect(statusUrl.searchParams.get("token")).toBe("owner+/&?");
  expect(statusUrl.pathname).toBe("/v1/audits/audit-owner/fixpack-status");
  rerender(<FixpackPurchase auditId="audit-owner" repoUrl="https://github.com/acme/app" />);
  await waitFor(() => expect(screen.queryByText("Your fix PR is open.")).toBeNull());
});

it("does not request private status when the page has no token", async () => {
  const fetchMock = vi.fn(async (_input: string) => new Response("{}", { status: 503 }));
  vi.stubGlobal("fetch", fetchMock);
  render(<FixpackPurchase auditId="audit-owner" repoUrl="https://github.com/acme/app" />);
  await screen.findByText(/couldn.t load the current price/);
  expect(fetchMock.mock.calls.some((args) => String(args[0]).includes("fixpack-status"))).toBe(false);
});
