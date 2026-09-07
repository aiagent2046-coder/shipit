import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { AuditForm } from "./AuditForm";

const { push } = vi.hoisted(() => ({ push: vi.fn() }));
vi.mock("next/navigation", () => ({ useRouter: () => ({ push }) }));

afterEach(() => { cleanup(); vi.restoreAllMocks(); push.mockReset(); });

function submitWithResponse(status: number, retryAfter?: string, reason = "rate_limited") {
  vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
    JSON.stringify({ detail: { reason, detail: "max 5 audits per day" } }),
    { status, headers: retryAfter === undefined ? {} : { "Retry-After": retryAfter } },
  ));
  render(<AuditForm />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "https://github.com/example/repo" } });
  fireEvent.click(screen.getByRole("button", { name: "Audit my app" }));
}

it("shows the server's retry time across midnight through the real API client", async () => {
  const now = Date.parse("2026-09-07T23:55:00Z");
  vi.spyOn(Date, "now").mockReturnValue(now);
  submitWithResponse(429, "600");
  const alert = await screen.findByRole("alert");
  const expected = new Date(now + 600_000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit", timeZoneName: "short",
  });
  expect(alert.textContent).toContain(`Try again after ${expected} (your local time).`);
  expect(push).not.toHaveBeenCalled();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1); // No automatic quota-consuming retry.
  expect((screen.getByRole("button", { name: "Audit my app" }) as HTMLButtonElement).disabled).toBe(false);
});

it.each([undefined, "", "-1", "no date", "1.5", "9".repeat(400)])(
  "does not fabricate a reset time for Retry-After=%s", async (header) => {
    submitWithResponse(429, header);
    expect((await screen.findByRole("alert")).textContent).toContain("next available time was not provided");
  },
);

it("does not attach quota advice to a different error", async () => {
  submitWithResponse(503, "600", "service_unavailable");
  expect((await screen.findByRole("alert")).textContent).not.toContain("Try again after");
});
