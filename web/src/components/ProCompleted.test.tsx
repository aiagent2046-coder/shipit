/**
 * ProCompleted's save button must tell the truth (LLM-audit finding,
 * triaged 2026-09-24):
 *
 *  1. "Saved to this browser" appears ONLY after the login actually
 *     succeeded. setKey swallows failures into context error and used to
 *     resolve anyway (Promise<void>), so the label flipped on a FAILED
 *     login — the confirmed MEDIUM of the triage.
 *  2. The button is disabled while the login request is in flight — the
 *     other half of the same finding (double-click fired duplicate
 *     logins; idempotent server-side, still wrong UI state).
 *  3. Logout, another login, or a newly displayed key makes this key usable
 *     again and removes the stale success label.
 */
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@/lib/api", () => ({
  ApiError: class ApiError extends Error {},
  createBankTransferInvoice: vi.fn(),
  getBankTransferInvoice: vi.fn(),
  reportBankTransferPaid: vi.fn(),
  getAccount: vi.fn(),
  login: vi.fn(),
  logout: vi.fn(),
}));

import { getAccount, login, logout } from "@/lib/api";
import type { Account } from "@/lib/types";
import { ApiKeyWidget } from "./ApiKeyWidget";
import { ProCompleted } from "./BankTransferCheckout";
import { Providers } from "./providers";

const COMPLETED = {
  reference: "DRY-TEST01",
  status: "completed",
  product: "pro_tier",
  tier: "pro",
  api_key: "sk_live_test_key",
} as const;

const PRO = {
  tier: "pro",
  authenticated: true,
  entitlements: { daily_audit_limit: 50 },
} as Account;
const FREE = {
  tier: "free",
  authenticated: false,
  entitlements: { daily_audit_limit: 1 },
} as Account;

const BUTTON = "Use this key now";
const SAVED = "Saved to this browser";

function mount() {
  return render(
    <Providers>
      <ApiKeyWidget />
      <ProCompleted completed={COMPLETED} copy={vi.fn()} copied={null} />
    </Providers>,
  );
}

/** The button at rest: mount's refresh() may still be settling loading. */
async function settledButton() {
  const btn = await screen.findByRole("button", { name: BUTTON });
  await waitFor(() => expect((btn as HTMLButtonElement).disabled).toBe(false));
  return btn as HTMLButtonElement;
}

afterEach(cleanup);
beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getAccount).mockResolvedValue(FREE);
  vi.mocked(logout).mockResolvedValue(undefined);
});

describe("ProCompleted save button", () => {
  it("flips to Saved only after a successful login", async () => {
    vi.mocked(login).mockResolvedValue(PRO);
    mount();
    const btn = await settledButton();

    fireEvent.click(btn);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: SAVED })).toBeTruthy(),
    );
    expect(vi.mocked(login)).toHaveBeenCalledTimes(1);
  });

  it("keeps 'Use this key now' when the login fails", async () => {
    vi.mocked(login).mockRejectedValue(new Error("invalid key"));
    mount();
    const btn = await settledButton();

    fireEvent.click(btn);
    await waitFor(() => expect(vi.mocked(login)).toHaveBeenCalledTimes(1));

    // The promise resolved (setKey swallows), but the RESULT is null:
    // the label must not claim a save that never happened.
    expect(screen.getByRole("button", { name: BUTTON })).toBeTruthy();
    expect(screen.queryByRole("button", { name: SAVED })).toBeNull();
    expect(btn.disabled).toBe(false); // retry stays possible
  });

  it("disables the button while the login is in flight", async () => {
    let release!: (a: Account) => void;
    vi.mocked(login).mockImplementation(
      () => new Promise((resolve) => { release = resolve; }),
    );
    mount();
    const btn = await settledButton();

    fireEvent.click(btn);
    await waitFor(() => expect(vi.mocked(login)).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(btn.disabled).toBe(true));

    release(PRO);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: SAVED })).toBeTruthy(),
    );
  });

  it("allows applying the displayed key again after logout", async () => {
    vi.mocked(login).mockResolvedValue(PRO);
    mount();
    fireEvent.click(await settledButton());
    await screen.findByRole("button", { name: SAVED });

    fireEvent.click(screen.getByRole("button", { name: "Pro" }));
    fireEvent.click(screen.getByRole("button", { name: "Remove" }));
    await screen.findByRole("button", { name: "I have a key" });
    expect(logout).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("button", { name: SAVED })).toBeNull();

    fireEvent.click(await settledButton());
    await screen.findByRole("button", { name: SAVED });
    expect(login).toHaveBeenNthCalledWith(2, COMPLETED.api_key);
  });

  it("allows restoring this key after another account is selected", async () => {
    vi.mocked(login).mockResolvedValueOnce(PRO)
      .mockResolvedValueOnce({ ...PRO }).mockResolvedValueOnce(PRO);
    mount();
    fireEvent.click(await settledButton());
    await screen.findByRole("button", { name: SAVED });

    fireEvent.click(screen.getByRole("button", { name: "Pro" }));
    fireEvent.change(screen.getByPlaceholderText("sk_live_…"), {
      target: { value: "sk_live_other_key" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save key" }));
    const restore = await settledButton();
    expect(login).toHaveBeenNthCalledWith(2, "sk_live_other_key");
    expect(screen.queryByRole("button", { name: SAVED })).toBeNull();

    fireEvent.click(restore);
    await screen.findByRole("button", { name: SAVED });
    expect(login).toHaveBeenNthCalledWith(3, COMPLETED.api_key);
  });

  it("does not mark a newly displayed key as already saved", async () => {
    vi.mocked(login).mockResolvedValue(PRO);
    const view = mount();
    fireEvent.click(await settledButton());
    await screen.findByRole("button", { name: SAVED });

    view.rerender(
      <Providers>
        <ApiKeyWidget />
        <ProCompleted completed={{ ...COMPLETED, api_key: "sk_live_new_key" }}
          copy={vi.fn()} copied={null} />
      </Providers>,
    );
    expect(screen.queryByRole("button", { name: SAVED })).toBeNull();
    fireEvent.click(await settledButton());
    await screen.findByRole("button", { name: SAVED });
    expect(login).toHaveBeenNthCalledWith(2, "sk_live_new_key");
  });

});
