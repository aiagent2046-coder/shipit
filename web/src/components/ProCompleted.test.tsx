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

import { login } from "@/lib/api";
import type { Account } from "@/lib/types";
import { ProCompleted } from "./BankTransferCheckout";
import { Providers } from "./providers";

const COMPLETED = {
  reference: "DRY-TEST01",
  status: "completed",
  product: "pro_tier",
  tier: "pro",
  api_key: "sk_live_test_key",
} as const;

const BUTTON = "Use this key now";
const SAVED = "Saved to this browser";

function mount() {
  return render(
    <Providers>
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
beforeEach(() => vi.clearAllMocks());

describe("ProCompleted save button", () => {
  it("flips to Saved only after a successful login", async () => {
    vi.mocked(login).mockResolvedValue({} as Account);
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

    // The promise resolved (setKey swallows), but the RESULT is false:
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

    release({} as Account);
    await waitFor(() =>
      expect(screen.getByRole("button", { name: SAVED })).toBeTruthy(),
    );
  });
});
