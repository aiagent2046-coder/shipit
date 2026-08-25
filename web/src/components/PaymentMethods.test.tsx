import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import type { Pricing } from "@/lib/types";
import { PaymentMethods } from "./FixpackPurchase";

/**
 * Which ways to pay get offered.
 *
 * The rule under all of these: the storefront must never offer a rail the
 * backend would refuse. A button that answers 503 after a click reads to a
 * buyer as "this is broken", not as "pay the other way", and they leave.
 */

const AUDIT = "2031a34d-3189-4401-98b5-77da859477dc";

function priced(methods?: Pricing["methods"]): Pricing {
  return { fixpack: { amount: "990.00", currency: "RUB" }, methods };
}

function mount(price: Pricing | null, priceFailed = false) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  act(() => {
    createRoot(container).render(
      <PaymentMethods
        auditId={AUDIT}
        accessToken={null}
        price={price}
        priceFailed={priceFailed}
      />,
    );
  });
  return container;
}

// The transfer CHECKOUT, as opposed to the one-line disclosure that offers to
// reveal it -- that link legitimately reads "Pay by bank transfer instead".
const TRANSFER_FORM = "Who you are paying";

const text = (c: HTMLElement) => c.textContent ?? "";

afterEach(() => {
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

describe("PaymentMethods", () => {
  it("offers the card when the deployment has one", () => {
    const c = mount(priced({ card: true, bank_transfer: true }));
    expect(text(c)).toContain("Pay by card");
  });

  it("keeps the slow rail out of the way when the fast one works", () => {
    // Side by side, a buyer can pick the one that waits on a human reading a
    // bank statement without knowing that is what they picked.
    const c = mount(priced({ card: true, bank_transfer: true }));
    expect(text(c)).not.toContain(TRANSFER_FORM);
    expect(text(c)).toContain("Card declined?");
  });

  it("reveals the transfer when asked for it", () => {
    const c = mount(priced({ card: true, bank_transfer: true }));
    const link = [...c.querySelectorAll("button")].find((b) =>
      b.textContent?.includes("Card declined?"),
    ) as HTMLButtonElement;

    act(() => {
      link.click();
    });

    expect(text(c)).toContain(TRANSFER_FORM);
  });

  it("does not offer a card rail this deployment has not configured", () => {
    const c = mount(priced({ card: false, bank_transfer: true }));
    expect(text(c)).not.toContain("Pay by card");
    expect(text(c)).toContain(TRANSFER_FORM);
  });

  it("reads an older API with no methods as transfer-only", () => {
    // The state every deployment was in before ЮKassa existed. Guessing "card
    // is on" here would put a 503 in front of a buyer.
    const c = mount(priced(undefined));
    expect(text(c)).not.toContain("Pay by card");
    expect(text(c)).toContain(TRANSFER_FORM);
  });

  it("says so plainly when there is no way to pay at all", () => {
    const c = mount(priced({ card: false, bank_transfer: false }));
    expect(text(c)).toContain("Card payment is being set up");
  });

  it("shows no checkout while the answer is still in flight", () => {
    // Which rails exist is part of that answer, so anything rendered first is
    // a guess -- and a guess swapping under someone who has started typing
    // into it is worse than a moment of nothing.
    const c = mount(null);
    expect(text(c)).toBe("");
  });

  it("falls back to the transfer when the price could not be loaded", () => {
    // A pay button naming no figure is the bait-price shape this section was
    // rewritten to remove, so no price means no card rail. The transfer
    // fetches its own amount when the invoice is created, so it survives.
    const c = mount(null, true);
    expect(text(c)).not.toContain("Pay by card");
    expect(text(c)).toContain(TRANSFER_FORM);
  });
});
