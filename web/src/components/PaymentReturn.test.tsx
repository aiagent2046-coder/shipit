import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { orderFromQuery, PaymentReturn } from "./PaymentReturn";
import * as api from "@/lib/api";

/**
 * The page ЮKassa returns a buyer to.
 *
 * Two properties carry the weight. The order reference goes into an href the
 * page invites someone to tap, so anything that is not an order reference must
 * not reach it. And the banner's claim has to stay true for someone who typed
 * `?paid=1` themselves, because anyone can.
 */

const ORDER = "DRY-SWU5M4";

function mount(order: string | null) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  act(() => {
    createRoot(container).render(<PaymentReturn order={order} />);
  });
  return container;
}

async function mountAsync(order: string | null) {
  const container = document.createElement("div");
  document.body.appendChild(container);
  await act(async () => {
    createRoot(container).render(<PaymentReturn order={order} />);
  });
  return container;
}

const link = (c: HTMLElement) =>
  c.querySelector('a[href^="https://t.me/"]') as HTMLAnchorElement | null;

afterEach(() => {
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

describe("orderFromQuery", () => {
  it("accepts a real order reference", () => {
    expect(orderFromQuery("DRY-SWU5M4")).toBe("DRY-SWU5M4");
    expect(orderFromQuery("dry-swu5m4")).toBe("DRY-SWU5M4");
  });

  it("rejects anything that is not one", () => {
    // The value ends up in an href. A page that renders whatever the query
    // string contains is a page that links wherever a stranger says.
    for (const bad of [
      null,
      "",
      "DRY-SHORT",
      "DRY-SWU5M4X",
      "https://evil.example/steal",
      "DRY-SWU5M4?x=1",
      "../../etc/passwd",
    ]) {
      expect(orderFromQuery(bad)).toBeNull();
    }
  });

  it("rejects the characters the reference alphabet leaves out", () => {
    // Exactly 0, 1, I and O -- the four that get misread as each other.
    // Everything else in A-Z and 2-9 is minted, U included; this list was
    // wrong on the first attempt and the test said so.
    for (const bad of ["DRY-ABCDE0", "DRY-ABCDE1", "DRY-ABCDEI", "DRY-ABCDEO"]) {
      expect(orderFromQuery(bad)).toBeNull();
    }
    expect(orderFromQuery("DRY-ABCDEU")).toBe("DRY-ABCDEU");
  });
});

describe("PaymentReturn", () => {
  it("does not claim the payment succeeded", async () => {
    // `paid=1` reaches this page in the buyer's own browser, so the wording
    // has to be true for someone who typed it by hand.
    vi.spyOn(api, "getBillingDetails").mockResolvedValue({ bank: null });
    const c = await mountAsync(ORDER);

    const text = c.textContent ?? "";
    expect(text).toContain("If the payment went through");
    expect(text).not.toContain("Payment received");
    expect(text).not.toContain("Thank you for your payment");
  });

  it("offers Telegram once the bot's name is known", async () => {
    vi.spyOn(api, "getBillingDetails").mockResolvedValue({
      bank: null,
      telegram_bot: "SyndiAI_bot",
    });

    const c = await mountAsync(ORDER);

    expect(link(c)?.href).toBe(`https://t.me/SyndiAI_bot?start=${ORDER}`);
  });

  it("shows no button when the deployment has no bot", async () => {
    vi.spyOn(api, "getBillingDetails").mockResolvedValue({ bank: null });
    const c = await mountAsync(ORDER);
    expect(link(c)).toBeNull();
  });

  it("shows no button, and no error, when the lookup fails", async () => {
    // The customer still gets the email. An error box about a convenience
    // channel, on top of a payment they just made, reads as something having
    // gone wrong.
    vi.spyOn(api, "getBillingDetails").mockRejectedValue(new Error("down"));
    const c = await mountAsync(ORDER);

    expect(link(c)).toBeNull();
    expect(c.textContent).not.toContain("down");
  });

  it("asks for nothing when there is no order to ask about", () => {
    const get = vi.spyOn(api, "getBillingDetails");
    mount(null);
    expect(get).not.toHaveBeenCalled();
  });
});
