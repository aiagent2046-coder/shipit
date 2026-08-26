import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { CardCheckout } from "./CardCheckout";
import * as api from "@/lib/api";
import { ApiError } from "@/lib/api";

/**
 * The checkout that takes the money.
 *
 * The property that matters most here is the last one: a failed create must
 * not navigate. Every other bug in this file is a bad afternoon; sending a
 * buyer to a URL that came out of a rejected response is sending them
 * somewhere nobody chose.
 */

const AUDIT = "2031a34d-3189-4401-98b5-77da859477dc";
const TOKEN = "81a43fa1e47aacf98be92f2953abfc36"; // scan-allow: fixture audit token
const PAY_URL = "https://yoomoney.ru/checkout/payments/v2/contract?orderId=x";

function mount() {
  const container = document.createElement("div");
  document.body.appendChild(container);
  const root = createRoot(container);
  act(() => {
    root.render(
      <CardCheckout
        auditId={AUDIT}
        returnToken={TOKEN}
        amount="990.00"
        currency="RUB"
      />,
    );
  });
  return container;
}

function type(container: HTMLElement, label: string, value: string) {
  const input = [...container.querySelectorAll("label")]
    .find((l) => l.textContent?.includes(label))
    ?.querySelector("input") as HTMLInputElement;
  const setter = Object.getOwnPropertyDescriptor(
    window.HTMLInputElement.prototype,
    "value",
  )!.set!;
  act(() => {
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

function payButton(container: HTMLElement): HTMLButtonElement {
  return [...container.querySelectorAll("button")].find((b) =>
    b.textContent?.includes("Pay"),
  ) as HTMLButtonElement;
}

function fillIn(container: HTMLElement) {
  type(container, "Your name", "Ада Лавлейс");
  type(container, "Your email", "ada@example.invalid");
}

afterEach(() => {
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

describe("CardCheckout", () => {
  it("names the price it is about to charge", () => {
    const container = mount();
    expect(payButton(container).textContent).toContain("990.00 ₽");
  });

  it("will not submit an empty form", () => {
    const container = mount();
    expect(payButton(container).disabled).toBe(true);

    fillIn(container);

    expect(payButton(container).disabled).toBe(false);
  });

  it("sends the audit's access token so the payer can read the page they return to", async () => {
    const create = vi
      .spyOn(api, "createFixpackCardPayment")
      .mockResolvedValue({
        reference: "DRY-ABC123",
        amount: "990.00",
        currency: "RUB",
        confirmation_url: PAY_URL,
      });
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });

    const container = mount();
    fillIn(container);
    await act(async () => {
      payButton(container).click();
    });

    expect(create).toHaveBeenCalledWith(
      AUDIT,
      expect.objectContaining({ payer_email: "ada@example.invalid" }),
      TOKEN,
    );
    vi.unstubAllGlobals();
  });

  it("sends the buyer to the URL the backend returned", async () => {
    vi.spyOn(api, "createFixpackCardPayment").mockResolvedValue({
      reference: "DRY-ABC123",
      amount: "990.00",
      currency: "RUB",
      confirmation_url: PAY_URL,
    });
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });

    const container = mount();
    fillIn(container);
    await act(async () => {
      payButton(container).click();
    });

    expect(assign).toHaveBeenCalledWith(PAY_URL);
    vi.unstubAllGlobals();
  });

  it("shows the backend's own words when it refuses", async () => {
    vi.spyOn(api, "createFixpackCardPayment").mockRejectedValue(
      new ApiError(
        "This audit has no findings a Fix Pack can fix automatically",
        409,
        "no_auto_fixable_findings",
      ),
    );
    vi.stubGlobal("location", { assign: vi.fn() });

    const container = mount();
    fillIn(container);
    await act(async () => {
      payButton(container).click();
    });

    const alert = container.querySelector('[role="alert"]');
    expect(alert?.textContent).toContain("no findings a Fix Pack can fix");
    vi.unstubAllGlobals();
  });

  it("does not navigate when the payment could not be opened", async () => {
    // THE ONE THAT MATTERS. A create that failed has no confirmation URL, and
    // navigating anyway would send a buyer somewhere nobody chose.
    vi.spyOn(api, "createFixpackCardPayment").mockRejectedValue(
      new ApiError("the payment system did not answer", 502),
    );
    const assign = vi.fn();
    vi.stubGlobal("location", { assign });

    const container = mount();
    fillIn(container);
    await act(async () => {
      payButton(container).click();
    });

    expect(assign).not.toHaveBeenCalled();
    // And the button comes back, so the buyer can try again rather than
    // sitting under a spinner that will never resolve.
    expect(payButton(container).disabled).toBe(false);
    vi.unstubAllGlobals();
  });
});
