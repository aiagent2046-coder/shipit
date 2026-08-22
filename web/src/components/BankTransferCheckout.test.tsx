/**
 * The checkout, which is where the money and the promises meet.
 *
 * WHAT IS ASSERTED HERE is narrow on purpose: that what the payer typed is what
 * the API is asked for, and that the language guess survives from the browser
 * to the request. Everything downstream of that request has tests already --
 * the column, the message bodies, the router, the operator's confirmation --
 * and every one of them is worth nothing if this form drops a field on the way
 * out.
 *
 * WHAT IS NOT ASSERTED HERE, and cannot be: whether a human can find the
 * language control. It was invisible for a release -- `text-xs text-muted`,
 * third in a row of identically styled small print -- and the first person
 * asked to find it could not, while every property below was already true. No
 * automated check was ever going to catch that. It is worth saying plainly
 * rather than letting a green suite imply otherwise.
 */

import { act } from "react";
import { createRoot } from "react-dom/client";
import { hydrateRoot } from "react-dom/client";
import { renderToString } from "react-dom/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { BankTransferCheckout } from "./BankTransferCheckout";
import type { PayerContact } from "@/lib/api";
import type { BankTransferInvoice } from "@/lib/types";

const INVOICE: BankTransferInvoice = {
  payment_id: "11111111-1111-1111-1111-111111111111",
  reference: "DRY-TEST12",
  amount: "5.00",
  currency: "USD",
  bank: {
    card: "0000000000000000",
    bank_name: "Test Bank",
    swift: "TESTSWIFT",
    beneficiary: "Test Beneficiary",
    account: "TESTACCOUNT",
    address: "Nowhere",
  },
  expires_at: "2099-01-01T00:00:00+00:00",
};

/** navigator.language is read once, after mount. Set it before rendering. */
function browserSpeaks(language: string) {
  vi.spyOn(navigator, "language", "get").mockReturnValue(language);
}

let container: HTMLDivElement;

beforeEach(() => {
  container = document.createElement("div");
  document.body.appendChild(container);
});

afterEach(() => {
  container.remove();
  vi.restoreAllMocks();
});

async function mount(node: React.ReactElement) {
  const root = createRoot(container);
  await act(async () => {
    root.render(node);
  });
  return root;
}

function button(text: string): HTMLButtonElement {
  const found = [...container.querySelectorAll("button")].find(
    (b) => b.textContent?.trim() === text,
  );
  if (!found) {
    const seen = [...container.querySelectorAll("button")]
      .map((b) => JSON.stringify(b.textContent?.trim()))
      .join(", ");
    throw new Error(`no button labelled ${JSON.stringify(text)}; saw: ${seen}`);
  }
  return found;
}

/** The checkout takes its creator as a prop, so the suite never reaches the
 *  network -- the same seam the Python transports use. */
function checkout(createInvoice: (p: PayerContact) => Promise<BankTransferInvoice>) {
  return (
    <BankTransferCheckout
      description="test"
      createInvoice={createInvoice}
      renderCompleted={() => null}
    />
  );
}

async function type(label: string, value: string) {
  const input = [...container.querySelectorAll("label")]
    .find((l) => l.textContent?.includes(label))
    ?.querySelector("input");
  if (!input) throw new Error(`no input labelled ${label}`);
  await act(async () => {
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype, "value",
    )!.set!;
    setter.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
}

describe("what reaches the API", () => {
  it("sends every contact field the payer filled in", async () => {
    browserSpeaks("en-GB");
    const createInvoice = vi.fn().mockResolvedValue(INVOICE);
    await mount(checkout(createInvoice));

    await type("Your name", "Ada Lovelace");
    await type("Your email", "ada@example.invalid");
    await type("Your X handle", "@ada");
    await act(async () => button("Show card number").click());

    expect(createInvoice).toHaveBeenCalledWith({
      payer_name: "Ada Lovelace",
      payer_email: "ada@example.invalid",
      payer_x: "@ada",
      payer_locale: "en",
    });
  });

  it("carries the browser's language into the request", async () => {
    // The column exists BECAUSE this value cannot be recovered later: the
    // operator confirms hours after the tab closed, and a refund is decided
    // days after that. If it does not leave the form it is gone for good, and
    // a Russian-speaking payer gets English mail about their own money.
    browserSpeaks("ru-RU");
    const createInvoice = vi.fn().mockResolvedValue(INVOICE);
    await mount(checkout(createInvoice));

    await type("Your name", "Ада");
    await type("Your email", "ada@example.invalid");
    await act(async () => button("Show card number").click());

    expect(createInvoice.mock.calls[0][0].payer_locale).toBe("ru");
  });

  it("sends the language the payer chose, not the one we guessed", async () => {
    // The whole point of showing the guess. Somebody reading a Russian
    // browser in an English-speaking office corrects it, and the correction
    // has to be the thing that travels.
    browserSpeaks("ru-RU");
    const createInvoice = vi.fn().mockResolvedValue(INVOICE);
    await mount(checkout(createInvoice));

    await act(async () => button("English").click());
    await type("Your name", "Ada");
    await type("Your email", "ada@example.invalid");
    await act(async () => button("Show card number").click());

    expect(createInvoice.mock.calls[0][0].payer_locale).toBe("en");
  });

  it("does not ask for an invoice until there is a name and an email", async () => {
    // The backend answers 422 for either. Letting the button fire anyway turns
    // a missing field into an error message about a "request", which tells the
    // payer nothing about what they left blank.
    browserSpeaks("en-GB");
    const createInvoice = vi.fn().mockResolvedValue(INVOICE);
    await mount(checkout(createInvoice));

    expect(button("Show card number").disabled).toBe(true);

    await type("Your name", "Ada");
    expect(button("Show card number").disabled).toBe(true);

    await type("Your email", "not-an-address");
    expect(button("Show card number").disabled).toBe(true);

    await type("Your email", "ada@example.invalid");
    expect(button("Show card number").disabled).toBe(false);
  });
});

describe("the language control says which language is chosen", () => {
  it.each([
    ["ru-RU", "Русский"],
    ["ru", "Русский"],
    ["en-GB", "English"],
    ["de-DE", "English"],
  ])("with navigator.language %s, %s is pressed", async (lang, expected) => {
    browserSpeaks(lang);
    await mount(checkout(vi.fn()));

    expect(button(expected).getAttribute("aria-pressed")).toBe("true");
  });
});

describe("server render and hydration agree", () => {
  it("hydrates a Russian browser without a mismatch", async () => {
    /**
     * THE DEFECT THIS EXISTS FOR, measured in a real Chromium before it was
     * fixed: React error #418.
     *
     * `navigator` does not exist during the server render, so the server
     * always produced "en"; a lazy useState initialiser then produced "ru" on
     * a Russian browser, and the two renders disagreed. React recovered by
     * re-rendering, so the control ended up CORRECT -- it worked, loudly, by
     * accident, and nothing in CI could hear it.
     *
     * This is the reason the runner uses jsdom rather than a browser:
     * renderToString followed by hydrateRoot is the same two-step the server
     * and the browser perform, and React reports the same mismatch either way.
     */
    const errors: unknown[] = [];
    vi.spyOn(console, "error").mockImplementation((...args) => {
      errors.push(args[0]);
    });

    const element = checkout(vi.fn());

    // THE SERVER HAS NO `navigator`, AND jsdom DOES -- which is the trap this
    // line exists to avoid. An earlier version of this test called
    // renderToString straight into the jsdom global, so the "server" render
    // read a Russian navigator too, both sides agreed, and the test passed
    // against the broken code. It was caught by putting the defect back and
    // watching nothing fail.
    vi.stubGlobal("navigator", undefined);
    const serverHtml = renderToString(element);
    vi.unstubAllGlobals();

    browserSpeaks("ru-RU");
    container.innerHTML = serverHtml;

    await act(async () => {
      hydrateRoot(container, element);
    });

    const mismatches = errors.filter((e) =>
      String(e).toLowerCase().includes("hydrat") ||
      String(e).includes("did not match") ||
      String(e).includes("418"),
    );
    expect(mismatches).toEqual([]);

    // And having agreed, it still ends up correct: agreeing on the wrong
    // answer would satisfy the assertion above and defeat the purpose.
    expect(button("Русский").getAttribute("aria-pressed")).toBe("true");
  });
});
