import type { ReactNode } from "react";
import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import type { BankTransferStatus } from "@/lib/types";
import { PaymentMethods } from "./FixpackPurchase";

const state = vi.hoisted(() => ({ review: true }));
vi.mock("./BankTransferCheckout", () => ({
  BankTransferCheckout: ({ renderCompleted }: {
    renderCompleted: (status: BankTransferStatus) => ReactNode;
  }) => renderCompleted({ reference: "TEST-SECOND", status: "completed",
    product: "fixpack", funding_review_required: state.review }),
}));
afterEach(cleanup);

it("does not promise queued work when the received payment needs reconciliation", () => {
  state.review = true;
  render(<PaymentMethods auditId="audit-test" accessToken={null} price={null} priceFailed />);
  const text = screen.getByRole("alert").textContent;
  expect(text).toContain("has not been confirmed");
  expect(text).toContain("TEST-SECOND");
  expect(text).toContain("No refund has been issued");
  expect(screen.queryByText(/generating your Fix Pack/)).toBeNull();
});

it("still announces work for the payment that funded the job", () => {
  state.review = false;
  render(<PaymentMethods auditId="audit-test" accessToken={null} price={null} priceFailed />);
  expect(screen.getByText(/generating your Fix Pack/)).toBeTruthy();
  expect(screen.queryByRole("alert")).toBeNull();
});
