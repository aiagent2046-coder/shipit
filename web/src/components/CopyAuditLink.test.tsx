import { afterEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react";
import { CopyAuditLink } from "./CopyAuditLink";

const originalLocation = window.location.href;
const accessPath = "/audit/pending/job-123?token=private%2Btoken%2Fvalue%3D&source=upload#status";

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
  window.history.replaceState(null, "", originalLocation);
});

function openPendingLink() {
  window.history.replaceState(null, "", accessPath);
  return window.location.href;
}

it("copies the complete access link from the click even when navigation happens before the clipboard resolves", async () => {
  const expected = openPendingLink();
  let finishCopy: () => void = () => {};
  const writeText = vi.fn(() => new Promise<void>((resolve) => { finishCopy = resolve; }));
  vi.stubGlobal("navigator", { clipboard: { writeText } });
  render(<CopyAuditLink />);

  fireEvent.click(screen.getByRole("button", { name: "Copy audit link" }));
  expect(writeText).toHaveBeenCalledWith(expected);
  expect((screen.getByRole("button") as HTMLButtonElement).disabled).toBe(true);
  expect(screen.getByRole("status").textContent).toBe("");

  window.history.replaceState(null, "", "/audit/finished?token=result-token");
  await act(async () => { finishCopy(); });

  expect(screen.getByRole("status").textContent).toContain("Link copied");
  expect(writeText).toHaveBeenCalledTimes(1);
  expect(screen.queryByRole("textbox")).toBeNull();
});

it.each(["denied", "unavailable"])("provides the complete selected link when clipboard access is %s", async (failure) => {
  const expected = openPendingLink();
  const writeText = vi.fn().mockRejectedValue(new Error("Permission denied"));
  vi.stubGlobal("navigator", failure === "denied" ? { clipboard: { writeText } } : {});
  render(<CopyAuditLink />);

  fireEvent.click(screen.getByRole("button", { name: "Copy audit link" }));
  const input = await screen.findByRole("textbox", { name: "Audit link" }) as HTMLInputElement;

  expect(input.value).toBe(expected);
  expect(input.readOnly).toBe(true);
  expect(document.activeElement).toBe(input);
  expect(input.selectionStart).toBe(0);
  expect(input.selectionEnd).toBe(expected.length);
  expect(screen.getByRole("status").textContent).not.toContain("Link copied");
  expect(document.getElementById(input.getAttribute("aria-describedby")!)?.textContent)
    .toContain("Copy the selected link below");
});
