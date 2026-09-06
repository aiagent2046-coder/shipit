import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { RlsCheck } from "./RlsCheck";

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

it("preserves hook state across a missing repository URL without querying a live database", () => {
  const fetch = vi.spyOn(globalThis, "fetch");
  const error = vi.spyOn(console, "error");
  const props = { auditId: "synthetic", token: null };
  const { rerender, container } = render(<RlsCheck {...props} repoUrl="https://github.com/example/repo" />);
  const input = screen.getByPlaceholderText("i-own-this-project");
  fireEvent.change(input, { target: { value: "draft consent" } });
  rerender(<RlsCheck {...props} repoUrl={null} />);
  expect(container.textContent).toBe("");
  rerender(<RlsCheck {...props} repoUrl="https://github.com/example/repo" />);
  expect((screen.getByPlaceholderText("i-own-this-project") as HTMLInputElement).value).toBe("draft consent");
  expect(error).not.toHaveBeenCalled();
  expect(fetch).not.toHaveBeenCalled();
});
