import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen, within } from "@testing-library/react";
import { DEMO_AUDIT } from "@/lib/demo";
import { DemoReport } from "./DemoReport";

afterEach(cleanup);

it("keeps the free example's evidence, scope and inventory consistent in the real report components", () => {
  const { container } = render(<DemoReport />);
  expect(screen.getByText("Illustrative data — not a real audit")).toBeTruthy();
  expect(screen.getByText(/All values are synthetic/)).toBeTruthy();
  expect(container.textContent).not.toMatch(/Legacy finding|verification not recorded|Model interpretation|Model hypothesis/);
  expect(container.textContent).not.toMatch(/sk_live_[A-Za-z0-9]{24,}/);
  expect(container.textContent).not.toContain("/ 10");

  // A fallback must not imply that the model examined authentication or payments.
  const scope = screen.getByRole("region", { name: "Audit coverage", hidden: true });
  for (const category of ["Auth", "Money & Data", "Frontend"]) {
    expect(within(scope).getByText(category).nextElementSibling?.textContent).toBe("Not checked");
  }
  expect(within(scope).getByText("Model review unavailable")).toBeTruthy();
  expect(within(scope).getByText("Model responses").nextElementSibling?.textContent).toBe("0");
  expect(DEMO_AUDIT.score.scan_manifest?.runtime_verified).toBe(false);
  expect(DEMO_AUDIT.score.scan_manifest?.rubrics_completed).toEqual([]);
  expect(screen.getAllByText("Static signal — unverified")).toHaveLength(2);
  expect(screen.getAllByText("A static rule emitted this observation. Its consequence was not tested.")).toHaveLength(3);

  // A missing Dockerfile is inventory when another deployment file is present;
  // it must not inflate potential-impact counts or advertise an Enterprise fix.
  const inventory = screen.getByRole("region", { name: "Deployment inventory" });
  expect(within(inventory).getByText("Informational")).toBeTruthy();
  expect(inventory.textContent).not.toMatch(/Potential .* impact|Enterprise/);
  expect(within(scope).getByText(/3 observations: 2 in source, 0 in tests\/examples, 1 informational/)).toBeTruthy();

  // Public environment settings must not inherit the old blanket deletion advice.
  const publicConfig = screen.getByText("Public frontend configuration included in the archive · .env.production").closest("li");
  expect(publicConfig?.textContent).toContain("Potential low impact");
  expect(publicConfig?.textContent).toContain("Keep intentional public build settings");
  expect(publicConfig?.textContent).not.toContain("git rm");
});
