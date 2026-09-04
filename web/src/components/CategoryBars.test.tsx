import { afterEach, describe, expect, it } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { CategoryBars } from "./ScoreRing";

/**
 * The category rows on the audit page, and the one sentence they must not say.
 *
 * MEASURED on a live report, 2026-09-04: the Auth row read "not checked" while
 * the findings table on the same page listed, under Auth, "request handler
 * runs with the service-role key, bypassing Row Level Security — found in 21
 * places". Both came off one score. Nobody surveyed Auth -- so it still draws
 * no bar and no number -- but something was found in it, and a reader who
 * believes "not checked" stops scrolling.
 *
 * The HTML report renders the same four states in app/report/html.py, and
 * tests/test_report.py holds the mirror of this file. Two surfaces, one rule,
 * asserted on both: they have drifted before (#181's bar, and the free-tier
 * banding that said "nothing serious found" on a page whose report said
 * "partly checked").
 */

const SERVICE_ROLE = {
  category: "Auth",
  severity: "high",
  confidence: 0.7,
};

let container: HTMLDivElement | null = null;

function render(ui: React.ReactElement): string {
  container = document.createElement("div");
  document.body.appendChild(container);
  act(() => {
    createRoot(container!).render(ui);
  });
  return container.textContent ?? "";
}

afterEach(() => {
  container?.remove();
  container = null;
});

describe("CategoryBars", () => {
  it("does not say 'not checked' over a category that holds a finding", () => {
    const text = render(
      <CategoryBars
        categories={{ Security: 10.0, Auth: 9.3 }}
        unexamined={["Auth"]}
        unexaminedWithFindings={["Auth"]}
        findings={[SERVICE_ROLE]}
      />,
    );

    expect(text).toContain("not surveyed");
    expect(text).not.toContain("not checked");
    // The number is still unearned: nobody surveyed the category.
    expect(text).not.toContain("9.3");
  });

  it("still says 'not checked' for a category that holds nothing", () => {
    const text = render(
      <CategoryBars
        categories={{ Auth: 9.3, "Money & Data": 10.0 }}
        unexamined={["Auth", "Money & Data"]}
        unexaminedWithFindings={["Auth"]}
        findings={[SERVICE_ROLE]}
      />,
    );

    // Both states on one page, which is the only way to see they differ.
    expect(text).toContain("not surveyed");
    expect(text).toContain("not checked");
  });

  it("falls back to the findings for a row stored before the key existed", () => {
    const text = render(
      <CategoryBars
        categories={{ Auth: 9.3 }}
        unexamined={["Auth"]}
        findings={[SERVICE_ROLE]}
      />,
    );

    expect(text).toContain("not surveyed");
  });

  it("prefers the score's list over the findings it was handed", () => {
    // The page does not always render every finding, so deriving would
    // under-report exactly the row this exists to correct. An empty list from
    // the scorer means "asked, nothing qualified" and must win over a
    // findings array that happens to contain an Auth row.
    const text = render(
      <CategoryBars
        categories={{ Auth: 10.0 }}
        unexamined={["Auth"]}
        unexaminedWithFindings={[]}
        findings={[SERVICE_ROLE]}
      />,
    );

    expect(text).toContain("not checked");
    expect(text).not.toContain("not surveyed");
  });
});
