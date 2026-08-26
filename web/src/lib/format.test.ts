/**
 * What a customer is told about their own security, on the page they see first.
 *
 * THESE RULES ALREADY HAD A TEST, and it was written in Python. Until this file
 * existed, web/ had no runner, so tests/test_web_score_parity.py read
 * format.ts as TEXT and matched it with regular expressions -- and said so:
 * "Text matching is brittle, and it is the only cross-language check available
 * here." That test still has a job no test here can do, because it compares
 * these numbers to app/scan/scoring.py's. What it should never have had to do
 * is assert BEHAVIOUR by pattern-matching source, and that half moves here,
 * where the functions can be called.
 *
 * The stakes are not cosmetic. Two of the defects in this repository's history
 * were a category reading "nothing serious found" over an endpoint with no
 * authentication at all. A band rule that quietly regresses does not crash and
 * does not fail a build; it reassures somebody about a product that is not
 * safe, and they ship it.
 */

import { describe, expect, it } from "vitest";

import {
  categoryBand,
  formatMoney,
  scoreColor,
  scoreVerdict,
  seriousCategories,
  severityCounts,
  sortFindings,
} from "./format";

describe("formatMoney", () => {
  it("writes roubles with the rouble sign", () => {
    expect(formatMoney("990.00", "RUB")).toBe("990.00 ₽");
  });

  it("never puts a dollar sign in front of a rouble amount", () => {
    // THE DEFECT, FOUND ON PRODUCTION 2026-08-24. The audit page — the screen a
    // buyer actually pays from, and the one a payment aggregator's reviewer
    // reaches — rendered "$990.00 RUB". A literal "$" had been typed beside a
    // value that carries its own currency code, so when the product was
    // repriced from dollars to roubles the two could disagree with nothing to
    // notice. Four days after the site was rejected for not stating its price
    // properly.
    for (const currency of ["RUB", "USD", "EUR", "XYZ"]) {
      expect(formatMoney("990.00", currency)).not.toContain("$");
    }
  });

  it("falls back to the ISO code rather than guessing a symbol", () => {
    // An unfamiliar currency should look unfamiliar. Reaching for "$" as a
    // default is how a rouble price came to be advertised in dollars.
    expect(formatMoney("10", "USD")).toBe("10 USD");
    expect(formatMoney("10", "XYZ")).toBe("10 XYZ");
  });

  it("shows the number alone when there is no currency to show", () => {
    // An older API response, or a row from before the column existed. A bare
    // number is honest; "990.00 undefined" is a bug the buyer reads.
    expect(formatMoney("990.00", null)).toBe("990.00");
    expect(formatMoney("990.00", undefined)).toBe("990.00");
    expect(formatMoney("990.00", "  ")).toBe("990.00");
  });
});

describe("categoryBand", () => {
  it("puts a value at the gate in the top band", () => {
    // 7.0 is GATE_THRESHOLD itself. An accidental `>` for `>=` moves exactly
    // this value and nothing else, which is why it is asserted alone.
    expect(categoryBand(7.0).label).toBe("nothing serious found");
    expect(categoryBand(6.99).label).toBe("problems found");
  });

  it("puts a value at the floor above 'serious problems'", () => {
    expect(categoryBand(3.5).label).toBe("problems found");
    expect(categoryBand(3.49).label).toBe("serious problems");
  });

  it("refuses the top band to a category holding a serious finding", () => {
    // THE REGRESSION THIS EXISTS FOR. Audits ba360e21 and b4bf9c07 both drew
    // Auth in the top band -- "nothing serious found" -- over an
    // unauthenticated API and unsalted SHA-256 passwords, with "Fix before
    // launch" rows immediately underneath. One high finding costs 1.0 against
    // a threshold of 7.0, so arithmetic alone needs four of them to move a
    // category out of the top band. The flag is what makes one enough.
    const top = categoryBand(9.5, false);
    const held = categoryBand(9.5, true);

    expect(top.label).toBe("nothing serious found");
    expect(held.label).toBe("problems found");
  });

  it("never lifts a row the flag does not apply to", () => {
    // The flag forbids the top band. It must not also PROMOTE: a category
    // scoring 1.0 that holds a serious finding is still at the bottom, and
    // rendering it as "problems found" would be an improvement it did not
    // earn.
    expect(categoryBand(1.0, true).label).toBe("serious problems");
    expect(categoryBand(1.0, false).label).toBe("serious problems");
  });

  it("draws the bar from the band and never from the value", () => {
    // Two rows in one band must look identical. Keying width or colour on the
    // value restates the exact number in pixels -- the same claim the band
    // exists to withhold, in a channel nobody thought to check.
    const low = categoryBand(3.6);
    const high = categoryBand(6.9);
    expect(low.pct).toBe(high.pct);
    expect(low.color).toBe(high.color);
  });
});

describe("seriousCategories", () => {
  it("collects the categories holding a confident critical or high", () => {
    expect(
      seriousCategories([
        { category: "Auth", severity: "critical", confidence: 0.9 },
        { category: "Security", severity: "high", confidence: 0.7 },
        { category: "Web", severity: "medium", confidence: 1.0 },
      ]),
    ).toEqual(new Set(["Auth", "Security"]));
  });

  it("ignores a serious finding nobody is sure about", () => {
    // 0.7 is the scorer's own floor for letting a single finding make a
    // categorical claim. Below it, one uncertain guess would demote a whole
    // category on the strength of something the engine itself doubts.
    expect(
      seriousCategories([
        { category: "Auth", severity: "critical", confidence: 0.69 },
      ]).size,
    ).toBe(0);
  });

  it("treats a missing confidence as no confidence", () => {
    // A finding with no confidence recorded is not a confident finding. The
    // opposite reading -- absent means certain -- would let older rows that
    // predate the field demote categories they were never meant to.
    expect(
      seriousCategories([{ category: "Auth", severity: "critical" }]).size,
    ).toBe(0);
  });

  it("ignores a serious finding with no category to attach it to", () => {
    expect(
      seriousCategories([{ severity: "critical", confidence: 1 }]).size,
    ).toBe(0);
  });
});

describe("scoreVerdict and scoreColor", () => {
  it.each([
    [10, "Ready to ship"],
    [8, "Ready to ship"],
    [7.99, "Some work before launch"],
    [5, "Some work before launch"],
    [4.99, "Not production-ready yet"],
    [0, "Not production-ready yet"],
  ])("reads %s as %s", (total, verdict) => {
    expect(scoreVerdict(total)).toBe(verdict);
  });

  it("changes colour on the same boundaries as the words", () => {
    // The sentence and the colour are two statements of one judgement. If they
    // part company, a report reads "Ready to ship" in red, and the reader has
    // to decide which of us to believe.
    expect(scoreColor(8)).not.toBe(scoreColor(7.99));
    expect(scoreColor(5)).not.toBe(scoreColor(4.99));
    expect(scoreColor(9)).toBe(scoreColor(8));
  });
});

describe("sortFindings", () => {
  it("puts the worst first and breaks ties by confidence", () => {
    const sorted = sortFindings([
      { severity: "low", confidence: 1.0, id: "low" },
      { severity: "critical", confidence: 0.5, id: "unsure-critical" },
      { severity: "critical", confidence: 0.9, id: "sure-critical" },
      { severity: "medium", confidence: 0.9, id: "medium" },
    ] as { severity: "low" | "critical" | "medium"; confidence: number; id: string }[]);

    expect(sorted.map((f) => f.id)).toEqual([
      "sure-critical", "unsure-critical", "medium", "low",
    ]);
  });

  it("does not reorder the array it was handed", () => {
    // The caller's array is often React state. Sorting in place would mutate
    // it without a re-render and leave the page showing the old order until
    // something unrelated moved.
    const input = [
      { severity: "low" as const },
      { severity: "critical" as const },
    ];
    sortFindings(input);
    expect(input.map((f) => f.severity)).toEqual(["low", "critical"]);
  });
});

describe("severityCounts", () => {
  it("counts every severity and reports zero for the absent ones", () => {
    // A missing key would render as "undefined" beside a label. Zero is a
    // fact; undefined is a bug the reader sees.
    expect(
      severityCounts([
        { severity: "critical" }, { severity: "critical" }, { severity: "low" },
      ]),
    ).toEqual({ critical: 2, high: 0, medium: 0, low: 1 });
  });
});
