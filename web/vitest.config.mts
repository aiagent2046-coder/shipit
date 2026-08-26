import { fileURLToPath } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

// The frontend's first test runner. Until now `next build` was the only thing
// standing between a change to web/ and production: it type-checks and
// compiles, so it catches a component that cannot exist, and nothing at all
// about one that exists and behaves wrongly.
//
// That gap was not theoretical. tests/test_web_score_parity.py -- a PYTHON
// test -- reads web/src/lib/format.ts as TEXT and matches it with regular
// expressions, and says so in its own docstring: "Text matching is brittle,
// and it is the only cross-language check available here -- web/ has no test
// runner, only `next build`." With a runner, the band rules can be CALLED
// instead of grepped.
//
// jsdom rather than a browser. The one frontend defect the pre-launch run
// found that a machine could have caught was a hydration mismatch, and jsdom
// reaches it: renderToString + hydrateRoot is the same two-step the server and
// the browser perform, and React reports the same mismatch either way.
//
// WITH ONE TRAP, and this environment is what sets it. jsdom defines
// `navigator`, and the server does not -- so a test that calls renderToString
// straight into these globals is not running a server render at all. The first
// version of the hydration test did exactly that, passed against the broken
// code, and was only found out by putting the defect back and watching nothing
// fail. See BankTransferCheckout.test.tsx, which stubs `navigator` away for the
// server half.
//
// A real browser buys layout and paint, which is where the OTHER defect lived
// -- a control nobody could see -- and no automated check was ever going to
// catch that one. Adding Playwright to look for it would be theatre.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./vitest.setup.ts"],
    include: ["src/**/*.test.ts", "src/**/*.test.tsx"],
    // Tests live beside what they test rather than in a mirrored tree, so a
    // module and its test move together and a deleted module leaves no orphan.
    restoreMocks: true,
  },
});
