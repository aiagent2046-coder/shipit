import { useContext, useEffect, type ReactNode } from "react";
import { afterAll, afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import LayoutRouter from "next/dist/client/components/layout-router";
import {
  AppRouterContext,
  GlobalLayoutRouterContext,
  LayoutRouterContext,
  TemplateContext,
} from "next/dist/shared/lib/app-router-context.shared-runtime";
import type { CacheNode, FlightRouterState } from "next/dist/shared/lib/app-router-types";
import { AuditForm } from "./AuditForm";

const { restoreBrowserVariant } = await vi.hoisted(async () => {
  // Next's compiler selects this browser variant (see its
  // build/browser-variant-modules.js). Vitest does not run that compiler.
  // Match the real browser bundle rather than importing the server-only
  // instant-validation implementation into jsdom. No router code is mocked.
  const { createRequire, Module } = await import("node:module");
  const require = createRequire(import.meta.url);
  // Every RSC node in this probe is already resolved. Fail closed if Next
  // unexpectedly attempts to load a Flight/bundler module in this unit test.
  vi.stubGlobal("__webpack_require__", () => {
    throw new Error("Unexpected webpack module load in resolved-route probe");
  });
  const key = require.resolve("next/dist/client/components/instant-validation/impl");
  const previous = require.cache[key];
  const replacement = new Module(key);
  replacement.exports = require("next/dist/client/components/instant-validation/impl.browser");
  require.cache[key] = replacement;
  // Match Next's other compiler-only browser alias; package consumers do not
  // have a standalone react-server-dom-webpack dependency installed.
  const resolver = Module as typeof Module & { _resolveFilename: (...args: unknown[]) => string };
  const originalResolve = resolver._resolveFilename;
  resolver._resolveFilename = function (request, ...args) {
    return originalResolve.call(this,
      request === "react-server-dom-webpack/client"
        ? require.resolve("next/dist/compiled/react-server-dom-webpack/client.browser")
        : request,
      ...args,
    );
  };
  return { restoreBrowserVariant: () => {
    vi.unstubAllGlobals();
    resolver._resolveFilename = originalResolve;
    if (previous) require.cache[key] = previous;
    else delete require.cache[key];
  } };
});

afterAll(restoreBrowserVariant);

// Exercise Next's actual segment renderer. This does not simulate a browser
// popstate event or claim to cover browser bfcache; route-tree changes are
// supplied directly, as they are after the App Router resolves a navigation.
// The application does not enable cacheComponents (Next 16.3.3 defaults false).
// Keeping a mocked router.push and the same mounted form alone would prove
// nothing about Back, because it would omit the segment renderer entirely.
function Template() {
  return useContext(TemplateContext);
}

function node(rsc: ReactNode): CacheNode {
  return {
    rsc,
    prefetchRsc: null,
    slots: null,
    scrollRef: null,
  } as CacheNode;
}

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  sessionStorage.clear();
});

it.each([
  { status: 202, body: { job_id: "job-fixture", status: "queued", access_token: "fixture" }, target: "/audit/pending/job-fixture?token=fixture" },
  { status: 200, body: { audit_id: "audit-fixture", access_token: "fixture" }, target: "/audit/audit-fixture?token=fixture" },
])("keeps the $status submit locked until leaving, then remounts ready when the home segment returns", async ({ status, body, target }) => {
  // Skip Next's development tooling only; React is already loaded in its
  // normal testing mode, so its real lifecycle and act checks remain enabled.
  vi.stubEnv("NODE_ENV", "production");
  const push = vi.fn();
  const fetch = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(
    JSON.stringify(body), { status },
  ));
  const mounted = vi.fn();
  const unmounted = vi.fn();
  function Home() {
    useEffect(() => { mounted(); return () => { unmounted(); }; }, []);
    return <AuditForm />;
  }
  const home = node(<Home />);
  const audit = node(<p>Audit destination</p>);
  function route(segment: string, active: CacheNode) {
    const tree: FlightRouterState = ["", { children: [segment, {}] }];
    return (
      <AppRouterContext.Provider value={{ push, back: vi.fn(), forward: vi.fn(), refresh: vi.fn(), replace: vi.fn(), prefetch: vi.fn(), bfcacheId: "fixture" }}>
        <GlobalLayoutRouterContext.Provider value={{ tree, focusAndScrollRef: { forceScroll: false, scrollRef: { current: false }, onlyHashChange: false, hashFragment: null }, nextUrl: null, previousNextUrl: null }}>
          <LayoutRouterContext.Provider value={{ parentTree: tree, parentCacheNode: { ...node(null), slots: { children: active } }, parentSegmentPath: null, parentParams: {}, parentLoadingData: null, debugNameContext: "/", url: segment === "__PAGE__" ? "/" : target, isActive: true }}>
            <LayoutRouter
              parallelRouterKey="children" template={<Template />}
              error={undefined} errorStyles={undefined} errorScripts={undefined}
              templateStyles={undefined} templateScripts={undefined}
              notFound={undefined} forbidden={undefined} unauthorized={undefined}
            />
          </LayoutRouterContext.Provider>
        </GlobalLayoutRouterContext.Provider>
      </AppRouterContext.Provider>
    );
  }
  const view = render(route("__PAGE__", home));
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "https://github.com/example/repo" } });
  fireEvent.click(screen.getByRole("button", { name: "Audit my app" }));
  await waitFor(() => expect(push).toHaveBeenCalledWith(target));

  const waiting = screen.getByRole("button", { name: /Submitting…/ }) as HTMLButtonElement;
  expect(waiting.disabled).toBe(true);
  fireEvent.click(waiting);
  expect(fetch).toHaveBeenCalledTimes(1);
  expect(mounted).toHaveBeenCalledTimes(1);
  expect(unmounted).not.toHaveBeenCalled();

  view.rerender(route("audit", audit));
  expect(screen.queryByRole("textbox")).toBeNull();
  expect(unmounted).toHaveBeenCalledTimes(1);

  // Reuse the same cached RSC element, as a restored router cache can do.
  // React component state still resets because the prior segment unmounted.
  view.rerender(route("__PAGE__", home));
  expect(mounted).toHaveBeenCalledTimes(2);
  expect((screen.getByRole("button", { name: "Audit my app" }) as HTMLButtonElement).disabled).toBe(false);
  expect((screen.getByRole("textbox") as HTMLInputElement).value).toBe("");
  expect(fetch).toHaveBeenCalledTimes(1);
});
