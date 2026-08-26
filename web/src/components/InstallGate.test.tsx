import { afterEach, describe, expect, it, vi } from "vitest";
import { act } from "react";
import { createRoot } from "react-dom/client";
import type { InstallationStatus } from "@/lib/types";
import { InstallGate } from "./FixpackPurchase";

/**
 * The gate between an audit report and buying a Fix Pack.
 *
 * A Fix Pack IS a pull request, so the gate has one job: never let somebody
 * pay for one that cannot be opened. The case this file was written for is the
 * one that slipped through -- an installation that exists and is SUSPENDED.
 * GitHub answers 200 for it exactly as for a healthy one, so the old check
 * said "installed", the button was offered, and delivery would have got a 403
 * after the money was taken.
 *
 * Blocking is only half of it. "Install the GitHub App first" is the wrong
 * sentence for somebody who already installed it, and an install button they
 * have already used is worse than no button at all.
 */

const REPO = "https://github.com/acme/app";
const CHILD = "BUY THE FIX PACK";

vi.mock("@/lib/api", () => ({
  getInstallationStatus: vi.fn(),
}));

import { getInstallationStatus } from "@/lib/api";

function status(over: Partial<InstallationStatus> = {}): InstallationStatus {
  return {
    owner: "acme",
    repo: "app",
    app_configured: true,
    installed: true,
    suspended: false,
    install_url: null,
    ...over,
  };
}

async function mount(resolved: InstallationStatus | Error) {
  vi.mocked(getInstallationStatus).mockImplementation(() =>
    resolved instanceof Error
      ? Promise.reject(resolved)
      : Promise.resolve(resolved),
  );
  const container = document.createElement("div");
  document.body.appendChild(container);
  await act(async () => {
    createRoot(container).render(
      <InstallGate repoUrl={REPO}>
        <span>{CHILD}</span>
      </InstallGate>,
    );
  });
  return container;
}

const text = (c: HTMLElement) => c.textContent ?? "";

afterEach(() => {
  vi.restoreAllMocks();
  document.body.innerHTML = "";
});

describe("InstallGate", () => {
  it("lets the purchase through on a live installation", async () => {
    const c = await mount(status());
    expect(text(c)).toContain(CHILD);
  });

  it("blocks a suspended installation", async () => {
    const c = await mount(status({ installed: false, suspended: true }));
    expect(text(c)).not.toContain(CHILD);
  });

  it("tells a suspended owner to unsuspend, not to install again", async () => {
    const c = await mount(status({ installed: false, suspended: true }));

    expect(text(c)).toContain("suspended");
    // The wrong instruction, and the one the old copy would have given.
    expect(text(c)).not.toContain("Install the GitHub App first");
    // No button either: they have already installed it, so an install link
    // sends them back through a flow that would not lift the suspension.
    expect(c.querySelector("a")).toBeNull();
  });

  it("still offers the install link when the App is simply absent", async () => {
    const c = await mount(
      status({
        installed: false,
        suspended: false,
        install_url: "https://github.com/apps/x/installations/new?state=acme%2Fapp",
      }),
    );

    expect(text(c)).toContain("Install the GitHub App first");
    const link = c.querySelector("a");
    expect(link).not.toBeNull();
    expect(link!.getAttribute("href")).toContain("installations/new");
  });

  it("does not block when the check itself fails", async () => {
    // An unknown is not a refusal: the backend gates delivery anyway, and
    // refusing a sale because our own status call broke costs a customer for
    // a problem that may not exist.
    const c = await mount(new Error("network down"));
    expect(text(c)).toContain(CHILD);
  });

  it("does not block when this deployment has no App at all", async () => {
    const c = await mount(
      status({ app_configured: false, installed: null, suspended: null }),
    );
    expect(text(c)).toContain(CHILD);
  });
});
