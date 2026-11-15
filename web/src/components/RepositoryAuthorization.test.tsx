import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { FixpackPurchase, PaymentMethods } from "./FixpackPurchase";
import { createFixpackBankTransferInvoice, createFixpackCardPayment } from "@/lib/api";

const GITHUB_TOKEN = "fixture_delivery_token";
const PAYER = { payer_name: "Ada", payer_email: "ada@example.invalid" };
afterEach(() => { cleanup(); vi.unstubAllGlobals(); vi.restoreAllMocks(); });

it.each(["bank", "card"])("sends the caller credential only as a header on %s checkout", async (rail) => {
  const fetchMock = vi.fn(async () => new Response("{}", { status: 201 }));
  vi.stubGlobal("fetch", fetchMock);
  if (rail === "bank") await createFixpackBankTransferInvoice("audit", PAYER, GITHUB_TOKEN);
  else await createFixpackCardPayment("audit", PAYER, "audit-read-token", GITHUB_TOKEN);
  const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
  expect(new Headers(init.headers).get("X-GitHub-Token")).toBe(GITHUB_TOKEN);
  expect(url).not.toContain(GITHUB_TOKEN);
  expect(init.body).not.toContain(GITHUB_TOKEN);
});

it("requires a repository token before allowing card payment, without checking the service App", () => {
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  const saved = vi.spyOn(Storage.prototype, "setItem");
  render(<PaymentMethods auditId="audit" repoUrl="https://github.com/acme/app"
    accessToken="audit-read-token" price={{ fixpack: { amount: "990", currency: "RUB" },
    methods: { card: true, bank_transfer: false } }} />);
  fireEvent.change(screen.getByLabelText("Your name"), { target: { value: "Ada" } });
  fireEvent.change(screen.getByLabelText("Your email"), { target: { value: "ada@example.invalid" } });
  expect((screen.getByRole("button", { name: /Pay .* by card/ }) as HTMLButtonElement).disabled).toBe(true);
  const token = screen.getByLabelText("GitHub delivery token") as HTMLInputElement;
  expect(token.type).toBe("password");
  expect(token.autocomplete).toBe("off");
  fireEvent.change(token, { target: { value: GITHUB_TOKEN } });
  expect((screen.getByRole("button", { name: /Pay .* by card/ }) as HTMLButtonElement).disabled).toBe(false);
  expect(saved.mock.calls.some((args) => args.includes(GITHUB_TOKEN))).toBe(false);
  expect(fetchMock).not.toHaveBeenCalled();
});

it("does not reveal bank payment details until repository authority is supplied", () => {
  render(<PaymentMethods auditId="audit" repoUrl="https://github.com/acme/app"
    accessToken="audit-read-token" price={{ fixpack: { amount: "990", currency: "RUB" },
    methods: { card: false, bank_transfer: true } }} />);
  fireEvent.change(screen.getByLabelText("Your name"), { target: { value: "Ada" } });
  fireEvent.change(screen.getByLabelText("Your email"), { target: { value: "ada@example.invalid" } });
  const submit = screen.getByRole("button", { name: "Show card number" }) as HTMLButtonElement;
  expect(submit.disabled).toBe(true);
  fireEvent.change(screen.getByLabelText("GitHub delivery token"), { target: { value: GITHUB_TOKEN } });
  expect(submit.disabled).toBe(false);
});

it("resumes an existing paid order with a new token and never opens another payment", async () => {
  const calls: Array<[string, RequestInit | undefined]> = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    calls.push([url, init]);
    if (url.includes("delivery-authorization")) return new Response("{}", { status: 200 });
    if (url.includes("fixpack-status")) return new Response(JSON.stringify({
      status: "awaiting_authorization", pr_url: null, delivery_reference: "DRY-EXISTING",
    }), { status: 200 });
    return new Response("{}", { status: 503 });
  }));
  render(<FixpackPurchase auditId="audit" repoUrl="https://github.com/acme/app" accessToken="owner-read-token" />);
  await screen.findByText("Renew GitHub access to continue your paid Fix Pack");
  expect((screen.getByLabelText("Payment reference") as HTMLInputElement).value).toBe("DRY-EXISTING");
  expect(screen.queryByText("Pay by bank transfer")).toBeNull();
  const inputs = screen.getAllByLabelText("GitHub delivery token");
  fireEvent.change(inputs[inputs.length - 1], { target: { value: GITHUB_TOKEN } });
  fireEvent.click(screen.getByRole("button", { name: "Authorize and resume existing order" }));
  await waitFor(() => expect(screen.queryByText("Renew GitHub access to continue your paid Fix Pack")).toBeNull());
  expect(screen.getByText(/Generating your fix/)).toBeTruthy();
  const posts = calls.filter(([, init]) => init?.method === "POST");
  expect(posts).toHaveLength(1);
  const [url, init] = posts[0];
  expect(url).toContain("/v1/audits/audit/fixpack/delivery-authorization");
  expect(new Headers(init!.headers).get("X-GitHub-Token")).toBe(GITHUB_TOKEN);
  expect(JSON.parse(init!.body as string)).toEqual({ reference: "DRY-EXISTING", audit_token: "owner-read-token" });
  expect(init!.body).not.toContain(GITHUB_TOKEN);
  expect(document.querySelector(`input[value="${GITHUB_TOKEN}"]`)).toBeNull();
});

it("keeps an unauthorized renewal recoverable and shows a fixed message", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url.includes("delivery-authorization")) return new Response(JSON.stringify({
      detail: { reason: "repository_write_access_required", detail: "upstream internal text" },
    }), { status: 403 });
    if (url.includes("fixpack-status")) return new Response(JSON.stringify({
      status: "awaiting_authorization", pr_url: null, delivery_reference: "DRY-EXISTING",
    }), { status: 200 });
    return new Response("{}", { status: 503 });
  }));
  render(<FixpackPurchase auditId="audit" repoUrl="https://github.com/acme/app" accessToken="owner-read-token" />);
  await screen.findByText("Renew GitHub access to continue your paid Fix Pack");
  fireEvent.change(screen.getByLabelText("Payment reference"), { target: { value: "DRY-EXISTING" } });
  const inputs = screen.getAllByLabelText("GitHub delivery token");
  fireEvent.change(inputs[inputs.length - 1], { target: { value: GITHUB_TOKEN } });
  fireEvent.click(screen.getByRole("button", { name: "Authorize and resume existing order" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent",
    "This token does not authorize this repository. Check the repository selection and your write access.");
  expect(screen.queryByText(/upstream internal/)).toBeNull();
  expect(screen.queryByText(/Generating your fix/)).toBeNull();
});

it("keeps recovery available for a previously paid order when the audit is no longer auto-fixable", async () => {
  const calls: Array<[string, RequestInit | undefined]> = [];
  vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
    calls.push([url, init]);
    if (url.includes("delivery-authorization")) return new Response("{}", { status: 200 });
    if (url.includes("fixpack-status")) return new Response(JSON.stringify({
      status: "awaiting_authorization", pr_url: null, delivery_reference: "DRY-LEGACY",
    }), { status: 200 });
    return new Response("{}", { status: 503 });
  }));
  render(<FixpackPurchase auditId="audit" repoUrl="https://github.com/acme/app"
    accessToken="owner-read-token" autoFixable={false} />);
  await screen.findByText("Renew GitHub access to continue your paid Fix Pack");
  expect(screen.queryByText("Pay by bank transfer")).toBeNull();
  expect(screen.queryByText("Pay by card")).toBeNull();
  expect((screen.getByLabelText("Payment reference") as HTMLInputElement).value).toBe("DRY-LEGACY");
  fireEvent.change(screen.getByLabelText("GitHub delivery token"), { target: { value: GITHUB_TOKEN } });
  fireEvent.click(screen.getByRole("button", { name: "Authorize and resume existing order" }));
  await screen.findByText(/Generating your fix/);
  expect(calls.filter(([, init]) => init?.method === "POST").map(([url]) => url))
    .toEqual([expect.stringContaining("/fixpack/delivery-authorization")]);
});

it("shows the existing order's failure when a legacy audit has no repository URL", async () => {
  vi.stubGlobal("fetch", vi.fn(async (url: string) => {
    if (url.includes("fixpack-status")) return new Response(JSON.stringify({
      status: "failed", pr_url: null,
    }), { status: 200 });
    return new Response("{}", { status: 503 });
  }));
  render(<FixpackPurchase auditId="legacy-audit" repoUrl={null} accessToken="owner-read-token" />);
  expect(await screen.findByText(/Fix Pack generation failed/)).toBeTruthy();
  expect(screen.queryByLabelText("GitHub delivery token")).toBeNull();
  expect(screen.queryByText("Pay by bank transfer")).toBeNull();
});
