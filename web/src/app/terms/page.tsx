import type { Metadata } from "next";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { LegalDocument } from "@/components/LegalDocument";

export const metadata: Metadata = {
  title: "Terms of Service — Drydock",
  description:
    "The terms governing your use of Drydock: what the service is, accounts and API keys, acceptable use, payment and refunds, liability, and governing law.",
};

async function loadContent(file: string): Promise<string> {
  return readFile(path.join(process.cwd(), "src/content", file), "utf8");
}

export default async function TermsPage() {
  const [en, ru] = await Promise.all([
    loadContent("terms.en.md"),
    loadContent("terms.ru.md"),
  ]);

  return <LegalDocument en={en} ru={ru} />;
}
