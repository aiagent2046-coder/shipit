import type { Metadata } from "next";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { LegalDocument } from "@/components/LegalDocument";

export const metadata: Metadata = {
  title: "Privacy Policy — Drydock",
  description:
    "How Drydock handles your code and data: what we collect, the third-party AI analysis, who we share data with, retention, and your rights.",
};

async function loadContent(file: string): Promise<string> {
  return readFile(path.join(process.cwd(), "src/content", file), "utf8");
}

export default async function PrivacyPage() {
  const [en, ru] = await Promise.all([
    loadContent("privacy.en.md"),
    loadContent("privacy.ru.md"),
  ]);

  return <LegalDocument en={en} ru={ru} />;
}
