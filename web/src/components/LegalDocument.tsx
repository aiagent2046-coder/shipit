"use client";

import { useState, type ComponentPropsWithoutRef } from "react";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type Lang = "en" | "ru";

// Element renderers map GitHub-flavored markdown onto the site's theme tokens
// (see globals.css / tailwind.config.ts) so the legal pages read like the rest
// of Drydock in both light and dark mode.
const markdownComponents = {
  h1: (props: ComponentPropsWithoutRef<"h1">) => (
    <h1
      className="mt-2 text-2xl font-semibold tracking-tight sm:text-3xl"
      {...props}
    />
  ),
  h2: (props: ComponentPropsWithoutRef<"h2">) => (
    <h2
      className="mt-10 border-b border-border pb-2 text-xl font-semibold tracking-tight"
      {...props}
    />
  ),
  h3: (props: ComponentPropsWithoutRef<"h3">) => (
    <h3 className="mt-6 text-lg font-semibold" {...props} />
  ),
  p: (props: ComponentPropsWithoutRef<"p">) => (
    <p className="mt-4 leading-7 text-text" {...props} />
  ),
  ul: (props: ComponentPropsWithoutRef<"ul">) => (
    <ul className="mt-4 list-disc space-y-2 pl-6 marker:text-muted" {...props} />
  ),
  ol: (props: ComponentPropsWithoutRef<"ol">) => (
    <ol
      className="mt-4 list-decimal space-y-2 pl-6 marker:text-muted"
      {...props}
    />
  ),
  li: (props: ComponentPropsWithoutRef<"li">) => (
    <li className="leading-7 text-text" {...props} />
  ),
  a: ({ href, ...props }: ComponentPropsWithoutRef<"a">) => (
    <a
      href={href}
      className="text-accent underline underline-offset-2 hover:opacity-80"
      {...props}
    />
  ),
  strong: (props: ComponentPropsWithoutRef<"strong">) => (
    <strong className="font-semibold text-text" {...props} />
  ),
  code: (props: ComponentPropsWithoutRef<"code">) => (
    <code
      className="rounded bg-surface px-1.5 py-0.5 font-mono text-[0.85em] text-text"
      {...props}
    />
  ),
  hr: () => <hr className="my-8 border-border" />,
  blockquote: (props: ComponentPropsWithoutRef<"blockquote">) => (
    <blockquote
      className="mt-4 border-l-2 border-border pl-4 italic text-muted"
      {...props}
    />
  ),
  table: (props: ComponentPropsWithoutRef<"table">) => (
    <div className="mt-4 overflow-x-auto rounded-xl border border-border">
      <table className="w-full min-w-[640px] border-collapse text-sm" {...props} />
    </div>
  ),
  thead: (props: ComponentPropsWithoutRef<"thead">) => (
    <thead className="bg-surface" {...props} />
  ),
  th: (props: ComponentPropsWithoutRef<"th">) => (
    <th
      className="border-b border-border px-4 py-3 text-left align-top font-medium text-muted"
      {...props}
    />
  ),
  td: (props: ComponentPropsWithoutRef<"td">) => (
    <td
      className="border-b border-border px-4 py-3 align-top leading-6 text-text"
      {...props}
    />
  ),
};

export function LegalDocument({ en, ru }: { en: string; ru: string }) {
  const [lang, setLang] = useState<Lang>("en");

  return (
    <div className="mx-auto max-w-3xl px-4 py-10">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Link href="/" className="text-sm text-muted hover:text-text">
          ← Back to audit
        </Link>
        <div
          role="group"
          aria-label="Document language"
          className="inline-flex overflow-hidden rounded-md border border-border text-sm"
        >
          <LangButton
            active={lang === "en"}
            onClick={() => setLang("en")}
            label="English"
          >
            EN
          </LangButton>
          <LangButton
            active={lang === "ru"}
            onClick={() => setLang("ru")}
            label="Русский"
          >
            RU
          </LangButton>
        </div>
      </div>

      <article className="mt-6">
        <ReactMarkdown
          remarkPlugins={[remarkGfm]}
          components={markdownComponents}
        >
          {lang === "en" ? en : ru}
        </ReactMarkdown>
      </article>
    </div>
  );
}

function LangButton({
  active,
  onClick,
  label,
  children,
}: {
  active: boolean;
  onClick: () => void;
  label: string;
  children: React.ReactNode;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      aria-label={label}
      className={`px-3 py-1.5 font-medium transition-colors ${
        active
          ? "bg-accent text-accent-fg"
          : "text-muted hover:text-text"
      }`}
    >
      {children}
    </button>
  );
}
