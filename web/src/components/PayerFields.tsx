"use client";

import { useEffect, useState } from "react";

/**
 * The contact fields both checkouts collect, in one place.
 *
 * There are two ways to pay for a Fix Pack — a card through ЮKassa and a
 * manual transfer confirmed by a person — and both need the same thing from
 * the buyer: who they are, where to write to them, and in which language.
 * These were written once for the manual rail; the card rail would otherwise
 * have grown a second copy, and the copy that drifts is always the one nobody
 * is looking at.
 */

export function PayerInput({
  label,
  type,
  autoComplete,
  placeholder,
  value,
  onChange,
  disabled,
}: {
  label: string;
  type: "text" | "email";
  autoComplete: string;
  placeholder: string;
  value: string;
  onChange: (v: string) => void;
  disabled?: boolean;
}) {
  return (
    <label className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm focus-within:border-accent">
      <span className="shrink-0 text-muted">{label}</span>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        autoComplete={autoComplete}
        disabled={disabled}
        maxLength={200}
        className="w-full min-w-0 bg-transparent text-right outline-hidden disabled:opacity-60"
      />
    </label>
  );
}

export type PayerLocale = "en" | "ru";

/**
 * What language we will write to this person in, guessed from their browser
 * and SHOWN rather than assumed.
 *
 * READ AFTER MOUNT, not in a lazy initialiser, and the difference is not
 * stylistic. `navigator` does not exist during the server render, so the
 * server always produced "en"; a lazy initialiser then produced "ru" on a
 * Russian browser during hydration, and the two disagreed. Measured in a real
 * Chromium under `locale: ru-RU`: the control ends up correct, and React logs
 * error #418 — a hydration mismatch it recovers from by re-rendering. So it
 * worked, loudly, by accident.
 *
 * Starting at "en" on both sides and correcting in an effect makes the two
 * renders agree, at the cost of one frame where English is highlighted.
 */
export function usePayerLocale(): [PayerLocale, (v: PayerLocale) => void] {
  const [locale, setLocale] = useState<PayerLocale>("en");
  useEffect(() => {
    if (
      typeof navigator !== "undefined" &&
      navigator.language?.toLowerCase().startsWith("ru")
    ) {
      setLocale("ru");
    }
  }, []);
  return [locale, setLocale];
}

/**
 * A FIELD, NOT A FOOTNOTE. This was a toggle in `text-xs text-muted` sitting
 * third in a row of identically styled small-print paragraphs, and the first
 * person asked to find it could not — which for a GUESS about somebody's
 * language is nearly the same as not showing it at all.
 *
 * Two named options rather than a toggle. The toggle was labelled with the
 * state it would move TO ("Switch to English" while Russian was selected),
 * which is the standard toggle ambiguity: the label reads equally well as the
 * current setting. Two buttons with `aria-pressed` say what is chosen and what
 * is available at the same time, and each is written in its own language, so
 * neither needs translating to be understood.
 */
export function LocaleField({
  value,
  onChange,
  disabled,
}: {
  value: PayerLocale;
  onChange: (v: PayerLocale) => void;
  disabled?: boolean;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border border-border bg-surface px-3 py-2 text-sm">
      <span className="shrink-0 text-muted">
        {value === "ru" ? "Язык писем о платеже" : "Language for payment emails"}
      </span>
      <div className="flex gap-1.5" role="group">
        {(["en", "ru"] as const).map((code) => (
          <button
            key={code}
            type="button"
            aria-pressed={value === code}
            onClick={() => onChange(code)}
            disabled={disabled}
            className={
              "rounded px-2.5 py-1 text-sm disabled:opacity-60 " +
              (value === code
                ? "bg-accent text-accent-fg"
                : "border border-border text-muted hover:text-text")
            }
          >
            {code === "ru" ? "Русский" : "English"}
          </button>
        ))}
      </div>
    </div>
  );
}

/**
 * Whether a name and an email have both been given. Deliberately the weakest
 * check that still rejects an empty form: the backend validates properly, and
 * a stricter guess here would disable the pay button for a real buyer with an
 * unusual address, which costs a sale to gain nothing.
 */
export function contactGiven(name: string, email: string): boolean {
  return name.trim().length > 0 && email.trim().includes("@");
}
