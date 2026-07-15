"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { Account } from "@/lib/types";
import { getAccount } from "@/lib/api";

/* ---------------- Theme ---------------- */

type Theme = "dark" | "light";
const THEME_KEY = "shipit-theme";

interface ThemeCtx {
  theme: Theme;
  toggle: () => void;
}
const ThemeContext = createContext<ThemeCtx | null>(null);

function applyTheme(theme: Theme) {
  const root = document.documentElement;
  root.classList.toggle("dark", theme === "dark");
  root.style.colorScheme = theme;
}

function ThemeProvider({ children }: { children: React.ReactNode }) {
  // Default identity is dark; the inline script in layout.tsx has already
  // set the class pre-hydration to avoid a flash. Mirror its logic here.
  const [theme, setTheme] = useState<Theme>("dark");

  useEffect(() => {
    const stored = window.localStorage.getItem(THEME_KEY) as Theme | null;
    const initial: Theme =
      stored ??
      (window.matchMedia?.("(prefers-color-scheme: light)").matches
        ? "light"
        : "dark");
    setTheme(initial);
    applyTheme(initial);
  }, []);

  const toggle = useCallback(() => {
    setTheme((prev) => {
      const next: Theme = prev === "dark" ? "light" : "dark";
      window.localStorage.setItem(THEME_KEY, next);
      applyTheme(next);
      return next;
    });
  }, []);

  return (
    <ThemeContext.Provider value={{ theme, toggle }}>
      {children}
    </ThemeContext.Provider>
  );
}

export function useTheme(): ThemeCtx {
  const ctx = useContext(ThemeContext);
  if (!ctx) throw new Error("useTheme must be used within ThemeProvider");
  return ctx;
}

/* ---------------- API key / account ---------------- */

const KEY_STORAGE = "shipit-api-key";

interface KeyCtx {
  apiKey: string | null;
  account: Account | null;
  loading: boolean;
  error: string | null;
  setKey: (key: string) => Promise<void>;
  clearKey: () => void;
}
const KeyContext = createContext<KeyCtx | null>(null);

function KeyProvider({ children }: { children: React.ReactNode }) {
  const [apiKey, setApiKey] = useState<string | null>(null);
  const [account, setAccount] = useState<Account | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async (key: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const acct = await getAccount(key);
      setAccount(acct);
    } catch (e) {
      setAccount(null);
      setError(e instanceof Error ? e.message : "Failed to resolve account");
    } finally {
      setLoading(false);
    }
  }, []);

  // This is a real standalone Vercel deployment (not a sandboxed iframe),
  // so localStorage is the right place to remember the key across visits.
  useEffect(() => {
    const stored = window.localStorage.getItem(KEY_STORAGE);
    if (stored) {
      setApiKey(stored);
      void refresh(stored);
    } else {
      void refresh(null);
    }
  }, [refresh]);

  const setKey = useCallback(
    async (key: string) => {
      const trimmed = key.trim();
      window.localStorage.setItem(KEY_STORAGE, trimmed);
      setApiKey(trimmed);
      await refresh(trimmed);
    },
    [refresh],
  );

  const clearKey = useCallback(() => {
    window.localStorage.removeItem(KEY_STORAGE);
    setApiKey(null);
    void refresh(null);
  }, [refresh]);

  return (
    <KeyContext.Provider
      value={{ apiKey, account, loading, error, setKey, clearKey }}
    >
      {children}
    </KeyContext.Provider>
  );
}

export function useApiKey(): KeyCtx {
  const ctx = useContext(KeyContext);
  if (!ctx) throw new Error("useApiKey must be used within KeyProvider");
  return ctx;
}

export function Providers({ children }: { children: React.ReactNode }) {
  return (
    <ThemeProvider>
      <KeyProvider>{children}</KeyProvider>
    </ThemeProvider>
  );
}
