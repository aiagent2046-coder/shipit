"use client";

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useState,
} from "react";
import type { Account } from "@/lib/types";
import { getAccount, login, logout } from "@/lib/api";

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

interface KeyCtx {
  // No apiKey here any more. The key lives in an HttpOnly cookie the backend
  // sets at /v1/auth/login, so this page cannot read it -- which is the
  // point. `account.authenticated` is what callers actually needed from it.
  account: Account | null;
  loading: boolean;
  error: string | null;
  setKey: (key: string) => Promise<void>;
  clearKey: () => void;
}
const KeyContext = createContext<KeyCtx | null>(null);

function KeyProvider({ children }: { children: React.ReactNode }) {
  const [account, setAccount] = useState<Account | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      // No argument: the cookie rides along on its own.
      const acct = await getAccount();
      setAccount(acct);
    } catch (e) {
      setAccount(null);
      setError(e instanceof Error ? e.message : "Failed to resolve account");
    } finally {
      setLoading(false);
    }
  }, []);

  // The key used to sit in sessionStorage, where any script on the page --
  // an XSS, a compromised dependency -- could read it and keep it. It now
  // lives in an HttpOnly cookie, so there is nothing here to read and nothing
  // to restore on mount: one unauthenticated-looking call to /v1/account
  // either comes back with the session the cookie carries, or with the free
  // tier. Same tab-scoped lifetime as before; the cookie has no max-age.
  useEffect(() => {
    void refresh();
  }, [refresh]);

  const setKey = useCallback(
    async (key: string) => {
      setLoading(true);
      setError(null);
      try {
        setAccount(await login(key));
      } catch (e) {
        setAccount(null);
        setError(e instanceof Error ? e.message : "Failed to resolve account");
      } finally {
        setLoading(false);
      }
    },
    [],
  );

  const clearKey = useCallback(() => {
    // Server-side: the cookie is HttpOnly, so the page cannot drop it itself.
    void logout().finally(() => void refresh());
  }, [refresh]);

  return (
    <KeyContext.Provider
      value={{ account, loading, error, setKey, clearKey }}
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
