import Link from "next/link";
import { AuditForm } from "@/components/AuditForm";
import { DemoReport } from "@/components/DemoReport";

/**
 * Landing copy. Two rules held on purpose.
 *
 * 1. Everything listed here maps to something the pipeline actually runs: the
 *    static checks in app/scan/checks.py (env-file-committed,
 *    gitignore-missing-secrets, no-tests, no-ci, no-dockerfile), the secret
 *    rules in app/scan/secrets.py, and the two LLM rubrics in
 *    app/scan/llm_scan.py (auth, security). Nothing aspirational, and the
 *    Correctness and Config score categories are not advertised because no
 *    producer assigns findings to them yet.
 *
 * 2. The free/paid line is stated together with what the paid thing does and
 *    does not change. The previous copy named "missing auth" and "no tests"
 *    and then said it "ships the fix as a pull request", which reads as a
 *    promise to fix those. A Fix Pack rewrites secrets and secret hygiene
 *    (FixpackPlan carries exactly secret_fixes and config_fixes) and touches
 *    nothing else. Selling the wider promise is how you earn a refund from
 *    someone who trusted you.
 *
 * No prices here: /pricing owns the numbers so they change in one place.
 */

const LOOKS_FOR: { title: string; body: string }[] = [
  {
    title: "Credentials sitting in the code",
    body: "AWS keys, GitHub tokens, Stripe live keys, Supabase service keys, bot tokens, private keys — committed to the repository, where anyone who gets the code gets them too.",
  },
  {
    title: "Secrets that slipped into git",
    body: "A .env committed by mistake, or a .gitignore that never covered the files holding your keys. Both are quiet until they aren't.",
  },
  {
    title: "Authentication that isn't",
    body: "Routes that change data without checking who asked, hand-rolled token verification, passwords compared without hashing, a server trusting whatever user id the browser sends it, row-level security left switched off.",
  },
  {
    title: "Ways in for a stranger",
    body: "SQL and command injection, user input reaching somewhere dangerous unchecked, CORS open to any site with credentials, secrets shipped to the browser in NEXT_PUBLIC_ variables, webhooks that accept anything.",
  },
  {
    title: "Nothing catching mistakes",
    body: "No tests at all, so nothing tells you the login broke — until a user does.",
  },
  {
    title: "No way to run it anywhere else",
    body: "No CI and no Dockerfile, so the app only really exists inside the tool that generated it.",
  },
];

export default function LandingPage() {
  return (
    <div className="mx-auto max-w-5xl px-4">
      {/* Hero — the one expressive marketing moment. Larger type is allowed
          here; interior pages stay capped. */}
      <section className="pt-16 pb-12 sm:pt-24 sm:pb-16">
        <div className="mx-auto max-w-3xl text-center">
          <span className="inline-block rounded-full border border-border bg-surface px-3 py-1 text-xs text-muted">
            Your AI Production Engineer
          </span>
          <h1 className="mt-5 text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
            Is your app{" "}
            <span className="text-accent">ready to ship?</span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-muted">
            You built it with Lovable, Bolt or v0, and it works. Drydock reads
            the code the way a production engineer would before letting it near
            real users — and tells you, in plain language, what would go wrong
            and what it costs you to leave it.
          </p>
        </div>

        <div className="mx-auto mt-10 max-w-2xl">
          <AuditForm />
        </div>

        <p className="mt-6 text-center text-sm text-muted">
          Free, and no signup. Paste a public repository URL.
        </p>
      </section>

      {/* The problem list. This is the "what does it actually solve" section
          the hero can only gesture at. */}
      <section className="border-t border-border pt-14 pb-16">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-2xl font-semibold tracking-tight sm:text-3xl">
            What we go looking for
          </h2>
          <p className="mt-3 text-muted">
            The things that turn a working demo into an incident: money spent by
            someone else&apos;s hands, a database anyone can read, an app nobody
            can redeploy. Every item below is a check that runs, not a plan.
          </p>
        </div>

        <ul className="mt-10 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {LOOKS_FOR.map((item) => (
            <li
              key={item.title}
              className="rounded-xl border border-border bg-elevated p-5"
            >
              <h3 className="font-medium">{item.title}</h3>
              <p className="mt-2 text-sm text-muted">{item.body}</p>
            </li>
          ))}
        </ul>
      </section>

      {/* The money section. Deliberately states the limits of the paid product
          in the same place it asks to be paid. */}
      <section className="border-t border-border pt-14 pb-16">
        <div className="mx-auto max-w-3xl">
          <h2 className="text-center text-2xl font-semibold tracking-tight sm:text-3xl">
            Finding it is free. Fixing it is what you pay for.
          </h2>

          <div className="mt-10 grid gap-6 sm:grid-cols-2">
            <div className="rounded-xl border border-border bg-elevated p-6">
              <h3 className="font-medium">Free, every time</h3>
              <p className="mt-3 text-sm text-muted">
                The audit, the score out of 10, and the full report: every
                finding with the file, the line, what a stranger could do with
                it, and how to fix it yourself. No account, no card, nothing
                held back to make you pay.
              </p>
            </div>

            <div className="rounded-xl border border-accent/40 bg-accent/5 p-6">
              <h3 className="font-medium">Paid: the fix, as a pull request</h3>
              <p className="mt-3 text-sm text-muted">
                A Fix Pack moves hardcoded credentials into environment
                variables, removes a committed .env, repairs .gitignore, and
                opens one pull request against your repository. You read the
                diff and decide whether to merge it. Bought once, for that one
                audit.
              </p>
            </div>
          </div>

          <div className="mt-6 rounded-xl border border-border p-6">
            <h3 className="font-medium">What a Fix Pack will not touch</h3>
            <p className="mt-3 text-sm text-muted">
              Authentication, injection, missing tests and missing CI come back
              as findings with guidance — not as code we wrote for you.
              Rewriting the login of an app we saw for the first time ten
              seconds ago is how an audit tool locks you out of your own
              product, so we don&apos;t. And when there is nothing a Fix Pack
              can safely change, checkout refuses the sale instead of taking
              your money and reporting that it found nothing to do.
            </p>
          </div>

          <p className="mt-8 text-center text-sm text-muted">
            <Link href="/pricing" className="text-accent hover:underline">
              How paying works →
            </Link>
          </p>
        </div>
      </section>

      {/* Instant demo — real-shaped sample report, zero interaction. */}
      <section className="border-t border-border pt-14 pb-20">
        <div className="mb-6 text-center">
          <h2 className="text-2xl font-semibold tracking-tight">
            See what you get
          </h2>
          <p className="mt-2 text-muted">
            A sample report, exactly as it renders for a real audit.
          </p>
        </div>
        <DemoReport />
      </section>
    </div>
  );
}
