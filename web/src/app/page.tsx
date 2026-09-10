import Link from "next/link";
import { AuditForm } from "@/components/AuditForm";
import { DemoReport } from "@/components/DemoReport";

/**
 * Keep scope aligned with app/scan/static.py and app/scan/pipeline.py:
 * anonymous audits run static checks plus a limited security model preview
 * when available. The full auth/security model review is included in Fix Pack.
 * Detection coverage and the set of supported automatic fixes are different.
 *
 * No prices here: /pricing owns the numbers so they change in one place.
 */

// Examples of supported static checks, not a promise of exhaustive coverage.
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
    title: "Access checks that may be missing",
    body: "Inconsistent identity checks between related Python/FastAPI routes, and supported Supabase patterns where row-level security is missing or a service key reaches browser code. These are source signals to verify, not proof that a route is publicly reachable.",
  },
  {
    title: "Risky queries, requests and file access",
    body: "Supported patterns for SQL injection, caller-controlled outbound URLs, disabled TLS verification, unsafe deserialization and path traversal. Coverage depends on the language, framework and code structure.",
  },
  {
    title: "No recognised test files",
    body: "No test files matching the scanner's supported conventions in the submitted source. Tests maintained elsewhere or in an unrecognised format may be outside this check.",
  },
  {
    title: "Gaps in project setup",
    body: "No recognised CI workflow or Dockerfile in the submitted source. These are configuration inventory findings: the app may use another build or deployment process.",
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
            Security risks and project setup gaps worth checking before a demo
            handles real users. These are examples of the static checks included in
            the free audit; each report explains what was checked and its limits.
          </p>
        </div>

        <ul className="mt-10 grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
          {LOOKS_FOR.map((item) => (
            <li
              key={item.title}
              className="rounded-xl border border-border bg-elevated p-5"
            >
              <div className="flex flex-wrap items-baseline gap-2">
                <h3 className="font-medium">{item.title}</h3>
              </div>
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
            The scan is free. The fix is what you pay for.
          </h2>

          <div className="mt-10 grid gap-6 sm:grid-cols-2">
            <div className="rounded-xl border border-border bg-elevated p-6">
              <h3 className="font-medium">Free, no account, no card</h3>
              <p className="mt-3 text-sm text-muted">
                Static checks for secrets, supported security and access-control
                patterns, and project setup. The report includes source references,
                explanations and guidance where available.
              </p>
              <p className="mt-3 text-sm text-muted">
                A limited model security preview reviews selected code when
                available. It does not cover every file or the full authentication
                review. Static results remain available if the preview is
                unavailable or incomplete. The report shows which model analysis
                completed and any limits that affected it.
              </p>
              <p className="mt-3 text-sm text-muted">
                Every report shows findings and verification limits. Neither the
                free scan nor the deeper review provides a validated readiness
                score out of 10. Absence of findings does not establish safety.
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
              Missing tests and missing CI come back as findings with guidance —
              not as code we wrote for you. Nor would we rewrite a login: doing
              that to an app we saw for the first time ten seconds ago is how an
              audit tool locks you out of your own product. And when there is
              nothing a Fix Pack can safely change, checkout refuses the sale
              instead of taking your money and reporting that it found nothing
              to do.
            </p>
          </div>

          {/* No longer dashed and no longer "not on sale yet": the deep review
              now ships with every Fix Pack (#188). The copy and the code moved
              in the same commit on purpose -- the whole lesson of #186 was that
              this block went stale the moment behaviour changed under it. */}
          <div className="mt-6 rounded-xl border border-accent/40 bg-accent/5 p-6">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="font-medium">The deeper review</h3>
              <span className="rounded-full border border-accent/40 px-2 py-0.5 text-[10px] uppercase tracking-wide text-accent">
                included with a Fix Pack
              </span>
            </div>
            <p className="mt-3 text-sm text-muted">
              The full model review adds broader authentication and security
              analysis to the static checks and limited free preview. It examines
              selected source code for access-control and injection risks; it
              does not establish that every file or vulnerability was covered.
              Model findings are hypotheses to verify, with source references
              and stated limitations. You
              can&apos;t buy it on its own — buy a Fix Pack and the pull request
              arrives with a link to the full review of the same code.
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
            A sample report, rendered exactly as a real one is. This one is the
            full review; both tiers show the source and verification limits
            alongside each finding.
          </p>
        </div>
        <DemoReport />
      </section>
    </div>
  );
}
