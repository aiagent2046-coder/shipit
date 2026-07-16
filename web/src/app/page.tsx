import Link from "next/link";
import { AuditForm } from "@/components/AuditForm";
import { DemoReport } from "@/components/DemoReport";

export default function LandingPage() {
  return (
    <div className="mx-auto max-w-5xl px-4">
      {/* Hero — the one expressive marketing moment. Larger type is allowed
          here; interior pages stay capped. */}
      <section className="pt-16 pb-12 sm:pt-24 sm:pb-16">
        <div className="mx-auto max-w-3xl text-center">
          <span className="inline-block rounded-full border border-border bg-surface px-3 py-1 text-xs text-muted">
            Production-readiness audits for vibe-coded apps
          </span>
          <h1 className="mt-5 text-4xl font-bold leading-tight tracking-tight sm:text-6xl">
            Is your app{" "}
            <span className="text-accent">ready to ship?</span>
          </h1>
          <p className="mx-auto mt-5 max-w-2xl text-lg text-muted">
            Built it with Lovable, Bolt, or v0? Drydock scans your code for the
            things that keep it from being safe in production — leaked secrets,
            missing auth, no tests — scores it out of 10, and generates the
            fixes as a pull request.
          </p>
        </div>

        <div className="mx-auto mt-10 max-w-2xl">
          <AuditForm />
        </div>

        <p className="mt-6 text-center text-sm text-muted">
          No signup to run a free audit.{" "}
          <Link href="/pricing" className="text-accent hover:underline">
            See Fix Pack pricing →
          </Link>
        </p>
      </section>

      {/* Instant demo — real-shaped sample report, zero interaction. */}
      <section className="pb-20">
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
