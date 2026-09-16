import { DEMO_AUDIT } from "@/lib/demo";
import { AuditCoverage } from "./AuditCoverage";
import { FindingsList, SeveritySummary } from "./FindingsList";

export function DemoReport() {
  const { score, findings, file_count } = DEMO_AUDIT;
  return (
    <div className="rounded-xl border border-border bg-elevated p-5 sm:p-6">
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">
          Free report example
        </span>
        <span className="text-xs text-muted">
          Illustrative data — not a real audit
        </span>
      </div>
      <p className="mb-5 text-sm text-muted">
        A short example of the free report when model review is unavailable.
        These selected static checks show what was observed, what remains
        unverified, and what to do next. All values are synthetic.
      </p>

      <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-3xl font-semibold">{findings.length} example observations</p>
        <div className="text-sm text-muted">
          <p>
            Example archive:{" "}
            <span className="font-mono text-text">{file_count} files</span>
          </p>
          <div className="mt-2">
            <SeveritySummary findings={findings} />
          </div>
        </div>
      </div>

      <div className="my-6 border-t border-border" />
      <FindingsList findings={findings} />
      <div className="my-6 border-t border-border" />
      <details>
        <summary className="cursor-pointer font-medium">Example scope and scan record</summary>
        <div className="mt-4">
          <AuditCoverage score={score} findings={findings} />
        </div>
      </details>
    </div>
  );
}
