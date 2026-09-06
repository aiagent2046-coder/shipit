import { DEMO_AUDIT } from "@/lib/demo";
import { AuditCoverage } from "./AuditCoverage";
import { FindingsList, SeveritySummary } from "./FindingsList";

export function DemoReport() {
  const { score, findings, stack, file_count } = DEMO_AUDIT;
  return (
    <div className="rounded-xl border border-border bg-elevated p-5 sm:p-6">
      <div className="mb-4 flex items-center gap-2">
        <span className="rounded-full border border-accent/40 bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">
          Example report
        </span>
        <span className="text-xs text-muted">
          Illustrative data — not a real audit
        </span>
      </div>

      <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-3xl font-semibold">{findings.length} findings</p>
        <div className="text-sm text-muted">
          <p>
            stack: <span className="font-mono text-text">{stack}</span>
          </p>
          <p>
            files scanned:{" "}
            <span className="font-mono text-text">{file_count}</span>
          </p>
          <div className="mt-2">
            <SeveritySummary findings={findings} />
          </div>
        </div>
      </div>

      <div className="my-6 border-t border-border" />
      <AuditCoverage score={score} findings={findings} />
      <div className="my-6 border-t border-border" />
      <FindingsList findings={findings} />
    </div>
  );
}
