import { projectChecksRows, PROJECT_CHECKS_SCOPE } from "@/lib/projectChecks";

export function ProjectChecks({ value }: { value: unknown }) {
  const rows = projectChecksRows(value);
  if (!rows.length) return null;
  return <section aria-label="Project checks" className="mb-4 text-sm">
    <h3 className="font-semibold">Project checks</h3>
    <dl className="mt-2 space-y-2 break-all">
      {rows.slice(0, 3).map(([name, detail]) => <div key={name}><dt>{name}</dt><dd className="text-muted">{detail}</dd></div>)}
    </dl>
    {rows.length > 3 ? <details className="mt-2"><summary>Project evidence bindings</summary>
      <dl className="mt-2 space-y-2 break-all">{rows.slice(3).map(([name, detail]) =>
        <div key={name}><dt>{name}</dt><dd translate="no" className="text-muted">{detail}</dd></div>)}</dl>
    </details> : null}
    <p className="mt-2 text-muted">{PROJECT_CHECKS_SCOPE}</p>
  </section>;
}
