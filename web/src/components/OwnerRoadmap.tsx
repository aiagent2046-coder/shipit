import type { OwnerRoadmapProjection, OwnerRoadmapTask } from "@/lib/ownerRoadmap";

const stages: { id: OwnerRoadmapTask["stage"]; title: string }[] = [
  { id: "first", title: "First" },
  { id: "after", title: "After clarification" },
  { id: "when_needed", title: "If needed" },
];

function revealRoadmapTarget(id: string) {
  const target = document.getElementById(id);
  for (let parent = target?.parentElement; parent; parent = parent.parentElement) {
    if (parent instanceof HTMLDetailsElement) parent.open = true;
  }
  target?.focus();
}

function findingReference(findings: unknown, index: number): string {
  const finding: unknown = Array.isArray(findings) ? findings[index] : null;
  if (!finding || typeof finding !== "object" || Array.isArray(finding)) return `Observation ${index + 1}`;
  const record = finding as Record<string, unknown>;
  const file = typeof record.file === "string" ? record.file : "";
  const line = typeof record.line === "number" && Number.isSafeInteger(record.line) && record.line > 0
    ? `:${record.line}` : "";
  return `Observation ${index + 1}${file ? ` · ${file}${line}` : ""}`;
}

function RoadmapLink({ target, children }: { target: string; children: React.ReactNode }) {
  return <a href={`#${target}`} onClick={() => revealRoadmapTarget(target)}
    className="break-words underline underline-offset-4">{children}</a>;
}

export function OwnerRoadmap({ projection, findings }: { projection: OwnerRoadmapProjection; findings: unknown }) {
  const tasksById = new Map(projection.tasks.map(task => [task.id, task]));
  return <section aria-label="Project roadmap" className="my-6 space-y-4 rounded-lg border border-border p-4">
    <h2 className="text-lg font-semibold">Project roadmap</h2>
    <p className="text-sm text-muted">Suggested next steps from this report. These tasks have not been carried out or verified.</p>
    {projection.tasks.length === 0 ? <p className="text-sm text-muted">
      No next steps can be generated from the recorded findings and coverage. This does not establish that the project is ready or safe.
    </p> : stages.map(stage => {
      const tasks = projection.tasks.filter(task => task.stage === stage.id);
      return tasks.length > 0 ? <div key={stage.id} className="space-y-3">
        <h3 className="font-semibold">{stage.title}</h3>
        <ol className="space-y-3">
          {tasks.map(task => <li key={task.id} id={`roadmap-task-${task.id}`} tabIndex={-1}
            className="scroll-mt-6 space-y-2 rounded-lg border border-border bg-surface p-3 text-sm">
            <h4 className="font-semibold">{task.title}</h4>
            <p className="text-muted">{task.why}</p>
            <p><strong>Action: </strong>{task.action}</p>
            <p><strong>Suggested owner: </strong>{task.owner}</p>
            <details className="space-y-2">
              <summary className="cursor-pointer">Completion criteria and references</summary>
              <dl className="space-y-3 pt-2">
                {task.needs.length > 0 ? <div><dt className="font-semibold">Needs</dt><dd>
                  <ul className="list-disc space-y-1 pl-5">{task.needs.map(need => <li key={need}>{need}</li>)}</ul>
                </dd></div> : null}
                {task.depends_on.length > 0 ? <div><dt className="font-semibold">After</dt><dd>
                  <ul className="space-y-1">{task.depends_on.map(id => <li key={id}>
                    <RoadmapLink target={`roadmap-task-${id}`}>{tasksById.get(id)?.title ?? id}</RoadmapLink>
                  </li>)}</ul>
                </dd></div> : null}
                <div><dt className="font-semibold">This step is complete when</dt><dd>{task.done_when}</dd></div>
                <div><dt className="font-semibold">Based on</dt><dd><ul className="space-y-1">
                  {task.finding_indices.map(index => <li key={index}>
                    <RoadmapLink target={`roadmap-finding-${index}`}>{findingReference(findings, index)}</RoadmapLink>
                  </li>)}
                  {task.coverage_refs.map(ref => <li key={ref}><RoadmapLink target="roadmap-coverage">
                    {ref === "dependency_cve" ? "Dependency coverage" : "Runtime verification scope"}
                  </RoadmapLink></li>)}
                </ul></dd></div>
              </dl>
            </details>
          </li>)}
        </ol>
      </div> : null;
    })}
  </section>;
}
