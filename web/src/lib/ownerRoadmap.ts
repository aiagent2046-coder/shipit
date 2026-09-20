import { projectOwnerReport, type OwnerReportContext } from "./ownerReport";

export interface OwnerRoadmapTask {
  id: string;
  stage: "first" | "after" | "when_needed";
  kind: "investigate" | "provide_information" | "review" | "verify";
  title: string;
  why: string;
  action: string;
  owner: string;
  needs: string[];
  depends_on: string[];
  done_when: string;
  finding_indices: number[];
  coverage_refs: string[];
}

export interface OwnerRoadmapProjection {
  version: 1;
  tasks: OwnerRoadmapTask[];
}

const roadmapObject = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
// Match Python's presentation contract explicitly; language-native trimming
// differs for some Unicode characters that can occur in filenames or titles.
const roadmapHasText = (value: unknown): value is string =>
  typeof value === "string" && /[^\t\n\v\f\r ]/.test(value);

function roadmapCodepointOrder(left: string, right: string): number {
  const a = Array.from(left, char => char.codePointAt(0)!);
  const b = Array.from(right, char => char.codePointAt(0)!);
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
}

// Follow-up work only: this projection cannot confirm vulnerabilities, apply
// changes, or mark an earlier suggestion as completed by a later scan.
export function projectOwnerRoadmap(findings: unknown, contextValue: OwnerReportContext | null = {}): OwnerRoadmapProjection {
  const context = roadmapObject(contextValue) ? contextValue : {};
  const records: unknown[] = Array.isArray(findings) ? findings : [];
  const fileIndices = projectOwnerReport(records, context).cards.map(card => card.finding_index);
  const deploymentIndices = records.flatMap((finding, index) =>
    roadmapObject(finding) && finding.rule_id === "no-dockerfile" && finding.source === "static" ? [index] : []);
  const covered = new Set([...fileIndices, ...deploymentIndices]);
  const remainingIndices = records.flatMap((finding, index) => roadmapObject(finding)
    && [finding.rule_id, finding.title].some(roadmapHasText)
    && !covered.has(index) ? [index] : []);
  const tasks: OwnerRoadmapTask[] = [];
  if (fileIndices.length > 0) tasks.push({
    id: "file-loading-origin", stage: "first", kind: "investigate",
    title: "Find out who supplies and can change loaded files",
    why: "The recorded file-loading calls need a trust check; source review alone does not establish a runtime problem.",
    action: "For every linked location, identify who produces the file, who can change it, and what checks happen before it is loaded.",
    owner: "Project owner and developer",
    needs: ["The linked file-loading observations.", "The people or services that create, store, and deliver these files."],
    depends_on: [],
    done_when: "Each linked location has a recorded file producer, write access, and trust check, or an explicitly named unanswered question.",
    finding_indices: fileIndices, coverage_refs: [],
  });
  const dependency = context.dependency_cve;
  if (roadmapObject(dependency) && (dependency.status === "partial" || dependency.status === "unavailable")) {
    const manifests = dependency.incomplete_manifests;
    const unresolved = roadmapObject(manifests) ? Object.entries(manifests)
      .filter(([path, reason]) => roadmapHasText(path) && reason === "unresolved").map(([path]) => path)
      .sort(roadmapCodepointOrder) : [];
    tasks.push({
      id: "dependency-coverage", stage: "first", kind: "provide_information",
      title: "Clarify the gaps in dependency checking",
      why: "The report records incomplete or unavailable dependency checking; the gaps do not establish whether the dependencies are safe.",
      action: unresolved.length > 0
        ? "Check the recorded dependency gaps and provide the exact installed versions or matching lockfiles for the unresolved manifests."
        : "Read the recorded dependency gaps, identify what information or checking capability is missing, and agree how to obtain it.",
      owner: "Developer",
      needs: ["The recorded dependency coverage and its limitations.", ...unresolved.map(path => `Unresolved manifest: ${path}`)],
      depends_on: [],
      done_when: "Record the cause of each gap, the information supplied or next check needed, and any limitations that remain. A later scan must record its own coverage.",
      finding_indices: [], coverage_refs: ["dependency_cve"],
    });
  }
  if (remainingIndices.length > 0) tasks.push({
    id: "remaining-observations", stage: "first", kind: "review",
    title: "Review the other recorded observations",
    why: "These observations need their own evidence and context reviewed before deciding whether any action is warranted.",
    action: "Review each linked observation with its original evidence, limits, and test or example context. Record what is supported, contradicted, or still unknown and decide the next step.",
    owner: "Developer",
    needs: ["The original linked observations and their evidence.", "Someone familiar with the affected part of the project."],
    depends_on: [],
    done_when: "Each linked observation has a documented assessment and a next step or a reason no change is needed; unverified claims remain marked as unverified.",
    finding_indices: remainingIndices, coverage_refs: [],
  });
  if (fileIndices.length > 0) tasks.push({
    id: "file-loading-decision", stage: "after", kind: "review",
    title: "Decide whether file-loading protection needs to change",
    why: "The right decision depends on where the files come from, who can change them, and the checks already in place.",
    action: "Review the file-origin answers with a developer. If protection needs to change, choose an approach compatible with existing files and plan a focused check of normal use and rejected input.",
    owner: "Developer",
    needs: ["The file-origin answers, including unresolved questions.", "Examples of legitimate files and their expected use."],
    depends_on: ["file-loading-origin"],
    done_when: "Document the decision and its evidence for each linked location. If a change is needed, record the compatibility requirements and how the change will be tested; this task does not certify a fix.",
    finding_indices: [...fileIndices], coverage_refs: [],
  });
  const runtimeUnverified = context.runtime_verified === false;
  if (runtimeUnverified || deploymentIndices.length > 0) tasks.push({
    id: "deployment-check", stage: "when_needed", kind: "verify",
    title: "Check the intended way to run the project",
    why: runtimeUnverified ? "The report records that application behavior has not been verified."
      : "A deployment inventory observation describes files in the archive; it does not establish whether the application can run.",
    action: "When preparing a deployment, confirm the intended hosting method, configuration, and startup steps, then run a basic user journey in an isolated test environment. Docker is only one possible hosting option.",
    owner: "Developer or person responsible for deployment",
    needs: ["The intended hosting method and required configuration.", "An isolated test environment and an agreed basic user journey."],
    depends_on: [],
    done_when: "Record the tested version, setup, steps, and actual results, including what was not tested. This does not verify every application behavior.",
    finding_indices: deploymentIndices, coverage_refs: runtimeUnverified ? ["runtime_verified"] : [],
  });
  return { version: 1, tasks };
}
