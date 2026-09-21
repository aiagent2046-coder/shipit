import { dependencyCoverageGap, projectOwnerReport, type OwnerReportContext } from "./ownerReport";

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

const roadmapReviewTasks: Record<string, Pick<OwnerRoadmapTask, "title" | "why" | "action" | "owner" | "needs" | "done_when">> = {
  "dependency-advisory-review": {
    "title": "Review the matched library versions and how they are used",
    "why": "The report matches recorded library versions to advisory entries. A match does not establish that affected functionality is used or exploitable in this application.",
    "action": "Group the linked matches by library, ecosystem, and installed version. Separate application dependencies, development dependencies, and unknown use from the recorded evidence. Review each advisory and check whether its conditions apply before choosing an update or other action.",
    "owner": "Developer responsible for dependencies",
    "needs": [
      "The linked library versions, advisory references, and manifest locations.",
      "How each library is installed and used in the application, development, or tests."
    ],
    "done_when": "For each library/version group, record its use, the applicable advisory conditions, any unanswered questions, and the chosen next step. A proposed update still needs compatibility testing and a new check; this review does not verify a fix."
  },
  "html-input-review": {
    "title": "Find out where inserted HTML comes from",
    "why": "The source observation records a value being inserted as HTML. It does not establish who controls that value, whether it is sanitized, or what happens in the browser.",
    "action": "Trace each linked value to its source, identify who can change it, and review any checks before insertion. Decide whether markup is needed and whether the existing handling is suitable.",
    "owner": "Frontend developer",
    "needs": [
      "The linked HTML insertion locations and the code that supplies their values.",
      "Examples of intended content and any validation or sanitization rules."
    ],
    "done_when": "Record each value's source, control, and handling. Document the decision and any focused browser check still needed; source review alone does not confirm an exploit or a fix."
  },
  "test-credential-review": {
    "title": "Check whether credential-like values in tests are synthetic",
    "why": "The scanner found credential-like assignments in test files. The pattern does not establish that these values are live credentials or accepted by a service.",
    "action": "Ask the test maintainer to confirm where the values came from and whether they are synthetic. If a real exposed credential is confirmed, arrange replacement or revocation with its owner; synthetic fixtures do not require account-level rotation.",
    "owner": "Test maintainer and credential owner, if applicable",
    "needs": [
      "The linked test locations and the purpose of their fixtures.",
      "Confirmation from the person responsible for the values; do not copy secret values into the review."
    ],
    "done_when": "Record whether each value is synthetic, real, or still unknown and the corresponding next step. Record no secret values and do not claim revocation or replacement until separately confirmed."
  },
  "ui-error-handling-review": {
    "title": "Review how the interface handles rendering errors",
    "why": "The static check did not identify the expected error-handling boundary. It does not establish that the running interface fails or that framework-provided handling is absent.",
    "action": "Review the actual application entry points, routes, and framework error handling. Agree what users should see after a rendering error and plan a focused check of that recovery path.",
    "owner": "Frontend developer",
    "needs": [
      "The linked entry points, route setup, and existing error-handling code.",
      "The expected fallback screen and recovery action for users."
    ],
    "done_when": "Document the existing handling, any gap requiring a change, and the planned or observed recovery check. Keep untested interface behavior explicitly unverified."
  },
  "archive-content-review": {
    "title": "Check why dependency-like directories are in the archive",
    "why": "The archive contains a directory commonly used for installed dependencies or generated files. Its name does not establish Git tracking or whether the contents should be removed.",
    "action": "Identify whether the linked directories contain reproducible dependencies, generated files, intentional vendored source, or test data. Check the archive's packaging rules and, if relevant, Git tracking before deciding what to retain or exclude.",
    "owner": "Developer responsible for packaging",
    "needs": [
      "The linked archive directories and the instructions used to assemble the archive.",
      "The purpose of the included files and, if relevant, evidence of Git tracking."
    ],
    "done_when": "Record what belongs in the archive and why, and how any excluded dependencies or generated files can be recreated. Do not record a deletion or Git change as completed without evidence."
  }
};

function roadmapReviewGroup(finding: Record<string, unknown>): string | null {
  const evidence = finding.claim_evidence;
  if (evidence != null) {
    if (!roadmapObject(evidence)) return null;
    const syntax = evidence.syntax_check;
    if (syntax != null && !roadmapObject(syntax)
      || roadmapObject(syntax) && syntax.result === "contradicted"
      || [evidence.source_assessments, evidence.premise_checks]
        .some(value => value != null && !(Array.isArray(value) && value.length === 0))) return null;
  }
  if (finding.verification_status === "contradicted") return null;
  const { source, rule_id: rule, context } = finding;
  if (source === "dependency" && rule === "dependency-cve-match" && (context == null || context === "")) {
    return "dependency-advisory-review";
  }
  if (source !== "static") return null;
  if (rule === "generic-assignment" && context === "test_file") return "test-credential-review";
  if (context != null && context !== "") return null;
  if (rule === "xss-unsafe-html-injection") return "html-input-review";
  if (rule === "missing-error-boundary") return "ui-error-handling-review";
  if (rule === "dependency-dir-committed") return "archive-content-review";
  return null;
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
  const groups = new Map(Object.keys(roadmapReviewTasks).map(name => [name, [] as number[]]));
  const remainingIndices: number[] = [];
  for (const [index, finding] of records.entries()) {
    if (!roadmapObject(finding) || ![finding.rule_id, finding.title].some(roadmapHasText) || covered.has(index)) continue;
    const group = roadmapReviewGroup(finding);
    if (group) groups.get(group)!.push(index); else remainingIndices.push(index);
  }
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
  const dependencyGap = dependencyCoverageGap(context);
  if (dependencyGap) {
    const unresolved = dependencyGap.unresolved_manifests;
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
  for (const [name, template] of Object.entries(roadmapReviewTasks)) {
    const indices = groups.get(name)!;
    if (indices.length) tasks.push({ ...template, id: name, stage: "first", kind: "review",
      needs: [...template.needs], depends_on: [], finding_indices: indices, coverage_refs: [] });
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
