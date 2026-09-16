import type { AuditResult, Finding } from "./types";

// Illustrative, unpersisted example: the three observations below were produced
// by scan_secrets and run_checks on an eight-file synthetic archive. Only a
// masked credential-shaped value is retained; no real credential was used.
// The example intentionally demonstrates the free report's static-only fallback.
// It is a selected-check example, not a complete audit or an LLM review.
export const DEMO_FINDINGS: Finding[] = [
  {
    "rule_id": "stripe-live-key",
    "title": "Stripe live secret key",
    "severity": "critical",
    "confidence": 0.95,
    "category": "Security",
    "file": "app/api/checkout/route.ts",
    "line": 1,
    "masked": "sk_l****(32 chars)",
    "explanation": "",
    "fix_hint": "",
    "context": null,
    "source": "static",
    "verification_status": "unverified",
    "verification_method": "source_pattern",
    "claim_evidence": {
      "version": 1,
      "source_check": {
        "kind": "static_rule"
      },
      "observation": null,
      "required_conditions": null,
      "conditions_status": "not_checked",
      "consequence_status": "not_checked"
    }
  },
  {
    "rule_id": "env-file-committed",
    "title": "Public frontend configuration included in the archive",
    "severity": "low",
    "confidence": 0.6,
    "category": "Security",
    "file": ".env.production",
    "line": 0,
    "masked": "",
    "explanation": ".env.production contains only recognized frontend-public settings with simple URLs or build values. Their names use frontend-public conventions. File presence alone is not evidence of credential exposure.",
    "fix_hint": "Keep intentional public build settings in version control when the project needs them. Put private credentials in separate ignored configuration; do not rotate values or delete this file solely because of its name.",
    "context": "public_configuration",
    "source": "static",
    "verification_status": "unverified",
    "verification_method": "source_pattern",
    "claim_evidence": {
      "version": 1,
      "source_check": {
        "kind": "static_rule"
      },
      "observation": null,
      "required_conditions": null,
      "conditions_status": "not_checked",
      "consequence_status": "not_checked"
    }
  },
  {
    "rule_id": "no-dockerfile",
    "title": "No Dockerfile found in the archive",
    "severity": "low",
    "confidence": 0.9,
    "category": "Deploy",
    "file": "",
    "line": 0,
    "masked": "",
    "explanation": "Deployment configuration files found: deploy/demo.service. This is file inventory only; configuration validity and live deployment are not checked.",
    "fix_hint": "Review existing deployment instructions; add a Dockerfile only if containers are needed.",
    "context": "deployment_inventory",
    "source": "static",
    "verification_status": "unverified",
    "verification_method": "source_pattern",
    "claim_evidence": {
      "version": 1,
      "source_check": {
        "kind": "static_rule"
      },
      "observation": null,
      "required_conditions": null,
      "conditions_status": "not_checked",
      "consequence_status": "not_checked"
    }
  }
];

// Legacy numeric fields come from the backend scorer; DemoReport does not
// present them as a readiness verdict. The hash identifies the synthetic input.
export const DEMO_AUDIT: AuditResult = {
  "audit_id": "example-0000-demo",
  "access_token": null,
  "persisted": false,
  "status": "completed",
  "stack": "nextjs",
  "file_count": 8,
  "score": {
    "total": 6.4,
    "categories": {
      "Security": 5.5,
      "Auth": 10.0,
      "Testing": 10.0,
      "Deploy": 10.0,
      "Money & Data": 10.0,
      "Frontend": 10.0
    },
    "gated_by": [
      {
        "kind": "critical",
        "category": "Security",
        "rule_id": "stripe-live-key",
        "title": "Stripe live secret key"
      }
    ],
    "readiness_score_validated": false,
    "unexamined": [
      "Auth",
      "Frontend",
      "Money & Data"
    ],
    "unexamined_with_findings": [],
    "reported_elsewhere": {},
    "basis": "static_only",
    "scan_manifest": {
      "archive_sha256": "570014dfbe0f0d2bc579e1757115947e3835dbe3b503ffe555aae5abf0fe29ea",
      "engine_version": "illustrative-demo",
      "archive_files": 8,
      "commit_sha": null,
      "inventory": {
        "Python manifests": [],
        "JavaScript manifests": [
          "package.json"
        ],
        "Lockfiles": [],
        "CI workflows": [
          ".github/workflows/ci.yml"
        ],
        "systemd units": [
          "deploy/demo.service"
        ],
        "Dockerfiles": []
      },
      "static_checks": [
        "secrets",
        "project_files"
      ],
      "static_checks_not_run": [],
      "sca_cve": null,
      "static_limits": {
        "secrets": "Illustrative scope: secret-format matching in an 8-file synthetic archive. Credential validity, permissions and runtime use were not checked.",
        "project_files": "Illustrative scope: archive file inventory and environment configuration inspection. File presence does not establish deployment or successful CI/test execution.",
        "example": "Selected checks only: secrets and project_files. Other static analyzers, model review and dependency vulnerability checks are outside this example."
      },
      "rule_coverage": null,
      "source_facts": null,
      "model": null,
      "model_calls": 0,
      "model_findings": [],
      "model_acceptance": null,
      "rejection_diagnostics": null,
      "rubrics_completed": [],
      "llm_candidate_files": 0,
      "llm_submitted_files": 0,
      "llm_files_not_submitted": 0,
      "llm_selection_exclusions": {},
      "limitations": [],
      "runtime_verified": false
    }
  },
  "repo_url": null,
  "llm": {
    "basis": "static_only",
    "calls": 0,
    "model": null,
    "rubrics_ran": []
  },
  findings: DEMO_FINDINGS,
};
