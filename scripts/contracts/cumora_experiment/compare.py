#!/usr/bin/env python3
"""Host-side evidence comparison, not an attestation of a hostile runner."""

import hashlib
import json
import pathlib
import re
import sys
import uuid

from . import verify


class Unavailable(ValueError):
    """Execution did not provide usable observations."""


def require(value, reason):
    if not value:
        raise ValueError(reason)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "Duplicate JSON key: " + key)
            result[key] = value
        return result

    require(path.stat().st_size < 1024 * 1024, "Evidence too large")
    return json.loads(
        path.read_text(),
        object_pairs_hook=unique,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("Nonfinite JSON value")),
    )


def sha(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def validate_mutant(r):
    """Recompute the six prerequisite checks and the precise expected disclosure."""
    require(r["authentication"] == "dedicated_database_seeded_sessions", "Unexpected authentication")
    for name in ("vulnerabilityRemediationVerified", "oauthVerified", "wholeApplicationVerified"):
        require(r[name] is False, "Unsupported claim: " + name)
    f = r["fixtures"]
    fields = (
        "company_a",
        "company_b",
        "project_id",
        "original_name",
        "updated_name",
        "original_description",
        "updated_description",
    )
    require(all(isinstance(f[k], str) and 0 < len(f[k]) <= 200 for k in fields), "Invalid fixtures")
    require(f["company_a"] != f["company_b"], "Tenants must differ")
    require(f["original_name"] != f["updated_name"], "Update must change data")
    require(re.fullmatch(r"p-[a-f0-9-]+", f["project_id"]) is not None, "Invalid project identity")
    checks = r["checks"]
    names = ["unauthenticated", "create", "db_created", "list_owner", "update_owner", "db_updated", "list_other"]
    require(type(checks) is list and [c["id"] for c in checks] == names, "Unexpected mutant check sequence")
    require(
        all(c["pass"] is True for c in checks[:6]) and checks[6]["pass"] is False,
        "Mutant must fail only list_other after six successful checks",
    )
    actual = {c["id"]: c["actual"] for c in checks}
    for name, status in [
        ("unauthenticated", 401),
        ("create", 201),
        ("list_owner", 200),
        ("update_owner", 200),
        ("list_other", 200),
    ]:
        require(
            type(actual[name]["status"]) is int and actual[name]["status"] == status,
            "Unexpected HTTP response: " + name,
        )
    require(actual["unauthenticated"] == {"status": 401}, "Unexpected unauthenticated receipt")
    body = actual["create"]["body"]
    require(
        body["id"] == f["project_id"]
        and body["name"] == f["original_name"]
        and body["description"] == f["original_description"]
        and body["status"] == "active",
        "Create response mismatch",
    )
    original = dict(
        company_id=f["company_a"],
        name=f["original_name"],
        description=f["original_description"],
        status="active",
        archived_at=None,
    )
    updated = dict(original, name=f["updated_name"], description=f["updated_description"])
    require(actual["db_created"] == {"rows": [original]}, "Created row mismatch")
    require(actual["list_owner"] == {"status": 200, "ids": [f["project_id"]]}, "Owner read mismatch")
    require(actual["update_owner"]["body"]["ok"] is True, "Owner update mismatch")
    require(actual["db_updated"] == {"rows": [updated]}, "Updated row mismatch")
    require(
        actual["list_other"] == {"status": 200, "ids": [f["project_id"]]},
        "Expected cross-tenant project disclosure missing",
    )
    require(r["status"] == "failed", "Mutant unexpectedly passed")
    require(
        r["error"] == {"kind": "Error", "reason": "check_failed:list_other", "code": None},
        "Failure was not the expected tenant disclosure",
    )


def compare(directory):
    root = pathlib.Path(directory)
    plan = read_json(root / "plan.json")
    require(type(plan["schema_version"]) is int and plan["schema_version"] == 1, "Unknown plan schema")
    require(plan["archive_sha256"] == verify.ARCHIVE, "Unexpected archive")
    require(
        plan["scenario_id"] == verify.SCENARIO
        and plan["scenario_sha256"] == "080d9eae864c8ca7e98cd0d3dd7b132b1b19b1fd12236357b4c81e356efaea20",
        "Unexpected scenario",
    )
    require(plan["router_path"] == "server/src/api/router.ts", "Unexpected mutation target")
    require(
        plan["mutation"]
        == {
            "id": "remove-project-list-tenant-predicate",
            "before": "WHERE company_id = $1",
            "after": "WHERE $1::text IS NOT NULL",
            "changed_files": ["server/src/api/router.ts"],
            "scope": "GET /projects only; one predicate substitution; parameter count unchanged",
        },
        "Unexpected mutation",
    )
    require(type(plan["llm_calls"]) is int and plan["llm_calls"] == 0, "Unexpected model calls")
    require(plan["fixture_setup"] == "clear_projects_in_disposable_database", "Unexpected fixture preparation")
    require(set(plan["variants"]) == {"baseline", "mutant", "restored"}, "Unexpected variants")
    detector = read_json(root / "detector.json")
    researcher = read_json(root / "researcher.json")
    for receipt, role in ((detector, "detector"), (researcher, "researcher")):
        require(
            receipt["schema_version"] == 1
            and receipt["role"] == role
            and receipt["status"] == "completed"
            and type(receipt["llm_calls"]) is int
            and receipt["llm_calls"] == 0,
            "Invalid agent receipt: " + role,
        )
    encoded_output = (json.dumps(detector["output"], sort_keys=True, indent=2) + "\n").encode()
    require(
        detector["input_sha256"] == plan["archive_sha256"]
        and detector["output_sha256"] == hashlib.sha256(encoded_output).hexdigest()
        and detector["output_sha256"] == plan["detector_output_sha256"],
        "Detector output binding mismatch",
    )
    require(
        detector["output"]["archive_sha256"] == plan["archive_sha256"]
        and detector["output"]["selected_scenario_id"] == plan["scenario_id"]
        and detector["output"]["router_sha256"] == plan["variants"]["baseline"]["router_sha256"],
        "Detector source binding mismatch",
    )
    require(
        researcher["input_sha256"] == digest(root / "detector.json")
        and researcher["output_sha256"] == digest(root / "plan.json")
        and researcher["output_artifact"] == "plan.json",
        "Researcher handoff mismatch",
    )
    baseline, mutant = plan["variants"]["baseline"], plan["variants"]["mutant"]
    restored = plan["variants"]["restored"]
    require(len({v["run_id"] for v in plan["variants"].values()}) == 3, "Reused run identity")
    require(
        plan["restoration"]
        == {
            "method": "inverse_predicate_on_mutant_copy",
            "from_variant": "mutant",
            "changed_files": ["server/src/api/router.ts"],
            "exact_original_tree": True,
        },
        "Unexpected restoration",
    )
    require(
        all(restored[k] == baseline[k] for k in ("router_sha256", "tree_sha256")),
        "Restored source differs from baseline",
    )
    for key in ("router_sha256", "tree_sha256"):
        require(all(sha(v[key]) for v in (baseline, mutant)), "Invalid source binding")
        require(baseline[key] != mutant[key], "Mutation source did not change")
    reports = {}
    for name, binding in plan["variants"].items():
        d = root / name
        require((d / "fixture-reset.log").read_text().strip() == "0", "Fixture reset not confirmed: " + name)
        image_id = (d / "image-id.txt").read_text().strip()
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is not None, "Invalid image identity: " + name)
        run_id = (d / "run-id.txt").read_text().strip()
        require(str(uuid.UUID(run_id)) == run_id and run_id == binding["run_id"], "Wrong run: " + name)
        require(
            (d / "observed-router-sha256.txt").read_text().strip() == binding["router_sha256"],
            "Executed router mismatch: " + name,
        )
        observed_tree = (d / "observed-tree-sha256.txt").read_text().strip()
        require(
            digest(d / "source-manifest.json") == binding["tree_sha256"]
            and observed_tree == binding["tree_sha256"],
            "Executed source tree mismatch: " + name,
        )
        require(digest(d / "scenario.mjs") == plan["scenario_sha256"], "Scenario code mismatch: " + name)
        require(
            (d / "archive.txt").read_text().splitlines().count("archive_sha256=" + plan["archive_sha256"]) == 1,
            "Archive receipt mismatch: " + name,
        )
        if (d / "cleanup-exit.txt").read_text().strip() != "0":
            raise Unavailable("Cleanup incomplete: " + name)
        if read_json(d / "probe.json")["status"] != "passed":
            raise Unavailable("Readiness failed: " + name)
        exit_code = (d / "scenario-exit.txt").read_text().strip()
        if exit_code not in ("0", "1"):
            raise Unavailable("Scenario timed out or could not execute: " + name)
        require(exit_code == ("1" if name == "mutant" else "0"), "Unexpected scenario exit: " + name)
        execution = read_json(d / "execution.json")
        require(
            execution["variant"] == name
            and execution["run_id"] == run_id
            and execution["status"] == "executed"
            and execution["readiness"] is True
            and type(execution["scenario_exit"]) is int
            and execution["scenario_exit"] == int(exit_code)
            and type(execution["cleanup_exit"]) is int
            and execution["cleanup_exit"] == 0,
            "Execution receipt mismatch: " + name,
        )
        r = read_json(d / "scenario.json")
        require(type(r["schema_version"]) is int and r["schema_version"] == 1, "Unknown evidence schema")
        require(
            r["scenario_id"] == plan["scenario_id"] and r["scope"] == "client_application_runtime",
            "Wrong evidence scope",
        )
        require(
            r["run_id"] == run_id
            and r["archive_sha256"] == plan["archive_sha256"]
            and r["scenario_sha256"] == plan["scenario_sha256"],
            "Evidence binding mismatch: " + name,
        )
        if name in ("baseline", "restored"):
            verify.verify(d)
        else:
            if r.get("error", {}).get("reason") != "check_failed:list_other":
                raise Unavailable("Mutant failed without tenant-disclosure evidence")
            validate_mutant(r)
        reports[name] = {
            "status": "rejected" if name == "mutant" else "accepted",
            "reason": "tenant_leak" if name == "mutant" else "scenario_passed",
            "run_id": run_id,
            "image_id": image_id,
            "checks_observed": len(r["checks"]),
            "evidence_sha256": digest(d / "scenario.json"),
            "tree_sha256": observed_tree,
            "router_sha256": binding["router_sha256"],
        }
    return {
        "schema_version": 1,
        "cycle_status": "passed",
        "variants": reports,
        "archive_sha256": plan["archive_sha256"],
        "scenario_sha256": plan["scenario_sha256"],
        "plan_sha256": digest(root / "plan.json"),
        "llm_calls": 0,
        "controlled_restoration_verified": True,
        "verification": "host_side_evidence_consistency",
        "scope": "project_list_cross_tenant_isolation_restoration_experiment",
        "customer_project_verified": False,
        "vulnerability_remediation_verified": False,
        "automatic_patch": False,
    }


def main():
    try:
        require(len(sys.argv) == 2, "Usage: compare.py results-directory")
        verdict = compare(sys.argv[1])
    except (OSError, Unavailable) as error:
        verdict = {"cycle_status": "unavailable", "reason": str(error)}
    except (ValueError, KeyError, TypeError, IndexError, AttributeError, RecursionError) as error:
        verdict = {"cycle_status": "failed", "reason": str(error)}
    print(json.dumps(verdict, ensure_ascii=False, indent=2))
    return 0 if verdict["cycle_status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
