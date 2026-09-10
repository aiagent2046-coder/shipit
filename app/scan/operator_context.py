"""Bounded source observations about an operator guard and direct payment reads.

Names and syntax only: no helper binding, credential validity, dependency effects,
route reachability or authorization policy is inferred. Submitted code is never run.
"""
import ast
import re


def operator_guard_context(fn) -> dict | None:
    nodes = list(ast.walk(fn))
    reads = [n for n in nodes if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and isinstance(n.func.value, ast.Name) and n.func.value.id == "payment_repo"
             and n.func.attr == "get"]
    if not reads:
        return None
    guards = [n.value for n in fn.body if isinstance(n, ast.Expr)
              and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
              and n.value.func.id == "_require_bearer_token"
              and [ast.dump(a) for a in n.value.args] ==
                  [ast.dump(ast.Name(id="request", ctx=ast.Load())),
                   ast.dump(ast.Name(id="token", ctx=ast.Load()))]
              and not n.value.keywords]
    if not guards:
        return None
    start = min([fn.lineno] + [d.lineno for d in fn.decorator_list])
    result = {"kind": "operator_guard_order", "result": "not_checked",
              "function": fn.name, "function_line_start": start, "function_line_end": fn.end_lineno,
              "guard_line": guards[0].lineno, "read_lines": [r.lineno for r in reads[:8]],
              "detail": "Direct _require_bearer_token(request, token) and payment_repo.get syntax. "
                        "Helper bindings, dependency/decorator effects, credentials and authorization policy "
                        "are not verified. This is not a finding that the endpoint is safe."}
    excluded = (ast.Try, ast.TryStar, ast.With, ast.AsyncWith, ast.Lambda, ast.ClassDef,
                ast.Yield, ast.YieldFrom)
    # The real route has a try/except validating UUID after the guard. That
    # does not enclose either operation; only the straight-line prefix matters.
    guard_index = next(i for i, n in enumerate(fn.body) if isinstance(n, ast.Expr)
                       and n.value is guards[0])
    prefix = [n for stmt in fn.body[:guard_index] for n in ast.walk(stmt)]
    if (len(reads) > 8 or len(guards) != 1
            or any(isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n is not fn for n in nodes)
            or any(isinstance(n, excluded) for n in prefix)):
        return result
    if all(r.lineno > guards[0].end_lineno for r in reads):
        result["result"] = "observed"
        result["detail"] = ("A direct top-level bearer-guard call precedes every direct payment_repo.get "
                            "call in this function's source. " + result["detail"])
    return result


def operator_finding_context(finding: dict, facts: dict) -> list[dict]:
    title = str(finding.get("title", ""))[:2000]
    if not re.search(r"\boperator\b", title, re.I):
        return []
    matches = []
    for record in (facts.get("functions") or {}).get("records", []):
        if record["file"] != finding.get("file"):
            continue
        for check in record["checks"]:
            if (check["kind"] == "operator_guard_order"
                    and check["function_line_start"] <= int(finding["line_start"])
                    <= int(finding["line_end"]) <= check["function_line_end"]):
                matches.append({**check, "file": record["file"]})
    if len(matches) != 1:
        return []
    # Equivalence is deliberately narrow: one direct lookup, same function,
    # both titles question ownership scoping. Rate limiting and other concerns
    # are never merged merely because they mention an operator endpoint.
    if (len(matches[0]["read_lines"]) == 1
            and re.search(r"\b(?:lookup|fetches|reads|query)\b", title, re.I)
            and re.search(r"\bownership[ -]scop", title, re.I)
            and not re.search(r"\b(?:and|or|rate|injection|write)\b|[;\n]", title, re.I)):
        matches[0]["equivalence"] = "operator_payment_lookup_ownership"
    return matches
