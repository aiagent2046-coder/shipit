"""Plain text presentation of bounded JavaScript SQL source evidence."""
from app.scan.js_sql_review import normalize_review


def js_sql_review_rows(value: object, source: object) -> list[tuple[str, str]]:
    review = normalize_review(value, source)
    if review is None:
        if value is None:
            return []
        return [("JavaScript SQL source review unavailable",
                 "The saved source review could not be validated; original findings are retained.")]
    budget = review["budget"]
    rows = [
        ("JavaScript SQL source review", f"{review['status']}; {budget['processed']} observations; "
         f"{budget['omitted']} omitted; limit {budget['max_candidates']}."),
        ("JavaScript SQL review limits", "No LLM calls, runtime execution or automatic patch. "
         "Fixed SQL fragments do not establish project safety."),
    ]
    for index, item in enumerate(review["observations"], 1):
        analysis = item["analysis"]
        descriptions = {
            "fixed_sql_fragments": "Query text uses fixed fragments within bounded source analysis.",
            "dynamic_sql_unresolved": ("Dynamic SQL text remains unresolved; "
                                       "external input control was not established."),
            "unavailable": "Source review unavailable; no conclusion about the query was established.",
        }
        rows.extend([
            (f"JavaScript SQL observation {index}", f"{item['file']}:{item['line']} — {descriptions[item['state']]}"),
            ("Source review reason", analysis["reason"].replace("_", " ")),
            ("Parameter argument", f"{analysis['parameter_argument']}; presence alone does not establish "
             "parameter binding or driver behavior."),
            ("Source fragments", "; ".join(
                f"Line {fragment['line']}: {fragment['kind'].replace('_', ' ')} "
                f"({fragment['reason'].replace('_', ' ')})" for fragment in analysis["fragments"]
            ) or "No source fragments established."),
            ("Task handoff", "Detector → researcher → verifier; bounded deterministic source review. "
             "Saved digests are consistency links, not independent attestation."),
            ("Source SHA-256", analysis["source_sha256"]),
            ("Source review scope", "Static source analysis only. Runtime exploitability and database driver "
             "behavior remain unverified. The original finding is retained."),
        ])
    return rows
