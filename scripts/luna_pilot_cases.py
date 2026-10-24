"""Synthetic offline regression pairs for the model pilot.

Inspired by the saved audit's pagination and fact-rendering mistakes; these
are not extracts of its repository. Review expectations are evaluator-only
metadata and must never be included in the model prompt.
"""

_MESSAGES = """export async function getMessages(db, matchId: string, afterTs?: string) {
  let query = db.from('messages')
    .select('*')
    .eq('match_id', matchId)
    .order('created_at', { ascending: true });
  if (afterTs) query = query.gt('created_at', afterTs);
  const { data, error } = await query;
  if (error) throw error;
  return data ?? [];
}
"""

_FACT_HELPER = """export const MAX_FACTS = 40;
export function sanitizeFacts(facts: Array<{content: string}>, opts: {maxFacts?: number} = {}) {
  const maxFacts = opts.maxFacts ?? MAX_FACTS;
  return (facts ?? []).map(f => f.content.trim()).filter(Boolean).slice(0, maxFacts);
}
export function buildFactBlock(facts: string[]) {
  if (!facts.length) return '';
  return `<facts>${facts.map(f => `- ${f}`).join('\\n')}</facts>`;
}
"""

_FACT_CALLER = """import { sanitizeFacts, buildFactBlock } from './fact_helpers';
export async function agentContext(db, userId: string) {
  const { data: facts } = await db.from('user_facts').select('content').eq('user_id', userId);
  const factList = sanitizeFacts(facts ?? []);
  const prefix = buildFactBlock(factList);
  return prefix;
}
"""


def supplemental_cases() -> list[dict]:
    """Return independent inputs and private review notes; perform no I/O."""
    return [
        {
            "id": "pagination-control",
            "files": {"src/messages.ts": _MESSAGES.replace(
                ".order('created_at', { ascending: true });",
                ".order('created_at', { ascending: true }).limit(50);",
            )},
            "rubric": "money",
            "review_expectation": (
                "The SELECT has an explicit 50-row limit, including when afterTs is supplied. "
                "Do not claim this query lacks a row cap or fetches all matching rows. "
                "The row cap does not prove bounded database work, bytes per row, total traffic, "
                "or monetary cost; no provider charges or workload are supplied."
            ),
        },
        {
            "id": "pagination-unbounded",
            "files": {"src/messages.ts": _MESSAGES},
            "rubric": "money",
            "review_expectation": (
                "The SELECT has no explicit limit/range; the timestamp filter is not a row cap. "
                "Report this source-level omission with a matching quote and make any growth "
                "consequence conditional on matching-row count and provider behavior. "
                "Do not claim unlimited results or actual charges: database defaults, data "
                "volume, traffic, and billing are not established by this source."
            ),
        },
        {
            "id": "facts-control",
            "files": {"src/agent_context.ts": _FACT_CALLER, "src/fact_helpers.ts": _FACT_HELPER},
            "rubric": "money",
            "review_expectation": (
                "Follow the imported sanitizeFacts result into buildFactBlock: at most 40 "
                "nonempty fact strings are rendered. A claim that all facts are rendered "
                "without a count cap is contradicted. This count cap does not bound the "
                "preceding database read, fact length, full prompt, request frequency, or "
                "cost. The query still lacks an explicit row limit; separate that issue "
                "from rendering, and do not assert an actual model call or charges."
            ),
        },
        {
            "id": "facts-unbounded",
            "files": {
                "src/agent_context.ts": _FACT_CALLER,
                "src/fact_helpers.ts": _FACT_HELPER.replace(".slice(0, maxFacts)", ""),
            },
            "rubric": "money",
            "review_expectation": (
                "The imported sanitizer now trims/filters but never applies its declared "
                "maxFacts value. No explicit count cap precedes buildFactBlock; all returned "
                "nonempty facts reach its mapping. Identify this with source quotes rather "
                "than treating the unused constant as a defense. Keep rendering count "
                "separate from database read bounds, full prompt size, and cost. Growth "
                "depends on available facts; this code does not show model calls or charges."
            ),
        },
    ]
