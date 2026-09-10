"""Source ownership/callback negatives: no target execution, model calls or policy assumptions."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import io
import zipfile

import pytest

from app.scan.auth_source_assessment import AuthSourceVerifier, MAX_CHECKS
from app.scan.claim_evidence import source_assessments, unsupported_transport
from app.scan.scoring import ScoredFinding, compute_scores
from tests.test_ownership_claims import SOURCE as OWNERSHIP, INSERT

PATH = "app/api/history/route.ts"
SERVICE = """import { createClient } from '@supabase/supabase-js';
export async function GET(req) {
  const token = req.headers.get('authorization');
  const db = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await db.auth.getUser(token);
  if (authError || !user) return forbidden();
  const { data: rows } = await db.from('history').select('id, content').eq('user_id', user.id);
  return rows;
}
"""
AUTH_GUARD = "  if (authError || !user) return forbidden();\n"
QUERY = "  const { data: rows } = await db.from('history').select('id, content').eq('user_id', user.id);\n"
TITLE = "Service-role client bypasses RLS on history queries"


def archive(files):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as z:
        for path, source in files.items():
            z.writestr(path, source)
    result.seek(0)
    return result


def raw(source, needle="db =", title=TITLE, path=PATH, **kwargs):
    line = next(n + 1 for n, line in enumerate(source.splitlines()) if needle in line)
    return {"title": title, "file": path, "line_start": line, "line_end": line, **kwargs}


def checks(source=SERVICE, **kwargs):
    f = raw(source, **kwargs)
    return AuthSourceVerifier(archive({f["file"]: source})).checks_for(f)


def test_verified_user_filter_is_a_bound_source_observation_not_policy_approval():
    (check,) = checks()
    assert check["kind"] == "verified_user_operation_scope"
    assert check["result"] == "observed"
    assert check["whole_finding"] is False
    assert check["source_sha256"] == hashlib.sha256(SERVICE.encode()).hexdigest()
    binding = check["source_binding"]
    assert binding["auth_call"]["line_start"] == 5
    assert binding["auth_return"]["line_start"] == 6
    assert binding["operations"][0]["operation"] == "SELECT"
    assert binding["operations"][0]["selected_columns"] == ["id", "content"]
    assert binding["sql_policy_status"] == "not_checked"
    assert binding["deferred_operations_assessed"] is False
    assert "narrative_review" not in check


def test_future_filter_narrative_requires_review_but_is_not_a_false_finding_exemption():
    (observed,) = checks(explanation="A future query omitting the ownership filter would expose rows.")
    assert observed["narrative_review"]["premise"] == observed["kind"]
    ev = {"version": 1, "source_assessments": [observed], "consequence_status": "not_checked"}
    assert source_assessments(ev) == [observed]
    assert not unsupported_transport(ev)
    f = ScoredFinding(
        rule_id="llm-auth",
        title=TITLE,
        category="Auth",
        severity="high",
        confidence=0.9,
        file=PATH,
        line=4,
        source="llm",
        claim_evidence=ev,
    )
    plain = ScoredFinding(**{**asdict(f), "claim_evidence": {}})
    assert compute_scores([f]) == compute_scores([plain])


@pytest.mark.parametrize(
    "old,new",
    [
        (".eq('user_id', user.id)", ""),
        (".eq('user_id', user.id)", ".eq('user_id', other.id)"),
        (".eq('user_id', user.id)", ".eq('owner_id', user.id)"),
        (".eq('user_id', user.id)", ".eq('user_id', user.id).or(requestFilter)"),
        (".eq('user_id', user.id)", ".eq('user_id', user.id).eq('user_id', other)"),
        (AUTH_GUARD, ""),
        (AUTH_GUARD, "  if (authError) return forbidden();\n"),
        (AUTH_GUARD, "  if (!user) log();\n"),
        (AUTH_GUARD, "  if (enabled) { if (!user) return forbidden(); }\n"),
        (AUTH_GUARD, "  const later = () => { if (!user) return forbidden(); };\n"),
        ("db.auth.getUser(token)", "other.auth.getUser(token)"),
        ("db.auth.getUser(token)", "db.auth.getUser?.(token)"),
        ("db.auth.getUser(token)", "db.auth.getSession(token)"),
        ("from '@supabase/supabase-js'", "from './custom-db'"),
        ("SUPABASE_SERVICE_ROLE_KEY", "SUPABASE_ANON_KEY"),
        ("const db =", "let db ="),
        ("const { data: { user }", "let { data: { user }"),
        (QUERY, QUERY + "  user.id = forged;\n"),
        (QUERY, "  mutate(user);\n" + QUERY),
        (QUERY, "  const alias = user; alias.id = forged;\n" + QUERY),
        (QUERY, "  const alias = db; alias.auth = forged;\n" + QUERY),
        (QUERY, "  setTimeout(() => { user.id = forged; }, 0);\n" + QUERY),
        (QUERY, "  const later = (user) => user.id;\n" + QUERY),
        (QUERY, "  db.auth.getUser = fake;\n" + QUERY),
        (QUERY, "  user.change();\n" + QUERY),
    ],
)
def test_missing_wrong_mutated_ambiguous_or_deferred_user_path_does_not_gain_scope(old, new):
    assert old in SERVICE
    assert checks(SERVICE.replace(old, new)) == []


def test_guard_after_query_does_not_cover_query():
    assert checks(SERVICE.replace(AUTH_GUARD + QUERY, QUERY + AUTH_GUARD)) == []


def test_const_user_id_alias_is_supported_only_with_same_scope_and_binding():
    source = SERVICE.replace(QUERY, "  const principal = user.id;\n" + QUERY.replace("user.id", "principal"))
    assert checks(source)
    assert not checks(source.replace("const principal", "let principal"))
    assert not checks(source.replace("  const principal = user.id;", "  if (enabled) { const principal = user.id; }"))
    assert not checks(source.replace("return rows;", "principal = other; return rows;"))


def test_distinct_query_without_filter_is_recorded_as_unassessed_not_hidden():
    source = SERVICE.replace(QUERY, QUERY + "  const x = await db.from('other').select('*');\n")
    (record,) = checks(source)
    assert len(record["source_binding"]["operations"]) == 1
    assert record["source_binding"]["unassessed_direct_operations"] == 1


@pytest.mark.parametrize("method", ["delete()", "update({content: 'value'})"])
def test_filter_binding_applies_to_checked_write_operation_only(method):
    (record,) = checks(SERVICE.replace("select('id, content')", method))
    assert record["source_binding"]["operations"][0]["operation"] == method.split("(")[0].upper()


def test_insert_with_explicit_verified_user_value_rejects_duplicate_spread_and_wrong_id():
    source = SERVICE.replace(
        "select('id, content').eq('user_id', user.id)", "insert({user_id: user.id, content: text})"
    )
    (record,) = checks(source)
    assert record["source_binding"]["operations"][0]["operation"] == "INSERT"
    assert not checks(source.replace("user_id: user.id", "user_id: other.id"))
    assert not checks(source.replace("user_id: user.id", "user_id: user.id, ...extra"))
    assert not checks(source.replace("user_id: user.id", "user_id: user.id, user_id: other"))


def test_sql_declarations_do_not_change_source_policy_status_or_disposition():
    f = raw(SERVICE)
    checks_without = AuthSourceVerifier(archive({PATH: SERVICE})).checks_for(f)
    checks_with = AuthSourceVerifier(
        archive(
            {
                PATH: SERVICE,
                "supabase/migrations/0001.sql": (
                    "ALTER TABLE history ENABLE ROW LEVEL SECURITY; CREATE POLICY own ON history USING (true);"
                ),
            }
        )
    ).checks_for(f)
    assert checks_with == checks_without


CALLBACK = """  if (insErr) return failure();
  after(async () => {
    const { count } = await admin.from('messages').select('*', {count: 'exact', head: true}).eq('match_id', matchId);
    if (count !== null && count <= 1) {
      const recipientId = match.founder1_id === myProfile.id ? match.founder2_id : match.founder1_id;
      const { data: recipient } = await admin.from('founder_profiles').select('*').eq('id', recipientId).single();
      if (recipient) {
        await fetch(endpoint);
        await admin.from('messages').insert({match_id: matchId, sender_id: recipientId, content: reply});
      }
    }
  });
"""
CALLBACK_SOURCE = "import { after } from 'next/server';\n" + OWNERSHIP.replace(
    "  return message;", CALLBACK + "  return message;"
).replace(
    "  const supabase = createClient(url, key);",
    "  const supabase = createClient(url, key);\n  const admin = createClient(url, key);",
)
CALLBACK_TITLE = "L2 auto-reply triggered on first message without verifying sender"


def callback_check(source=CALLBACK_SOURCE, title=CALLBACK_TITLE):
    return checks(source, needle="const { count }", title=title, path="app/api/messages/route.ts")


def test_callback_guard_link_checks_sender_insert_and_same_recipient_target():
    (record,) = callback_check()
    assert record["kind"] == "ownership_guard_before_callback"
    assert record["result"] == "contradicted" and not record["whole_finding"]
    assert record["source_binding"]["callback_revalidation"] == "not_checked"
    assert record["source_binding"]["ownership_proof"]["source_entities"]["subject"] == "matchId"
    assert "later membership changes" in record["detail"]


def test_missing_reverification_inside_callback_is_not_contradicted_by_prior_guard():
    (record,) = callback_check(title="L2 auto-reply callback does not re-verify sender after scheduling")
    assert record["result"] == "observed"
    assert "not a missing recheck inside the callback" in record["detail"]


@pytest.mark.parametrize(
    "old,new",
    [
        ("if (insErr) return failure();", "if (insErr) log();"),
        ("if (insErr) return failure();", ""),
        ("from 'next/server'", "from './custom-scheduler'"),
        (".eq('id', recipientId)", ".eq('id', otherRecipient)"),
        ("sender_id: recipientId", "sender_id: otherRecipient"),
        ("match_id: matchId, sender_id: recipientId", "match_id: otherMatch, sender_id: recipientId"),
        ("match.founder1_id === myProfile.id", "match.founder1_id === otherProfile.id"),
        ("? match.founder2_id : match.founder1_id", "? match.founder1_id : match.founder2_id"),
        ("const recipientId", "let recipientId"),
        ("const { count }", "myProfile.id = forged; const { count }"),
        ("const { count }", "const alias = match; alias.founder1_id = forged; const { count }"),
        ("const { count }", "mutate(match); const { count }"),
        ("const { count }", "after = fake; const { count }"),
        ("const { count }", "const another = (myProfile) => myProfile.id; const { count }"),
        (".eq('user_id', user.id)", ".eq('user_id', other.id)"),
        (
            "myProfile.id !== match.founder1_id && myProfile.id !== match.founder2_id",
            "myProfile.id !== match.founder1_id || myProfile.id !== match.founder2_id",
        ),
    ],
)
def test_other_callback_targets_guard_failures_and_object_mutation_abstain(old, new):
    assert old in CALLBACK_SOURCE
    assert callback_check(CALLBACK_SOURCE.replace(old, new)) == []


def test_guard_in_another_callback_or_registered_after_unchecked_write_cannot_cover_callback():
    assert callback_check(CALLBACK_SOURCE.replace(INSERT + CALLBACK, CALLBACK + INSERT)) == []
    assert (
        callback_check(
            CALLBACK_SOURCE.replace("  after(async () => {", "  const invokeLater = () => after(async () => {")
        )
        == []
    )


@pytest.mark.parametrize(
    "override",
    [
        {"line_start": True},
        {"line_end": 9999},
        {"line_start": 0},
        {"line_end": 1},
        {"file": "../source.ts"},
        {"file": "tests/source.ts"},
        {"file": "/tmp/source.ts"},
    ],
)
def test_invalid_source_paths_or_locations_do_not_produce_dispositions(override):
    verifier = AuthSourceVerifier(archive({PATH: SERVICE}))
    assert verifier.checks_for({**raw(SERVICE), **override}) == []


def test_cache_isolated_and_caller_mutation_cannot_change_assessment():
    verifier = AuthSourceVerifier(archive({PATH: SERVICE}))
    finding = raw(SERVICE)
    snapshot = deepcopy(finding)
    result = verifier.checks_for(finding)
    result[0]["source_binding"]["operations"].clear()
    assert verifier.checks_for(finding)[0]["source_binding"]["operations"]
    assert finding == snapshot
    verifier.checks = MAX_CHECKS
    assert verifier.checks_for({**finding, "title": TITLE + " different"}) == []
    assert AuthSourceVerifier(archive({PATH: SERVICE + "\nfunction {"})).checks_for(finding) == []


def test_untrusted_model_assessments_never_create_auth_observations():
    raw_finding = raw(
        SERVICE.replace(".eq('user_id', user.id)", ""),
        source_assessments=[{"kind": "verified_user_operation_scope", "result": "observed"}],
    )
    verifier = AuthSourceVerifier(archive({PATH: SERVICE.replace(".eq('user_id', user.id)", "")}))
    assert verifier.checks_for(raw_finding) == []


MATCHES = """import { createClient } from '@supabase/supabase-js';
export async function GET(req) {
  const token = req.headers.get('authorization');
  const db = createClient(process.env.URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  const { data: { user }, error: authError } = await db.auth.getUser(token);
  if (authError || !user) return forbidden();
  const principal = user.id;
  const { data: myProfile } = await db.from('founder_profiles').select('id').eq('user_id', principal).single();
  if (!myProfile) return missing();
  const founder = myProfile.id;
  const { data: matches } = await db.from('matches').select('id, founder1_id, founder2_id')
    .or(`founder1_id.eq.${founder},founder2_id.eq.${founder}`).order('created_at');
  if (!matches || matches.length === 0) return empty();
  const peerIds = [];
  const matchIds = [];
  for (const m of matches) {
    matchIds.push(m.id);
    const peerId = m.founder1_id === founder ? m.founder2_id : m.founder1_id;
    peerIds.push(peerId);
  }
  const { data: peers } = await db.from('founder_profiles').select('id, user_id, name, role').in('id', peerIds);
  return peers;
}
"""


def peer_checks(source=MATCHES, **kw):
    return [r for r in checks(source, **kw) if r["kind"] == "matched_peer_operation_scope"]


def test_verified_match_peer_scope_retains_projection_and_sql_unknown():
    (record,) = peer_checks()
    assert record["source_binding"]["selected_columns"] == ["id", "user_id", "name", "role"]
    assert record["source_binding"]["sql_policy_status"] == "not_checked"
    assert record["source_binding"]["dto_assessed"] is False
    assert record["result"] == "observed" and not record["whole_finding"]


@pytest.mark.parametrize(
    "old,new",
    [
        (".eq('user_id', principal)", ".eq('user_id', requestedId)"),
        ("founder2_id.eq.${founder}", "founder2_id.eq.${otherFounder}"),
        ("const founder = myProfile.id;", "const founder = requestedFounder;"),
        ("if (!myProfile) return missing();", ""),
        ("m.founder1_id === founder", "m.founder1_id === otherFounder"),
        ("? m.founder2_id : m.founder1_id", "? m.founder1_id : m.founder2_id"),
        (".in('id', peerIds)", ".in('id', requestedIds)"),
        (".in('id', peerIds)", ".in('id', peerIds).or(requestFilter)"),
        ("const peerIds = [];", "const peerIds = requestedIds;"),
        ("const peerIds = [];", "const peerIds = []; peerIds.push(other);"),
        ("const peerIds = [];", "const peerIds = []; const alias = peerIds; alias.push(other);"),
        ("const peerIds = [];", "const peerIds = []; setTimeout(() => peerIds.push(other), 0);"),
        ("const peerIds = [];", "const peerIds = []; mutate(matches);"),
        ("const peerIds = [];", "const peerIds = []; const alias = matches; alias.push(other);"),
        ("const peerIds = [];", "const peerIds = []; matches.splice(0, 0, other);"),
        ("const peerIds = [];", "const peerIds = []; matches[0].founder1_id = other;"),
        ("const peerIds = [];", "const peerIds = []; myProfile.id = other;"),
        ("const peerIds = [];", "const peerIds = []; founder = other;"),
        ("for (const m of matches)", "for (const m of allMatches)"),
        ("matchIds.push(m.id);", "m.founder1_id = requested;"),
        ("peerIds.push(peerId);", "peerIds.push(requested);"),
        ("select('id, user_id, name, role')", "select('*')"),
    ],
)
def test_wrong_peer_row_array_alias_mutation_or_selector_abstains(old, new):
    assert old in MATCHES
    assert peer_checks(MATCHES.replace(old, new)) == []


def test_profile_read_before_auth_return_is_not_an_auth_bound_peer_chain():
    profile = (
        "  const { data: myProfile } = await db.from('founder_profiles')"
        ".select('id').eq('user_id', principal).single();\n"
    )
    source = MATCHES.replace(AUTH_GUARD, "").replace(profile, profile + AUTH_GUARD)
    assert peer_checks(source) == []


def test_correctness_acknowledgment_does_not_invent_an_absent_guard_or_review():
    for text in (
        "Ownership checked; the service-role client uses a verified user filter.",
        "No claim of future bypass: ownership is correctly checked before the query.",
    ):
        (record,) = checks(explanation=text)
        assert record["result"] == "observed"
        assert "narrative_review" not in record


@pytest.mark.parametrize(
    "mutation",
    [
        "const auth = db.auth; auth.getUser = fake;",
        "Object.assign(db.auth, {getUser: fake});",
        "const getUser = db.auth.getUser; getUser.override = fake;",
        "db.auth.setSession(forged);",
    ],
)
def test_intermediate_auth_object_alias_or_mutator_does_not_gain_scope(mutation):
    source = SERVICE.replace("  const { data: { user }", "  " + mutation + "\n  const { data: { user }")
    assert checks(source) == []


def test_callback_recipient_must_be_declared_in_query_and_reply_scope():
    source = CALLBACK_SOURCE.replace("      const recipientId =", "      { const recipientId =").replace(
        "      const { data: recipient }", "      }\n      const { data: recipient }"
    )
    assert callback_check(source) == []


@pytest.mark.parametrize(
    "old,new",
    [
        ("admin.from", "attacker.from"),
        ("const admin = createClient(url, key);", "const admin = unknownClient;"),
        ("const admin = createClient(url, key);", "const admin = createClient(url, key); const alias = admin;"),
        ("const admin = createClient(url, key);", "const admin = createClient(url, key); admin.from = fake;"),
    ],
)
def test_callback_database_receiver_must_have_unambiguous_sdk_binding(old, new):
    assert callback_check(CALLBACK_SOURCE.replace(old, new)) == []


@pytest.mark.parametrize(
    "replacement",
    [
        "  try { return mutate(db); } finally {\n" + QUERY + "  }\n",
        "  try { return mutate({db}); } finally {\n" + QUERY + "  }\n",
        "  try { return mutate(db); } catch (e) {\n" + QUERY + "  }\n",
        "  return (mutate(db), await db.from('history').select('id, content').eq('user_id', user.id));\n",
        "  return helper(mutate(db), await db.from('history').select('id, content').eq('user_id', user.id));\n",
    ],
)
def test_returning_client_escape_cannot_cover_finally_catch_or_later_argument_queries(replacement):
    assert checks(SERVICE.replace(QUERY, replacement)) == []


def test_direct_helper_return_in_separate_terminating_branch_preserves_later_query_context():
    (record,) = checks(
        SERVICE.replace(QUERY, "  if (remember) return await rememberFacts({db, userId: user.id});\n" + QUERY)
    )
    assert record["source_binding"]["operations"][0]["operation"] == "SELECT"


def test_client_escape_after_registration_can_mutate_deferred_callback_receiver():
    source = CALLBACK_SOURCE.replace("  return message;", "  return mutate(admin);")
    assert callback_check(source) == []


@pytest.mark.parametrize(
    "title",
    [
        "L2 auto-reply runs without verifying sender email ownership",
        "L2 auto-reply runs without verifying sender signature",
        "L2 auto-reply is not run without verifying sender",
        "No evidence that L2 auto-reply runs without verifying sender",
        "Check whether L2 auto-reply runs without verifying sender",
    ],
)
def test_other_sender_verification_claims_and_negation_remain_observations(title):
    (record,) = callback_check(title=title)
    assert record["result"] == "observed"


@pytest.mark.parametrize(
    "mutation",
    [
        "const auth = supabase.auth; auth.getUser = fake;",
        "Object.assign(supabase.auth, {getUser: fake});",
    ],
)
def test_callback_prior_authentication_client_also_rejects_intermediate_alias_mutation(mutation):
    source = CALLBACK_SOURCE.replace("  const { data: { user }", "  " + mutation + "\n  const { data: { user }")
    assert callback_check(source) == []
