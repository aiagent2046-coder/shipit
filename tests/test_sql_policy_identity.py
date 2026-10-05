"""Minimized, offline regressions for policy and cascade review hypotheses."""
from copy import deepcopy
from dataclasses import replace
import io
import zipfile

import pytest

from app.scan import sql_policy_identity as sql
from app.scan.scoring import ScoredFinding


SOURCE = '''-- Миграция: Unicode before AST offsets.
CREATE TABLE public.profiles (id uuid PRIMARY KEY);
CREATE TABLE public.matches (
 id uuid PRIMARY KEY,
 first_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE,
 second_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE
);
CREATE TABLE public.messages (
 id uuid PRIMARY KEY,
 match_id uuid REFERENCES public.matches(id) ON DELETE CASCADE,
 sender_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE
);
CREATE POLICY read_messages ON public.messages FOR SELECT USING (true);
CREATE POLICY send_messages ON public.messages FOR INSERT WITH CHECK (
 sender_id IS NOT NULL
);
'''
POLICY_TITLES = ["Message insert policy does not scope the match to its participants",
                 "Message insert policy does not check match membership"]
CASCADE_TITLES = ["Deleting a profile can delete shared match messages",
                  "Deleting a profile can remove match conversations"]


def archive(source=SOURCE, path="schema.sql"):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w") as zf:
        zf.writestr(path, source)
    result.seek(0)
    return result


def raw(title, start, end):
    return {"title": title, "file": "schema.sql", "line_start": start, "line_end": end,
            "observation": ("The schema cascades profile deletion to matches and match deletion to messages."
                            if title.startswith("Deleting") else
                            "The INSERT policy checks that sender_id belongs to the authenticated user's profile, "
                            "but does not check that the user participates in the match identified by match_id."),
            "explanation": "Deployed policy, grants and recovery remain unverified.",
            "fix_hint": "Check the intended behavior.", "required_conditions": ["Relevant code is deployed."]}


def scored(record, identity, response=1):
    return ScoredFinding(rule_id="llm-security", title=record["title"], file=record["file"],
                         line=record["line_start"], category="Security", severity="medium", confidence=.9,
                         source="llm", verification_method="model_review", explanation=record["explanation"],
                         fix_hint=record["fix_hint"], claim_evidence={
                             "source_issue_identity": identity, "observation": record["observation"],
                             "source_check": {"kind": "quote_match", "line_start": record["line_start"],
                                              "line_end": record["line_end"]},
                             "producer": {"model": "fixture", "rubric": "security", "response": response},
                             "conditions_status": "not_checked", "consequence_status": "not_checked",
                             "required_conditions": record["required_conditions"]})


@pytest.mark.parametrize("titles,ranges,kind", [
    (POLICY_TITLES, [(14, 16), (13, 16)], sql.POLICY),
    (CASCADE_TITLES, [(2, 12), (8, 12)], sql.CASCADE),
])
def test_paraphrases_bind_same_ast_operation_and_preserve_uncertainty(titles, ranges, kind):
    resolver = sql.SQLPolicyResolver(archive())
    records = [raw(title, *span) for title, span in zip(titles, ranges)]
    identities = [resolver.identity(record) for record in records]
    assert identities[0] == identities[1]
    assert sql.valid_sql_policy_identity(identities[0], "schema.sql")
    assert identities[0]["mechanism"] == kind
    left, right = [scored(record, identity, response) for response, (record, identity)
                   in enumerate(zip(records, identities), 1)]
    right.claim_evidence["required_conditions"] = ["Grants have not been tested."]
    assert sql.compatible_sql_policy_claims(left, right, identities[0])
    lo, hi = identities[0]["operation_span"]
    selected = SOURCE.encode()[lo:hi].decode()
    assert SOURCE.encode()[:lo].count(b"\n") + 1 == identities[0]["operation_line_start"]
    assert SOURCE.encode()[:hi - 1].count(b"\n") + 1 == identities[0]["operation_line_end"]
    assert selected.startswith("CREATE POLICY" if kind == sql.POLICY else "match_id")
    assert "source_sha256" in identities[0]
    assert "sender_id IS NOT NULL" not in str(identities[0])
    assert left.verification_status == right.verification_status == "unverified"


def test_different_policy_and_broad_ambiguous_citation_stay_separate():
    source = SOURCE + "CREATE POLICY other ON public.messages FOR INSERT WITH CHECK (true);\n"
    resolver = sql.SQLPolicyResolver(archive(source))
    first = resolver.identity(raw(POLICY_TITLES[0], 14, 16))
    second = resolver.identity(raw(POLICY_TITLES[1], 17, 17))
    assert first and second and first != second
    assert resolver.identity(raw(POLICY_TITLES[0], 14, 17)) is None
    assert resolver.identity(raw(POLICY_TITLES[0], 13, 13)) is None


def test_membership_target_is_a_source_relation_not_arbitrary_title_noun():
    source = SOURCE.replace(" sender_id uuid", " other_id uuid REFERENCES public.teams(id),\n sender_id uuid")
    resolver = sql.SQLPolicyResolver(archive(source))
    left = resolver.identity(raw(POLICY_TITLES[0], 15, 17))
    team = raw("Message insert policy does not check team membership", 15, 17)
    team["observation"] = team["observation"].replace("match", "team")
    right = resolver.identity(team)
    assert left and right and left != right
    assert resolver.identity(raw("Message insert policy does not check nonexistent membership", 15, 17)) is None


def test_distinct_terminal_constraints_are_separate_and_broad_chain_abstains():
    source = SOURCE.replace(" sender_id uuid",
                            " other_match uuid REFERENCES public.matches(id) ON DELETE CASCADE,\n sender_id uuid")
    resolver = sql.SQLPolicyResolver(archive(source))
    left = resolver.identity(raw(CASCADE_TITLES[0], 10, 10))
    right = resolver.identity(raw(CASCADE_TITLES[1], 11, 11))
    assert left and right and left != right
    assert resolver.identity(raw(CASCADE_TITLES[0], 8, 13)) is None


@pytest.mark.parametrize("source", [
    SOURCE.replace("public.matches(id) ON DELETE CASCADE", "public.matches(id) ON DELETE RESTRICT"),
    SOURCE.replace("public.profiles(id) ON DELETE CASCADE", "public.profiles(id) ON DELETE SET NULL"),
    SOURCE.replace("public.profiles", "profiles"),
    SOURCE + "CREATE TABLE public.matches(id int);\n",
    SOURCE.replace("second_id uuid REFERENCES public.profiles", "second_id uuid REFERENCES archive.profiles"),
])
def test_unsupported_or_ambiguous_cascade_chain_abstains(source):
    assert sql.SQLPolicyResolver(archive(source)).identity(raw(CASCADE_TITLES[0], 2, 12)) is None


def test_direct_sender_cascade_and_unrelated_coordinates_do_not_select_chain():
    resolver = sql.SQLPolicyResolver(archive())
    assert resolver.identity(raw(CASCADE_TITLES[0], 11, 11)) is None
    assert resolver.identity(raw(CASCADE_TITLES[0], 1, 1)) is None
    assert resolver.identity(raw(POLICY_TITLES[0], 2, 2)) is None


@pytest.mark.parametrize("title", [
    "Message insert policy does not check match membership and permits SQL injection",
    "Message insert policy does not check match membership; missing encryption",
    "Message insert policy lacks a check constraint",
    "Deleting a profile can remove match conversations and tokens",
    "Deleting a profile can remove messages",  # A different, direct cascade.
])
def test_compound_and_unsupported_titles_abstain(title):
    assert sql.SQLPolicyResolver(archive()).identity(raw(title, 1, 16)) is None


@pytest.mark.parametrize("key,value", [
    ("observation", "The same operation also causes SQL injection."),
    ("required_conditions", "not a list"), ("premises", [{"kind": "another_claim"}]),
    ("line_start", True), ("line_end", 999), ("file", "../schema.sql"),
])
def test_malformed_or_compound_claims_abstain(key, value):
    record = raw(POLICY_TITLES[0], 14, 16)
    record[key] = value
    assert sql.SQLPolicyResolver(archive()).identity(record) is None


@pytest.mark.parametrize("changed", ["source", "verification_status", "category", "conditions_status",
                                     "consequence_status", "premise_checks", "source_hash", "quote_result"])
def test_incompatible_evidence_cannot_share_a_group(changed):
    record = raw(POLICY_TITLES[0], 14, 16)
    identity = sql.SQLPolicyResolver(archive()).identity(record)
    left, right = scored(record, identity), scored(record, identity, 2)
    if changed in {"source", "verification_status", "category"}:
        right = replace(right, **{changed: "different"})
    elif changed == "source_hash":
        right.claim_evidence["source_check"]["source_sha256"] = "a" * 64
    elif changed == "quote_result":
        right.claim_evidence["source_check"]["result"] = "contradicted"
    else:
        right.claim_evidence[changed] = [{"result": "observed"}] if changed == "premise_checks" else "observed"
    assert not sql.compatible_sql_policy_claims(left, right, identity)


def test_invalid_schema_and_tampered_identity_fail_closed():
    assert sql.SQLPolicyResolver(archive("CREATE TABLE (;")).identity(raw(POLICY_TITLES[0], 1, 1)) is None
    record = raw(POLICY_TITLES[0], 14, 16)
    identity = sql.SQLPolicyResolver(archive()).identity(record)
    for key, value in [("version", True), ("claim_scope", "all_security"), ("operation_span", [0, 999999]),
                       ("binding_sha256", "x"), ("extra", "injected"), ("mechanism", []), ("version", {}),
                       ("operation_span", {}), ("operation_line_end", [])]:
        altered = deepcopy(identity)
        altered[key] = value
        assert not sql.valid_sql_policy_identity(altered, "schema.sql")


def test_work_and_archive_limits_abstain(monkeypatch):
    record = raw(POLICY_TITLES[0], 14, 16)
    resolver = sql.SQLPolicyResolver(archive())
    resolver.work = 0
    assert resolver.identity(record) is None
    resolver = sql.SQLPolicyResolver(archive())
    resolver.checks = sql.MAX_CHECKS
    assert resolver.identity(record) is None
    monkeypatch.setattr(sql, "MAX_BYTES", 1)
    assert sql.SQLPolicyResolver(archive()).identity(record) is None


def test_closing_table_line_is_not_a_foreign_key_citation():
    source = SOURCE.replace(" match_id uuid REFERENCES public.matches(id) ON DELETE CASCADE,\n"
                            " sender_id uuid REFERENCES public.profiles(id) ON DELETE CASCADE",
                            " match_id uuid REFERENCES public.matches(id) ON DELETE CASCADE")
    resolver = sql.SQLPolicyResolver(archive(source))
    assert resolver.identity(raw(CASCADE_TITLES[0], 10, 10)) is not None
    assert resolver.identity(raw(CASCADE_TITLES[0], 11, 11)) is None


@pytest.mark.parametrize("title,span,extra", [
    (POLICY_TITLES[0], (14, 16),
     " The policy also permits changing the sender identity without ownership validation."),
    (CASCADE_TITLES[0], (2, 12),
     " The schema also deletes messages when only the sender profile is removed."),
])
def test_additional_observation_hypothesis_cannot_hide_behind_supported_title(title, span, extra):
    record = raw(title, *span)
    resolver = sql.SQLPolicyResolver(archive())
    identity = resolver.identity(record)
    assert identity is not None
    compound = deepcopy(record)
    compound["observation"] += extra
    assert resolver.identity(compound) is None
    # Also reject replay with an old or injected otherwise-valid identity.
    assert not sql.compatible_sql_policy_claims(scored(record, identity), scored(compound, identity), identity)


@pytest.mark.parametrize("observation", [
    "The INSERT policy checks that the authenticated user owns the message’s sender profile, "
    "but this condition does not check whether that profile participates in the message’s match.",
    "The INSERT policy checks that sender_id belongs to the authenticated user’s profile, "
    "but does not check that the user participates in the match identified by match_id.",
])
def test_supported_policy_observation_paraphrases(observation):
    record = raw(POLICY_TITLES[0], 14, 16)
    record["observation"] = observation
    assert sql.SQLPolicyResolver(archive()).identity(record) is not None


@pytest.mark.parametrize("observation", [
    "The schema cascades profile deletion to matches and match deletion to messages.",
    "Founder profile references in the matches table use ON DELETE CASCADE, "
    "and messages reference matches with ON DELETE CASCADE.",
])
def test_supported_cascade_observation_paraphrases(observation):
    record = raw(CASCADE_TITLES[0], 2, 12)
    record["observation"] = observation
    assert sql.SQLPolicyResolver(archive()).identity(record) is not None


@pytest.mark.parametrize("replacement", ["team", "sender", "unknown"])
def test_observation_relation_must_match_title_scope(replacement):
    record = raw(POLICY_TITLES[0], 14, 16)
    record["observation"] = record["observation"].replace("match", replacement)
    assert sql.SQLPolicyResolver(archive()).identity(record) is None
