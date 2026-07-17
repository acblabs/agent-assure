from __future__ import annotations

from agent_assure.canonical.hmac_tokens import hmac_sha256_token
from agent_assure.examples.prior_auth_synthetic.app import run_prior_auth_app
from agent_assure.examples.prior_auth_synthetic.rag import (
    RetrievalResult,
    evidence_from_retrieval,
    retrieve_for_variant,
)
from agent_assure.runner.fixture_runner import LoadedFixtures, RunnerContext, VariantConfig
from agent_assure.runner.records import build_fixture_run_record
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.suite import SuiteCase


def run_prior_auth_case(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    variant: VariantConfig,
    context: RunnerContext,
) -> AgentRunRecord:
    if variant.behavior.runtime_error_case == case.case_id:
        raise RuntimeError("fixture-declared runtime failure")

    decision = run_prior_auth_app(
        fixtures.model_output,
        fixtures.tool_output,
        evidence_assembly=variant.behavior.evidence_assembly,
        forbidden_providers=variant.provider_policy.forbidden_providers,
        runtime_allowed_providers=variant.provider_policy.runtime_allowed_providers,
        provider_policy_precedence=variant.behavior.provider_policy_precedence,
    )
    return build_fixture_run_record(
        case=case,
        variant=variant,
        context=context,
        recommendation=decision.recommendation,
        outcome=decision.outcome,
        input_summary=_input_summary(case, fixtures, context),
        provider=decision.provider,
        model=decision.model,
        tools=decision.tools,
        evidence=decision.evidence,
        policy_events=decision.policy_events,
        human_review_required=decision.human_review_required,
        human_review_performed=decision.human_review_performed,
    )


def run_prior_auth_case_evidence_refactor(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    variant: VariantConfig,
    context: RunnerContext,
) -> AgentRunRecord:
    refactor_variant = variant.model_copy(
        update={
            "behavior": variant.behavior.model_copy(
                update={"evidence_assembly": "source_digest_normalized"}
            )
        }
    )
    return run_prior_auth_case(case, fixtures, refactor_variant, context)


def run_prior_auth_case_rag(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    variant: VariantConfig,
    context: RunnerContext,
) -> AgentRunRecord:
    retrieval = retrieve_for_variant(
        context.suite_root,
        fixtures.request,
        variant_id=variant.variant_id,
        fixture_bytes_reader=context.read_fixture_bytes,
    )
    tool_output = dict(fixtures.tool_output)
    tool_output["evidence"] = tuple(
        {
            "ref_id": item.ref_id,
            "source_id": item.source_id,
            "content_digest": item.content_digest,
            "claim_ids": item.claim_ids,
        }
        for item in evidence_from_retrieval(retrieval)
    )
    decision = run_prior_auth_app(
        fixtures.model_output,
        tool_output,
        evidence_assembly=variant.behavior.evidence_assembly,
        forbidden_providers=variant.provider_policy.forbidden_providers,
        runtime_allowed_providers=variant.provider_policy.runtime_allowed_providers,
        provider_policy_precedence=variant.behavior.provider_policy_precedence,
    )
    record = build_fixture_run_record(
        case=case,
        variant=variant,
        context=context,
        recommendation=decision.recommendation,
        outcome=decision.outcome,
        input_summary=_rag_input_summary(case, fixtures, context, retrieval),
        provider=decision.provider,
        model=decision.model,
        tools=decision.tools,
        evidence=decision.evidence,
        policy_events=decision.policy_events,
        human_review_required=decision.human_review_required,
        human_review_performed=decision.human_review_performed,
    )
    return record.model_copy(
        update={
            "provenance": record.provenance.model_copy(
                update={
                    "retrieval_corpus_digest": retrieval.corpus.retrieval_corpus_digest,
                }
            )
        }
    )


def _input_summary(case: SuiteCase, fixtures: LoadedFixtures, context: RunnerContext) -> str:
    subject_id = fixtures.request.get("member_id")
    subject_token = hmac_sha256_token(str(subject_id or case.case_id), key=context.hmac_key)[:32]
    return f"case={case.case_id}; subject_token={subject_token}; fixture={fixtures.fixture_id}"


def _rag_input_summary(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    context: RunnerContext,
    retrieval: RetrievalResult,
) -> str:
    subject_id = fixtures.request.get("member_id")
    subject_token = hmac_sha256_token(str(subject_id or case.case_id), key=context.hmac_key)[:32]
    return (
        f"case={case.case_id}; subject_token={subject_token}; fixture={fixtures.fixture_id}; "
        f"query_digest={retrieval.normalized_query_digest}; "
        f"corpus_version={retrieval.corpus.corpus_version}"
    )
