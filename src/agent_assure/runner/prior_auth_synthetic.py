from __future__ import annotations

from agent_assure.canonical.hmac_tokens import hmac_sha256_token
from agent_assure.runner.fixture_runner import LoadedFixtures, RunnerContext, VariantConfig
from agent_assure.runner.prior_auth_app import EvidenceAssociation, run_prior_auth_app
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, EvidenceRef, PolicyResult
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
        fixtures.request,
        fixtures.model_output,
        fixtures.tool_output,
        evidence_assembly=variant.behavior.evidence_assembly,
        forbidden_providers=variant.provider_policy.forbidden_providers,
        runtime_allowed_providers=variant.provider_policy.runtime_allowed_providers,
        provider_policy_precedence=variant.behavior.provider_policy_precedence,
    )
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=context.ids.run_id(context.suite.suite_id, variant.variant_id, case.case_id),
        case_id=case.case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=variant.pipeline_id,
        recommendation=decision.recommendation,
        outcome=decision.outcome,
        input_summary=_input_summary(case, fixtures, context),
        output_summary=f"recommendation={decision.recommendation}; outcome={decision.outcome}",
        provider=decision.provider,
        model=decision.model,
        tools=decision.tools,
        evidence_refs=_evidence_refs(decision.evidence),
        policy_results=tuple(
            PolicyResult(
                artifact_kind="policy-result",
                policy_id=event.policy_id,
                state=event.state,
                reason_codes=event.reason_codes,
            )
            for event in decision.policy_events
        ),
        human_review_required=decision.human_review_required,
        human_review_performed=decision.human_review_performed,
        provenance=Provenance(
            artifact_kind="provenance",
            configuration_digest=variant.configuration_digest,
            fixture_manifest_digest=context.fixture_manifest_digest,
            model_identifier=decision.model,
        ),
    )


def _input_summary(case: SuiteCase, fixtures: LoadedFixtures, context: RunnerContext) -> str:
    subject_id = fixtures.request.get("member_id")
    subject_token = hmac_sha256_token(str(subject_id or case.case_id), key=context.hmac_key)[:16]
    return f"case={case.case_id}; subject_token={subject_token}; fixture={fixtures.fixture_id}"


def _evidence_refs(evidence: tuple[EvidenceAssociation, ...]) -> tuple[EvidenceRef, ...]:
    refs = [
        EvidenceRef(
            artifact_kind="evidence-ref",
            ref_id=item.ref_id,
            source_id=item.source_id,
            claim_ids=tuple(sorted(item.claim_ids)),
        )
        for item in evidence
    ]
    return tuple(sorted(refs, key=lambda ref: ref.ref_id))
