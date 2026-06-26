from __future__ import annotations

from agent_assure.runner.evidence import EvidenceAssociation, evidence_refs_from_associations
from agent_assure.runner.fixture_runner import RunnerContext, VariantConfig
from agent_assure.runner.governance_controls import PolicyEvent
from agent_assure.schema.common import ExecutionMode
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult
from agent_assure.schema.suite import SuiteCase


def build_fixture_run_record(
    *,
    case: SuiteCase,
    variant: VariantConfig,
    context: RunnerContext,
    recommendation: str,
    outcome: str,
    input_summary: str,
    provider: str | None,
    model: str | None,
    tools: tuple[str, ...],
    evidence: tuple[EvidenceAssociation, ...],
    policy_events: tuple[PolicyEvent, ...],
    human_review_required: bool,
    human_review_performed: bool,
) -> AgentRunRecord:
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=context.ids.run_id(context.suite.suite_id, variant.variant_id, case.case_id),
        case_id=case.case_id,
        execution_mode=ExecutionMode.fixture,
        pipeline_id=variant.pipeline_id,
        recommendation=recommendation,
        outcome=outcome,
        input_summary=input_summary,
        output_summary=f"recommendation={recommendation}; outcome={outcome}",
        provider=provider,
        model=model,
        tools=tools,
        evidence_refs=evidence_refs_from_associations(evidence),
        policy_results=policy_results_from_events(policy_events),
        human_review_required=human_review_required,
        human_review_performed=human_review_performed,
        provenance=Provenance(
            artifact_kind="provenance",
            configuration_digest=variant.configuration_digest,
            fixture_manifest_digest=context.fixture_manifest_digest,
            model_identifier=model,
        ),
    )


def policy_results_from_events(events: tuple[PolicyEvent, ...]) -> tuple[PolicyResult, ...]:
    return tuple(
        PolicyResult(
            artifact_kind="policy-result",
            policy_id=event.policy_id,
            state=event.state,
            reason_codes=event.reason_codes,
        )
        for event in events
    )
