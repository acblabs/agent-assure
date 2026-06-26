from __future__ import annotations

from agent_assure.runner.evidence import EvidenceAssociation, evidence_refs_from_associations
from agent_assure.runner.fixture_runner import RunnerContext, VariantConfig
from agent_assure.runner.governance_controls import PolicyEvent
from agent_assure.schema.common import ExecutionMode, GateState, Severity
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
            severity=event.severity or _severity_for_state(event.state),
            message=event.message or _message_for_event(event),
        )
        for event in events
    )


def _severity_for_state(state: GateState) -> Severity:
    if state is GateState.fail:
        return Severity.error
    if state is GateState.warn:
        return Severity.warning
    if state is GateState.not_evaluated:
        return Severity.info
    return Severity.info


def _message_for_event(event: PolicyEvent) -> str:
    if event.reason_codes:
        reason_codes = ", ".join(reason.value for reason in event.reason_codes)
        return f"{event.policy_id} emitted {reason_codes}"
    return f"{event.policy_id} state is {event.state.value}"
