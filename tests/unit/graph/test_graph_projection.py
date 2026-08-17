from __future__ import annotations

from dataclasses import dataclass

import pytest
from pydantic import ValidationError

from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
)
from agent_assure.graph.builder import build_evidence_graph
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.packet import build_privacy_filtered_evidence_graph
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
)
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphControlEfficacyProjection,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphFindingPayload,
    EvidenceGraphFindingType,
    EvidenceGraphNodeKind,
    EvidenceGraphReferenceRole,
    EvidenceGraphRequirementPayload,
    EvidenceGraphRequirementType,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import (
    HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
    STOCHASTIC_SUFFICIENCY_LIMITATION,
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    EvidenceState,
    GateEffect,
    MutationResultState,
)
from tests.unit.controls.test_control_efficacy import (
    _DROP_OPERATOR,
    _campaign,
    _manifest,
    _profile,
    _replace_result_state,
)


@dataclass(frozen=True)
class _RepresentativeSources:
    evaluation: EvaluationSummary
    comparison: ComparisonSummary
    mutation_result: AssuranceMutationResult
    efficacy: ControlEfficacyReport
    gate_profile: ControlEfficacyGateProfile
    gate_decision: ControlEfficacyGateDecision

    @property
    def subject(self) -> EvidenceGraphSubjectPayload:
        return EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=self.evaluation.runset_id,
            subject_digest=self.efficacy.source_digest,
        )


@pytest.fixture(scope="module")
def representative_sources() -> _RepresentativeSources:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    mutation_result = execution.campaign.operator_results[0].result
    efficacy = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = _profile()
    decision = evaluate_control_efficacy_gate(efficacy, profile)
    evaluation = _evaluation(
        runset_id="control-efficacy-test-runset",
        message="The material claim lost its evidence link.",
    )
    comparison = ComparisonSummary(
        baseline_runset_id="control-efficacy-baseline",
        candidate_runset_id=evaluation.runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.new_failure,
        fixture_equivalence_state=GateState.pass_,
        baseline_state=GateState.pass_,
        candidate_state=GateState.fail,
        provenance_changes=("Candidate provenance differs from the baseline.",),
        verdict_findings=("Candidate introduced a material evidence failure.",),
    )
    return _RepresentativeSources(
        evaluation=evaluation,
        comparison=comparison,
        mutation_result=mutation_result,
        efficacy=efficacy,
        gate_profile=profile,
        gate_decision=decision,
    )


def _evaluation(*, runset_id: str, message: str) -> EvaluationSummary:
    return EvaluationSummary(
        runset_id=runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="finding-material-evidence",
                case_id="case-material-evidence",
                control_id="material_claims_have_evidence",
                target="claim:material",
                state=GateState.fail,
                reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                message=message,
            ),
        ),
    )


def _complete_graph(sources: _RepresentativeSources) -> AssuranceEvidenceGraph:
    return build_evidence_graph(
        subject=sources.subject,
        evaluation=sources.evaluation,
        comparison=sources.comparison,
        mutation_results=(sources.mutation_result,),
        control_efficacy=sources.efficacy,
        gate_profile=sources.gate_profile,
        gate_decision=sources.gate_decision,
        limitations=("Packet-level review remains required.",),
    )


def _mutation_with_evaluation_basis(
    result: AssuranceMutationResult,
    basis: EvidenceEvaluationBasis,
    limitation: str,
) -> AssuranceMutationResult:
    payload = result.model_dump(mode="python", exclude={"result_digest"})
    payload.update(
        {
            "evaluator_evaluation_basis": basis,
            "evaluator_protocol_digest": "e" * 64,
            "limitations": (*result.limitations, limitation),
        }
    )
    return AssuranceMutationResult.build(**payload)


def test_representative_projection_exercises_the_complete_closed_vocabulary(
    representative_sources: _RepresentativeSources,
) -> None:
    graph = _complete_graph(representative_sources)

    assert {node.kind for node in graph.nodes} == set(EvidenceGraphNodeKind)
    assert {edge.kind for edge in graph.edges} == set(EvidenceGraphEdgeKind)
    assert {
        node.payload.requirement_type
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphRequirementPayload)
    } == set(EvidenceGraphRequirementType)
    assert {
        node.payload.evidence_type
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
    } == set(EvidenceGraphEvidenceType)
    assert {
        node.payload.finding_type
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
    } == set(EvidenceGraphFindingType)


def test_projection_preserves_verdict_states_provenance_and_gate_effects(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    graph = _complete_graph(sources)

    evaluation_finding_node = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.evaluation
    )
    assert evaluation_finding_node.payload.state is EvidenceState.violated
    assert evaluation_finding_node.payload.messages == (
        "The material claim lost its evidence link.",
    )
    assert any(
        edge.kind is EvidenceGraphEdgeKind.contradicts
        and edge.source_node_id == evaluation_finding_node.node_id
        for edge in graph.edges
    )

    comparison_finding = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.comparison_verdict
    )
    assert comparison_finding.state is EvidenceState.violated
    assert comparison_finding.messages == sources.comparison.verdict_findings
    comparison_evidence = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.comparison
    )
    assert comparison_evidence.privacy_profile_id == sources.comparison.privacy_profile_id
    assert comparison_evidence.privacy_profile_digest == sources.comparison.privacy_profile_digest
    assert comparison_evidence.comparison_projection is not None
    assert comparison_evidence.comparison_projection.model_dump(mode="json") == {
        "classification": sources.comparison.classification.value,
        "fixture_equivalence_state": sources.comparison.fixture_equivalence_state.value,
        "baseline_state": sources.comparison.baseline_state.value,
        "candidate_state": sources.comparison.candidate_state.value,
    }

    mutation_finding_node = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.mutation_result
    )
    assert mutation_finding_node.payload.state is EvidenceState.supported
    assert mutation_finding_node.payload.reason_codes == ("MUTATION_CAUGHT",)
    assert any(
        edge.kind is EvidenceGraphEdgeKind.supports
        and edge.source_node_id == mutation_finding_node.node_id
        for edge in graph.edges
    )

    efficacy_evidence = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.control_efficacy
    )
    assert efficacy_evidence.source_digest == sources.efficacy.report_digest
    assert efficacy_evidence.state is EvidenceState.supported
    assert efficacy_evidence.control_efficacy_projection is not None
    efficacy_projection = efficacy_evidence.control_efficacy_projection
    assert efficacy_projection.semantic_state is sources.efficacy.semantic_state
    assert efficacy_projection.threat_scope_state is sources.efficacy.threat_scope_state
    assert efficacy_projection.state_counts == sources.efficacy.state_counts
    assert efficacy_projection.catalog_kill_rate == sources.efficacy.catalog_kill_rate
    assert (
        efficacy_projection.independent_threat_challenge_rate
        == sources.efficacy.independent_threat_challenge_rate
    )
    assert (
        efficacy_projection.required_survivor_operator_ids
        == sources.efficacy.required_survivor_operator_ids
    )

    gate_finding = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_gate
    )
    assert gate_finding.reason_codes == (sources.gate_decision.findings[0].reason_code.value,)
    assert gate_finding.gate_effect is GateEffect.review
    assert gate_finding.state is EvidenceState.inconclusive

    efficacy_outcome = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_outcome
    )
    assert efficacy_outcome.required is True
    efficacy_threat = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_threat
    )
    assert efficacy_threat.critical is True
    assert isinstance(efficacy_threat.independently_challenged, bool)


def test_contradictions_and_every_supplied_limitation_remain_visible(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    graph = _complete_graph(sources)
    limitation_messages = {
        message
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.limitation
        for message in node.payload.messages
    }

    assert "Packet-level review remains required." in limitation_messages
    assert set(sources.mutation_result.limitations).issubset(limitation_messages)
    assert set(sources.efficacy.limitations).issubset(limitation_messages)
    assert EvidenceGraphEdgeKind.contradicts in {edge.kind for edge in graph.edges}
    assert any(
        isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.state in {EvidenceState.violated, EvidenceState.contradicted}
        for node in graph.nodes
    )


def test_wording_only_changes_do_not_change_stable_node_ids() -> None:
    first_evaluation = _evaluation(
        runset_id="wording-stability-runset",
        message="Original reviewer wording.",
    )
    second_evaluation = _evaluation(
        runset_id="wording-stability-runset",
        message="Revised reviewer wording with identical semantics.",
    )
    subject = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id="wording-stability-runset",
        subject_digest="d" * 64,
    )

    first = build_evidence_graph(subject=subject, evaluation=first_evaluation)
    second = build_evidence_graph(subject=subject, evaluation=second_evaluation)

    assert tuple(node.node_id for node in first.nodes) == tuple(
        node.node_id for node in second.nodes
    )
    assert first.graph_digest != second.graph_digest
    first_finding = next(
        node
        for node in first.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.evaluation
    )
    second_finding = next(
        node
        for node in second.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.evaluation
    )
    assert first_finding.node_id == second_finding.node_id
    assert first_finding.payload_digest != second_finding.payload_digest


def test_comparison_display_wording_is_payload_not_identity() -> None:
    subject = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id="candidate",
    )
    first_summary = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.new_failure,
        candidate_state=GateState.fail,
        verdict_findings=("Original comparison explanation.",),
    )
    second_summary = first_summary.model_copy(
        update={"verdict_findings": ("Reworded comparison explanation.",)}
    )

    first = build_evidence_graph(subject=subject, comparison=first_summary)
    second = build_evidence_graph(subject=subject, comparison=second_summary)
    first_finding = next(
        node for node in first.nodes if isinstance(node.payload, EvidenceGraphFindingPayload)
    )
    second_finding = next(
        node for node in second.nodes if isinstance(node.payload, EvidenceGraphFindingPayload)
    )

    assert first_finding.node_id == second_finding.node_id
    assert first_finding.payload_digest != second_finding.payload_digest
    assert first.graph_digest != second.graph_digest


def test_projection_is_pure_and_sources_remain_graph_independent(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    source_models = (
        sources.evaluation,
        sources.comparison,
        sources.mutation_result,
        sources.efficacy,
        sources.gate_profile,
        sources.gate_decision,
    )
    before = tuple(model.model_dump(mode="json") for model in source_models)

    _complete_graph(sources)

    assert tuple(model.model_dump(mode="json") for model in source_models) == before
    assert all("graph_digest" not in payload for payload in before)

    subject_only = build_evidence_graph(subject=sources.subject)
    assert len(subject_only.nodes) == 1
    assert subject_only.nodes[0].kind is EvidenceGraphNodeKind.subject
    assert subject_only.edges == ()


def test_projection_rejects_cross_artifact_identity_mismatches(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources

    with pytest.raises(ValueError, match="evaluation runset_id"):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id="different-runset",
                subject_digest=sources.efficacy.source_digest,
            ),
            evaluation=sources.evaluation,
        )

    with pytest.raises(ValueError, match="subject digest does not match"):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id=sources.evaluation.runset_id,
                subject_digest="f" * 64,
            ),
            mutation_results=(sources.mutation_result,),
        )

    mismatched_profile = ControlEfficacyGateProfile(
        profile_id="control-efficacy/mismatched",
        required_catalog=sources.gate_profile.required_catalog,
        required_operators=sources.gate_profile.required_operators,
    )
    with pytest.raises(ValueError, match="profile and decision identities"):
        build_evidence_graph(
            subject=sources.subject,
            control_efficacy=sources.efficacy,
            gate_profile=mismatched_profile,
            gate_decision=sources.gate_decision,
        )

    forged_decision = sources.gate_decision.model_copy(
        update={
            "state": (
                GateState.pass_
                if sources.gate_decision.state is not GateState.pass_
                else GateState.fail
            )
        }
    )
    with pytest.raises(ValueError, match="does not match the supplied report and profile"):
        build_evidence_graph(
            subject=sources.subject,
            control_efficacy=sources.efficacy,
            gate_profile=sources.gate_profile,
            gate_decision=forged_decision,
        )


def test_subject_identity_is_stable_between_primary_and_baseline_roles() -> None:
    subject = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id="same-runset",
    )
    primary_graph = build_evidence_graph(subject=subject)
    comparison_graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="other-runset",
        ),
        comparison=ComparisonSummary(
            baseline_runset_id="same-runset",
            candidate_runset_id="other-runset",
            privacy_profile_id=PRIVACY_PROFILE_ID,
            privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
            classification=ComparisonClassification.not_evaluated,
        ),
    )
    baseline = next(
        node
        for node in comparison_graph.nodes
        if isinstance(node.payload, EvidenceGraphSubjectPayload)
        and node.payload.subject_id == "same-runset"
    )

    assert primary_graph.primary_subject_node_id == baseline.node_id


def test_not_evaluated_comparison_messages_remain_non_verdict_findings() -> None:
    summary = ComparisonSummary(
        baseline_runset_id="not-evaluated-baseline",
        candidate_runset_id="not-evaluated-candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.not_evaluated,
        verdict_findings=("Comparison evidence was unavailable.",),
    )

    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=summary.candidate_runset_id,
        ),
        comparison=summary,
    )
    finding = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.comparison_verdict
    )

    assert finding.payload.verdict_bearing is False
    assert not any(
        edge.source_node_id == finding.node_id
        and edge.kind
        in {
            EvidenceGraphEdgeKind.supports,
            EvidenceGraphEdgeKind.contradicts,
        }
        for edge in graph.edges
    )


def test_agent_release_is_supported_only_as_a_subject_only_graph(
    representative_sources: _RepresentativeSources,
) -> None:
    subject = EvidenceGraphSubjectPayload(
        subject_type="agent_release",
        subject_id="agent-assure-0.6.3",
        subject_digest="a" * 64,
    )

    graph = build_evidence_graph(subject=subject)

    assert len(graph.nodes) == 1
    assert graph.nodes[0].payload == subject
    with pytest.raises(ValueError, match="subject-only"):
        build_evidence_graph(
            subject=subject,
            evaluation=representative_sources.evaluation,
        )


def test_distinct_mutation_execution_identities_do_not_collide(
    representative_sources: _RepresentativeSources,
) -> None:
    first = representative_sources.mutation_result
    second_values = first.model_dump(mode="json", exclude={"result_digest"})
    replacement_digest = "e" * 64
    if replacement_digest == first.evaluator_implementation_digest:
        replacement_digest = "f" * 64
    second_values["evaluator_implementation_digest"] = replacement_digest
    second = AssuranceMutationResult.build(**second_values)

    graph = build_evidence_graph(
        subject=representative_sources.subject,
        mutation_results=(first, second),
    )
    reversed_graph = build_evidence_graph(
        subject=representative_sources.subject,
        mutation_results=(second, first),
    )
    evidence_nodes = tuple(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.mutation_result
    )

    assert len(evidence_nodes) == 2
    assert len({node.node_id for node in evidence_nodes}) == 2
    assert reversed_graph == graph


def test_digest_only_mutation_evidence_is_not_joined_to_textual_runset_id(
    representative_sources: _RepresentativeSources,
) -> None:
    result = representative_sources.mutation_result
    replacement_digest = "f" * 64
    if replacement_digest == result.mutated_digest:
        replacement_digest = "e" * 64
    values = result.model_dump(mode="json", exclude={"result_digest"})
    values["source_digest"] = replacement_digest
    foreign_result = AssuranceMutationResult.build(**values)
    subject = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id=representative_sources.evaluation.runset_id,
    )

    graph = build_evidence_graph(
        subject=subject,
        evaluation=representative_sources.evaluation,
        mutation_results=(foreign_result,),
    )
    primary = next(node for node in graph.nodes if node.node_id == graph.primary_subject_node_id)
    mutation_evidence = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.mutation_result
    )
    scoped_subject_id = next(
        edge.target_node_id
        for edge in graph.edges
        if edge.kind is EvidenceGraphEdgeKind.scoped_to
        and edge.source_node_id == mutation_evidence.node_id
    )
    scoped_subject = next(node for node in graph.nodes if node.node_id == scoped_subject_id)

    assert isinstance(primary.payload, EvidenceGraphSubjectPayload)
    assert primary.payload.subject_digest is None
    assert scoped_subject_id != graph.primary_subject_node_id
    assert isinstance(scoped_subject.payload, EvidenceGraphSubjectPayload)
    assert scoped_subject.payload.subject_id == f"sha256:{replacement_digest}"
    assert scoped_subject.payload.subject_digest == replacement_digest

    scopes_by_node: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.kind is EvidenceGraphEdgeKind.scoped_to:
            scopes_by_node.setdefault(edge.source_node_id, []).append(edge.target_node_id)
    assert all(
        len(scopes_by_node.get(node.node_id, ())) == 1
        for node in graph.nodes
        if node.kind is not EvidenceGraphNodeKind.subject
    )

    evaluation_controls = {
        finding.control_id
        for finding in representative_sources.evaluation.findings
        if finding.control_id is not None
    }
    mutation_controls = {
        target.control_id for target in foreign_result.provenance.target_controls
    } | {finding.control_id for finding in foreign_result.observed_findings}
    shared_controls = evaluation_controls & mutation_controls
    assert shared_controls
    shared_control = sorted(shared_controls)[0]
    shared_requirements = tuple(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphRequirementPayload)
        and node.payload.requirement_type is EvidenceGraphRequirementType.control
        and node.payload.requirement_id == shared_control
    )
    assert len(shared_requirements) == 2
    assert {scopes_by_node[node.node_id][0] for node in shared_requirements} == {
        graph.primary_subject_node_id,
        scoped_subject_id,
    }


def test_authenticated_packet_graph_keeps_gate_decision_on_primary_subject(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    evaluation = sources.evaluation.model_copy(
        update={"runset_digest": sources.efficacy.source_digest}
    )
    graph = build_privacy_filtered_evidence_graph(
        evaluation,
        control_efficacy=sources.efficacy,
        control_efficacy_gate_profile=sources.gate_profile,
        control_efficacy_gate=sources.gate_decision,
        limitations=(),
    )
    gate_evidence = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.gate_decision
    )
    gate_subject_id = next(
        edge.target_node_id
        for edge in graph.edges
        if edge.kind is EvidenceGraphEdgeKind.scoped_to
        and edge.source_node_id == gate_evidence.node_id
    )
    primary_subject = next(
        node for node in graph.nodes if node.node_id == graph.primary_subject_node_id
    )

    assert gate_subject_id == graph.primary_subject_node_id
    assert isinstance(primary_subject.payload, EvidenceGraphSubjectPayload)
    assert primary_subject.payload.subject_digest == sources.efficacy.source_digest


def test_authenticated_packet_graph_rejects_conflicting_source_digest(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    conflicting_digest = "f" * 64 if sources.efficacy.source_digest != "f" * 64 else "e" * 64
    evaluation = sources.evaluation.model_copy(update={"runset_digest": conflicting_digest})

    with pytest.raises(ValueError, match="graph sources do not share one subject digest"):
        build_privacy_filtered_evidence_graph(
            evaluation,
            control_efficacy=sources.efficacy,
            control_efficacy_gate_profile=sources.gate_profile,
            control_efficacy_gate=sources.gate_decision,
            limitations=(),
        )


def test_graph_builder_rejects_dropping_authenticated_evaluation_digest(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    evaluation = sources.evaluation.model_copy(
        update={"runset_digest": sources.efficacy.source_digest}
    )

    with pytest.raises(
        ValueError,
        match="graph subject digest does not match evaluation runset digest",
    ):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id=evaluation.runset_id,
            ),
            evaluation=evaluation,
        )


def test_missing_gate_decision_does_not_trigger_gate_derivation(
    representative_sources: _RepresentativeSources,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sources = representative_sources

    def fail_derivation(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("gate derivation must not run without a supplied decision")

    monkeypatch.setattr(
        "agent_assure.graph.builder.derive_control_efficacy_gate_decision",
        fail_derivation,
    )
    graph = build_evidence_graph(
        subject=sources.subject,
        control_efficacy=sources.efficacy,
        gate_profile=sources.gate_profile,
        gate_decision=None,
    )

    assert not any(
        isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.gate_decision
        for node in graph.nodes
    )


def test_primary_subject_is_an_identity_anchor_not_a_complete_traversal_root(
    representative_sources: _RepresentativeSources,
) -> None:
    sources = representative_sources
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=sources.evaluation.runset_id,
        ),
        evaluation=sources.evaluation,
        control_efficacy=sources.efficacy,
        gate_profile=sources.gate_profile,
        gate_decision=sources.gate_decision,
    )
    adjacency = {node.node_id: set[str]() for node in graph.nodes}
    for edge in graph.edges:
        adjacency[edge.source_node_id].add(edge.target_node_id)
        adjacency[edge.target_node_id].add(edge.source_node_id)
    primary_component: set[str] = set()
    pending = [graph.primary_subject_node_id]
    while pending:
        node_id = pending.pop()
        if node_id in primary_component:
            continue
        primary_component.add(node_id)
        pending.extend(adjacency[node_id] - primary_component)

    gate_evidence = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.gate_decision
    )
    gate_subject_id = next(
        edge.target_node_id
        for edge in graph.edges
        if edge.kind is EvidenceGraphEdgeKind.scoped_to
        and edge.source_node_id == gate_evidence.node_id
    )
    gate_subject = next(node for node in graph.nodes if node.node_id == gate_subject_id)

    assert gate_evidence.node_id not in primary_component
    assert gate_subject_id not in primary_component
    assert isinstance(gate_subject.payload, EvidenceGraphSubjectPayload)
    assert gate_subject.payload.subject_id == f"sha256:{sources.efficacy.source_digest}"
    assert gate_subject.payload.subject_digest == sources.efficacy.source_digest


def test_legacy_empty_evaluation_runset_id_fails_explicitly_at_graph_boundary() -> None:
    summary = EvaluationSummary(
        schema_version="0.6.2",
        runset_id="",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )

    with pytest.raises(ValueError, match="graph evaluation runset_id must be non-empty"):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id="legacy-runset",
            ),
            evaluation=summary,
        )


def test_legacy_empty_comparison_runset_id_fails_explicitly_at_graph_boundary() -> None:
    summary = ComparisonSummary(
        schema_version="0.6.2",
        baseline_runset_id="",
        candidate_runset_id="legacy-candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.not_evaluated,
    )

    with pytest.raises(
        ValueError,
        match="graph comparison baseline_runset_id must be non-empty",
    ):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id=summary.candidate_runset_id,
            ),
            comparison=summary,
        )


def test_legacy_empty_finding_identity_fails_explicitly_at_graph_boundary() -> None:
    finding = Finding(
        schema_version="0.6.2",
        finding_id="",
        case_id="legacy-case",
        state=GateState.fail,
        reason_code=ReasonCode.RUNTIME_FAILED,
        message="Legacy finding.",
    )
    summary = EvaluationSummary(
        schema_version="0.6.2",
        runset_id="legacy-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )

    with pytest.raises(
        ValueError,
        match="graph evaluation finding 0 finding_id must be non-empty",
    ):
        build_evidence_graph(
            subject=EvidenceGraphSubjectPayload(
                subject_type="run_set",
                subject_id=summary.runset_id,
            ),
            evaluation=summary,
        )


def test_unscoped_evaluation_finding_projects_without_case_reference() -> None:
    finding = Finding(
        finding_id="unscoped-finding",
        case_id="",
        state=GateState.fail,
        reason_code=ReasonCode.RUNTIME_FAILED,
        message="Unscoped finding.",
    )
    summary = EvaluationSummary(
        runset_id="unscoped-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(finding,),
    )

    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=summary.runset_id,
        ),
        evaluation=summary,
    )
    projected = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.evaluation
    )

    assert all(
        reference.role is not EvidenceGraphReferenceRole.case for reference in projected.references
    )


def test_evaluation_requirement_identity_distinguishes_control_from_reason_code() -> None:
    reason_code = ReasonCode.RUNTIME_FAILED
    summary = EvaluationSummary(
        runset_id="requirement-origin-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.fail,
        findings=(
            Finding(
                finding_id="actual-control",
                case_id="case-actual-control",
                control_id=reason_code.value,
                state=GateState.fail,
                reason_code=reason_code,
                message="Actual control failed.",
            ),
            Finding(
                finding_id="reason-fallback",
                case_id="case-reason-fallback",
                state=GateState.fail,
                reason_code=reason_code,
                message="No control ID was supplied.",
            ),
        ),
    )

    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=summary.runset_id,
        ),
        evaluation=summary,
    )
    requirements = tuple(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphRequirementPayload)
        and node.payload.requirement_type is EvidenceGraphRequirementType.control
    )

    assert len(requirements) == 2
    assert len({node.node_id for node in requirements}) == 2
    assert {node.payload.requirement_id for node in requirements} == {
        reason_code.value,
        f"reason-code:{reason_code.value}",
    }


def test_control_efficacy_projection_rejects_incoherent_duplicate_counts(
    representative_sources: _RepresentativeSources,
) -> None:
    graph = _complete_graph(representative_sources)
    evidence = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.control_efficacy
    )
    assert evidence.control_efficacy_projection is not None
    payload = evidence.control_efficacy_projection.model_dump(mode="json")
    payload["caught_operator_count"] += 1

    with pytest.raises(ValidationError, match="counts must match state counts"):
        EvidenceGraphControlEfficacyProjection.model_validate(payload)

    evidence_payload = evidence.model_dump(mode="json")
    evidence_payload["state"] = EvidenceState.violated.value
    with pytest.raises(ValidationError, match="efficacy evidence state contradicts"):
        EvidenceGraphEvidencePayload.model_validate(evidence_payload)


def test_graph_rejects_deleted_control_efficacy_outcome_children(
    representative_sources: _RepresentativeSources,
) -> None:
    graph = _complete_graph(representative_sources)
    outcome = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_outcome
    )

    with pytest.raises(ValidationError, match="exactly cover evaluated operators"):
        AssuranceEvidenceGraph.from_parts(
            primary_subject_node_id=graph.primary_subject_node_id,
            nodes=tuple(node for node in graph.nodes if node.node_id != outcome.node_id),
            edges=tuple(
                edge
                for edge in graph.edges
                if outcome.node_id not in {edge.source_node_id, edge.target_node_id}
            ),
            compatibility=graph.compatibility,
            limitations=graph.limitations,
        )


@pytest.mark.parametrize(
    ("basis", "limitation"),
    (
        (
            EvidenceEvaluationBasis.stochastic,
            STOCHASTIC_SUFFICIENCY_LIMITATION,
        ),
        (
            EvidenceEvaluationBasis.human_reviewed,
            HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
        ),
    ),
)
def test_non_deterministic_mutation_results_remain_non_verdict(
    representative_sources: _RepresentativeSources,
    basis: EvidenceEvaluationBasis,
    limitation: str,
) -> None:
    result = _mutation_with_evaluation_basis(
        representative_sources.mutation_result,
        basis,
        limitation,
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=f"basis-{basis.value}",
            subject_digest=result.source_digest,
        ),
        mutation_results=(result,),
    )
    mutation_evidence = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.mutation_result
    )
    mutation_findings = tuple(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type
        in {
            EvidenceGraphFindingType.mutation_result,
            EvidenceGraphFindingType.mutation_observed_finding,
        }
    )

    assert mutation_evidence.payload.evaluation_basis is basis
    assert mutation_evidence.payload.state is EvidenceState.inconclusive
    assert mutation_evidence.payload.verdict_bearing is False
    outcome = next(
        node.payload
        for node in mutation_findings
        if node.payload.finding_type is EvidenceGraphFindingType.mutation_result
    )
    assert outcome.state is EvidenceState.inconclusive
    assert outcome.verdict_bearing is False
    assert all(node.payload.verdict_bearing is False for node in mutation_findings)
    mutation_node_ids = {
        mutation_evidence.node_id,
        *(node.node_id for node in mutation_findings),
    }
    assert not any(
        edge.source_node_id in mutation_node_ids
        and edge.kind in {EvidenceGraphEdgeKind.supports, EvidenceGraphEdgeKind.contradicts}
        for edge in graph.edges
    )


def test_gate_profile_is_provenance_not_a_verdict(
    representative_sources: _RepresentativeSources,
) -> None:
    graph = build_evidence_graph(
        subject=representative_sources.subject,
        gate_profile=representative_sources.gate_profile,
    )
    profile = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.gate_profile
    )

    assert profile.payload.state is EvidenceState.inconclusive
    assert profile.payload.verdict_bearing is False
    assert not any(
        edge.source_node_id == profile.node_id
        and edge.kind in {EvidenceGraphEdgeKind.supports, EvidenceGraphEdgeKind.contradicts}
        for edge in graph.edges
    )
    compatibility = {field.source_path: field for field in graph.compatibility.fields}
    assert compatibility["/control_efficacy_gate_profile"].verdict_bearing is False


@pytest.mark.parametrize(
    ("fixture_state", "expected_state"),
    (
        (GateState.fail, EvidenceState.error),
        (GateState.warn, EvidenceState.inconclusive),
        (GateState.not_evaluated, EvidenceState.not_evaluated),
    ),
)
def test_non_pass_fixture_equivalence_cannot_support_comparison_acceptability(
    fixture_state: GateState,
    expected_state: EvidenceState,
) -> None:
    summary = ComparisonSummary(
        baseline_runset_id="fixture-baseline",
        candidate_runset_id="fixture-candidate",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=fixture_state,
        baseline_state=GateState.pass_,
        candidate_state=GateState.pass_,
        verdict_findings=("Candidate and baseline verdicts match.",),
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=summary.candidate_runset_id,
        ),
        comparison=summary,
    )
    comparison = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
        and node.payload.evidence_type is EvidenceGraphEvidenceType.comparison
    )

    assert comparison.payload.state is expected_state
    assert comparison.payload.verdict_bearing is False
    assert not any(
        edge.source_node_id == comparison.node_id
        and edge.kind in {EvidenceGraphEdgeKind.supports, EvidenceGraphEdgeKind.contradicts}
        for edge in graph.edges
    )


def test_mutation_diagnostics_use_a_dedicated_reference_role(
    representative_sources: _RepresentativeSources,
) -> None:
    source = representative_sources.mutation_result
    payload = source.model_dump(mode="python", exclude={"result_digest"})
    payload["diagnostic_code"] = "synthetic_detector_diagnostic"
    result = AssuranceMutationResult.build(**payload)
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="mutation-diagnostic",
            subject_digest=result.source_digest,
        ),
        mutation_results=(result,),
    )
    outcome = next(
        node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.mutation_result
    )

    assert tuple(
        reference.value
        for reference in outcome.references
        if reference.role is EvidenceGraphReferenceRole.diagnostic
    ) == ("synthetic_detector_diagnostic",)
    assert not any(
        reference.role is EvidenceGraphReferenceRole.applicability
        for reference in outcome.references
    )


def test_survived_only_threat_is_challenged_while_detector_is_contradicted() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.survived,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    graph = build_evidence_graph(
        subject=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="survived-threat",
            subject_digest=report.source_digest,
        ),
        control_efficacy=report,
    )
    threat = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_threat
    )
    detector = next(
        node
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphFindingPayload)
        and node.payload.finding_type is EvidenceGraphFindingType.control_efficacy_outcome
    )

    assert threat.payload.reason_codes == ("THREAT_CHALLENGED",)
    assert any(
        edge.source_node_id == threat.node_id and edge.kind is EvidenceGraphEdgeKind.supports
        for edge in graph.edges
    )
    assert detector.payload.reason_codes == ("MUTATION_SURVIVED",)
    assert any(
        edge.source_node_id == detector.node_id and edge.kind is EvidenceGraphEdgeKind.contradicts
        for edge in graph.edges
    )
