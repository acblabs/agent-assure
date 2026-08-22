from __future__ import annotations

from dataclasses import dataclass, field
from typing import TypeAlias, TypeVar, assert_never

from pydantic import BaseModel

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import (
    ComparisonSummary,
    comparison_evaluation_binding_error,
)
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    ControlEfficacySemanticState,
    ThreatApplicability,
    ThreatCoverageItem,
    derive_control_efficacy_gate_decision,
)
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphComparisonProjection,
    EvidenceGraphCompatibilityManifest,
    EvidenceGraphControlEfficacyProjection,
    EvidenceGraphEdge,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphFieldCompatibility,
    EvidenceGraphFindingPayload,
    EvidenceGraphFindingType,
    EvidenceGraphNode,
    EvidenceGraphNodeKind,
    EvidenceGraphPayload,
    EvidenceGraphProjectionDisposition,
    EvidenceGraphProjectionReason,
    EvidenceGraphReference,
    EvidenceGraphReferenceRole,
    EvidenceGraphRequirementPayload,
    EvidenceGraphRequirementType,
    EvidenceGraphSensitivityProjection,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import (
    AssuranceMutationResult,
    EvidenceEvaluationBasis,
    EvidenceState,
    GateEffect,
    MutationResultState,
)
from agent_assure.schema.sensitivity import (
    EvidenceSensitivityState,
    RAGSensitivityReport,
)
from agent_assure.sensitivity_comparison import sensitivity_comparison_binding_error

EvaluationInput: TypeAlias = EvaluationSummary
ComparisonInput: TypeAlias = ComparisonSummary
SensitivityInput: TypeAlias = RAGSensitivityReport
GraphSourceT = TypeVar("GraphSourceT", bound=BaseModel)

DEFAULT_GRAPH_LIMITATIONS = (
    "The graph is a deterministic projection of the supplied privacy-filtered artifacts; "
    "its digest establishes canonical identity, not authenticity or evidence adequacy.",
    "The graph uses only the AssuranceEvidenceGraph/v1 four-node and five-edge vocabulary; "
    "it is not an assurance case, broad ontology, inference engine, or graph database.",
)


def build_evidence_graph(
    *,
    subject: EvidenceGraphSubjectPayload,
    evaluation: EvaluationInput | None = None,
    comparison: ComparisonInput | None = None,
    evidence_sensitivity: SensitivityInput | None = None,
    mutation_results: tuple[AssuranceMutationResult, ...] = (),
    control_efficacy: ControlEfficacyReport | None = None,
    gate_profile: ControlEfficacyGateProfile | None = None,
    gate_decision: ControlEfficacyGateDecision | None = None,
    limitations: tuple[str, ...] = (),
) -> AssuranceEvidenceGraph:
    """Build a pure, deterministic graph from existing assurance artifacts.

    Source semantic states are retained in graph payloads. Edges summarize those
    states but never rewrite them through a gate profile.
    """
    # Pydantic's model_copy(update=...) intentionally skips validation. Reparse
    # every typed input at this public trust boundary before consuming identity,
    # semantic-state, policy, or digest fields.
    subject = _revalidate_graph_source(
        subject,
        EvidenceGraphSubjectPayload,
        label="subject",
    )
    if evaluation is not None:
        evaluation = _revalidate_graph_source(
            evaluation,
            EvaluationSummary,
            label="evaluation",
        )
    if comparison is not None:
        comparison = _revalidate_graph_source(
            comparison,
            ComparisonSummary,
            label="comparison",
        )
    if evidence_sensitivity is not None:
        evidence_sensitivity = _revalidate_graph_source(
            evidence_sensitivity,
            RAGSensitivityReport,
            label="evidence-sensitivity",
        )
    mutation_results = tuple(
        _revalidate_graph_source(
            result,
            AssuranceMutationResult,
            label=f"mutation result {index}",
        )
        for index, result in enumerate(mutation_results)
    )
    if control_efficacy is not None:
        control_efficacy = _revalidate_graph_source(
            control_efficacy,
            ControlEfficacyReport,
            label="control-efficacy",
        )
    if gate_profile is not None:
        gate_profile = _revalidate_graph_source(
            gate_profile,
            ControlEfficacyGateProfile,
            label="gate-profile",
        )
    if gate_decision is not None:
        gate_decision = _revalidate_graph_source(
            gate_decision,
            ControlEfficacyGateDecision,
            label="gate-decision",
        )
    _validate_subject_digest_coherence(
        subject,
        evaluation=evaluation,
        comparison=comparison,
        evidence_sensitivity=evidence_sensitivity,
        mutation_results=mutation_results,
        control_efficacy=control_efficacy,
    )
    _validate_source_coherence(
        subject,
        evaluation=evaluation,
        comparison=comparison,
        evidence_sensitivity=evidence_sensitivity,
        mutation_results=mutation_results,
        control_efficacy=control_efficacy,
        gate_profile=gate_profile,
        gate_decision=gate_decision,
        limitations=limitations,
    )

    graph = _GraphAccumulator()
    primary_subject_id = graph.add_node(
        EvidenceGraphNodeKind.subject,
        subject,
    )
    if evaluation is not None:
        _project_evaluation(graph, primary_subject_id, evaluation)
    if comparison is not None:
        _project_comparison(graph, comparison)
    if evidence_sensitivity is not None:
        _project_evidence_sensitivity(
            graph,
            primary_subject_id,
            evidence_sensitivity,
        )
    for result in mutation_results:
        mutation_subject_id = _source_evidence_subject_id(
            graph,
            primary_subject_id,
            subject,
            source_digest=result.source_digest,
            unbound_identity=f"mutation-result:{result.result_digest}",
        )
        _project_mutation_result(graph, mutation_subject_id, result)
    efficacy_subject_id = primary_subject_id
    if control_efficacy is not None:
        efficacy_subject_id = _source_evidence_subject_id(
            graph,
            primary_subject_id,
            subject,
            source_digest=control_efficacy.source_digest,
            unbound_identity=(f"control-efficacy-report:{control_efficacy.report_digest}"),
        )
        _project_control_efficacy(graph, efficacy_subject_id, control_efficacy)
    if gate_profile is not None:
        _project_gate_profile(graph, efficacy_subject_id, gate_profile)
    if gate_decision is not None:
        _project_gate_decision(
            graph,
            efficacy_subject_id,
            gate_decision,
            control_efficacy=control_efficacy,
        )
    if limitations:
        _project_packet_limitations(graph, primary_subject_id, limitations)

    return AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=primary_subject_id,
        nodes=tuple(graph.nodes.values()),
        edges=tuple(graph.edges.values()),
        compatibility=legacy_packet_compatibility_manifest(),
        limitations=DEFAULT_GRAPH_LIMITATIONS,
    )


def legacy_packet_compatibility_manifest() -> EvidenceGraphCompatibilityManifest:
    represented = EvidenceGraphProjectionDisposition.represented
    unsupported = EvidenceGraphProjectionDisposition.unsupported
    fields = (
        EvidenceGraphFieldCompatibility(
            source_path="/artifact_digests",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="exact-file-binding-remains-in-packet",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/artifact_kind",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="source-envelope-identity-not-projected",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/comparison",
            verdict_bearing=True,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "finding", "requirement", "subject"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/control_efficacy",
            verdict_bearing=True,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "finding", "requirement"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/control_efficacy_gate",
            verdict_bearing=True,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "finding", "requirement"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/control_efficacy_gate_profile",
            verdict_bearing=False,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "requirement"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/environment",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="environment-metadata-remains-in-packet",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/evaluation",
            verdict_bearing=True,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "finding", "requirement", "subject"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/interpretation",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="review-guidance-remains-in-packet",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/limitations",
            verdict_bearing=False,
            disposition=represented,
            target_node_kinds=_node_kinds("evidence", "finding"),
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/packet_id",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="packet-identity-excluded-to-prevent-digest-cycle",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/release_manifest",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="release-binding-remains-in-packet",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/schema_version",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="source-envelope-version-not-projected",
        ),
        EvidenceGraphFieldCompatibility(
            source_path="/usage_summary",
            verdict_bearing=False,
            disposition=unsupported,
            reason_code="usage-evidence-remains-in-packet",
        ),
    )
    return EvidenceGraphCompatibilityManifest(fields=fields)


def _revalidate_graph_source(
    value: object,
    model: type[GraphSourceT],
    *,
    label: str,
) -> GraphSourceT:
    if not isinstance(value, model):
        raise TypeError(f"graph {label} input must be a {model.__name__}")
    return model.model_validate(value.model_dump(mode="json", warnings="error"))


@dataclass
class _GraphAccumulator:
    nodes: dict[str, EvidenceGraphNode] = field(default_factory=dict)
    edges: dict[tuple[str, str, str], EvidenceGraphEdge] = field(default_factory=dict)

    def add_node(
        self,
        kind: EvidenceGraphNodeKind,
        payload: EvidenceGraphPayload,
        *,
        subject_node_id: str | None = None,
        parent_evidence_node_id: str | None = None,
    ) -> str:
        node = EvidenceGraphNode.build(
            kind=kind,
            payload=payload,
            subject_node_id=subject_node_id,
            parent_evidence_node_id=parent_evidence_node_id,
        )
        node_id = node.node_id
        prior = self.nodes.get(node_id)
        if prior is not None and prior != node:
            if (
                isinstance(prior.payload, EvidenceGraphRequirementPayload)
                and isinstance(payload, EvidenceGraphRequirementPayload)
                and prior.payload.requirement_type is payload.requirement_type
                and prior.payload.requirement_id == payload.requirement_id
            ):
                merged_references = _references(
                    *(
                        (reference.role.value, reference.value)
                        for reference in (*prior.payload.references, *payload.references)
                    )
                )
                merged_payload = EvidenceGraphRequirementPayload(
                    requirement_type=payload.requirement_type,
                    requirement_id=payload.requirement_id,
                    references=merged_references,
                )
                node = EvidenceGraphNode.build(
                    kind=kind,
                    payload=merged_payload,
                    subject_node_id=subject_node_id,
                    parent_evidence_node_id=parent_evidence_node_id,
                )
            else:
                raise ValueError("graph source identities collide with different payloads")
        self.nodes[node_id] = node
        return node_id

    def add_edge(
        self,
        kind: EvidenceGraphEdgeKind,
        source_node_id: str,
        target_node_id: str,
    ) -> None:
        key = (kind.value, source_node_id, target_node_id)
        self.edges[key] = EvidenceGraphEdge(
            kind=kind,
            source_node_id=source_node_id,
            target_node_id=target_node_id,
        )


def _project_evaluation(
    graph: _GraphAccumulator,
    subject_id: str,
    value: EvaluationInput,
) -> None:
    summary = value
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.evaluation,
            source_artifact_kind="evaluation-summary",
            source_id=summary.runset_id,
            source_digest=_model_digest(summary),
            state=_gate_state(summary.state),
            verdict_bearing=summary.state is not GateState.not_evaluated,
            privacy_profile_id=summary.privacy_profile_id,
            privacy_profile_digest=summary.privacy_profile_digest,
            references=_references(("candidate_subject", summary.runset_id)),
        ),
        subject_node_id=subject_id,
    )
    requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.declared_expectations,
        f"declared-expectations:{summary.runset_id}",
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    _add_semantic_edge(graph, _gate_state(summary.state), evidence_id, requirement_id)
    for index, finding in enumerate(summary.findings):
        _project_evaluation_finding(
            graph,
            subject_id,
            evidence_id,
            finding,
            source_path=f"/findings/{index}",
        )


def _project_evaluation_finding(
    graph: _GraphAccumulator,
    subject_id: str,
    evidence_id: str,
    finding: Finding,
    *,
    source_path: str,
) -> None:
    if finding.control_id:
        requirement_key = finding.control_id
        requirement_references = _references(("control", finding.control_id))
    else:
        requirement_key = f"reason-code:{finding.reason_code.value}"
        requirement_references = ()
    requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.control,
        requirement_key,
        references=requirement_references,
    )
    state = _gate_state(finding.state)
    finding_id = graph.add_node(
        EvidenceGraphNodeKind.finding,
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evaluation,
            source_artifact_kind="finding",
            source_id=finding.finding_id,
            source_path=source_path,
            state=state,
            verdict_bearing=finding.state is not GateState.not_evaluated,
            reason_codes=(finding.reason_code.value,),
            references=_references(
                *(("case", finding.case_id),) if finding.case_id else (),
                *(("control", finding.control_id),) if finding.control_id else (),
                *(("target", finding.target),) if finding.target else (),
            ),
            messages=(finding.message,),
        ),
        subject_node_id=subject_id,
        parent_evidence_node_id=evidence_id,
    )
    _link_finding(graph, finding_id, evidence_id, requirement_id, subject_id, state)


def _project_comparison(
    graph: _GraphAccumulator,
    value: ComparisonInput,
) -> None:
    summary = value
    candidate_subject_id = graph.add_node(
        EvidenceGraphNodeKind.subject,
        EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=summary.candidate_runset_id,
            subject_digest=summary.candidate_runset_digest,
        ),
    )
    baseline_payload = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id=summary.baseline_runset_id,
        subject_digest=summary.baseline_runset_digest,
    )
    graph.add_node(
        EvidenceGraphNodeKind.subject,
        baseline_payload,
    )
    state = _comparison_state(summary)
    verdict_bearing = _comparison_verdict_bearing(summary)
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.comparison,
            source_artifact_kind="comparison-summary",
            source_id=f"{summary.baseline_runset_id}->{summary.candidate_runset_id}",
            source_digest=_model_digest(summary),
            state=state,
            verdict_bearing=verdict_bearing,
            privacy_profile_id=summary.privacy_profile_id,
            privacy_profile_digest=summary.privacy_profile_digest,
            comparison_projection=EvidenceGraphComparisonProjection(
                classification=summary.classification,
                fixture_equivalence_state=summary.fixture_equivalence_state,
                baseline_state=summary.baseline_state,
                candidate_state=summary.candidate_state,
            ),
            references=_references(
                ("baseline_subject", summary.baseline_runset_id),
                ("candidate_subject", summary.candidate_runset_id),
            ),
        ),
        subject_node_id=candidate_subject_id,
    )
    requirement_id = _add_requirement(
        graph,
        candidate_subject_id,
        EvidenceGraphRequirementType.comparison,
        "candidate-comparison-acceptability",
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, candidate_subject_id)
    _add_semantic_edge(graph, state, evidence_id, requirement_id)
    for index, message in enumerate(summary.verdict_findings):
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.comparison_verdict,
                source_artifact_kind="comparison-summary",
                source_id=f"comparison-verdict-finding-{index}",
                source_path=f"/verdict_findings/{index}",
                state=state,
                verdict_bearing=verdict_bearing,
                reason_codes=(),
                references=_references(
                    ("baseline_subject", summary.baseline_runset_id),
                    ("candidate_subject", summary.candidate_runset_id),
                ),
                messages=(message,),
            ),
            subject_node_id=candidate_subject_id,
            parent_evidence_node_id=evidence_id,
        )
        _link_finding(
            graph,
            finding_id,
            evidence_id,
            requirement_id,
            candidate_subject_id,
            state,
        )
    for index, message in enumerate(summary.provenance_changes):
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.comparison_provenance,
                source_artifact_kind="comparison-summary",
                source_id=f"comparison-provenance-change-{index}",
                source_path=f"/provenance_changes/{index}",
                state=EvidenceState.inconclusive,
                verdict_bearing=False,
                messages=(message,),
            ),
            subject_node_id=candidate_subject_id,
            parent_evidence_node_id=evidence_id,
        )
        graph.add_edge(EvidenceGraphEdgeKind.derived_from, finding_id, evidence_id)
        graph.add_edge(EvidenceGraphEdgeKind.scoped_to, finding_id, candidate_subject_id)


def _project_evidence_sensitivity(
    graph: _GraphAccumulator,
    subject_id: str,
    report: SensitivityInput,
) -> None:
    baseline = report.baseline_arm
    counterfactual = report.counterfactual_arm
    graph.add_node(
        EvidenceGraphNodeKind.subject,
        EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id=baseline.runset_id,
            subject_digest=baseline.runset_digest,
        ),
    )
    state = _evidence_sensitivity_state(report.state)
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.evidence_sensitivity,
            source_artifact_kind=report.artifact_kind,
            source_id=report.report_id,
            source_digest=report.report_digest,
            state=state,
            verdict_bearing=report.verdict_bearing,
            evidence_sensitivity_projection=EvidenceGraphSensitivityProjection(
                state=report.state,
                gate_effect=report.gate_effect,
                endpoint=report.endpoint,
                endpoint_value=report.endpoint_value,
                expected_relation=report.expected_relation,
                observed_relation=report.observed_relation,
                outcome_classification=report.outcome_classification,
                baseline_expected_decision=baseline.expected_decision,
                counterfactual_expected_decision=counterfactual.expected_decision,
                baseline_observed_decision=baseline.decision,
                counterfactual_observed_decision=counterfactual.decision,
                deterministic=report.deterministic,
                detector_test_status=report.detector_test_status,
                subject_execution_scope=report.subject_execution_scope,
                provenance_binding=report.provenance_binding,
                synthetic_data_provenance=report.synthetic_data_provenance,
                synthetic_data_attestation_digest=(
                    report.protocol.synthetic_data_attestation_digest
                ),
                raw_content_persistence=report.raw_content_persistence,
                claim_scope=report.claim_scope,
                population_claim=report.population_claim,
                protocol_digest=report.protocol.protocol_digest,
                knowledge_contract_digest=(report.authority_contract.knowledge_contract_digest),
                baseline_runset_id=baseline.runset_id,
                baseline_runset_digest=baseline.runset_digest,
                counterfactual_runset_id=counterfactual.runset_id,
                counterfactual_runset_digest=counterfactual.runset_digest,
                decision_inertia_detected=report.decision_inertia_finding.detected,
                reason_codes=report.reason_codes,
            ),
            references=_references(
                ("baseline_subject", baseline.runset_id),
                ("candidate_subject", counterfactual.runset_id),
            ),
            limitations=report.limitations,
        ),
        subject_node_id=subject_id,
    )
    requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.expected_decision_response,
        (f"expected-decision-response:{report.authority_contract.knowledge_contract_digest}"),
        references=_references(
            ("baseline_subject", baseline.runset_id),
            ("candidate_subject", counterfactual.runset_id),
        ),
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    _add_semantic_edge(graph, state, evidence_id, requirement_id)
    outcome_id = graph.add_node(
        EvidenceGraphNodeKind.finding,
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.evidence_sensitivity_outcome,
            source_artifact_kind=report.artifact_kind,
            source_id=f"{report.report_id}:outcome",
            source_path="/outcome_classification",
            state=state,
            verdict_bearing=report.verdict_bearing,
            reason_codes=tuple(item.value for item in report.reason_codes),
            references=_references(
                ("baseline_subject", baseline.runset_id),
                ("candidate_subject", counterfactual.runset_id),
            ),
            messages=(report.outcome_message,),
        ),
        subject_node_id=subject_id,
        parent_evidence_node_id=evidence_id,
    )
    _link_finding(
        graph,
        outcome_id,
        evidence_id,
        requirement_id,
        subject_id,
        state,
    )
    _project_limitations(
        graph,
        subject_id,
        evidence_id,
        source_artifact_kind=report.artifact_kind,
        limitations=report.limitations,
    )


def _project_mutation_result(
    graph: _GraphAccumulator,
    subject_id: str,
    result: AssuranceMutationResult,
) -> None:
    state = _mutation_state(
        result.state,
        evaluation_basis=result.evaluator_evaluation_basis,
    )
    verdict_bearing = _mutation_verdict_bearing(
        result.state,
        evaluation_basis=result.evaluator_evaluation_basis,
    )
    matched_finding_ids = frozenset(result.matched_finding_ids)
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.mutation_result,
            source_artifact_kind=result.artifact_kind,
            source_id=result.result_digest,
            source_digest=result.result_digest,
            state=state,
            verdict_bearing=verdict_bearing,
            evaluation_basis=result.evaluator_evaluation_basis,
            references=_references(
                ("operator", result.operator_id),
                ("gate_profile", result.gate_profile_id),
                ("independence_class", result.independence_class.value),
                *(("source_digest", result.source_digest),) if result.source_digest else (),
            ),
            limitations=result.limitations,
        ),
        subject_node_id=subject_id,
    )
    requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.mutation_detector,
        result.operator_id,
        references=_references(("operator", result.operator_id)),
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    outcome_id = graph.add_node(
        EvidenceGraphNodeKind.finding,
        EvidenceGraphFindingPayload(
            finding_type=EvidenceGraphFindingType.mutation_result,
            source_artifact_kind=result.artifact_kind,
            source_id=f"{result.operator_id}:outcome",
            source_path="/state",
            state=state,
            verdict_bearing=verdict_bearing,
            reason_codes=(_mutation_reason(result.state).value,),
            references=_references(
                ("operator", result.operator_id),
                ("gate_profile", result.gate_profile_id),
                *(("target", result.expected_finding_target_digest),)
                if result.expected_finding_target_digest
                else (),
                *(("diagnostic", result.diagnostic_code),) if result.diagnostic_code else (),
            ),
        ),
        subject_node_id=subject_id,
        parent_evidence_node_id=evidence_id,
    )
    _link_finding(graph, outcome_id, evidence_id, requirement_id, subject_id, state)
    for target_control in result.provenance.target_controls:
        target_control_id = _add_requirement(
            graph,
            subject_id,
            EvidenceGraphRequirementType.control,
            target_control.control_id,
            references=_references(("control", target_control.control_id)),
        )
        graph.add_edge(
            EvidenceGraphEdgeKind.targets,
            outcome_id,
            target_control_id,
        )
    for index, observed in enumerate(result.observed_findings):
        observed_requirement_id = _add_requirement(
            graph,
            subject_id,
            EvidenceGraphRequirementType.control,
            observed.control_id,
            references=_references(("control", observed.control_id)),
        )
        observed_state = _gate_state(observed.state)
        observed_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.mutation_observed_finding,
                source_artifact_kind=result.artifact_kind,
                source_id=observed.finding_id,
                source_path=f"/observed_findings/{index}",
                state=observed_state,
                verdict_bearing=(
                    observed.finding_id in matched_finding_ids
                    and result.evaluator_evaluation_basis is EvidenceEvaluationBasis.deterministic
                ),
                reason_codes=(observed.reason_code.value,),
                references=_references(
                    ("control", observed.control_id),
                    *(("matched_finding", observed.finding_id),)
                    if observed.finding_id in matched_finding_ids
                    else (),
                    *(("target", observed.target_digest),) if observed.target_digest else (),
                ),
            ),
            subject_node_id=subject_id,
            parent_evidence_node_id=evidence_id,
        )
        _link_finding(
            graph,
            observed_id,
            evidence_id,
            observed_requirement_id,
            subject_id,
            observed_state,
        )
    _project_limitations(
        graph,
        subject_id,
        evidence_id,
        source_artifact_kind=result.artifact_kind,
        limitations=result.limitations,
    )


def _project_control_efficacy(
    graph: _GraphAccumulator,
    subject_id: str,
    report: ControlEfficacyReport,
) -> None:
    state = _efficacy_state(report.semantic_state)
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.control_efficacy,
            source_artifact_kind=report.artifact_kind,
            source_id=report.campaign_digest,
            source_digest=report.report_digest,
            state=state,
            verdict_bearing=report.semantic_state is not ControlEfficacySemanticState.not_evaluated,
            control_efficacy_projection=_control_efficacy_projection(report),
            references=_references(
                ("catalog", report.catalog_id),
                ("source_digest", report.source_digest),
            ),
            limitations=report.limitations,
        ),
        subject_node_id=subject_id,
    )
    requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.control_efficacy,
        report.catalog_id,
        references=_references(("catalog", report.catalog_id)),
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    _add_semantic_edge(graph, state, evidence_id, requirement_id)
    for index, outcome in enumerate(report.operator_outcomes):
        detector_id = _add_requirement(
            graph,
            subject_id,
            EvidenceGraphRequirementType.mutation_detector,
            outcome.operator_id,
            references=_references(
                ("operator", outcome.operator_id),
                *(("control", item) for item in outcome.target_control_ids),
            ),
        )
        outcome_state = _mutation_state(outcome.state)
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.control_efficacy_outcome,
                source_artifact_kind=report.artifact_kind,
                source_id=outcome.operator_id,
                source_path=f"/operator_outcomes/{index}",
                state=outcome_state,
                verdict_bearing=outcome.state
                in {MutationResultState.caught, MutationResultState.survived},
                reason_codes=(_mutation_reason(outcome.state).value,),
                references=_references(
                    ("operator", outcome.operator_id),
                    ("invariant_family", outcome.invariant_family),
                    ("independence_class", outcome.independence_class.value),
                    ("applicability", outcome.applicability.value),
                    *(("threat", item) for item in outcome.catalog_threat_ids),
                    *(("scoped_threat", item) for item in outcome.threat_ids),
                    *(("unscoped_threat", item) for item in outcome.unscoped_catalog_threat_ids),
                    *(("critical_threat", item) for item in outcome.critical_threat_ids),
                    *(("control", item) for item in outcome.target_control_ids),
                    *(("present_control", item) for item in outcome.present_target_control_ids),
                ),
                required=outcome.required,
            ),
            subject_node_id=subject_id,
            parent_evidence_node_id=evidence_id,
        )
        _link_finding(graph, finding_id, evidence_id, detector_id, subject_id, outcome_state)
    for index, coverage in enumerate(report.threat_coverage):
        threat_requirement_id = _add_requirement(
            graph,
            subject_id,
            EvidenceGraphRequirementType.threat_scope,
            coverage.threat_id,
            references=_references(("threat", coverage.threat_id)),
        )
        coverage_state, reason = _threat_coverage_state(coverage)
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.control_efficacy_threat,
                source_artifact_kind=report.artifact_kind,
                source_id=coverage.threat_id,
                source_path=f"/threat_coverage/{index}",
                state=coverage_state,
                verdict_bearing=coverage.applicability is ThreatApplicability.applicable,
                reason_codes=(reason.value,),
                references=_references(
                    ("threat", coverage.threat_id),
                    ("applicability", coverage.applicability.value),
                    *(("operator", item) for item in coverage.challenging_operator_ids),
                    *(
                        ("independent_challenger", item)
                        for item in coverage.independent_challenging_operator_ids
                    ),
                ),
                critical=coverage.critical,
                independently_challenged=coverage.independently_challenged,
            ),
            subject_node_id=subject_id,
            parent_evidence_node_id=evidence_id,
        )
        _link_finding(
            graph,
            finding_id,
            evidence_id,
            threat_requirement_id,
            subject_id,
            coverage_state,
        )
    _project_limitations(
        graph,
        subject_id,
        evidence_id,
        source_artifact_kind=report.artifact_kind,
        limitations=report.limitations,
    )


def _control_efficacy_projection(
    report: ControlEfficacyReport,
) -> EvidenceGraphControlEfficacyProjection:
    return EvidenceGraphControlEfficacyProjection(
        semantic_state=report.semantic_state,
        threat_scope_state=report.threat_scope_state,
        canonical_operator_ids=report.canonical_operator_ids,
        canonical_invariant_families=report.canonical_invariant_families,
        selected_operator_ids=report.selected_operator_ids,
        pending_operator_ids=report.pending_operator_ids,
        required_operator_ids=report.required_operator_ids,
        state_counts=report.state_counts,
        applicable_operator_count=report.applicable_operator_count,
        caught_operator_count=report.caught_operator_count,
        survived_operator_count=report.survived_operator_count,
        inapplicable_operator_count=report.inapplicable_operator_count,
        invalid_operator_count=report.invalid_operator_count,
        invalid_subject_count=report.invalid_subject_count,
        execution_error_count=report.execution_error_count,
        catalog_kill_rate=report.catalog_kill_rate,
        required_survivor_count=report.required_survivor_count,
        critical_survivor_count=report.critical_survivor_count,
        required_survivor_operator_ids=report.required_survivor_operator_ids,
        critical_survivor_operator_ids=report.critical_survivor_operator_ids,
        required_not_evaluated_operator_ids=(report.required_not_evaluated_operator_ids),
        invalid_or_error_operator_ids=report.invalid_or_error_operator_ids,
        kill_rate_by_invariant_family=report.kill_rate_by_invariant_family,
        kill_rate_by_independence_class=report.kill_rate_by_independence_class,
        applicable_threat_category_count=report.applicable_threat_category_count,
        challenged_threat_category_count=report.challenged_threat_category_count,
        independently_challenged_threat_category_count=(
            report.independently_challenged_threat_category_count
        ),
        critical_uncovered_threat_count=report.critical_uncovered_threat_count,
        unknown_applicability_count=report.unknown_applicability_count,
        critical_uncovered_threat_ids=report.critical_uncovered_threat_ids,
        unknown_applicability_threat_ids=report.unknown_applicability_threat_ids,
        unscoped_catalog_threat_count=report.unscoped_catalog_threat_count,
        unscoped_catalog_threat_ids=report.unscoped_catalog_threat_ids,
        threat_coverage_ids=tuple(item.threat_id for item in report.threat_coverage),
        threat_challenge_rate=report.threat_challenge_rate,
        independent_threat_challenge_rate=report.independent_threat_challenge_rate,
    )


def _project_gate_profile(
    graph: _GraphAccumulator,
    subject_id: str,
    profile: ControlEfficacyGateProfile,
) -> None:
    digest = sha256_hexdigest(profile.model_dump(mode="json"))
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.gate_profile,
            source_artifact_kind="control-efficacy-gate-profile",
            source_id=profile.profile_id,
            source_digest=digest,
            state=EvidenceState.inconclusive,
            verdict_bearing=False,
            references=_references(
                ("gate_profile", profile.profile_id),
                ("catalog", profile.required_catalog),
                *(("operator", item) for item in profile.required_operators),
            ),
        ),
        subject_node_id=subject_id,
    )
    _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.gate_profile,
        profile.profile_id,
        references=_references(("gate_profile", profile.profile_id)),
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)


def _project_gate_decision(
    graph: _GraphAccumulator,
    subject_id: str,
    decision: ControlEfficacyGateDecision,
    *,
    control_efficacy: ControlEfficacyReport | None,
) -> None:
    state = _gate_state(decision.state)
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.gate_decision,
            source_artifact_kind="control-efficacy-gate-decision",
            source_id=decision.profile_id,
            source_digest=sha256_hexdigest(decision.model_dump(mode="json")),
            state=state,
            verdict_bearing=True,
            references=_references(
                ("gate_profile", decision.profile_id),
                ("source_digest", decision.report_digest),
            ),
        ),
        subject_node_id=subject_id,
    )
    gate_requirement_id = _add_requirement(
        graph,
        subject_id,
        EvidenceGraphRequirementType.gate_profile,
        decision.profile_id,
        references=_references(("gate_profile", decision.profile_id)),
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    _add_semantic_edge(graph, state, evidence_id, gate_requirement_id)
    for index, finding in enumerate(decision.findings):
        finding_state = (
            EvidenceState.violated
            if finding.effect is GateEffect.block
            else EvidenceState.inconclusive
        )
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.control_efficacy_gate,
                source_artifact_kind="control-efficacy-gate-decision",
                source_id=finding.reason_code.value,
                source_path=f"/findings/{index}",
                state=finding_state,
                verdict_bearing=True,
                reason_codes=(finding.reason_code.value,),
                references=_references(
                    ("gate_profile", decision.profile_id),
                    *(("operator", item) for item in finding.operator_ids),
                    *(("threat", item) for item in finding.threat_ids),
                ),
                gate_effect=finding.effect,
            ),
            subject_node_id=subject_id,
            parent_evidence_node_id=evidence_id,
        )
        graph.add_edge(EvidenceGraphEdgeKind.derived_from, finding_id, evidence_id)
        graph.add_edge(EvidenceGraphEdgeKind.scoped_to, finding_id, subject_id)
        graph.add_edge(EvidenceGraphEdgeKind.targets, finding_id, gate_requirement_id)
        _add_semantic_edge(graph, finding_state, finding_id, gate_requirement_id)
        for operator_id in finding.operator_ids:
            target_id = _add_requirement(
                graph,
                subject_id,
                EvidenceGraphRequirementType.mutation_detector,
                operator_id,
                references=_references(("operator", operator_id)),
            )
            graph.add_edge(EvidenceGraphEdgeKind.targets, finding_id, target_id)
        for threat_id in finding.threat_ids:
            target_id = _add_requirement(
                graph,
                subject_id,
                EvidenceGraphRequirementType.threat_scope,
                threat_id,
                references=_references(("threat", threat_id)),
            )
            graph.add_edge(EvidenceGraphEdgeKind.targets, finding_id, target_id)


def _project_packet_limitations(
    graph: _GraphAccumulator,
    subject_id: str,
    limitations: tuple[str, ...],
) -> None:
    evidence_id = graph.add_node(
        EvidenceGraphNodeKind.evidence,
        EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.packet_limitations,
            source_artifact_kind="evidence-packet",
            source_id="packet-limitations",
            source_digest=sha256_hexdigest({"limitations": limitations}),
            state=EvidenceState.inconclusive,
            verdict_bearing=False,
        ),
        subject_node_id=subject_id,
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, evidence_id, subject_id)
    _project_limitations(
        graph,
        subject_id,
        evidence_id,
        source_artifact_kind="evidence-packet",
        limitations=limitations,
    )


def _project_limitations(
    graph: _GraphAccumulator,
    subject_id: str,
    evidence_id: str,
    *,
    source_artifact_kind: str,
    limitations: tuple[str, ...],
) -> None:
    for index, limitation in enumerate(limitations):
        finding_id = graph.add_node(
            EvidenceGraphNodeKind.finding,
            EvidenceGraphFindingPayload(
                finding_type=EvidenceGraphFindingType.limitation,
                source_artifact_kind=source_artifact_kind,
                source_id=f"limitation-{index}",
                source_path=f"/limitations/{index}",
                state=EvidenceState.inconclusive,
                verdict_bearing=False,
                reason_codes=(EvidenceGraphProjectionReason.evidence_scope_limitation.value,),
                messages=(limitation,),
            ),
            subject_node_id=subject_id,
            parent_evidence_node_id=evidence_id,
        )
        graph.add_edge(EvidenceGraphEdgeKind.derived_from, finding_id, evidence_id)
        graph.add_edge(EvidenceGraphEdgeKind.scoped_to, finding_id, subject_id)


def _add_requirement(
    graph: _GraphAccumulator,
    subject_id: str,
    requirement_type: EvidenceGraphRequirementType,
    requirement_id: str,
    *,
    references: tuple[EvidenceGraphReference, ...] = (),
) -> str:
    node_id = graph.add_node(
        EvidenceGraphNodeKind.requirement,
        EvidenceGraphRequirementPayload(
            requirement_type=requirement_type,
            requirement_id=requirement_id,
            references=references,
        ),
        subject_node_id=subject_id,
    )
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, node_id, subject_id)
    return node_id


def _link_finding(
    graph: _GraphAccumulator,
    finding_id: str,
    evidence_id: str,
    requirement_id: str,
    subject_id: str,
    state: EvidenceState,
) -> None:
    graph.add_edge(EvidenceGraphEdgeKind.derived_from, finding_id, evidence_id)
    graph.add_edge(EvidenceGraphEdgeKind.scoped_to, finding_id, subject_id)
    graph.add_edge(EvidenceGraphEdgeKind.targets, finding_id, requirement_id)
    finding = graph.nodes[finding_id].payload
    if not isinstance(finding, EvidenceGraphFindingPayload):
        raise TypeError("finding link source must be a typed finding payload")
    if finding.verdict_bearing:
        _add_semantic_edge(graph, state, finding_id, requirement_id)


def _add_semantic_edge(
    graph: _GraphAccumulator,
    state: EvidenceState,
    source_id: str,
    requirement_id: str,
) -> None:
    if state is EvidenceState.supported:
        graph.add_edge(EvidenceGraphEdgeKind.supports, source_id, requirement_id)
    elif state in {EvidenceState.contradicted, EvidenceState.violated}:
        graph.add_edge(EvidenceGraphEdgeKind.contradicts, source_id, requirement_id)


def _validate_subject_digest_coherence(
    subject: EvidenceGraphSubjectPayload,
    *,
    evaluation: EvaluationInput | None,
    comparison: ComparisonInput | None,
    evidence_sensitivity: SensitivityInput | None,
    mutation_results: tuple[AssuranceMutationResult, ...],
    control_efficacy: ControlEfficacyReport | None,
) -> None:
    evaluation_digest = evaluation.runset_digest if evaluation is not None else None
    if evaluation_digest is not None and subject.subject_digest != evaluation_digest:
        raise ValueError("graph subject digest does not match evaluation runset digest")
    comparison_digest = comparison.candidate_runset_digest if comparison is not None else None
    if (
        comparison_digest is not None
        and evaluation_digest is not None
        and comparison_digest != evaluation_digest
    ):
        raise ValueError(
            "comparison candidate_runset_digest does not match evaluation runset digest"
        )
    if (
        comparison_digest is not None
        and subject.subject_digest is not None
        and comparison_digest != subject.subject_digest
    ):
        raise ValueError("comparison candidate_runset_digest does not match graph subject digest")
    sensitivity_digest = (
        evidence_sensitivity.counterfactual_arm.runset_digest
        if evidence_sensitivity is not None
        else None
    )
    if sensitivity_digest is not None and subject.subject_digest != sensitivity_digest:
        raise ValueError(
            "graph subject digest does not match sensitivity counterfactual runset digest"
        )
    digests = {
        digest
        for digest in (
            evaluation_digest,
            comparison_digest,
            sensitivity_digest,
            *(result.source_digest for result in mutation_results),
            *((control_efficacy.source_digest,) if control_efficacy is not None else ()),
        )
        if digest is not None
    }
    if len(digests) > 1:
        raise ValueError("graph sources do not share one subject digest")
    observed = next(iter(digests), None)
    if subject.subject_digest is not None and observed is not None:
        if subject.subject_digest != observed:
            raise ValueError("graph subject digest does not match source artifacts")


def _source_evidence_subject_id(
    graph: _GraphAccumulator,
    primary_subject_id: str,
    primary_subject: EvidenceGraphSubjectPayload,
    *,
    source_digest: str | None,
    unbound_identity: str,
) -> str:
    if source_digest is not None and primary_subject.subject_digest == source_digest:
        return primary_subject_id
    source_subject = EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id=(
            f"sha256:{source_digest}"
            if source_digest is not None
            else f"unbound:{unbound_identity}"
        ),
        subject_digest=source_digest,
    )
    return graph.add_node(
        EvidenceGraphNodeKind.subject,
        source_subject,
    )


def _validate_source_coherence(
    subject: EvidenceGraphSubjectPayload,
    *,
    evaluation: EvaluationInput | None,
    comparison: ComparisonInput | None,
    evidence_sensitivity: SensitivityInput | None,
    mutation_results: tuple[AssuranceMutationResult, ...],
    control_efficacy: ControlEfficacyReport | None,
    gate_profile: ControlEfficacyGateProfile | None,
    gate_decision: ControlEfficacyGateDecision | None,
    limitations: tuple[str, ...],
) -> None:
    if subject.subject_type == "agent_release":
        if any(
            (
                evaluation is not None,
                comparison is not None,
                evidence_sensitivity is not None,
                bool(mutation_results),
                control_efficacy is not None,
                gate_profile is not None,
                gate_decision is not None,
                bool(limitations),
            )
        ):
            raise ValueError("agent_release graph projection is subject-only")
        return
    if evaluation is not None:
        if not evaluation.runset_id:
            raise ValueError("graph evaluation runset_id must be non-empty")
        for index, finding in enumerate(evaluation.findings):
            if not finding.finding_id:
                raise ValueError(f"graph evaluation finding {index} finding_id must be non-empty")
        if evaluation.runset_id != subject.subject_id:
            raise ValueError("evaluation runset_id does not match the graph subject")
    if comparison is not None:
        if not comparison.baseline_runset_id:
            raise ValueError("graph comparison baseline_runset_id must be non-empty")
        if not comparison.candidate_runset_id:
            raise ValueError("graph comparison candidate_runset_id must be non-empty")
        if comparison.candidate_runset_id != subject.subject_id:
            raise ValueError("comparison candidate_runset_id does not match the graph subject")
    if evidence_sensitivity is not None:
        baseline = evidence_sensitivity.baseline_arm
        counterfactual = evidence_sensitivity.counterfactual_arm
        if counterfactual.runset_id != subject.subject_id:
            raise ValueError(
                "sensitivity counterfactual runset_id does not match the graph subject"
            )
        if (
            baseline.runset_id,
            baseline.runset_digest,
        ) == (
            counterfactual.runset_id,
            counterfactual.runset_digest,
        ):
            raise ValueError("sensitivity graph arms must have distinct run-set identities")
        if comparison is not None and (
            comparison.baseline_runset_id,
            comparison.candidate_runset_id,
        ) != (
            baseline.runset_id,
            counterfactual.runset_id,
        ):
            raise ValueError("sensitivity graph arms must match the comparison run-set identities")
        if comparison is not None:
            comparison_error = sensitivity_comparison_binding_error(
                comparison,
                evidence_sensitivity,
            )
            if comparison_error is not None:
                raise ValueError(comparison_error)
        if evaluation is not None and _model_digest(evaluation) != (
            counterfactual.evaluation_summary_digest
        ):
            raise ValueError(
                "graph evaluation canonical digest does not match the sensitivity "
                "counterfactual evaluation digest"
            )
    if evaluation is not None and comparison is not None:
        comparison_evaluation_error = comparison_evaluation_binding_error(
            comparison,
            evaluation,
            role="candidate",
        )
        if comparison_evaluation_error is not None:
            raise ValueError(comparison_evaluation_error)
    mutation_identities = tuple(_mutation_identity(result) for result in mutation_results)
    mutation_identity_keys = tuple(tuple(identity.items()) for identity in mutation_identities)
    if len(set(mutation_identity_keys)) != len(mutation_identity_keys):
        raise ValueError("mutation result identities must be unique")
    if gate_decision is not None and (gate_profile is None or control_efficacy is None):
        raise ValueError("gate decisions require their exact efficacy report and profile")
    if gate_profile is not None and gate_decision is not None:
        if gate_profile.profile_id != gate_decision.profile_id:
            raise ValueError("gate profile and decision identities do not match")
    if gate_decision is not None and gate_profile is not None and control_efficacy is not None:
        expected_decision = derive_control_efficacy_gate_decision(
            control_efficacy,
            gate_profile,
        )
        if gate_decision != expected_decision:
            raise ValueError("gate decision does not match the supplied report and profile")
    if control_efficacy is not None and gate_decision is not None:
        if control_efficacy.report_digest != gate_decision.report_digest:
            raise ValueError("gate decision does not bind the supplied efficacy report")


def _model_digest(value: object) -> str:
    model_dump = getattr(value, "model_dump", None)
    if not callable(model_dump):
        raise TypeError("graph source must be a typed artifact model")
    return sha256_hexdigest(model_dump(mode="json"))


def _mutation_identity(result: AssuranceMutationResult) -> dict[str, object]:
    return {
        "source_artifact_kind": result.source_artifact_kind,
        "source_digest": result.source_digest,
        "mutated_digest": result.mutated_digest,
        "operator_id": result.operator_id,
        "operator_version": result.operator_version,
        "operator_digest": result.operator_digest,
        "implementation_digest": result.implementation_digest,
        "seed": result.seed,
        "changed_paths": result.changed_paths,
        "expected_finding_target_digest": result.expected_finding_target_digest,
        "evaluator_method_id": result.evaluator_method_id,
        "evaluator_implementation_digest": result.evaluator_implementation_digest,
        "evaluator_implementation_version": result.evaluator_implementation_version,
        "evaluator_evaluation_basis": result.evaluator_evaluation_basis.value,
        "evaluator_protocol_digest": result.evaluator_protocol_digest,
        "evaluator_population_id": result.evaluator_population_id,
        "gate_profile_id": result.gate_profile_id,
        "gate_profile_digest": result.gate_profile_digest,
        "waiver_set_digest": result.waiver_set_digest,
        "evaluation_date": result.evaluation_date,
        "expected_detection_contract_digest": result.expected_detection_contract_digest,
        "independence_class": result.independence_class.value,
    }


def _references(
    *items: tuple[str, str | None],
) -> tuple[EvidenceGraphReference, ...]:
    unique = {
        (EvidenceGraphReferenceRole(role), value)
        for role, value in items
        if value is not None and value != ""
    }
    return tuple(
        EvidenceGraphReference(role=role, value=value)
        for role, value in sorted(unique, key=lambda item: (item[0].value, item[1]))
    )


def _node_kinds(*values: str) -> tuple[EvidenceGraphNodeKind, ...]:
    return tuple(
        sorted({EvidenceGraphNodeKind(value) for value in values}, key=lambda item: item.value)
    )


def _gate_state(state: GateState) -> EvidenceState:
    match state:
        case GateState.pass_:
            return EvidenceState.supported
        case GateState.fail:
            return EvidenceState.violated
        case GateState.warn:
            return EvidenceState.inconclusive
        case GateState.not_evaluated:
            return EvidenceState.not_evaluated
        case _ as unreachable:
            assert_never(unreachable)


def _mutation_state(
    state: MutationResultState,
    *,
    evaluation_basis: EvidenceEvaluationBasis = EvidenceEvaluationBasis.deterministic,
) -> EvidenceState:
    if (
        state in {MutationResultState.caught, MutationResultState.survived}
        and evaluation_basis is not EvidenceEvaluationBasis.deterministic
    ):
        return EvidenceState.inconclusive
    match state:
        case MutationResultState.caught:
            return EvidenceState.supported
        case MutationResultState.survived:
            return EvidenceState.contradicted
        case MutationResultState.inapplicable:
            return EvidenceState.out_of_scope
        case (
            MutationResultState.invalid_operator
            | MutationResultState.invalid_subject
            | MutationResultState.execution_error
        ):
            return EvidenceState.error
        case _ as unreachable:
            assert_never(unreachable)


def _mutation_verdict_bearing(
    state: MutationResultState,
    *,
    evaluation_basis: EvidenceEvaluationBasis,
) -> bool:
    return (
        state in {MutationResultState.caught, MutationResultState.survived}
        and evaluation_basis is EvidenceEvaluationBasis.deterministic
    )


def _mutation_reason(
    state: MutationResultState,
) -> EvidenceGraphProjectionReason:
    match state:
        case MutationResultState.caught:
            return EvidenceGraphProjectionReason.mutation_caught
        case MutationResultState.survived:
            return EvidenceGraphProjectionReason.mutation_survived
        case MutationResultState.inapplicable:
            return EvidenceGraphProjectionReason.mutation_inapplicable
        case MutationResultState.invalid_operator:
            return EvidenceGraphProjectionReason.mutation_invalid_operator
        case MutationResultState.invalid_subject:
            return EvidenceGraphProjectionReason.mutation_invalid_subject
        case MutationResultState.execution_error:
            return EvidenceGraphProjectionReason.mutation_execution_error
        case _ as unreachable:
            assert_never(unreachable)


def _comparison_state(summary: ComparisonSummary) -> EvidenceState:
    if summary.fixture_equivalence_state is GateState.fail:
        return EvidenceState.error
    if summary.fixture_equivalence_state is GateState.warn:
        return EvidenceState.inconclusive
    if summary.fixture_equivalence_state is GateState.not_evaluated:
        return EvidenceState.not_evaluated
    if summary.fixture_equivalence_state is not GateState.pass_:
        assert_never(summary.fixture_equivalence_state)
    match summary.classification:
        case ComparisonClassification.invalid_comparison:
            return EvidenceState.error
        case ComparisonClassification.new_failure | ComparisonClassification.persistent_failure:
            return EvidenceState.violated
        case ComparisonClassification.not_evaluated:
            return EvidenceState.not_evaluated
        case (
            ComparisonClassification.unchanged
            | ComparisonClassification.resolved_failure
            | ComparisonClassification.allowed_behavioral_change
            | ComparisonClassification.allowed_behavioral_and_provenance_change
            | ComparisonClassification.provenance_only_change
        ):
            return _gate_state(summary.candidate_state)
        case _ as unreachable:
            assert_never(unreachable)


def _evidence_sensitivity_state(
    state: EvidenceSensitivityState,
) -> EvidenceState:
    match state:
        case EvidenceSensitivityState.responsive:
            return EvidenceState.supported
        case EvidenceSensitivityState.evidence_insensitive:
            return EvidenceState.violated
        case EvidenceSensitivityState.confounded:
            return EvidenceState.inconclusive
        case EvidenceSensitivityState.prerequisites_unmet:
            return EvidenceState.prerequisites_unmet
        case _ as unreachable:
            assert_never(unreachable)


def _comparison_verdict_bearing(summary: ComparisonSummary) -> bool:
    return summary.fixture_equivalence_state is GateState.pass_ and summary.classification not in {
        ComparisonClassification.invalid_comparison,
        ComparisonClassification.not_evaluated,
    }


def _efficacy_state(state: ControlEfficacySemanticState) -> EvidenceState:
    match state:
        case ControlEfficacySemanticState.survivor_observed:
            return EvidenceState.contradicted
        case ControlEfficacySemanticState.indeterminate:
            return EvidenceState.inconclusive
        case ControlEfficacySemanticState.not_evaluated:
            return EvidenceState.not_evaluated
        case ControlEfficacySemanticState.all_evaluated_applicable_caught:
            return EvidenceState.supported
        case _ as unreachable:
            assert_never(unreachable)


def _threat_coverage_state(
    coverage: ThreatCoverageItem,
) -> tuple[EvidenceState, EvidenceGraphProjectionReason]:
    applicability = coverage.applicability
    challenged = bool(coverage.challenging_operator_ids)
    if applicability is ThreatApplicability.not_applicable:
        return (
            EvidenceState.out_of_scope,
            EvidenceGraphProjectionReason.threat_not_applicable,
        )
    if applicability is ThreatApplicability.unknown:
        return (
            EvidenceState.inconclusive,
            EvidenceGraphProjectionReason.threat_applicability_unknown,
        )
    if challenged:
        return EvidenceState.supported, EvidenceGraphProjectionReason.threat_challenged
    return EvidenceState.contradicted, EvidenceGraphProjectionReason.threat_uncovered
