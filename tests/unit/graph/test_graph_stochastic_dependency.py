from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

import pytest
from pydantic import ValidationError

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.graph.builder import legacy_packet_compatibility_manifest
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphEdge,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphNode,
    EvidenceGraphNodeKind,
    EvidenceGraphStatisticalSufficiencyProjection,
    EvidenceGraphStochasticSensitivityProjection,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import EvidenceState
from agent_assure.schema.stochastic_sensitivity import (
    StochasticGateEffect,
    StochasticSensitivityState,
    SufficiencyState,
)

_PROTOCOL_DIGEST = "a" * 64
_SUFFICIENCY_DIGEST = "b" * 64
_STOCHASTIC_DIGEST = "c" * 64
_PopulationClaim = Literal[
    "none",
    "expected_decision_response_cluster_rate_above_null_supported",
    "expected_decision_response_cluster_rate_above_null_not_supported",
]


@dataclass(frozen=True)
class _DependencyParts:
    subject: EvidenceGraphNode
    sufficiency: EvidenceGraphNode
    stochastic: EvidenceGraphNode
    edges: tuple[EvidenceGraphEdge, ...]


def _parts(
    *,
    protocol_id: str = "paired-protocol",
    protocol_digest: str = _PROTOCOL_DIGEST,
    sufficiency_protocol_digest: str | None = None,
    sufficiency_digest: str = _SUFFICIENCY_DIGEST,
    sufficiency_state: SufficiencyState = SufficiencyState.satisfied,
    stochastic_state: StochasticSensitivityState = StochasticSensitivityState.pass_,
    stochastic_verdict: bool = True,
    population_claim: _PopulationClaim = (
        "expected_decision_response_cluster_rate_above_null_supported"
    ),
    stochastic_candidate_configuration_digest: str = "e" * 64,
) -> _DependencyParts:
    sufficiency_id = f"{protocol_id}/sufficiency"
    subject = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.subject,
        payload=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="stochastic-subject",
            subject_digest="d" * 64,
        ),
    )
    sufficiency_verdict = sufficiency_state is SufficiencyState.satisfied
    sufficiency = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.statistical_sufficiency,
            source_artifact_kind="statistical-sufficiency-report",
            source_id=sufficiency_id,
            source_digest=sufficiency_digest,
            state=(
                {
                    SufficiencyState.satisfied: EvidenceState.supported,
                    SufficiencyState.prerequisites_unmet: (EvidenceState.prerequisites_unmet),
                    SufficiencyState.inconclusive: EvidenceState.inconclusive,
                }[sufficiency_state]
            ),
            verdict_bearing=sufficiency_verdict,
            statistical_sufficiency_projection=(
                EvidenceGraphStatisticalSufficiencyProjection(
                    protocol_id=protocol_id,
                    protocol_digest=(sufficiency_protocol_digest or protocol_digest),
                    baseline_expected_recommendation="approve",
                    baseline_expected_outcome="approved",
                    counterfactual_expected_recommendation="deny",
                    counterfactual_expected_outcome="denied",
                    candidate_runset_id="stochastic-subject",
                    candidate_runset_digest="d" * 64,
                    candidate_configuration_digest="e" * 64,
                    state=sufficiency_state,
                    verdict_bearing=sufficiency_verdict,
                    population_claim_permitted=sufficiency_verdict,
                    planned_pairs=2,
                    actual_pairs=2,
                    included_pairs=2,
                    missing_pairs=0,
                    excluded_pairs=0,
                    planned_clusters=2,
                    actual_clusters=2,
                    analyzable_clusters=2,
                    analysis_method="cluster_binomial_exact",
                    analysis_compared_clusters=2,
                    analysis_responding_clusters=2,
                    analysis_p_value_upper_bound="0.040000",
                    analysis_adjusted_alpha="0.050000",
                )
            ),
        ),
        subject_node_id=subject.node_id,
    )
    stochastic = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.stochastic_evidence_sensitivity,
            source_artifact_kind="stochastic-evidence-sensitivity-report",
            source_id=f"{protocol_id}/stochastic-result",
            source_digest=_STOCHASTIC_DIGEST,
            state=(
                {
                    StochasticSensitivityState.pass_: EvidenceState.supported,
                    StochasticSensitivityState.block: EvidenceState.violated,
                    StochasticSensitivityState.prerequisites_unmet: (
                        EvidenceState.prerequisites_unmet
                    ),
                    StochasticSensitivityState.inconclusive: EvidenceState.inconclusive,
                }[stochastic_state]
            ),
            verdict_bearing=stochastic_verdict,
            stochastic_evidence_sensitivity_projection=(
                EvidenceGraphStochasticSensitivityProjection(
                    protocol_id=protocol_id,
                    protocol_digest=protocol_digest,
                    baseline_expected_recommendation="approve",
                    baseline_expected_outcome="approved",
                    counterfactual_expected_recommendation="deny",
                    counterfactual_expected_outcome="denied",
                    candidate_runset_id="stochastic-subject",
                    candidate_runset_digest="d" * 64,
                    candidate_configuration_digest=(stochastic_candidate_configuration_digest),
                    state=stochastic_state,
                    gate_effect={
                        StochasticSensitivityState.pass_: StochasticGateEffect.pass_,
                        StochasticSensitivityState.block: StochasticGateEffect.block,
                        StochasticSensitivityState.prerequisites_unmet: (
                            StochasticGateEffect.non_verdict
                        ),
                        StochasticSensitivityState.inconclusive: (StochasticGateEffect.non_verdict),
                    }[stochastic_state],
                    verdict_bearing=stochastic_verdict,
                    population_claim=population_claim,
                    observed_pair_count=2,
                    observed_response_count=2,
                    observed_counterexample_count=0,
                    observed_cluster_count=2,
                    observed_cluster_response_count=2,
                    estimated_response_rate="1.000000",
                    sufficiency_report_id=sufficiency_id,
                    sufficiency_report_digest=sufficiency_digest,
                )
            ),
        ),
        subject_node_id=subject.node_id,
    )
    return _DependencyParts(
        subject=subject,
        sufficiency=sufficiency,
        stochastic=stochastic,
        edges=(
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.scoped_to,
                source_node_id=sufficiency.node_id,
                target_node_id=subject.node_id,
            ),
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.scoped_to,
                source_node_id=stochastic.node_id,
                target_node_id=subject.node_id,
            ),
            EvidenceGraphEdge(
                kind=EvidenceGraphEdgeKind.depends_on,
                source_node_id=stochastic.node_id,
                target_node_id=sufficiency.node_id,
            ),
        ),
    )


def _build(
    parts: _DependencyParts,
    *,
    nodes: tuple[EvidenceGraphNode, ...] | None = None,
    edges: tuple[EvidenceGraphEdge, ...] | None = None,
) -> AssuranceEvidenceGraph:
    return AssuranceEvidenceGraph.from_parts(
        primary_subject_node_id=parts.subject.node_id,
        nodes=nodes or (parts.subject, parts.sufficiency, parts.stochastic),
        edges=parts.edges if edges is None else edges,
        compatibility=legacy_packet_compatibility_manifest(),
        limitations=("Synthetic stochastic dependency fixture.",),
    )


def test_verdict_stochastic_evidence_has_one_exact_satisfied_dependency() -> None:
    graph = _build(_parts())

    dependency = next(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on)
    assert dependency.source_node_id != dependency.target_node_id


def test_dependency_rejects_unrelated_candidate_configuration() -> None:
    with pytest.raises(
        ValidationError,
        match="preserve the sufficiency candidate RunSet and configuration binding",
    ):
        _build(
            _parts(
                stochastic_candidate_configuration_digest="f" * 64,
            )
        )


def test_verdict_stochastic_evidence_rejects_missing_or_duplicate_dependency() -> None:
    parts = _parts()
    without_dependency = tuple(
        edge for edge in parts.edges if edge.kind is not EvidenceGraphEdgeKind.depends_on
    )
    with pytest.raises(ValidationError, match="exactly one sufficiency dependency"):
        _build(parts, edges=without_dependency)

    other = _parts(
        protocol_id="other-protocol",
        protocol_digest="f" * 64,
        sufficiency_digest="e" * 64,
    ).sufficiency
    other_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=other.node_id,
        target_node_id=parts.subject.node_id,
    )
    other_dependency = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.depends_on,
        source_node_id=parts.stochastic.node_id,
        target_node_id=other.node_id,
    )
    with pytest.raises(ValidationError, match="exactly one sufficiency dependency"):
        _build(
            parts,
            nodes=(parts.subject, parts.sufficiency, other, parts.stochastic),
            edges=(*parts.edges, other_scope, other_dependency),
        )


def test_dependency_rejects_wrong_identity_digest_type_and_unsatisfied_target() -> None:
    declared = _parts()
    other = _parts(
        protocol_id="other-protocol",
        protocol_digest="f" * 64,
        sufficiency_digest="e" * 64,
    ).sufficiency
    other_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=other.node_id,
        target_node_id=declared.subject.node_id,
    )
    wrong_dependency = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.depends_on,
        source_node_id=declared.stochastic.node_id,
        target_node_id=other.node_id,
    )
    base_scopes = tuple(
        edge for edge in declared.edges if edge.kind is EvidenceGraphEdgeKind.scoped_to
    )
    with pytest.raises(ValidationError, match="declared sufficiency identity and digest"):
        _build(
            declared,
            nodes=(declared.subject, declared.sufficiency, other, declared.stochastic),
            edges=(*base_scopes, other_scope, wrong_dependency),
        )

    wrong_type_dependency = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.depends_on,
        source_node_id=declared.stochastic.node_id,
        target_node_id=EvidenceGraphNode.build(
            kind=EvidenceGraphNodeKind.evidence,
            payload=EvidenceGraphEvidencePayload(
                evidence_type=EvidenceGraphEvidenceType.evaluation,
                source_artifact_kind="evaluation-summary",
                source_id="untyped-target",
                source_digest="f" * 64,
                state=EvidenceState.not_evaluated,
                verdict_bearing=False,
            ),
            subject_node_id=declared.subject.node_id,
        ).node_id,
    )
    wrong_target = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.evaluation,
            source_artifact_kind="evaluation-summary",
            source_id="untyped-target",
            source_digest="f" * 64,
            state=EvidenceState.not_evaluated,
            verdict_bearing=False,
        ),
        subject_node_id=declared.subject.node_id,
    )
    wrong_target_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=wrong_target.node_id,
        target_node_id=declared.subject.node_id,
    )
    with pytest.raises(ValidationError, match="typed statistical-sufficiency"):
        _build(
            declared,
            nodes=(declared.subject, declared.sufficiency, declared.stochastic, wrong_target),
            edges=(*base_scopes, wrong_target_scope, wrong_type_dependency),
        )

    unsatisfied = _parts(
        sufficiency_state=SufficiencyState.inconclusive,
    )
    with pytest.raises(ValidationError, match="requires satisfied sufficiency"):
        _build(unsatisfied)


def test_nonverdict_evidence_binds_sufficiency_without_fabricating_dependency() -> None:
    nonverdict = _parts(
        stochastic_state=StochasticSensitivityState.inconclusive,
        stochastic_verdict=False,
        population_claim="none",
    )
    without_dependency = tuple(
        edge for edge in nonverdict.edges if edge.kind is not EvidenceGraphEdgeKind.depends_on
    )
    graph = _build(nonverdict, edges=without_dependency)

    assert not tuple(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on)

    with pytest.raises(ValidationError, match="non-verdict stochastic"):
        _build(nonverdict)

    stochastic_scope = next(
        edge for edge in without_dependency if edge.source_node_id == nonverdict.stochastic.node_id
    )
    with pytest.raises(
        ValidationError,
        match="exactly one typed statistical-sufficiency node",
    ):
        _build(
            nonverdict,
            nodes=(nonverdict.subject, nonverdict.stochastic),
            edges=(stochastic_scope,),
        )

    wrong_protocol = _parts(
        sufficiency_protocol_digest="f" * 64,
        stochastic_state=StochasticSensitivityState.inconclusive,
        stochastic_verdict=False,
        population_claim="none",
    )
    wrong_protocol_edges = tuple(
        edge for edge in wrong_protocol.edges if edge.kind is not EvidenceGraphEdgeKind.depends_on
    )
    with pytest.raises(ValidationError, match="exact same protocol"):
        _build(wrong_protocol, edges=wrong_protocol_edges)

    wrong_candidate = _parts(
        stochastic_state=StochasticSensitivityState.inconclusive,
        stochastic_verdict=False,
        population_claim="none",
        stochastic_candidate_configuration_digest="f" * 64,
    )
    wrong_candidate_edges = tuple(
        edge for edge in wrong_candidate.edges if edge.kind is not EvidenceGraphEdgeKind.depends_on
    )
    with pytest.raises(ValidationError, match="candidate RunSet and configuration"):
        _build(wrong_candidate, edges=wrong_candidate_edges)


def test_deterministic_evidence_cannot_fabricate_dependency() -> None:
    parts = _parts()
    deterministic = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=EvidenceGraphEvidencePayload(
            evidence_type=EvidenceGraphEvidenceType.evaluation,
            source_artifact_kind="evaluation-summary",
            source_id="deterministic-evaluation",
            source_digest="f" * 64,
            state=EvidenceState.not_evaluated,
            verdict_bearing=False,
        ),
        subject_node_id=parts.subject.node_id,
    )
    deterministic_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=deterministic.node_id,
        target_node_id=parts.subject.node_id,
    )
    fabricated = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.depends_on,
        source_node_id=deterministic.node_id,
        target_node_id=parts.sufficiency.node_id,
    )
    stochastic_scope = next(
        edge
        for edge in parts.edges
        if edge.kind is EvidenceGraphEdgeKind.scoped_to
        and edge.source_node_id == parts.sufficiency.node_id
    )
    with pytest.raises(ValidationError, match="reserved for stochastic"):
        _build(
            parts,
            nodes=(parts.subject, parts.sufficiency, deterministic),
            edges=(stochastic_scope, deterministic_scope, fabricated),
        )


def test_dependency_rejects_cross_subject_scope_and_cycles() -> None:
    parts = _parts()
    other_subject = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.subject,
        payload=EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="other-subject",
            subject_digest="e" * 64,
        ),
    )
    other_sufficiency = EvidenceGraphNode.build(
        kind=EvidenceGraphNodeKind.evidence,
        payload=parts.sufficiency.payload,
        subject_node_id=other_subject.node_id,
    )
    stochastic_scope = next(
        edge
        for edge in parts.edges
        if edge.kind is EvidenceGraphEdgeKind.scoped_to
        and edge.source_node_id == parts.stochastic.node_id
    )
    cross_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=other_sufficiency.node_id,
        target_node_id=other_subject.node_id,
    )
    cross_dependency = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.depends_on,
        source_node_id=parts.stochastic.node_id,
        target_node_id=other_sufficiency.node_id,
    )
    with pytest.raises(
        ValidationError,
        match="cannot cross subject scopes|candidate RunSet id and digest",
    ):
        _build(
            parts,
            nodes=(parts.subject, other_subject, other_sufficiency, parts.stochastic),
            edges=(stochastic_scope, cross_scope, cross_dependency),
        )

    first = parts.stochastic
    second = _parts(
        protocol_id="second-protocol",
        protocol_digest="e" * 64,
        sufficiency_digest="f" * 64,
    ).stochastic
    first_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=first.node_id,
        target_node_id=parts.subject.node_id,
    )
    second_scope = EvidenceGraphEdge(
        kind=EvidenceGraphEdgeKind.scoped_to,
        source_node_id=second.node_id,
        target_node_id=parts.subject.node_id,
    )
    with pytest.raises(ValidationError, match="must be acyclic"):
        _build(
            parts,
            nodes=(parts.subject, first, second),
            edges=(
                first_scope,
                second_scope,
                EvidenceGraphEdge(
                    kind=EvidenceGraphEdgeKind.depends_on,
                    source_node_id=first.node_id,
                    target_node_id=second.node_id,
                ),
                EvidenceGraphEdge(
                    kind=EvidenceGraphEdgeKind.depends_on,
                    source_node_id=second.node_id,
                    target_node_id=first.node_id,
                ),
            ),
        )


def test_stochastic_dependency_content_is_gated_to_graph_schema_0_6_5() -> None:
    graph = _build(_parts())
    payload = graph.model_dump(mode="json")
    payload["schema_version"] = "0.6.4"
    payload["graph_digest"] = sha256_hexdigest(
        {key: value for key, value in payload.items() if key != "graph_digest"}
    )

    with pytest.raises(ValidationError, match="requires schema_version '0.6.5'"):
        AssuranceEvidenceGraph.model_validate(payload)
