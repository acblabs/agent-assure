from __future__ import annotations

from typing import Literal

import pytest
from pydantic import ValidationError

from agent_assure.graph.builder import build_evidence_graph
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    plan_binary_paired_design,
)
from agent_assure.schema.graph import (
    AssuranceEvidenceGraph,
    EvidenceGraphEdgeKind,
    EvidenceGraphEvidencePayload,
    EvidenceGraphEvidenceType,
    EvidenceGraphStatisticalSufficiencyProjection,
    EvidenceGraphStochasticSensitivityProjection,
    EvidenceGraphSubjectPayload,
)
from agent_assure.schema.mutation import EvidenceState
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingClassification,
    CouplingDescriptor,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    RunRecordArtifactDependency,
    RunSetArtifactDependency,
    SensitivityArmBinding,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
)
from tests.stochastic_source_support import build_case_authority_bindings

_ArmId = Literal["baseline_evidence", "counterfactual_evidence"]
_EndpointValue = Literal[0, 1]


def _arm(
    arm_id: _ArmId,
    *,
    configuration_digest: str,
    corpus_digest: str,
) -> SensitivityArmBinding:
    is_baseline = arm_id == "baseline_evidence"
    return SensitivityArmBinding(
        arm_id=arm_id,
        expected_recommendation="approve" if is_baseline else "deny",
        expected_outcome="approved" if is_baseline else "denied",
        configuration_digest=configuration_digest,
        corpus_digest=corpus_digest,
        prompt_manifest_digest="d" * 64,
        case_manifest_digest="e" * 64,
        knowledge_contract_digest="f" * 64,
        provider="synthetic-provider",
        requested_model="synthetic-model",
        adapter_id="openai-chat-completions",
        pipeline_id="synthetic-pipeline",
        tool_schema_digest="1" * 64,
        policy_bundle_digest="2" * 64,
    )


def _reports(
    *,
    response_values: tuple[_EndpointValue, _EndpointValue] = (1, 1),
    deterministic_fixture: bool = False,
) -> tuple[StatisticalSufficiencyReport, StochasticEvidenceSensitivityReport]:
    design = plan_binary_paired_design(
        familywise_alpha="0.500000",
        desired_power="0.500000",
        null_response_rate="0.100000",
        alternative_response_rate="0.900000",
        monte_carlo_resamples=1_000,
    )
    case_ids = ("case-a", "case-b")
    baseline_arm = _arm(
        "baseline_evidence",
        configuration_digest="a" * 64,
        corpus_digest="b" * 64,
    )
    counterfactual_arm = _arm(
        "counterfactual_evidence",
        configuration_digest="c" * 64,
        corpus_digest="3" * 64,
    )
    protocol = RepeatedEvidenceSensitivityProtocol.build(
        protocol_id=(
            "deterministic-graph-protocol" if deterministic_fixture else "stochastic-graph-protocol"
        ),
        interpretation=("exploratory" if deterministic_fixture else "confirmatory"),
        execution_mode=("deterministic_fixture" if deterministic_fixture else "stochastic_live"),
        baseline_arm=baseline_arm,
        counterfactual_arm=counterfactual_arm,
        planned_case_ids=case_ids,
        planned_cluster_ids=case_ids,
        case_cluster_bindings=tuple(
            CaseClusterBinding(case_id=case_id, cluster_id=case_id) for case_id in case_ids
        ),
        case_authority_bindings=build_case_authority_bindings(
            case_ids,
            baseline_arm,
            counterfactual_arm,
        ),
        repetitions_per_arm=1,
        planned_pairs=2,
        multiplicity_family="evidence-sensitivity",
        coupling=CouplingDescriptor(
            pairing_identity_verified=True,
            stochastic_dimensions=(
                ("deterministic_fixture_execution",)
                if deterministic_fixture
                else (
                    "provider_sampling_randomness",
                    "temporal_execution_order",
                )
            ),
            shared=(("deterministic_fixture_execution",) if deterministic_fixture else ()),
            intentionally_different=("governing_corpus_digest",),
            not_shared=(
                ()
                if deterministic_fixture
                else (
                    "provider_sampling_randomness",
                    "temporal_execution_order",
                )
            ),
            unknown=(),
            classification=(
                CouplingClassification.fully_coupled
                if deterministic_fixture
                else CouplingClassification.nominally_paired
            ),
        ),
        design=design,
        limitations=("Synthetic paired graph projection fixture.",),
    )
    observations = tuple(
        PairedSensitivityObservation(
            case_id=case_id,
            repetition_index=0,
            cluster_id=case_id,
            disposition=PairDisposition.included,
            baseline_run_id=f"baseline-{case_id}",
            baseline_run_digest=_run_digest("baseline_evidence", case_id),
            counterfactual_run_id=f"counterfactual-{case_id}",
            counterfactual_run_digest=_run_digest("counterfactual_evidence", case_id),
            baseline_recommendation="approve",
            baseline_outcome="approved",
            counterfactual_recommendation=("deny" if endpoint_value else "approve"),
            counterfactual_outcome=("denied" if endpoint_value else "approved"),
            baseline_expected_recommendation="approve",
            baseline_expected_outcome="approved",
            counterfactual_expected_recommendation="deny",
            counterfactual_expected_outcome="denied",
            endpoint_value=endpoint_value,
        )
        for case_id, endpoint_value in zip(case_ids, response_values, strict=True)
    )
    sufficiency = evaluate_statistical_sufficiency(
        protocol,
        observations,
        source_runsets=(() if deterministic_fixture else _runset_dependencies(protocol, case_ids)),
    )
    return sufficiency, build_stochastic_sensitivity_report(sufficiency)


def _run_digest(arm_id: _ArmId, case_id: str) -> str:
    return {
        ("baseline_evidence", "case-a"): "4" * 64,
        ("baseline_evidence", "case-b"): "5" * 64,
        ("counterfactual_evidence", "case-a"): "6" * 64,
        ("counterfactual_evidence", "case-b"): "7" * 64,
    }[(arm_id, case_id)]


def _runset_dependencies(
    protocol: RepeatedEvidenceSensitivityProtocol,
    case_ids: tuple[str, ...],
) -> tuple[RunSetArtifactDependency, RunSetArtifactDependency]:
    def dependency(arm_id: _ArmId) -> RunSetArtifactDependency:
        arm = (
            protocol.baseline_arm if arm_id == "baseline_evidence" else protocol.counterfactual_arm
        )
        run_id_prefix = "baseline" if arm_id == "baseline_evidence" else "counterfactual"
        return RunSetArtifactDependency(
            arm_id=arm_id,
            runset_id=f"{arm_id}-runset",
            runset_digest=("8" if arm_id == "baseline_evidence" else "9") * 64,
            execution_configuration_digest=arm.configuration_digest,
            operational_protocol_id="synthetic-operational-protocol",
            operational_protocol_digest="0" * 64,
            evidence_sensitivity_design_digest=protocol.design_commitment_digest,
            records=tuple(
                RunRecordArtifactDependency(
                    case_id=case_id,
                    repetition_index=0,
                    run_id=f"{run_id_prefix}-{case_id}",
                    run_digest=_run_digest(arm_id, case_id),
                )
                for case_id in case_ids
            ),
        )

    return dependency("baseline_evidence"), dependency("counterfactual_evidence")


def _subject() -> EvidenceGraphSubjectPayload:
    return EvidenceGraphSubjectPayload(
        subject_type="run_set",
        subject_id="counterfactual_evidence-runset",
        subject_digest="9" * 64,
    )


def _evidence_payloads(
    graph: AssuranceEvidenceGraph,
) -> dict[EvidenceGraphEvidenceType, EvidenceGraphEvidencePayload]:
    return {
        node.payload.evidence_type: node.payload
        for node in graph.nodes
        if isinstance(node.payload, EvidenceGraphEvidencePayload)
    }


def test_builder_automatically_projects_exact_embedded_sufficiency_dependency() -> None:
    sufficiency, stochastic = _reports()

    automatic = build_evidence_graph(
        subject=_subject(),
        stochastic_evidence_sensitivity=stochastic,
    )
    explicit = build_evidence_graph(
        subject=_subject(),
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
    )

    assert automatic == explicit
    assert automatic.graph_digest == explicit.graph_digest
    payloads = _evidence_payloads(automatic)
    assert set(payloads) == {
        EvidenceGraphEvidenceType.statistical_sufficiency,
        EvidenceGraphEvidenceType.stochastic_evidence_sensitivity,
    }
    sufficiency_payload = payloads[EvidenceGraphEvidenceType.statistical_sufficiency]
    stochastic_payload = payloads[EvidenceGraphEvidenceType.stochastic_evidence_sensitivity]
    assert sufficiency_payload.source_id == sufficiency.report_id
    assert sufficiency_payload.source_digest == sufficiency.report_digest
    assert sufficiency_payload.state is EvidenceState.supported
    assert sufficiency_payload.verdict_bearing
    assert isinstance(
        sufficiency_payload.statistical_sufficiency_projection,
        EvidenceGraphStatisticalSufficiencyProjection,
    )
    sufficiency_projection = sufficiency_payload.statistical_sufficiency_projection
    assert sufficiency_projection.candidate_runset_id == "counterfactual_evidence-runset"
    assert sufficiency_projection.candidate_runset_digest == "9" * 64
    assert sufficiency_projection.candidate_configuration_digest == "c" * 64
    assert (
        sufficiency_projection.baseline_expected_recommendation.value,
        sufficiency_projection.baseline_expected_outcome.value,
        sufficiency_projection.counterfactual_expected_recommendation.value,
        sufficiency_projection.counterfactual_expected_outcome.value,
    ) == ("approve", "approved", "deny", "denied")
    assert sufficiency.analysis is not None
    assert sufficiency_projection.analyzable_clusters == sufficiency.analyzable_clusters
    assert (
        sufficiency_projection.analysis_compared_clusters == sufficiency.analysis.compared_clusters
    )
    assert (
        sufficiency_projection.analysis_responding_clusters
        == sufficiency.analysis.responding_clusters
    )
    assert (
        sufficiency_projection.analysis_p_value_upper_bound
        == sufficiency.analysis.p_value_upper_bound
    )
    assert stochastic_payload.source_id == stochastic.report_id
    assert stochastic_payload.source_digest == stochastic.report_digest
    assert stochastic_payload.state is EvidenceState.supported
    assert stochastic_payload.verdict_bearing
    assert isinstance(
        stochastic_payload.stochastic_evidence_sensitivity_projection,
        EvidenceGraphStochasticSensitivityProjection,
    )
    stochastic_projection = stochastic_payload.stochastic_evidence_sensitivity_projection
    assert stochastic_projection.candidate_runset_id == "counterfactual_evidence-runset"
    assert stochastic_projection.candidate_runset_digest == "9" * 64
    assert stochastic_projection.candidate_configuration_digest == "c" * 64
    assert (
        stochastic_projection.baseline_expected_recommendation.value,
        stochastic_projection.baseline_expected_outcome.value,
        stochastic_projection.counterfactual_expected_recommendation.value,
        stochastic_projection.counterfactual_expected_outcome.value,
    ) == ("approve", "approved", "deny", "denied")
    assert stochastic_projection.sufficiency_report_id == sufficiency.report_id
    assert stochastic_projection.sufficiency_report_digest == sufficiency.report_digest
    assert stochastic_projection.observed_cluster_count == stochastic.observed_cluster_count
    assert (
        stochastic_projection.observed_cluster_response_count
        == stochastic.observed_cluster_response_count
    )
    dependency = tuple(
        edge for edge in automatic.edges if edge.kind is EvidenceGraphEdgeKind.depends_on
    )
    assert len(dependency) == 1
    assert "baseline_recommendation" not in automatic.model_dump_json()


@pytest.mark.parametrize(
    "subject",
    (
        EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="unrelated-runset",
            subject_digest="9" * 64,
        ),
        EvidenceGraphSubjectPayload(
            subject_type="run_set",
            subject_id="counterfactual_evidence-runset",
            subject_digest="f" * 64,
        ),
    ),
)
def test_builder_rejects_unrelated_stochastic_candidate_graph_subject(
    subject: EvidenceGraphSubjectPayload,
) -> None:
    _, stochastic = _reports()

    with pytest.raises(
        ValueError,
        match="graph subject|counterfactual source RunSet",
    ):
        build_evidence_graph(
            subject=subject,
            stochastic_evidence_sensitivity=stochastic,
        )


def test_blocking_stochastic_verdict_still_requires_satisfied_dependency() -> None:
    sufficiency, stochastic = _reports(response_values=(0, 0))
    assert stochastic.verdict_bearing
    graph = build_evidence_graph(
        subject=_subject(),
        stochastic_evidence_sensitivity=stochastic,
    )
    payload = _evidence_payloads(graph)[EvidenceGraphEvidenceType.stochastic_evidence_sensitivity]

    assert payload.state is EvidenceState.violated
    assert (
        len(tuple(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on))
        == 1
    )
    assert sufficiency.population_claim_permitted


def test_nonverdict_deterministic_report_projects_no_dependency() -> None:
    sufficiency, stochastic = _reports(deterministic_fixture=True)
    assert not stochastic.verdict_bearing
    assert stochastic.dependency is None

    graph = build_evidence_graph(
        subject=_subject(),
        stochastic_evidence_sensitivity=stochastic,
    )
    payloads = _evidence_payloads(graph)

    assert not tuple(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on)
    assert (
        payloads[EvidenceGraphEvidenceType.statistical_sufficiency].state
        is EvidenceState.inconclusive
    )
    assert (
        payloads[EvidenceGraphEvidenceType.stochastic_evidence_sensitivity].state
        is EvidenceState.inconclusive
    )


def test_builder_rejects_mismatched_explicit_sufficiency_and_model_copy_tampering() -> None:
    sufficiency, stochastic = _reports()
    other_sufficiency, _ = _reports(response_values=(1, 0))
    assert other_sufficiency.report_digest != sufficiency.report_digest

    with pytest.raises(ValueError, match="does not match.*exact embedded sufficiency"):
        build_evidence_graph(
            subject=_subject(),
            statistical_sufficiency=other_sufficiency,
            stochastic_evidence_sensitivity=stochastic,
        )

    tampered_stochastic = stochastic.model_copy(update={"dependency": None})
    with pytest.raises(ValidationError):
        build_evidence_graph(
            subject=_subject(),
            stochastic_evidence_sensitivity=tampered_stochastic,
        )

    tampered_sufficiency = sufficiency.model_copy(update={"population_claim_permitted": False})
    with pytest.raises(ValidationError):
        build_evidence_graph(
            subject=_subject(),
            statistical_sufficiency=tampered_sufficiency,
        )


def test_standalone_sufficiency_projects_without_fabricating_dependency() -> None:
    sufficiency, _ = _reports()
    graph = build_evidence_graph(
        subject=_subject(),
        statistical_sufficiency=sufficiency,
    )

    payloads = _evidence_payloads(graph)
    assert set(payloads) == {EvidenceGraphEvidenceType.statistical_sufficiency}
    assert not tuple(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on)
