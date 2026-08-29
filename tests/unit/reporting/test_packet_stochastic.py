from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    plan_binary_paired_design,
)
from agent_assure.reporting.packet import (
    build_evidence_packet,
    build_privacy_filtered_evidence_graph,
    load_evaluation_summary_snapshot,
    load_packet_source_file_snapshot,
    load_statistical_sufficiency_report,
    load_statistical_sufficiency_report_snapshot,
    load_stochastic_evidence_sensitivity_report,
    load_stochastic_evidence_sensitivity_report_snapshot,
    packet_artifact_digest_from_snapshot,
    packet_summary_files_binding_error_for_trusted_publication,
    packet_summary_snapshots_binding_error,
    release_artifact_from_source_snapshot,
    release_artifact_from_summary_snapshot,
    render_evidence_packet_markdown,
)
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.graph import EvidenceGraphEdgeKind
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    CaseClusterBinding,
    CouplingDescriptor,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    SensitivityArmBinding,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    StochasticGateEffect,
    StochasticSensitivityState,
)
from tests.stochastic_source_support import (
    build_case_authority_bindings,
    materialize_stochastic_sources,
)

_ArmId = Literal["baseline_evidence", "counterfactual_evidence"]


def test_packet_projects_bound_stochastic_evidence_without_raw_decisions() -> None:
    sufficiency, stochastic, _ = _reports()
    evaluation = _evaluation(sufficiency)
    packet = build_evidence_packet(
        evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        artifact_digests=_artifact_digests(),
    )
    deterministic_only = build_evidence_packet(
        evaluation,
        artifact_digests=(_evaluation_digest(),),
    )

    assert packet.statistical_sufficiency == sufficiency
    assert packet.stochastic_evidence_sensitivity == stochastic
    assert packet.packet_id != deterministic_only.packet_id
    assert tuple(item.arm_id for item in sufficiency.source_runsets) == (
        "baseline_evidence",
        "counterfactual_evidence",
    )
    assert sufficiency.analyzable_clusters == 2
    assert stochastic.observed_cluster_count == 2
    assert stochastic.observed_cluster_response_count == 2

    graph = build_privacy_filtered_evidence_graph(
        evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        limitations=packet.limitations,
    )
    dependency_edges = tuple(
        edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on
    )
    assert len(dependency_edges) == 1

    markdown = render_evidence_packet_markdown(packet)
    assert "## Stochastic Evidence Sensitivity" in markdown
    assert "Sufficiency state: `satisfied`" in markdown
    assert "Gate effect: `pass`" in markdown
    assert "Estimated independent-cluster response rate: `1.000000`" in markdown
    assert sufficiency.report_digest in markdown
    assert stochastic.report_digest in markdown
    assert "baseline_recommendation" not in markdown
    assert "counterfactual_recommendation" not in markdown


def test_packet_requires_atomic_reports_exact_digests_and_exact_dependency() -> None:
    sufficiency, stochastic, _ = _reports()
    evaluation = _evaluation(sufficiency)

    with pytest.raises(ValidationError, match="must be present together"):
        build_evidence_packet(
            evaluation,
            statistical_sufficiency=sufficiency,
            artifact_digests=(
                _evaluation_digest(),
                PacketArtifactDigest(
                    role="statistical-sufficiency-report",
                    sha256="b" * 64,
                ),
            ),
        )

    with pytest.raises(ValidationError, match="statistical-sufficiency-report digest"):
        build_evidence_packet(
            evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            artifact_digests=(
                _evaluation_digest(),
                PacketArtifactDigest(
                    role="stochastic-evidence-sensitivity-report",
                    sha256="c" * 64,
                ),
            ),
        )

    other_sufficiency, _, _ = _reports(response_values=(1, 0))
    with pytest.raises(ValidationError, match="exact packet statistical sufficiency"):
        build_evidence_packet(
            evaluation,
            statistical_sufficiency=other_sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            artifact_digests=_artifact_digests(),
        )

    assert stochastic.dependency is not None
    tampered_dependency = stochastic.dependency.model_copy(update={"target_digest": "f" * 64})
    tampered_stochastic = _tampered_stochastic_report(
        stochastic, update={"dependency": tampered_dependency}
    )
    with pytest.raises(ValidationError, match="dependency"):
        build_evidence_packet(
            evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=tampered_stochastic,
            artifact_digests=_artifact_digests(),
        )

    legacy_evaluation = evaluation.model_copy(update={"schema_version": "0.6.4"})
    with pytest.raises(ValidationError, match="evaluation.schema_version '0.6.5'"):
        build_evidence_packet(
            legacy_evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            artifact_digests=_artifact_digests(),
        )


@pytest.mark.parametrize(
    ("field_name", "unrelated_value"),
    (
        ("runset_id", "unrelated-candidate-runset"),
        ("runset_digest", "f" * 64),
    ),
)
def test_packet_rejects_stochastic_evidence_for_an_unrelated_evaluation_subject(
    field_name: str,
    unrelated_value: str,
) -> None:
    sufficiency, stochastic, _ = _reports()
    unrelated_evaluation = _evaluation(sufficiency).model_copy(update={field_name: unrelated_value})

    with pytest.raises(
        ValidationError,
        match="counterfactual source RunSet id and digest.*packet evaluation subject",
    ):
        build_evidence_packet(
            unrelated_evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            artifact_digests=_artifact_digests(),
        )


def test_packet_rejects_stochastic_source_configuration_not_bound_to_protocol() -> None:
    sufficiency, stochastic, _ = _reports()
    baseline, candidate = sufficiency.source_runsets
    unrelated_candidate = candidate.model_copy(update={"execution_configuration_digest": "f" * 64})
    unrelated_sufficiency = _tampered_sufficiency_report(
        sufficiency,
        update={"source_runsets": (baseline, unrelated_candidate)},
    )
    unrelated_stochastic = _tampered_stochastic_report(
        stochastic,
        update={"sufficiency_report": unrelated_sufficiency},
    )

    with pytest.raises(
        ValidationError,
        match="source_runsets|execution configurations",
    ):
        build_evidence_packet(
            _evaluation(sufficiency),
            statistical_sufficiency=unrelated_sufficiency,
            stochastic_evidence_sensitivity=unrelated_stochastic,
            artifact_digests=_artifact_digests(),
        )


def test_packet_binds_stochastic_sources_to_both_comparison_subjects() -> None:
    sufficiency, stochastic, _ = _reports()
    baseline_source, candidate_source = sufficiency.source_runsets
    comparison = ComparisonSummary(
        baseline_runset_id=baseline_source.runset_id,
        baseline_runset_digest=baseline_source.runset_digest,
        candidate_runset_id=candidate_source.runset_id,
        candidate_runset_digest=candidate_source.runset_digest,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
    )
    comparison_digest = PacketArtifactDigest(
        role="comparison-summary",
        sha256="d" * 64,
    )

    packet = build_evidence_packet(
        _evaluation(sufficiency),
        comparison=comparison,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        artifact_digests=(*_artifact_digests(), comparison_digest),
    )
    assert packet.comparison == comparison

    unrelated_baseline = comparison.model_copy(update={"baseline_runset_id": "unrelated-baseline"})
    with pytest.raises(
        ValidationError,
        match="source RunSet identities and digests.*comparison baseline and candidate",
    ):
        build_evidence_packet(
            _evaluation(sufficiency),
            comparison=unrelated_baseline,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            artifact_digests=(*_artifact_digests(), comparison_digest),
        )


def test_packet_json_schema_enforces_atomic_stochastic_artifact_group() -> None:
    sufficiency, stochastic, _ = _reports()
    packet = build_evidence_packet(
        _evaluation(sufficiency),
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        artifact_digests=_artifact_digests(),
    )
    validator = Draft202012Validator(EvidencePacket.model_json_schema(mode="validation"))
    payload = packet.model_dump(mode="json")
    validator.validate(payload)

    partial_payload = json.loads(json.dumps(payload))
    partial_payload.pop("stochastic_evidence_sensitivity")
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(partial_payload)

    missing_digest_payload = json.loads(json.dumps(payload))
    missing_digest_payload["artifact_digests"] = [
        item
        for item in missing_digest_payload["artifact_digests"]
        if item["role"] != "statistical-sufficiency-report"
    ]
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(missing_digest_payload)

    deterministic_packet = build_evidence_packet(
        _evaluation(),
        artifact_digests=(_evaluation_digest(),),
    ).model_dump(mode="json")
    deterministic_packet["artifact_digests"].append(
        PacketArtifactDigest(
            role="stochastic-evidence-sensitivity-report",
            sha256="c" * 64,
        ).model_dump(mode="json")
    )
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(deterministic_packet)


def test_underpowered_packet_remains_nonverdict() -> None:
    sufficiency, stochastic, _ = _reports(underpowered=True)
    assert sufficiency.state.value == "inconclusive"
    assert stochastic.state.value == "inconclusive"
    assert stochastic.gate_effect.value == "non_verdict"
    assert not stochastic.verdict_bearing
    assert stochastic.dependency is None

    packet = build_evidence_packet(
        _evaluation(sufficiency),
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        artifact_digests=_artifact_digests(),
    )
    graph = build_privacy_filtered_evidence_graph(
        packet.evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        limitations=packet.limitations,
    )
    assert not tuple(edge for edge in graph.edges if edge.kind is EvidenceGraphEdgeKind.depends_on)
    assert "Gate effect: `non_verdict`" in render_evidence_packet_markdown(packet)

    false_pass = _tampered_stochastic_report(
        stochastic,
        update={
            "state": StochasticSensitivityState.pass_,
            "gate_effect": StochasticGateEffect.pass_,
            "verdict_bearing": True,
        },
    )
    with pytest.raises(ValidationError, match="state|dependency|non-verdict"):
        build_evidence_packet(
            packet.evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=false_pass,
            artifact_digests=_artifact_digests(),
        )


def test_stochastic_summary_snapshots_bind_exact_files(tmp_path: Path) -> None:
    sufficiency, stochastic, sources = _reports()
    evaluation = _evaluation(sufficiency)
    evaluation_path = tmp_path / "evaluation.json"
    sufficiency_path = tmp_path / "sufficiency.json"
    stochastic_path = tmp_path / "stochastic.json"
    baseline_path = tmp_path / "baseline.source.runset.json"
    counterfactual_path = tmp_path / "counterfactual.source.runset.json"
    _write_json(evaluation_path, evaluation.model_dump(mode="json"))
    _write_json(sufficiency_path, sufficiency.model_dump(mode="json"))
    _write_json(stochastic_path, stochastic.model_dump(mode="json"))
    _write_json(baseline_path, sources[0].model_dump(mode="json"))
    _write_json(counterfactual_path, sources[1].model_dump(mode="json"))

    evaluation_snapshot = load_evaluation_summary_snapshot(
        evaluation_path,
        root=tmp_path,
        artifact_root=tmp_path,
    )
    sufficiency_snapshot = load_statistical_sufficiency_report_snapshot(
        sufficiency_path,
        root=tmp_path,
        artifact_root=tmp_path,
    )
    stochastic_snapshot = load_stochastic_evidence_sensitivity_report_snapshot(
        stochastic_path,
        root=tmp_path,
        artifact_root=tmp_path,
    )
    baseline_snapshot = load_packet_source_file_snapshot(
        baseline_path,
        root=tmp_path,
        artifact_root=tmp_path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="stochastic baseline source RunSet",
    )
    counterfactual_snapshot = load_packet_source_file_snapshot(
        counterfactual_path,
        root=tmp_path,
        artifact_root=tmp_path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="stochastic counterfactual source RunSet",
    )
    assert load_statistical_sufficiency_report(sufficiency_path) == sufficiency
    assert load_stochastic_evidence_sensitivity_report(stochastic_path) == stochastic

    release_artifacts = (
        release_artifact_from_summary_snapshot(
            "evaluation-summary",
            evaluation_snapshot,
        ),
        release_artifact_from_summary_snapshot(
            "statistical-sufficiency-report",
            sufficiency_snapshot,
        ),
        release_artifact_from_summary_snapshot(
            "stochastic-evidence-sensitivity-report",
            stochastic_snapshot,
        ),
        release_artifact_from_source_snapshot(
            "stochastic-baseline-source-runset",
            baseline_snapshot,
        ),
        release_artifact_from_source_snapshot(
            "stochastic-counterfactual-source-runset",
            counterfactual_snapshot,
        ),
    )
    packet = build_evidence_packet(
        evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        release_manifest=ReleaseArtifactManifest(
            manifest_id="stochastic-packet-snapshots",
            artifacts=release_artifacts,
            environment=EnvironmentInfo(platform="test", python_version="3.12"),
        ),
        artifact_digests=(
            packet_artifact_digest_from_snapshot(
                "evaluation-summary",
                evaluation_snapshot,
            ),
            packet_artifact_digest_from_snapshot(
                "statistical-sufficiency-report",
                sufficiency_snapshot,
            ),
            packet_artifact_digest_from_snapshot(
                "stochastic-evidence-sensitivity-report",
                stochastic_snapshot,
            ),
            PacketArtifactDigest(
                role="stochastic-baseline-source-runset",
                sha256=baseline_snapshot.contents.sha256,
            ),
            PacketArtifactDigest(
                role="stochastic-counterfactual-source-runset",
                sha256=counterfactual_snapshot.contents.sha256,
            ),
        ),
    )
    snapshots = {
        evaluation_snapshot.relative_path: evaluation_snapshot.contents,
        sufficiency_snapshot.relative_path: sufficiency_snapshot.contents,
        stochastic_snapshot.relative_path: stochastic_snapshot.contents,
        baseline_snapshot.relative_path: baseline_snapshot.contents,
        counterfactual_snapshot.relative_path: counterfactual_snapshot.contents,
    }
    assert (
        packet_summary_snapshots_binding_error(
            packet,
            snapshots_by_path=snapshots,
        )
        is None
    )
    expected_graph = build_privacy_filtered_evidence_graph(
        evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        limitations=packet.limitations,
    )
    assert (
        packet_summary_files_binding_error_for_trusted_publication(
            packet,
            artifact_root=tmp_path,
            expected_graph=expected_graph,
            captured_snapshots_by_path={
                baseline_snapshot.relative_path: baseline_snapshot.contents,
                counterfactual_snapshot.relative_path: counterfactual_snapshot.contents,
            },
        )
        is None
    )

    tampered_snapshots = {
        **snapshots,
        stochastic_snapshot.relative_path: sufficiency_snapshot.contents,
    }
    assert packet_summary_snapshots_binding_error(
        packet,
        snapshots_by_path=tampered_snapshots,
    ) == (
        "evidence packet stochastic-evidence-sensitivity-report source file digest "
        "does not match release manifest"
    )

    missing_source_snapshots = {
        path: contents
        for path, contents in snapshots.items()
        if path != baseline_snapshot.relative_path
    }
    assert (
        packet_summary_snapshots_binding_error(
            packet,
            snapshots_by_path=missing_source_snapshots,
        )
        == "evidence packet stochastic-baseline-source-runset source snapshot is missing"
    )

    unmanifested_snapshots = {
        **snapshots,
        "unmanifested.runset.json": baseline_snapshot.contents,
    }
    assert (
        packet_summary_snapshots_binding_error(
            packet,
            snapshots_by_path=unmanifested_snapshots,
        )
        == "evidence packet artifact snapshots contain unmanifested paths"
    )

    summary_release_artifacts = release_artifacts[:3]
    swapped_release_artifacts = (
        *summary_release_artifacts,
        ReleaseArtifact(
            role="stochastic-baseline-source-runset",
            path=counterfactual_snapshot.relative_path,
            sha256=counterfactual_snapshot.contents.sha256,
        ),
        ReleaseArtifact(
            role="stochastic-counterfactual-source-runset",
            path=baseline_snapshot.relative_path,
            sha256=baseline_snapshot.contents.sha256,
        ),
    )
    swapped_packet = build_evidence_packet(
        evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        release_manifest=ReleaseArtifactManifest(
            manifest_id="stochastic-packet-swapped-sources",
            artifacts=swapped_release_artifacts,
            environment=EnvironmentInfo(platform="test", python_version="3.12"),
        ),
        artifact_digests=tuple(
            PacketArtifactDigest(role=artifact.role, sha256=artifact.sha256)
            for artifact in swapped_release_artifacts
        ),
    )
    assert (
        packet_summary_snapshots_binding_error(
            swapped_packet,
            snapshots_by_path=snapshots,
        )
        == "stochastic source RunSets could not be safely revalidated"
    )

    with pytest.raises(
        ValidationError,
        match="release manifest.*stochastic-baseline-source-runset",
    ):
        build_evidence_packet(
            evaluation,
            statistical_sufficiency=sufficiency,
            stochastic_evidence_sensitivity=stochastic,
            release_manifest=ReleaseArtifactManifest(
                manifest_id="stochastic-packet-missing-source-role",
                artifacts=tuple(
                    artifact
                    for artifact in release_artifacts
                    if artifact.role != "stochastic-baseline-source-runset"
                ),
                environment=EnvironmentInfo(platform="test", python_version="3.12"),
            ),
            artifact_digests=packet.artifact_digests,
        )


def _evaluation(
    sufficiency: StatisticalSufficiencyReport | None = None,
) -> EvaluationSummary:
    candidate = sufficiency.source_runsets[1] if sufficiency is not None else None
    return EvaluationSummary(
        runset_id=(candidate.runset_id if candidate is not None else "deterministic-runset"),
        runset_digest=(candidate.runset_digest if candidate is not None else "9" * 64),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
    )


def _reports(
    *,
    response_values: tuple[Literal[0, 1], Literal[0, 1]] = (1, 1),
    underpowered: bool = False,
) -> tuple[
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    tuple[RunSet, RunSet],
]:
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
        protocol_id="stochastic-packet-protocol",
        interpretation="confirmatory",
        execution_mode="stochastic_live",
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
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            intentionally_different=("governing_corpus_digest",),
            not_shared=(
                "provider_sampling_randomness",
                "temporal_execution_order",
            ),
            classification="nominally_paired",
        ),
        design=design,
        limitations=("Synthetic stochastic packet fixture.",),
    )
    observations = tuple(
        PairedSensitivityObservation(
            case_id=case_id,
            repetition_index=0,
            cluster_id=case_id,
            disposition=(
                PairDisposition.missing_counterfactual
                if underpowered and index == 1
                else PairDisposition.included
            ),
            disposition_reason=(
                "counterfactual-pair-missing" if underpowered and index == 1 else None
            ),
            baseline_run_id=f"baseline-{case_id}",
            baseline_run_digest="0" * 64,
            counterfactual_run_id=(
                None if underpowered and index == 1 else f"counterfactual-{case_id}"
            ),
            counterfactual_run_digest=(None if underpowered and index == 1 else "0" * 64),
            baseline_recommendation=(None if underpowered and index == 1 else "approve"),
            baseline_outcome=None if underpowered and index == 1 else "approved",
            counterfactual_recommendation=(
                None if underpowered and index == 1 else "deny" if endpoint_value else "approve"
            ),
            counterfactual_outcome=(
                None if underpowered and index == 1 else "denied" if endpoint_value else "approved"
            ),
            baseline_expected_recommendation=(None if underpowered and index == 1 else "approve"),
            baseline_expected_outcome=(None if underpowered and index == 1 else "approved"),
            counterfactual_expected_recommendation=(
                None if underpowered and index == 1 else "deny"
            ),
            counterfactual_expected_outcome=(None if underpowered and index == 1 else "denied"),
            endpoint_value=(None if underpowered and index == 1 else endpoint_value),
        )
        for index, (case_id, endpoint_value) in enumerate(
            zip(case_ids, response_values, strict=True)
        )
    )
    observations, dependencies, sources = materialize_stochastic_sources(
        protocol,
        observations,
    )
    sufficiency = evaluate_statistical_sufficiency(
        protocol,
        observations,
        source_runsets=dependencies,
    )
    return sufficiency, build_stochastic_sensitivity_report(sufficiency), sources


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


def _evaluation_digest() -> PacketArtifactDigest:
    return PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64)


def _artifact_digests() -> tuple[PacketArtifactDigest, ...]:
    return (
        _evaluation_digest(),
        PacketArtifactDigest(
            role="statistical-sufficiency-report",
            sha256="b" * 64,
        ),
        PacketArtifactDigest(
            role="stochastic-evidence-sensitivity-report",
            sha256="c" * 64,
        ),
        PacketArtifactDigest(
            role="stochastic-baseline-source-runset",
            sha256="e" * 64,
        ),
        PacketArtifactDigest(
            role="stochastic-counterfactual-source-runset",
            sha256="f" * 64,
        ),
    )


def _tampered_stochastic_report(
    report: StochasticEvidenceSensitivityReport,
    *,
    update: dict[str, object],
) -> StochasticEvidenceSensitivityReport:
    tampered = report.model_copy(update=update)
    digest = sha256_hexdigest(tampered.model_dump(mode="json", exclude={"report_digest"}))
    return tampered.model_copy(update={"report_digest": digest})


def _tampered_sufficiency_report(
    report: StatisticalSufficiencyReport,
    *,
    update: dict[str, object],
) -> StatisticalSufficiencyReport:
    tampered = report.model_copy(update=update)
    digest = sha256_hexdigest(tampered.model_dump(mode="json", exclude={"report_digest"}))
    return tampered.model_copy(update={"report_digest": digest})


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
