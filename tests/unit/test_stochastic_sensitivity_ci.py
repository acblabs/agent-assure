from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Literal

import pytest
from click import unstyle
from typer.testing import CliRunner

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.ci import GateOutcome, gate_artifact, gate_evidence_packet
from agent_assure.cli.main import app
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.rag.repeated_sensitivity import build_paired_runset_dependencies
from agent_assure.rag.sensitivity_statistics import (
    build_stochastic_sensitivity_report,
    evaluate_statistical_sufficiency,
    plan_binary_paired_design,
)
from agent_assure.reporting.packet import build_evidence_packet
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    ArtifactDependency,
    CaseClusterBinding,
    CouplingClassification,
    CouplingDescriptor,
    PairDisposition,
    PairedSensitivityObservation,
    RepeatedEvidenceSensitivityProtocol,
    RunRecordArtifactDependency,
    SensitivityArmBinding,
    StatisticalSufficiencyReport,
    StochasticEvidenceSensitivityReport,
    StochasticGateEffect,
)
from tests.stochastic_source_support import (
    build_case_authority_bindings,
    materialize_stochastic_sources,
)

_ArmId = Literal["baseline_evidence", "counterfactual_evidence"]
_EndpointValue = Literal[0, 1]
_ReportMode = Literal["pass", "block", "inconclusive", "prerequisites_unmet"]
RUNNER = CliRunner()
REQUIRE_FLAG = "--require-stochastic-evidence-sensitivity"


@pytest.mark.parametrize(
    (
        "mode",
        "state",
        "gate_effect",
        "default_outcome",
        "default_exit_code",
        "required_outcome",
        "required_exit_code",
    ),
    (
        ("pass", "pass", "pass", GateOutcome.pass_, 0, GateOutcome.pass_, 0),
        ("block", "block", "block", GateOutcome.fail, 1, GateOutcome.fail, 1),
        (
            "inconclusive",
            "inconclusive",
            "non_verdict",
            GateOutcome.invalid,
            2,
            GateOutcome.fail,
            1,
        ),
        (
            "prerequisites_unmet",
            "prerequisites_unmet",
            "non_verdict",
            GateOutcome.invalid,
            2,
            GateOutcome.fail,
            1,
        ),
    ),
)
def test_stochastic_packet_gate_fails_closed_on_present_nonverdict_evidence(
    mode: _ReportMode,
    state: str,
    gate_effect: str,
    default_outcome: GateOutcome,
    default_exit_code: int,
    required_outcome: GateOutcome,
    required_exit_code: int,
) -> None:
    packet, source_runsets = _packet_fixture(mode)

    default = gate_evidence_packet(
        packet,
        stochastic_source_runsets=source_runsets,
    )
    required = gate_evidence_packet(
        packet,
        stochastic_source_runsets=source_runsets,
        require_stochastic_evidence_sensitivity=True,
    )

    assert default.outcome is default_outcome
    assert default.exit_code == default_exit_code
    assert required.outcome is required_outcome
    assert required.exit_code == required_exit_code
    if required_outcome is GateOutcome.pass_:
        assert required.reason_code is None
        assert "stochastic_evidence_sensitivity=required" in required.message
        assert "state=pass gate_effect=pass" in required.message
    else:
        assert required.reason_code is ReasonCode.POLICY_FAILED
    if required_outcome is not GateOutcome.pass_:
        assert f"state={state} gate_effect={gate_effect}" in required.message
    if gate_effect == "non_verdict":
        allowed = gate_evidence_packet(
            packet,
            stochastic_source_runsets=source_runsets,
            allow_sensitivity_non_verdict=True,
        )
        strict_default = gate_evidence_packet(
            packet,
            stochastic_source_runsets=source_runsets,
            fail_on_not_evaluated=True,
        )
        assert allowed.outcome is GateOutcome.not_evaluated
        assert allowed.exit_code == 0
        assert "state=" + state in allowed.message
        assert "--allow-sensitivity-non-verdict" in default.message
        assert strict_default.outcome is GateOutcome.fail
        assert strict_default.exit_code == 1
        assert "accepts only a verdict-bearing pass" in required.message
        assert REQUIRE_FLAG in required.message


def test_required_stochastic_evidence_rejects_absence_and_nonpacket_use() -> None:
    evaluation = _evaluation()
    packet = build_evidence_packet(
        evaluation,
        artifact_digests=(_evaluation_digest(),),
    )

    assert gate_evidence_packet(packet).outcome is GateOutcome.pass_
    missing = gate_evidence_packet(
        packet,
        require_stochastic_evidence_sensitivity=True,
    )
    nonpacket = gate_artifact(
        evaluation,
        require_stochastic_evidence_sensitivity=True,
    )

    assert missing.outcome is GateOutcome.invalid
    assert missing.exit_code == 2
    assert REQUIRE_FLAG in missing.message
    assert nonpacket.outcome is GateOutcome.invalid
    assert nonpacket.exit_code == 2
    assert "require an evidence packet" in nonpacket.message


def test_stochastic_packet_gate_requires_and_recomputes_exact_source_runsets() -> None:
    packet, source_runsets = _packet_fixture("pass")

    missing = gate_evidence_packet(packet)
    generic_missing = gate_artifact(packet)
    exact = gate_evidence_packet(
        packet,
        stochastic_source_runsets=source_runsets,
    )
    generic_exact = gate_artifact(
        packet,
        stochastic_source_runsets=source_runsets,
    )
    swapped = gate_evidence_packet(
        packet,
        stochastic_source_runsets=(source_runsets[1], source_runsets[0]),
    )
    candidate_payload = source_runsets[1].model_dump(mode="json")
    candidate_payload["runs"][0]["output_summary"] = "privacy-safe tampered decision"
    tampered_candidate = RunSet.model_validate(candidate_payload)
    tampered = gate_evidence_packet(
        packet,
        stochastic_source_runsets=(source_runsets[0], tampered_candidate),
    )
    one_arm = gate_evidence_packet(
        packet,
        stochastic_source_runsets=(source_runsets[0],),  # type: ignore[arg-type]
    )

    assert missing.outcome is GateOutcome.invalid
    assert generic_missing.outcome is GateOutcome.invalid
    assert generic_missing.exit_code == 2
    assert "requires either a confined release-manifest artifact root" in missing.message
    assert exact.outcome is GateOutcome.pass_
    assert generic_exact == exact
    assert swapped.outcome is GateOutcome.invalid
    assert "could not be safely revalidated" in swapped.message
    assert tampered.outcome is GateOutcome.invalid
    assert "do not exactly match" in tampered.message
    assert one_arm.outcome is GateOutcome.invalid
    assert "exact baseline and counterfactual RunSets" in one_arm.message

    unexpected_sources = gate_artifact(
        _evaluation(),
        stochastic_source_runsets=source_runsets,
    )
    assert unexpected_sources.outcome is GateOutcome.invalid
    assert "only valid for an evidence packet" in unexpected_sources.message


def test_forged_record_membership_cannot_pass_against_exact_source_runsets() -> None:
    packet, source_runsets = _packet_fixture("pass")
    sufficiency = packet.statistical_sufficiency
    stochastic = packet.stochastic_evidence_sensitivity
    assert sufficiency is not None
    assert stochastic is not None
    baseline_dependency, candidate_dependency = sufficiency.source_runsets
    forged_records = tuple(
        RunRecordArtifactDependency(
            case_id=record.case_id,
            repetition_index=record.repetition_index,
            run_id=f"forged-{record.case_id}",
            run_digest=sha256_hexdigest(f"forged-{record.case_id}"),
        )
        for record in candidate_dependency.records
    )
    forged_by_cell = {
        (record.case_id, record.repetition_index): record for record in forged_records
    }
    forged_observations = tuple(
        observation.model_copy(
            update={
                "counterfactual_run_id": forged_by_cell[
                    (observation.case_id, observation.repetition_index)
                ].run_id,
                "counterfactual_run_digest": forged_by_cell[
                    (observation.case_id, observation.repetition_index)
                ].run_digest,
            }
        )
        for observation in sufficiency.observations
    )
    forged_dependency = candidate_dependency.model_copy(update={"records": forged_records})
    forged_sufficiency = _tampered_sufficiency_report(
        sufficiency,
        update={
            "observations": forged_observations,
            "source_runsets": (baseline_dependency, forged_dependency),
        },
    )
    forged_stochastic = _tampered_stochastic_report(
        stochastic,
        update={
            "sufficiency_report": forged_sufficiency,
            "dependency": ArtifactDependency(
                target_artifact_id=forged_sufficiency.report_id,
                target_digest=forged_sufficiency.report_digest,
            ),
        },
    )
    forged_packet = build_evidence_packet(
        packet.evaluation,
        statistical_sufficiency=forged_sufficiency,
        stochastic_evidence_sensitivity=forged_stochastic,
        artifact_digests=packet.artifact_digests,
    )

    decision = gate_evidence_packet(
        forged_packet,
        stochastic_source_runsets=source_runsets,
    )

    assert forged_packet.stochastic_evidence_sensitivity is not None
    assert forged_packet.stochastic_evidence_sensitivity.state.value == "pass"
    assert decision.outcome is GateOutcome.invalid
    assert "RunSet and record digests do not exactly match" in decision.message


def test_forged_observation_semantics_fail_for_explicit_and_persisted_sources(
    tmp_path: Path,
) -> None:
    forged_packet, source_runsets = _semantic_mismatch_fixture()

    explicit = gate_evidence_packet(
        forged_packet,
        stochastic_source_runsets=source_runsets,
    )
    _, persisted_packet = _write_packet_fixture_bundle(
        tmp_path,
        forged_packet,
        source_runsets,
        packet_name="semantic-mismatch.packet.json",
    )
    persisted = gate_evidence_packet(
        persisted_packet,
        artifact_root=tmp_path,
    )

    assert forged_packet.stochastic_evidence_sensitivity is not None
    assert forged_packet.stochastic_evidence_sensitivity.state.value == "pass"
    assert explicit.outcome is GateOutcome.invalid
    assert persisted.outcome is GateOutcome.invalid
    assert "observations do not exactly reassemble" in explicit.message
    assert "observations do not exactly reassemble" in persisted.message


@pytest.mark.parametrize(
    ("mode", "default_exit_code", "required_exit_code"),
    (
        ("pass", 0, 0),
        ("block", 1, 1),
        ("inconclusive", 2, 1),
        ("prerequisites_unmet", 2, 1),
    ),
)
def test_ci_gate_flag_enforces_stochastic_pass(
    tmp_path: Path,
    mode: _ReportMode,
    default_exit_code: int,
    required_exit_code: int,
) -> None:
    packet_path = _write_packet_bundle(tmp_path, mode)

    default = RUNNER.invoke(app, ["ci", "gate", str(packet_path)])
    required = RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path), REQUIRE_FLAG],
    )

    assert default.exit_code == default_exit_code, default.output
    assert required.exit_code == required_exit_code, required.output
    if mode in {"inconclusive", "prerequisites_unmet"}:
        allowed = RUNNER.invoke(
            app,
            [
                "ci",
                "gate",
                str(packet_path),
                "--allow-sensitivity-non-verdict",
            ],
        )
        assert allowed.exit_code == 0, allowed.output
        assert f"state={mode} gate_effect=non_verdict" in allowed.output
        assert "--allow-sensitivity-non-verdict" in default.output
        assert f"state={mode}" in required.output


def test_ci_gate_flag_is_rejected_outside_packet_gate(tmp_path: Path) -> None:
    evaluation_path = tmp_path / "evaluation.json"
    _write_json(evaluation_path, _evaluation().model_dump(mode="json"))

    nonpacket_gate = RUNNER.invoke(
        app,
        ["ci", "gate", str(evaluation_path), REQUIRE_FLAG],
    )
    normal_ci = RUNNER.invoke(
        app,
        ["ci", "candidate.json", REQUIRE_FLAG],
    )

    assert nonpacket_gate.exit_code == 2
    assert "require an evidence packet" in nonpacket_gate.output
    assert normal_ci.exit_code == 2
    normal_output = unstyle(normal_ci.output)
    assert f"{REQUIRE_FLAG} is only valid with" in normal_output
    assert "ci gate" in normal_output


def test_default_gate_still_rejects_structurally_tampered_stochastic_report() -> None:
    packet = _packet("pass")
    report = packet.stochastic_evidence_sensitivity
    assert report is not None
    tampered = _tampered_stochastic_report(
        report,
        update={"gate_effect": StochasticGateEffect.block},
    )
    unchecked = packet.model_copy(update={"stochastic_evidence_sensitivity": tampered})

    decision = gate_evidence_packet(unchecked)

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "failed trusted model revalidation" in decision.message


@pytest.mark.parametrize(
    ("field_name", "unrelated_value"),
    (
        ("runset_id", "unrelated-candidate-runset"),
        ("runset_digest", "f" * 64),
    ),
)
def test_required_ci_gate_rejects_model_copy_stochastic_subject_bypass(
    field_name: str,
    unrelated_value: str,
) -> None:
    packet = _packet("pass")
    unrelated_evaluation = packet.evaluation.model_copy(update={field_name: unrelated_value})
    unchecked = packet.model_copy(update={"evaluation": unrelated_evaluation})

    decision = gate_evidence_packet(
        unchecked,
        require_stochastic_evidence_sensitivity=True,
    )

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "failed trusted model revalidation" in decision.message
    assert "counterfactual source RunSet id and digest" in decision.message


def test_required_ci_gate_rejects_model_copy_configuration_bypass() -> None:
    packet = _packet("pass")
    sufficiency = packet.statistical_sufficiency
    stochastic = packet.stochastic_evidence_sensitivity
    assert sufficiency is not None
    assert stochastic is not None
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
    unchecked = packet.model_copy(
        update={
            "statistical_sufficiency": unrelated_sufficiency,
            "stochastic_evidence_sensitivity": unrelated_stochastic,
        }
    )

    decision = gate_evidence_packet(
        unchecked,
        require_stochastic_evidence_sensitivity=True,
    )

    assert decision.outcome is GateOutcome.invalid
    assert decision.exit_code == 2
    assert "failed trusted model revalidation" in decision.message
    assert "source_runsets" in decision.message


def _packet_fixture(mode: _ReportMode) -> tuple[EvidencePacket, tuple[RunSet, RunSet]]:
    sufficiency, stochastic, source_runsets = _reports(mode)
    packet = build_evidence_packet(
        _evaluation(sufficiency),
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        artifact_digests=(
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
                sha256="d" * 64,
            ),
            PacketArtifactDigest(
                role="stochastic-counterfactual-source-runset",
                sha256="e" * 64,
            ),
        ),
    )
    return packet, source_runsets


def _packet(mode: _ReportMode) -> EvidencePacket:
    return _packet_fixture(mode)[0]


def _semantic_mismatch_fixture() -> tuple[EvidencePacket, tuple[RunSet, RunSet]]:
    packet, source_runsets = _packet_fixture("pass")
    sufficiency = packet.statistical_sufficiency
    stochastic = packet.stochastic_evidence_sensitivity
    assert sufficiency is not None
    assert stochastic is not None
    candidate_payload = source_runsets[1].model_dump(mode="json")
    for run in candidate_payload["runs"]:
        run["recommendation"] = "approve"
        run["outcome"] = "approved"
    counterfactual_source = RunSet.model_validate(candidate_payload)
    semantic_sources = (source_runsets[0], counterfactual_source)
    dependencies = build_paired_runset_dependencies(
        sufficiency.protocol,
        *semantic_sources,
    )
    candidate_records = {
        (record.case_id, record.repetition_index): record for record in dependencies[1].records
    }
    claimed_observations = tuple(
        observation.model_copy(
            update={
                "counterfactual_run_id": candidate_records[
                    (observation.case_id, observation.repetition_index)
                ].run_id,
                "counterfactual_run_digest": candidate_records[
                    (observation.case_id, observation.repetition_index)
                ].run_digest,
            }
        )
        for observation in sufficiency.observations
    )
    forged_sufficiency = _tampered_sufficiency_report(
        sufficiency,
        update={
            "source_runsets": dependencies,
            "observations": claimed_observations,
        },
    )
    forged_stochastic = _tampered_stochastic_report(
        stochastic,
        update={
            "sufficiency_report": forged_sufficiency,
            "dependency": ArtifactDependency(
                target_artifact_id=forged_sufficiency.report_id,
                target_digest=forged_sufficiency.report_digest,
            ),
        },
    )
    forged_packet = build_evidence_packet(
        _evaluation(forged_sufficiency),
        statistical_sufficiency=forged_sufficiency,
        stochastic_evidence_sensitivity=forged_stochastic,
        artifact_digests=packet.artifact_digests,
    )
    return forged_packet, semantic_sources


def _write_packet_bundle(root: Path, mode: _ReportMode) -> Path:
    packet, source_runsets = _packet_fixture(mode)
    packet_path, _ = _write_packet_fixture_bundle(
        root,
        packet,
        source_runsets,
        packet_name=f"{mode}.packet.json",
    )
    return packet_path


def _write_packet_fixture_bundle(
    root: Path,
    packet: EvidencePacket,
    source_runsets: tuple[RunSet, RunSet],
    *,
    packet_name: str,
) -> tuple[Path, EvidencePacket]:
    sufficiency = packet.statistical_sufficiency
    stochastic = packet.stochastic_evidence_sensitivity
    assert sufficiency is not None
    assert stochastic is not None
    sources = (
        ("evaluation-summary", root / "evaluation-summary.json", packet.evaluation),
        (
            "statistical-sufficiency-report",
            root / "statistical-sufficiency-report.json",
            sufficiency,
        ),
        (
            "stochastic-evidence-sensitivity-report",
            root / "stochastic-evidence-sensitivity-report.json",
            stochastic,
        ),
        (
            "stochastic-baseline-source-runset",
            root / "baseline.source.runset.json",
            source_runsets[0],
        ),
        (
            "stochastic-counterfactual-source-runset",
            root / "counterfactual.source.runset.json",
            source_runsets[1],
        ),
    )
    for _, path, artifact in sources:
        _write_json(path, artifact.model_dump(mode="json"))
    release_artifacts = tuple(
        ReleaseArtifact(
            role=role,
            path=path.name,
            sha256=sha256(path.read_bytes()).hexdigest(),
        )
        for role, path, _ in sources
    )
    manifest = ReleaseArtifactManifest(
        manifest_id=f"stochastic-ci-{packet.packet_id}",
        artifacts=release_artifacts,
        environment=EnvironmentInfo(platform="test", python_version="3.12"),
    )
    persisted_packet = build_evidence_packet(
        packet.evaluation,
        statistical_sufficiency=sufficiency,
        stochastic_evidence_sensitivity=stochastic,
        release_manifest=manifest,
        artifact_digests=tuple(
            PacketArtifactDigest(role=artifact.role, sha256=artifact.sha256)
            for artifact in release_artifacts
        ),
    )
    packet_path = root / packet_name
    _write_json(packet_path, persisted_packet.model_dump(mode="json"))
    return packet_path, persisted_packet


def _reports(
    mode: _ReportMode,
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
        protocol_id=f"stochastic-ci-{mode}",
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
            classification=CouplingClassification.nominally_paired,
        ),
        design=design,
        limitations=("Synthetic stochastic CI fixture.",),
    )
    observations: list[PairedSensitivityObservation] = []
    endpoint_value: _EndpointValue = 0 if mode == "block" else 1
    for index, case_id in enumerate(case_ids):
        if index == 1 and mode in {"inconclusive", "prerequisites_unmet"}:
            disposition = (
                PairDisposition.missing_counterfactual
                if mode == "inconclusive"
                else PairDisposition.identity_mismatch
            )
            reason = (
                "counterfactual-pair-missing"
                if mode == "inconclusive"
                else "paired-record-identity-mismatch"
            )
            observations.append(
                PairedSensitivityObservation(
                    case_id=case_id,
                    repetition_index=0,
                    cluster_id=case_id,
                    disposition=disposition,
                    disposition_reason=reason,
                    baseline_run_id=f"baseline-{case_id}",
                    baseline_run_digest=_run_digest("baseline_evidence", case_id),
                    counterfactual_run_id=(
                        None if mode == "inconclusive" else f"counterfactual-{case_id}"
                    ),
                    counterfactual_run_digest=(
                        None
                        if mode == "inconclusive"
                        else _run_digest("counterfactual_evidence", case_id)
                    ),
                )
            )
            continue
        observations.append(
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
        )
    observation_tuple = tuple(observations)
    observation_tuple, dependencies, source_runsets = materialize_stochastic_sources(
        protocol,
        observation_tuple,
    )
    sufficiency = evaluate_statistical_sufficiency(
        protocol,
        observation_tuple,
        source_runsets=dependencies,
    )
    return sufficiency, build_stochastic_sensitivity_report(sufficiency), source_runsets


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


def _run_digest(arm_id: _ArmId, case_id: str) -> str:
    return {
        ("baseline_evidence", "case-a"): "4" * 64,
        ("baseline_evidence", "case-b"): "5" * 64,
        ("counterfactual_evidence", "case-a"): "6" * 64,
        ("counterfactual_evidence", "case-b"): "7" * 64,
    }[(arm_id, case_id)]


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


def _evaluation_digest() -> PacketArtifactDigest:
    return PacketArtifactDigest(role="evaluation-summary", sha256="a" * 64)


def _tampered_stochastic_report(
    report: StochasticEvidenceSensitivityReport,
    *,
    update: dict[str, object],
) -> StochasticEvidenceSensitivityReport:
    tampered = report.model_copy(update=update)
    report_digest = sha256_hexdigest(tampered.model_dump(mode="json", exclude={"report_digest"}))
    return tampered.model_copy(update={"report_digest": report_digest})


def _tampered_sufficiency_report(
    report: StatisticalSufficiencyReport,
    *,
    update: dict[str, object],
) -> StatisticalSufficiencyReport:
    tampered = report.model_copy(update=update)
    report_digest = sha256_hexdigest(tampered.model_dump(mode="json", exclude={"report_digest"}))
    return tampered.model_copy(update={"report_digest": report_digest})


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
