from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import agent_assure.ci as ci_module
from agent_assure.ci import (
    GateDecision,
    GateOutcome,
    gate_artifact,
    gate_control_efficacy_decision,
    load_gate_artifact,
)
from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.release_evidence import build_digest_replay, verify_digest_replay
from agent_assure.reporting import packet as packet_reporting
from agent_assure.reporting.efficacy import write_control_efficacy_report
from agent_assure.reporting.packet import (
    build_evidence_packet as _build_evidence_packet,
)
from agent_assure.reporting.packet import (
    load_evidence_packet,
    packet_artifact_digest,
    render_evidence_packet_markdown,
    write_evidence_packet,
)
from agent_assure.schema.base import SCHEMA_VERSION
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyGateReason,
    ControlEfficacyReport,
    ThreatApplicabilityManifest,
)
from agent_assure.schema.environment import EnvironmentInfo, InstalledPackage
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.mutation import GateEffect, MutationResultState
from agent_assure.schema.packet import EvidencePacket, PacketArtifactDigest
from agent_assure.schema.release import ReleaseArtifact, ReleaseArtifactManifest
from agent_assure.schema.usage import UsageSummary
from tests.unit.controls.test_control_efficacy import (
    _DROP_OPERATOR,
    _campaign,
    _manifest,
    _profile,
    _replace_result_state,
)


@pytest.fixture(scope="module")
def required_survivor_report() -> ControlEfficacyReport:
    execution = _campaign()
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.survived,
    )
    return build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=True),
        required_operator_ids=(_DROP_OPERATOR,),
    )


def test_packet_accepts_bound_report_gate_and_digest_and_rejects_mismatch(
    tmp_path: Path,
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report = required_survivor_report
    profile = _profile()
    gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(
        report,
        tmp_path / "efficacy",
        gate_decision=gate,
        gate_profile=profile,
    ).report
    artifact_digest = packet_artifact_digest(
        "control-efficacy-report",
        report_path,
    )
    config_digest = _config_digest(tmp_path)

    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=gate,
        artifact_digests=(artifact_digest, config_digest),
    )

    assert packet.control_efficacy == report
    assert packet.control_efficacy_gate == gate
    assert tuple(item.role for item in packet.artifact_digests) == (
        "evaluation-summary",
        "control-efficacy-report",
        "control-efficacy-onboarding-config",
    )
    assert packet.control_efficacy_gate.report_digest == report.report_digest

    mismatched_gate = ControlEfficacyGateDecision(
        report_digest="f" * 64,
        profile_id=gate.profile_id,
        state=gate.state,
        findings=gate.findings,
    )
    with pytest.raises(ValidationError, match="must exactly match"):
        _build_packet(
            _passing_evaluation(),
            control_efficacy=report,
            control_efficacy_gate_profile=_profile(),
            control_efficacy_gate=mismatched_gate,
            artifact_digests=(artifact_digest, config_digest),
        )

    with pytest.raises(ValidationError, match="exactly one artifact digest"):
        _build_packet(
            _passing_evaluation(),
            control_efficacy=report,
            control_efficacy_gate_profile=_profile(),
            control_efficacy_gate=gate,
            artifact_digests=(),
        )

    with pytest.raises(ValidationError, match="exactly one config artifact digest"):
        _build_packet(
            _passing_evaluation(),
            control_efficacy=report,
            control_efficacy_gate_profile=_profile(),
            control_efficacy_gate=gate,
            artifact_digests=(artifact_digest,),
        )


def test_packet_rejects_same_digest_decision_that_omits_report_findings(
    required_survivor_report: ControlEfficacyReport,
    tmp_path: Path,
) -> None:
    report = required_survivor_report
    profile = _profile()
    report_path = write_control_efficacy_report(
        report,
        tmp_path / "efficacy",
    ).report
    config_digest = _config_digest(tmp_path)
    forged_pass = ControlEfficacyGateDecision(
        report_digest=report.report_digest,
        profile_id=profile.profile_id,
        state=GateState.pass_,
        findings=(),
    )

    with pytest.raises(ValidationError, match="must exactly match"):
        _build_packet(
            _passing_evaluation(),
            control_efficacy=report,
            control_efficacy_gate_profile=profile,
            control_efficacy_gate=forged_pass,
            artifact_digests=(
                packet_artifact_digest("control-efficacy-report", report_path),
                config_digest,
            ),
        )


def test_standalone_advisory_ci_blocks_required_survivor_with_stable_reason(
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report = required_survivor_report

    decision = gate_artifact(report, strict_efficacy=False)

    assert report.catalog_kill_rate.numerator == 6
    assert report.catalog_kill_rate.denominator == 7
    assert decision.exit_code == 1
    assert decision.outcome is GateOutcome.fail
    assert decision.reason_code is ControlEfficacyGateReason.required_operator_survived
    assert decision.artifact_kind == "control-efficacy-report"
    assert "gate_state=fail" in decision.message
    assert "semantic_state=survivor_observed" in decision.message
    assert "required_survivors=1" in decision.message
    assert "critical_survivors=1" in decision.message


def test_standalone_advisory_ci_reviews_unscoped_catalog_references() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )

    decision = gate_artifact(report, strict_efficacy=False)

    assert report.threat_scope_state.value == "unscoped_catalog_references"
    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.review
    assert decision.reason_code is (ControlEfficacyGateReason.unscoped_catalog_threat_reference)
    assert "gate_state=warn" in decision.message
    assert "threat_scope_state=unscoped_catalog_references" in decision.message
    assert "unscoped_catalog_threats=1" in decision.message


def test_packet_uses_embedded_custom_efficacy_decision_to_block(tmp_path: Path) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest_with_unknown(),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = ControlEfficacyGateProfile(
        profile_id="control-efficacy/custom-unknown-block",
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
        unknown_threat_applicability=GateEffect.block,
    )
    custom_gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(
        report,
        tmp_path / "efficacy",
        gate_decision=custom_gate,
        gate_profile=profile,
    ).report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=custom_gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )

    decision = gate_artifact(packet, strict_efficacy=False)

    assert report.required_survivor_count == 0
    assert report.independently_challenged_threat_category_count == 0
    assert custom_gate.state is GateState.fail
    assert decision.exit_code == 1
    assert decision.outcome is GateOutcome.fail
    assert decision.reason_code is (ControlEfficacyGateReason.unknown_threat_applicability)
    assert decision.artifact_kind == "evidence-packet"
    assert packet.packet_id in decision.message
    assert "semantic_state=all_evaluated_applicable_caught" in decision.message


def test_packet_preserves_review_outcome_and_reason(tmp_path: Path) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest_with_unknown(),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = ControlEfficacyGateProfile(
        profile_id="control-efficacy/custom-review",
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
    )
    gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(report, tmp_path / "review").report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )

    decision = gate_artifact(packet, strict_efficacy=False)

    assert gate.state is GateState.warn
    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.review
    assert decision.reason_code is ControlEfficacyGateReason.unknown_threat_applicability
    assert decision.artifact_kind == "evidence-packet"
    assert "ci gate review:" in decision.message
    assert packet.packet_id in decision.message


def test_packet_gate_message_does_not_infer_context_from_display_text() -> None:
    packet = _build_packet(_passing_evaluation())
    controlling_decision = GateDecision(
        exit_code=1,
        outcome=GateOutcome.fail,
        message="ci gate fail: efficacy_evidence=display-only",
    )

    message = ci_module._packet_gate_message(
        packet,
        controlling_decision,
        None,
        efficacy_required=False,
    )

    assert "efficacy_evidence=absent " in message
    assert "efficacy_verification=not_requested " in message
    assert "efficacy_required=false" in message


def test_direct_efficacy_gate_rejects_a_forged_same_digest_decision(
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report = required_survivor_report
    profile = _profile()
    decision = ControlEfficacyGateDecision(
        report_digest=report.report_digest,
        profile_id=profile.profile_id,
        state=GateState.pass_,
        findings=(),
    )

    gate = gate_control_efficacy_decision(report, decision, profile=profile)

    assert gate.exit_code == 2
    assert gate.outcome is GateOutcome.invalid
    assert gate.reason_code is None
    assert "does not exactly match" in gate.message


def test_fail_on_not_evaluated_applies_to_standalone_and_packet_efficacy(
    tmp_path: Path,
) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    manifest = ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "not_applicable",
                "critical": False,
                "rationale": "Synthetic scope exclusion.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "material-claim-link-regression",
                "applicability": "not_applicable",
                "critical": False,
                "rationale": "Synthetic scope exclusion.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = _profile()
    efficacy_gate = evaluate_control_efficacy_gate(report, profile)

    assert report.threat_scope_state.value == "not_evaluated"
    assert gate_artifact(report, strict_efficacy=False).outcome is GateOutcome.pass_
    strict_report_gate = gate_artifact(
        report,
        fail_on_not_evaluated=True,
        strict_efficacy=False,
    )
    assert strict_report_gate.exit_code == 1
    assert strict_report_gate.outcome is GateOutcome.fail
    assert "threat_scope_state" in strict_report_gate.message

    report_path = write_control_efficacy_report(report, tmp_path / "strict").report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=efficacy_gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )
    assert gate_artifact(packet, strict_efficacy=False).outcome is GateOutcome.pass_
    strict_packet_gate = gate_artifact(
        packet,
        fail_on_not_evaluated=True,
        strict_efficacy=False,
    )
    assert strict_packet_gate.exit_code == 1
    assert strict_packet_gate.outcome is GateOutcome.fail
    assert "threat_scope_state" in strict_packet_gate.message


def test_required_not_evaluated_effect_cannot_be_bypassed() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    campaign = _replace_result_state(
        execution.campaign,
        operator_id=_DROP_OPERATOR,
        state=MutationResultState.inapplicable,
    )
    report = build_control_efficacy_report(
        campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    assert report.semantic_state.value == "not_evaluated"
    with pytest.raises(ValidationError, match="block"):
        ControlEfficacyGateProfile(
            required_catalog=report.catalog_id,
            required_operators=report.required_operator_ids,
            unevaluated_required_operator=GateEffect.ignore,
        )

    profile = ControlEfficacyGateProfile(
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
    )
    bypassed_profile = profile.model_copy(
        update={"unevaluated_required_operator": GateEffect.ignore}
    )
    with pytest.raises(ValidationError, match="block"):
        evaluate_control_efficacy_gate(report, bypassed_profile)


def test_packet_pass_preserves_efficacy_semantic_facts(tmp_path: Path) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = ControlEfficacyGateProfile(
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
        unscoped_catalog_threat_reference=GateEffect.ignore,
    )
    efficacy_gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(report, tmp_path / "passing").report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=efficacy_gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )

    decision = gate_artifact(packet, strict_efficacy=False)

    assert efficacy_gate.state is GateState.pass_
    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.pass_
    assert decision.artifact_kind == "evidence-packet"
    assert "ci gate pass: control-efficacy-report" in decision.message
    assert "semantic_state=all_evaluated_applicable_caught" in decision.message
    assert "required_survivors=0" in decision.message
    assert "critical_survivors=0" in decision.message
    assert f"threat_scope_state={report.threat_scope_state.value}" in decision.message
    assert f"unscoped_catalog_threats={report.unscoped_catalog_threat_count}" in decision.message
    assert packet.packet_id in decision.message


def test_packet_evaluation_review_precedes_efficacy_pass(tmp_path: Path) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _manifest(critical=False),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    profile = ControlEfficacyGateProfile(
        required_catalog=report.catalog_id,
        required_operators=report.required_operator_ids,
        unscoped_catalog_threat_reference=GateEffect.ignore,
    )
    efficacy_gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(report, tmp_path / "review-precedence").report
    warning_evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="control-efficacy-warning-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.warn,
        findings=(),
    )
    packet = _build_packet(
        warning_evaluation,
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=efficacy_gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )

    decision = gate_artifact(packet, strict_efficacy=False)

    assert efficacy_gate.state is GateState.pass_
    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.review
    assert decision.artifact_kind == "evidence-packet"
    assert "ci gate review: evaluation-summary" in decision.message
    assert "state=warn" in decision.message
    assert (
        "control-efficacy observation: efficacy_verification=advisory gate_state=pass"
        in decision.message
    )
    assert "semantic_state=all_evaluated_applicable_caught" in decision.message
    assert "required_survivors=0 critical_survivors=0" in decision.message
    assert packet.packet_id in decision.message


@pytest.mark.parametrize(
    "tampered_state",
    (GateState.pass_, GateState.warn, GateState.not_evaluated),
)
def test_nonfailing_evaluation_summary_cannot_hide_fail_findings(
    tampered_state: GateState,
) -> None:
    finding = Finding(
        finding_id="hidden-finding",
        case_id="case-001",
        control_id="required_policy_evaluated",
        target="provider-selection",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        message="required policy was not evaluated",
    )
    payload = _passing_evaluation().model_dump(mode="json")
    payload["state"] = tampered_state.value
    payload["findings"] = [finding.model_dump(mode="json")]

    with pytest.raises(ValidationError, match="contradicts finding-derived state"):
        EvaluationSummary.model_validate(payload)

    unchecked = _passing_evaluation().model_copy(
        update={"state": tampered_state, "findings": (finding,)}
    )
    decision = ci_module.gate_evaluation_summary(unchecked)
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid


def test_evaluation_summary_rejects_pass_finding_even_with_failure() -> None:
    fail_finding = Finding(
        finding_id="fail-finding",
        case_id="case-001",
        control_id="required_policy_evaluated",
        target="provider-selection",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        message="required policy was not evaluated",
    )
    pass_finding = fail_finding.model_copy(
        update={
            "finding_id": "unexpected-pass-finding",
            "control_id": "unexpected-pass-control",
            "state": GateState.pass_,
        }
    )
    payload = _passing_evaluation().model_dump(mode="json")
    payload["state"] = GateState.fail.value
    payload["findings"] = [
        fail_finding.model_dump(mode="json"),
        pass_finding.model_dump(mode="json"),
    ]

    with pytest.raises(ValidationError, match="must not carry pass-state findings"):
        EvaluationSummary.model_validate(payload)

    legacy_payload = {**payload, "schema_version": "0.6.1"}
    legacy_summary = EvaluationSummary.model_validate(legacy_payload)
    assert legacy_summary.schema_version == "0.6.1"
    legacy_decision = ci_module.gate_evaluation_summary(legacy_summary)
    assert legacy_decision.exit_code == 2
    assert legacy_decision.outcome is GateOutcome.invalid

    unchecked = _passing_evaluation().model_copy(
        update={
            "state": GateState.fail,
            "findings": (fail_finding, pass_finding),
        }
    )
    decision = ci_module.gate_evaluation_summary(unchecked)
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid


def test_current_packet_cannot_omit_or_duplicate_summary_digests() -> None:
    with pytest.raises(ValidationError, match="exactly one evaluation-summary digest"):
        _build_evidence_packet(_passing_evaluation())

    packet = _build_packet(_passing_evaluation())
    assert tuple(item.role for item in packet.artifact_digests) == ("evaluation-summary",)
    missing_payload = packet.model_dump(mode="json")
    missing_payload["artifact_digests"] = []
    duplicate_payload = packet.model_dump(mode="json")
    duplicate_payload["artifact_digests"].append(duplicate_payload["artifact_digests"][0])

    with pytest.raises(ValidationError, match="exactly one evaluation-summary digest"):
        EvidencePacket.model_validate(missing_payload)
    with pytest.raises(ValidationError, match="exactly one evaluation-summary digest"):
        EvidencePacket.model_validate(duplicate_payload)

    unchecked = packet.model_copy(update={"artifact_digests": ()})
    decision = ci_module.gate_evidence_packet(unchecked)
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid


def test_current_packet_model_enforces_summary_digest_cardinality() -> None:
    valid_payload = _passing_evaluation_packet_payload()
    missing_evaluation = json.loads(json.dumps(valid_payload))
    missing_evaluation["artifact_digests"] = []
    duplicate_evaluation = json.loads(json.dumps(valid_payload))
    duplicate_evaluation["artifact_digests"].append(duplicate_evaluation["artifact_digests"][0])
    comparison_without_summary = json.loads(json.dumps(valid_payload))
    comparison_digest = {
        "artifact_kind": "packet-artifact-digest",
        "schema_version": SCHEMA_VERSION,
        "role": "comparison-summary",
        "sha256": "2" * 64,
    }
    comparison_without_summary["artifact_digests"].extend((comparison_digest, comparison_digest))

    for payload in (
        missing_evaluation,
        duplicate_evaluation,
        comparison_without_summary,
    ):
        with pytest.raises(ValidationError):
            EvidencePacket.model_validate(payload)


def test_packet_model_binds_exact_summary_digests_to_release_manifest() -> None:
    evaluation = _passing_evaluation()
    comparison = _passing_comparison(evaluation)
    valid_manifest = _summary_release_manifest(comparison=True)

    packet = _build_packet(
        evaluation,
        comparison=comparison,
        release_manifest=valid_manifest,
    )

    assert packet.release_manifest == valid_manifest

    evaluation_artifact, comparison_artifact = valid_manifest.artifacts
    invalid_manifests = (
        (
            valid_manifest.model_copy(update={"artifacts": (comparison_artifact,)}),
            "requires exactly one evaluation-summary artifact",
        ),
        (
            valid_manifest.model_copy(
                update={
                    "artifacts": (
                        *valid_manifest.artifacts,
                        evaluation_artifact.model_copy(update={"path": "evaluation-copy.json"}),
                    )
                }
            ),
            "duplicate artifact role: evaluation-summary",
        ),
        (
            valid_manifest.model_copy(
                update={
                    "artifacts": (
                        evaluation_artifact.model_copy(update={"sha256": "a" * 64}),
                        comparison_artifact,
                    )
                }
            ),
            "evaluation-summary digest must match release manifest",
        ),
        (
            valid_manifest.model_copy(update={"artifacts": (evaluation_artifact,)}),
            "comparison-summary artifact must match nested comparison",
        ),
    )
    for manifest, message in invalid_manifests:
        with pytest.raises(ValidationError, match=message):
            _build_packet(
                evaluation,
                comparison=comparison,
                release_manifest=manifest,
            )

    with pytest.raises(
        ValidationError,
        match="comparison-summary artifact must match nested comparison",
    ):
        _build_packet(evaluation, release_manifest=valid_manifest)


def test_packet_writer_and_ci_reject_unchecked_manifest_digest_mismatch(
    tmp_path: Path,
) -> None:
    evaluation = _passing_evaluation()
    packet = _build_packet(
        evaluation,
        release_manifest=_summary_release_manifest(),
    )
    tampered_digests = tuple(
        item.model_copy(update={"sha256": "a" * 64}) if item.role == "evaluation-summary" else item
        for item in packet.artifact_digests
    )
    unchecked = packet.model_copy(update={"artifact_digests": tampered_digests})
    output = tmp_path / "mismatched-packet.json"

    with pytest.raises(
        ValidationError,
        match="evaluation-summary digest must match release manifest",
    ):
        write_evidence_packet(unchecked, output)

    decision = ci_module.gate_evidence_packet(unchecked)

    assert not output.exists()
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "evaluation-summary digest must match release manifest" in decision.message

    assert packet.release_manifest is not None
    manifest_artifact = packet.release_manifest.artifacts[0]
    duplicate_manifest = packet.release_manifest.model_copy(
        update={
            "artifacts": (
                manifest_artifact,
                manifest_artifact.model_copy(update={"path": "evaluation-copy.json"}),
            )
        }
    )
    duplicate_unchecked = packet.model_copy(update={"release_manifest": duplicate_manifest})

    duplicate_decision = ci_module.gate_evidence_packet(duplicate_unchecked)

    assert duplicate_decision.exit_code == 2
    assert duplicate_decision.outcome is GateOutcome.invalid
    assert "requires exactly one evaluation-summary artifact" in duplicate_decision.message


def test_packet_preserves_not_evaluated_outcome() -> None:
    evaluation = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="control-efficacy-not-evaluated-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.not_evaluated,
        findings=(),
    )
    packet = _build_packet(evaluation)

    decision = gate_artifact(packet)

    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.not_evaluated
    assert decision.artifact_kind == "evidence-packet"
    assert "ci gate not-evaluated: evaluation-summary" in decision.message
    assert packet.packet_id in decision.message


@pytest.mark.parametrize(
    ("outcome", "exit_code"),
    (
        (GateOutcome.pass_, 0),
        (GateOutcome.review, 0),
        (GateOutcome.not_evaluated, 0),
        (GateOutcome.fail, 1),
        (GateOutcome.invalid, 2),
    ),
)
def test_packet_aggregation_routes_explicit_outcomes_without_parsing_messages(
    monkeypatch: pytest.MonkeyPatch,
    outcome: GateOutcome,
    exit_code: int,
) -> None:
    packet = _build_packet(_passing_evaluation())
    component = GateDecision(
        exit_code=exit_code,
        outcome=outcome,
        message="opaque component decision with no routing prefix",
    )
    monkeypatch.setattr(
        ci_module,
        "gate_evaluation_summary",
        lambda *_args, **_kwargs: component,
    )

    decision = ci_module.gate_evidence_packet(packet)

    assert decision.outcome is outcome
    assert decision.exit_code == exit_code
    assert decision.model_dump()["outcome"] == outcome.value
    if outcome is GateOutcome.pass_:
        assert decision.message == (
            f"ci gate pass: evidence-packet {packet.packet_id}; "
            "efficacy_evidence=absent efficacy_verification=not_requested "
            "efficacy_required=false"
        )
    else:
        assert "opaque component decision with no routing prefix" in decision.message
        assert packet.packet_id in decision.message


def test_packet_aggregation_preserves_review_over_not_evaluated_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = _passing_evaluation()
    comparison = ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id=evaluation.runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )
    packet = _build_packet(evaluation, comparison=comparison)
    not_evaluated = GateDecision(
        exit_code=0,
        outcome=GateOutcome.not_evaluated,
        message="opaque evaluation outcome",
    )
    review = GateDecision(
        exit_code=0,
        outcome=GateOutcome.review,
        message="opaque comparison outcome",
    )
    monkeypatch.setattr(
        ci_module,
        "gate_evaluation_summary",
        lambda *_args, **_kwargs: not_evaluated,
    )
    monkeypatch.setattr(
        ci_module,
        "gate_comparison_summary",
        lambda *_args, **_kwargs: review,
    )

    decision = ci_module.gate_evidence_packet(packet)

    assert decision.outcome is GateOutcome.review
    assert decision.exit_code == 0
    assert "opaque comparison outcome" in decision.message


def test_gate_decision_rejects_outcome_exit_code_mismatch() -> None:
    with pytest.raises(ValueError, match="outcome/exit_code mismatch"):
        GateDecision(
            exit_code=0,
            outcome=GateOutcome.fail,
            message="inconsistent",
        )


def test_packet_markdown_renders_actionable_gate_findings_and_survivor_ids(
    tmp_path: Path,
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report = required_survivor_report
    profile = _profile()
    gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(report, tmp_path / "markdown").report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )

    rendered = render_evidence_packet_markdown(packet)

    assert "### Gate Findings" in rendered
    assert "`REQUIRED_OPERATOR_SURVIVED`" in rendered
    assert "effect: `block`" in rendered
    assert f"operator IDs: `{_DROP_OPERATOR}`" in rendered
    assert "- Critical survivors: `1`; operator IDs:" in rendered
    assert (
        f"- Unscoped catalog threats: `{report.unscoped_catalog_threat_count}`; threat IDs:"
    ) in rendered
    assert f"`{report.unscoped_catalog_threat_ids[0]}`" in rendered
    assert "verdict-bearing applicable operators" not in rendered

    for missing_field in ("control_efficacy_gate_profile", "control_efficacy_gate"):
        malformed = packet.model_copy(update={missing_field: None})
        with pytest.raises(ValueError, match="requires a gate profile and decision"):
            render_evidence_packet_markdown(malformed)


def test_packet_markdown_bounds_long_identifier_lists() -> None:
    identifiers = tuple(f"threat-{index:02d}" for index in range(25))

    rendered = packet_reporting._identifier_list(identifiers)

    assert "`threat-00`" in rendered
    assert "`threat-19`" in rendered
    assert "threat-20" not in rendered
    assert "`5` omitted" in rendered


def test_efficacy_packet_json_schemas_reject_partial_members_and_digests(
    tmp_path: Path,
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report = required_survivor_report
    profile = _profile()
    gate = evaluate_control_efficacy_gate(report, profile)
    report_path = write_control_efficacy_report(report, tmp_path / "schema").report
    packet = _build_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=profile,
        control_efficacy_gate=gate,
        artifact_digests=(
            packet_artifact_digest("control-efficacy-report", report_path),
            _config_digest(tmp_path),
        ),
    )
    valid_payload = packet.model_dump(mode="json")
    _assert_json_schemas_accept(valid_payload)
    gate_profile_payload = json.loads(json.dumps(valid_payload))
    gate_profile_digest = next(
        item
        for item in gate_profile_payload["artifact_digests"]
        if item["role"] == "control-efficacy-onboarding-config"
    )
    gate_profile_digest["role"] = "control-efficacy-gate-profile"
    EvidencePacket.model_validate(gate_profile_payload)
    _assert_json_schemas_accept(gate_profile_payload)
    partial_payload = json.loads(json.dumps(valid_payload))
    partial_payload.pop("control_efficacy_gate")
    missing_config_digest = json.loads(json.dumps(valid_payload))
    missing_config_digest["artifact_digests"] = [
        item
        for item in missing_config_digest["artifact_digests"]
        if item["role"] != "control-efficacy-onboarding-config"
    ]
    digest_without_efficacy = _passing_evaluation_packet_payload()
    digest_without_efficacy["artifact_digests"].append(
        {
            "artifact_kind": "packet-artifact-digest",
            "schema_version": SCHEMA_VERSION,
            "role": "control-efficacy-onboarding-config",
            "sha256": "0" * 64,
        }
    )
    legacy_generic_digest = json.loads(json.dumps(valid_payload))
    legacy_config_digest = next(
        item
        for item in legacy_generic_digest["artifact_digests"]
        if item["role"] == "control-efficacy-onboarding-config"
    )
    legacy_config_digest["role"] = "control-efficacy-config"
    duplicate_typed_config_digests = json.loads(json.dumps(valid_payload))
    duplicate_typed_config_digests["artifact_digests"].append(
        {
            **legacy_config_digest,
            "role": "control-efficacy-gate-profile",
        }
    )

    for payload in (
        partial_payload,
        missing_config_digest,
        legacy_generic_digest,
        duplicate_typed_config_digests,
    ):
        with pytest.raises(ValidationError):
            EvidencePacket.model_validate(payload)
        _assert_json_schemas_reject(payload)
    with pytest.raises(
        ValidationError,
        match="control-efficacy config digest requires a nested report and gate profile",
    ):
        EvidencePacket.model_validate(digest_without_efficacy)
    _assert_json_schemas_reject_at(digest_without_efficacy, ("artifact_digests",))


def test_release_replay_recognizes_efficacy_report_and_config(
    tmp_path: Path,
    required_survivor_report: ControlEfficacyReport,
) -> None:
    report_path = write_control_efficacy_report(
        required_survivor_report,
        tmp_path / "release",
    ).report
    config_path = tmp_path / "controls-mutation.yaml"
    config_path.write_text("package_version: 0.6.2\n", encoding="utf-8", newline="\n")
    profile_path = tmp_path / "control-efficacy-gate-profile.json"
    profile_path.write_text("{}\n", encoding="utf-8", newline="\n")
    replay = build_digest_replay(
        (
            ("control-efficacy-report", report_path),
            ("control-efficacy-onboarding-config", config_path),
            ("control-efficacy-gate-profile", profile_path),
        ),
        project_root=tmp_path,
        source_commit="abc123",
    )

    verification = verify_digest_replay(replay, artifact_root=tmp_path)

    assert verification.ok
    assert tuple(item.digest_mode for item in replay.artifacts) == (
        "replay-stable-json-sha256",
        "raw-sha256",
        "raw-sha256",
    )
    with pytest.raises(ValueError, match="unknown release artifact role"):
        build_digest_replay(
            (("control-efficacy-config", config_path),),
            project_root=tmp_path,
            source_commit="abc123",
        )


def test_packet_build_and_writer_reject_mixed_schema_versions_before_output(
    tmp_path: Path,
) -> None:
    legacy_evaluation = _passing_evaluation().model_copy(update={"schema_version": "0.6.1"})

    with pytest.raises(
        ValidationError,
        match="evaluation.schema_version '0.6.3'; received '0.6.1'",
    ):
        _build_packet(legacy_evaluation)

    mixed_packet = _build_packet(_passing_evaluation()).model_copy(
        update={"evaluation": legacy_evaluation}
    )
    output = tmp_path / "not-created" / "evidence-packet.json"
    with pytest.raises(
        ValidationError,
        match="evaluation.schema_version '0.6.3'; received '0.6.1'",
    ):
        write_evidence_packet(mixed_packet, output)

    assert not output.parent.exists()


def test_coherent_v061_packet_remains_loadable_writable_and_gateable(
    tmp_path: Path,
) -> None:
    evaluation = _passing_evaluation().model_copy(
        update={"usage_summary": UsageSummary(total_tokens=1)}
    )
    payload = _build_packet(evaluation).model_dump(
        mode="json",
        exclude_none=True,
    )
    payload["schema_version"] = "0.6.1"
    payload["artifact_digests"] = []
    evaluation_payload = payload["evaluation"]
    assert isinstance(evaluation_payload, dict)
    evaluation_payload["schema_version"] = "0.6.1"
    source = tmp_path / "legacy-evidence-packet.json"
    source.write_text(json.dumps(payload), encoding="utf-8", newline="\n")

    legacy_packet = load_evidence_packet(source)
    output = tmp_path / "round-tripped-evidence-packet.json"
    write_evidence_packet(legacy_packet, output)
    reloaded = load_evidence_packet(output)
    gate = gate_artifact(load_gate_artifact(output))

    assert legacy_packet.schema_version == "0.6.1"
    assert legacy_packet.evaluation.schema_version == "0.6.1"
    assert legacy_packet.usage_summary is not None
    assert legacy_packet.usage_summary.schema_version == "0.4.3"
    assert reloaded == legacy_packet
    assert gate.exit_code == 0
    assert gate.outcome is GateOutcome.pass_


def test_v061_packet_writer_omits_only_efficacy_fields(tmp_path: Path) -> None:
    packet = _build_packet(_passing_evaluation())
    legacy_evaluation = packet.evaluation.model_copy(
        update={"schema_version": "0.6.1"},
    )
    legacy_packet = packet.model_copy(
        update={
            "schema_version": "0.6.1",
            "evaluation": legacy_evaluation,
            "artifact_digests": (),
        }
    )
    output = tmp_path / "legacy-evidence-packet.json"

    write_evidence_packet(legacy_packet, output)

    payload = json.loads(output.read_text(encoding="utf-8"))
    efficacy_fields = {
        "control_efficacy",
        "control_efficacy_gate_profile",
        "control_efficacy_gate",
    }
    assert not efficacy_fields.intersection(payload)
    evaluation_payload = payload["evaluation"]
    assert isinstance(evaluation_payload, dict)
    assert "environment" in evaluation_payload
    assert evaluation_payload["environment"] is None


def test_packet_schema_version_coherence_covers_deep_persisted_children() -> None:
    evaluation = _passing_evaluation().model_copy(
        update={
            "environment": EnvironmentInfo(
                platform="test",
                python_version="3.14",
                installed_packages=(InstalledPackage(name="example", version="1.0"),),
            )
        }
    )
    payload = _build_packet(evaluation).model_dump(mode="json")
    evaluation_payload = payload["evaluation"]
    assert isinstance(evaluation_payload, dict)
    environment_payload = evaluation_payload["environment"]
    assert isinstance(environment_payload, dict)
    installed_packages = environment_payload["installed_packages"]
    assert isinstance(installed_packages, list)
    installed_package = installed_packages[0]
    assert isinstance(installed_package, dict)
    installed_package["schema_version"] = "0.6.1"

    with pytest.raises(
        ValidationError,
        match=r"evaluation\.environment\.installed_packages\[0\]\.schema_version",
    ):
        EvidencePacket.model_validate(payload)


def _build_packet(evaluation: EvaluationSummary, **kwargs: Any) -> EvidencePacket:
    """Build with explicit exact-file digest fixtures for packet-focused tests."""
    comparison = kwargs.get("comparison")
    provided = kwargs.pop("artifact_digests", ())
    summary_digests = [
        PacketArtifactDigest(role="evaluation-summary", sha256="e" * 64),
    ]
    if comparison is not None:
        summary_digests.append(PacketArtifactDigest(role="comparison-summary", sha256="f" * 64))
    return _build_evidence_packet(
        evaluation,
        artifact_digests=(*summary_digests, *provided),
        **kwargs,
    )


def _passing_comparison(evaluation: EvaluationSummary) -> ComparisonSummary:
    return ComparisonSummary(
        baseline_runset_id="baseline",
        candidate_runset_id=evaluation.runset_id,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        classification=ComparisonClassification.unchanged,
        fixture_equivalence_state=GateState.pass_,
        candidate_state=GateState.pass_,
    )


def _summary_release_manifest(*, comparison: bool = False) -> ReleaseArtifactManifest:
    artifacts = [
        ReleaseArtifact(
            role="evaluation-summary",
            path="evaluation-summary.json",
            sha256="e" * 64,
        )
    ]
    if comparison:
        artifacts.append(
            ReleaseArtifact(
                role="comparison-summary",
                path="comparison-summary.json",
                sha256="f" * 64,
            )
        )
    return ReleaseArtifactManifest(
        manifest_id="manifest-summary-digests",
        artifacts=tuple(artifacts),
        environment=EnvironmentInfo(platform="test", python_version="3.14"),
    )


def _passing_evaluation() -> EvaluationSummary:
    return EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="control-efficacy-ci-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
        findings=(),
    )


def _config_digest(tmp_path: Path) -> PacketArtifactDigest:
    config_path = tmp_path / "controls-mutation.yaml"
    config_path.write_text("package_version: 0.6.2\n", encoding="utf-8", newline="\n")
    return packet_artifact_digest("control-efficacy-onboarding-config", config_path)


def _passing_evaluation_packet_payload() -> dict[str, object]:
    return _build_packet(_passing_evaluation()).model_dump(mode="json")


def _assert_json_schemas_reject(payload: dict[str, object]) -> None:
    frozen_schema_path = (
        Path(__file__).resolve().parents[2]
        / "schemas"
        / f"v{SCHEMA_VERSION}"
        / "evidence-packet.schema.json"
    )
    schemas = (
        EvidencePacket.model_json_schema(mode="validation"),
        json.loads(frozen_schema_path.read_text(encoding="utf-8")),
    )
    for schema in schemas:
        assert list(Draft202012Validator(schema).iter_errors(payload))


def _assert_json_schemas_reject_at(
    payload: dict[str, object],
    expected_path: tuple[str, ...],
) -> None:
    frozen_schema_path = (
        Path(__file__).resolve().parents[2]
        / "schemas"
        / f"v{SCHEMA_VERSION}"
        / "evidence-packet.schema.json"
    )
    schemas = (
        EvidencePacket.model_json_schema(mode="validation"),
        json.loads(frozen_schema_path.read_text(encoding="utf-8")),
    )
    for schema in schemas:
        errors = tuple(Draft202012Validator(schema).iter_errors(payload))
        assert any(tuple(error.absolute_path) == expected_path for error in errors), tuple(
            (tuple(error.absolute_path), error.validator) for error in errors
        )


def _assert_json_schemas_accept(payload: dict[str, object]) -> None:
    frozen_schema_path = (
        Path(__file__).resolve().parents[2]
        / "schemas"
        / f"v{SCHEMA_VERSION}"
        / "evidence-packet.schema.json"
    )
    schemas = (
        EvidencePacket.model_json_schema(mode="validation"),
        json.loads(frozen_schema_path.read_text(encoding="utf-8")),
    )
    for schema in schemas:
        Draft202012Validator(schema).validate(payload)


def _manifest_with_unknown() -> ThreatApplicabilityManifest:
    return ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=("material_claims_have_evidence",),
        items=(
            {
                "threat_id": "AML.T0067.000",
                "applicability": "applicable",
                "critical": False,
                "rationale": "Synthetic fixture threat is in scope.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
            {
                "threat_id": "unknown-threat",
                "applicability": "unknown",
                "critical": True,
                "rationale": "Applicability has not yet been established.",
                "owner": "test-owner",
                "reviewed_at": "2026-08-08",
            },
        ),
        limitations=("Synthetic fixture scope only.",),
    )
