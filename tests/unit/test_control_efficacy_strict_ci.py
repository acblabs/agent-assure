from __future__ import annotations

import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from click import unstyle
from typer.testing import CliRunner

from agent_assure.ci import (
    GateOutcome,
    VerifierEfficacyPolicy,
    VerifierThreatScopeProjection,
    gate_artifact,
    gate_control_efficacy_report,
    gate_evidence_packet,
    load_control_efficacy_verifier_policy,
)
from agent_assure.cli.main import app
from agent_assure.controls.efficacy import (
    build_control_efficacy_report,
    evaluate_control_efficacy_gate,
    load_threat_applicability_manifest,
)
from agent_assure.mutation.campaign import build_core_catalog
from agent_assure.onboarding.controls_mutation import (
    CONFIG_FILENAME,
    THREAT_MANIFEST_FILENAME,
    expected_scaffold_files,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.efficacy import write_control_efficacy_report
from agent_assure.reporting.packet import build_evidence_packet, write_evidence_packet
from agent_assure.schema.common import GateState
from agent_assure.schema.efficacy import (
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    ControlEfficacySemanticState,
    ThreatApplicabilityManifest,
    ThreatScopeSemanticState,
)
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.mutation import GateEffect, MutationResultState
from agent_assure.schema.packet import PacketArtifactDigest
from tests.unit.controls.test_control_efficacy import (
    _DROP_OPERATOR,
    _campaign,
    _replace_result_state,
)

_BYPASS_OPERATOR = "bypass-required-human-review"
_POLICY_SHA256 = "a" * 64
_SCOPE_SHA256 = "b" * 64
_RUNNER = CliRunner()


def _plain_cli_output(output: str) -> str:
    return " ".join(unstyle(output).split())


def test_library_entrypoints_default_to_strict_efficacy() -> None:
    report = _passing_report()
    packet = _packet(report, _permissive_profile(report))

    decisions = (
        gate_artifact(report),
        gate_control_efficacy_report(report),
        gate_artifact(packet),
        gate_evidence_packet(packet),
    )

    for decision in decisions:
        dumped = decision.model_dump()
        assert decision.exit_code == 2
        assert decision.outcome is GateOutcome.invalid
        assert dumped["efficacy_evidence"] == "present"
        assert dumped["efficacy_verification"] == "strict"
        assert "separate verifier-owned efficacy policy" in decision.message


def test_packet_without_efficacy_fails_closed_unless_migration_is_explicit() -> None:
    packet = _packet_without_efficacy()

    default_decisions = (gate_artifact(packet), gate_evidence_packet(packet))
    migration_decisions = (
        gate_artifact(packet, allow_missing_efficacy_for_migration=True),
        gate_evidence_packet(packet, allow_missing_efficacy_for_migration=True),
    )

    for decision in default_decisions:
        dumped = decision.model_dump()
        assert decision.exit_code == 2
        assert decision.outcome is GateOutcome.invalid
        assert dumped["efficacy_evidence"] == "absent"
        assert dumped["efficacy_verification"] == "strict"
        assert dumped["efficacy_required"] is True
        assert "default evidence-packet gate" in decision.message

    for decision in migration_decisions:
        dumped = decision.model_dump()
        assert decision.exit_code == 0
        assert decision.outcome is GateOutcome.pass_
        assert dumped["efficacy_evidence"] == "absent"
        assert dumped["efficacy_verification"] == "not_requested"
        assert dumped["efficacy_required"] is False


def test_require_efficacy_rejects_packet_without_efficacy_with_specific_message() -> None:
    packet = _packet_without_efficacy()

    decisions = (
        gate_artifact(packet, require_efficacy=True),
        gate_evidence_packet(packet, require_efficacy=True),
    )

    for decision in decisions:
        dumped = decision.model_dump()
        assert decision.exit_code == 2
        assert decision.outcome is GateOutcome.invalid
        assert dumped["efficacy_evidence"] == "absent"
        assert dumped["efficacy_required"] is True
        assert f"evidence-packet {packet.packet_id}" in decision.message
        assert "has no control-efficacy evidence" in decision.message
        assert "required by the default evidence-packet gate" in decision.message


def test_verifier_policy_implies_required_efficacy_for_packet() -> None:
    packet = _packet_without_efficacy()
    policy = _verifier_policy(_passing_report())

    decision = gate_artifact(packet, verifier_efficacy_policy=policy)

    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert decision.model_dump()["efficacy_required"] is True
    assert f"evidence-packet {packet.packet_id}" in decision.message
    assert "has no control-efficacy evidence" in decision.message
    assert "required by the default evidence-packet gate" in decision.message


def test_non_efficacy_artifact_discloses_not_applicable_verification() -> None:
    summary = _passing_evaluation()

    dumped = gate_artifact(summary).model_dump()

    assert dumped["efficacy_evidence"] == "not_applicable"
    assert dumped["efficacy_verification"] == "not_requested"
    assert dumped["efficacy_required"] is False


def test_strict_efficacy_requires_verifier_owned_threat_scope() -> None:
    report = _passing_report()
    unpinned_policy = _verifier_policy(report, pin_threat_scope=False)

    decision = gate_artifact(
        report,
        verifier_efficacy_policy=unpinned_policy,
        strict_efficacy=True,
    )

    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "verifier-owned threat applicability manifest" in decision.message


def test_verifier_scope_mismatches_are_invalid_before_acceptance() -> None:
    execution = _campaign()
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _complete_manifest(execution),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    policy = _verifier_policy(report)
    other_operator = next(
        operator_id for operator_id in report.selected_operator_ids if operator_id != _DROP_OPERATOR
    )
    mismatched_required_profile = _permissive_profile(
        report,
        required_operators=(other_operator,),
    )
    mismatched_catalog_profile = ControlEfficacyGateProfile(
        profile_id="control-efficacy/wrong-catalog",
        required_catalog="alternate/v1",
        required_operators=report.required_operator_ids,
    )
    selected_without_optional = tuple(
        operator_id for operator_id in report.selected_operator_ids if operator_id != other_operator
    )
    cases = (
        (
            "selected_operator_ids",
            replace(
                policy,
                expected_selected_operator_ids=selected_without_optional,
            ),
        ),
        (
            "required_operator_ids",
            replace(policy, profile=mismatched_required_profile),
        ),
        (
            "catalog_id",
            replace(policy, profile=mismatched_catalog_profile),
        ),
        (
            "catalog_digest",
            replace(policy, expected_catalog_digest="0" * 64),
        ),
        (
            "threat_manifest_digest",
            replace(policy, expected_threat_manifest_digest="0" * 64),
        ),
    )

    for mismatch, mismatched_policy in cases:
        decision = gate_artifact(
            report,
            verifier_efficacy_policy=mismatched_policy,
        )

        assert decision.exit_code == 2
        assert decision.outcome is GateOutcome.invalid
        assert mismatch in decision.message


def test_strict_verifier_rejects_report_that_omits_verifier_owned_critical_scope() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report_manifest = _complete_manifest(execution)
    verifier_manifest = _complete_manifest(
        execution,
        extra_items=(
            {
                "threat_id": "verifier-owned-critical-threat",
                "applicability": "applicable",
                "critical": True,
                "reviewed_at": "2026-08-08",
            },
        ),
    )
    incomplete_report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        report_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    forged_report = _report_with_claimed_manifest_digest(
        incomplete_report,
        verifier_manifest.manifest_digest,
    )
    policy = _verifier_policy(
        forged_report,
        threat_manifest=verifier_manifest,
    )

    decision = gate_artifact(
        forged_report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )

    assert incomplete_report.threat_scope_state is (
        ThreatScopeSemanticState.all_applicable_challenged
    )
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "threat_coverage.manifest_projection" in decision.message


@pytest.mark.parametrize(
    ("applicability", "critical"),
    (
        ("unknown", False),
        ("applicable", True),
    ),
)
def test_strict_verifier_rejects_report_owned_threat_semantics(
    applicability: str,
    critical: bool,
) -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report_manifest = _complete_manifest(execution)
    first_threat_id = report_manifest.items[0].threat_id
    verifier_items = []
    for item in report_manifest.items:
        payload = item.model_dump(mode="json")
        if item.threat_id == first_threat_id:
            payload["applicability"] = applicability
            payload["critical"] = critical
        verifier_items.append(payload)
    verifier_manifest = ThreatApplicabilityManifest.build(
        threat_source=report_manifest.threat_source,
        present_control_ids=report_manifest.present_control_ids,
        items=tuple(verifier_items),
        limitations=report_manifest.limitations,
    )
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        report_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    forged_report = _report_with_claimed_manifest_digest(
        report,
        verifier_manifest.manifest_digest,
    )

    decision = gate_artifact(
        forged_report,
        verifier_efficacy_policy=_verifier_policy(
            forged_report,
            threat_manifest=verifier_manifest,
        ),
        strict_efficacy=True,
    )

    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "threat_coverage.manifest_projection" in decision.message


def test_strict_verifier_rejects_report_that_invents_present_controls() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report_manifest = _complete_manifest(execution)
    verifier_manifest = _manifest_with_present_controls(report_manifest, ())
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        report_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    forged_report = _report_with_claimed_manifest_digest(
        report,
        verifier_manifest.manifest_digest,
    )
    policy = _verifier_policy(
        forged_report,
        threat_manifest=verifier_manifest,
    )

    decision = gate_artifact(
        forged_report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )

    assert report.threat_scope_state is ThreatScopeSemanticState.all_applicable_challenged
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "operator_outcomes.present_target_control_ids" in decision.message


def test_strict_verifier_rejects_report_owned_catalog_operator_semantics() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    verifier_manifest = _complete_manifest(execution)
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        verifier_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    payload = report.model_dump(mode="json", exclude={"report_digest"})
    outcomes = payload["operator_outcomes"]
    assert isinstance(outcomes, list)
    first_outcome = outcomes[0]
    assert isinstance(first_outcome, dict)
    first_outcome["target_control_ids"] = ["forged-control"]
    first_outcome["present_target_control_ids"] = ["forged-control"]
    forged_report = ControlEfficacyReport.build(**payload)

    decision = gate_artifact(
        forged_report,
        verifier_efficacy_policy=_verifier_policy(
            forged_report,
            threat_manifest=verifier_manifest,
        ),
        strict_efficacy=True,
    )

    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "operator_outcomes.target_control_ids" in decision.message


def test_strict_verifier_rejects_internally_consistent_independence_class_forgery() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    verifier_manifest = _complete_manifest(execution)
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        verifier_manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )
    payload = report.model_dump(mode="json", exclude={"report_digest"})
    outcomes = payload["operator_outcomes"]
    assert isinstance(outcomes, list)
    outcome = outcomes[0]
    assert isinstance(outcome, dict)
    original_class = outcome["independence_class"]
    forged_class = "external_preexisting"
    assert original_class != forged_class
    outcome["independence_class"] = forged_class

    strata = payload["kill_rate_by_independence_class"]
    assert isinstance(strata, list)
    original_stratum = next(item for item in strata if item["stratum"] == original_class)
    forged_stratum = next(item for item in strata if item["stratum"] == forged_class)
    original_counts = original_stratum["state_counts"]
    original_rate = original_stratum["kill_rate"]
    original_stratum["state_counts"] = forged_stratum["state_counts"]
    original_stratum["kill_rate"] = forged_stratum["kill_rate"]
    forged_stratum["state_counts"] = original_counts
    forged_stratum["kill_rate"] = original_rate

    threat_coverage = payload["threat_coverage"]
    assert isinstance(threat_coverage, list)
    for coverage in threat_coverage:
        assert isinstance(coverage, dict)
        coverage["independent_challenging_operator_ids"] = list(
            coverage["challenging_operator_ids"]
        )
    payload["independently_challenged_threat_category_count"] = payload[
        "challenged_threat_category_count"
    ]
    payload["independent_threat_challenge_rate"] = payload["threat_challenge_rate"]
    forged_report = ControlEfficacyReport.build(**payload)

    decision = gate_artifact(
        forged_report,
        verifier_efficacy_policy=_verifier_policy(
            forged_report,
            threat_manifest=verifier_manifest,
        ),
        strict_efficacy=True,
    )

    assert forged_report.independently_challenged_threat_category_count > 0
    assert decision.exit_code == 2
    assert decision.outcome is GateOutcome.invalid
    assert "operator_outcomes.independence_class" in decision.message


def test_verifier_profile_overrides_permissive_embedded_packet_profile() -> None:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    report = build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _complete_manifest(
            execution,
            extra_items=(
                {
                    "threat_id": "unknown-scope",
                    "applicability": "unknown",
                    "critical": False,
                    "reviewed_at": "2026-08-08",
                },
            ),
        ),
        required_operator_ids=(_DROP_OPERATOR,),
    )
    embedded_profile = _permissive_profile(report)
    packet = _packet(report, embedded_profile)
    verifier_profile = _permissive_profile(report).model_copy(
        update={
            "profile_id": "control-efficacy/verifier-unknown-block",
            "unknown_threat_applicability": GateEffect.block,
        }
    )
    verifier_policy = _verifier_policy(report, profile=verifier_profile)

    embedded_result = gate_artifact(packet, strict_efficacy=False)
    verifier_result = gate_artifact(
        packet,
        verifier_efficacy_policy=verifier_policy,
    )

    assert packet.control_efficacy_gate is not None
    assert packet.control_efficacy_gate.state is GateState.pass_
    assert embedded_result.outcome is GateOutcome.pass_
    assert verifier_result.exit_code == 1
    assert verifier_result.outcome is GateOutcome.fail
    assert "verifier_profile=control-efficacy/verifier-unknown-block" in (verifier_result.message)


@pytest.mark.parametrize(
    ("case", "semantic_fragment"),
    (
        ("optional-survivor", "semantic_state:survivor_observed"),
        ("threat-gap", "threat_scope_state:gap_observed"),
        ("unknown-scope", "threat_scope_state:unknown_applicability"),
        (
            "unscoped-reference",
            "threat_scope_state:unscoped_catalog_references",
        ),
        ("threat-not-evaluated", "threat_scope_state:not_evaluated"),
    ),
)
def test_strict_policy_rejects_incomplete_efficacy_that_advisory_policy_allows(
    case: str,
    semantic_fragment: str,
) -> None:
    report = _incomplete_report(case)
    policy = _verifier_policy(report)

    advisory = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=False,
    )
    strict = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )

    assert advisory.exit_code == 0
    assert advisory.outcome is GateOutcome.pass_
    assert strict.exit_code == 1
    assert strict.outcome is GateOutcome.fail
    assert semantic_fragment in strict.message


def test_invalid_optional_operator_blocks_even_under_advisory_policy() -> None:
    report = _incomplete_report("invalid-optional-operator")
    policy = _verifier_policy(report)

    decision = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=False,
    )

    assert policy.profile.invalid_or_error_operator is GateEffect.block
    assert decision.exit_code == 1
    assert decision.outcome is GateOutcome.fail
    assert "semantic_state=indeterminate" in decision.message


def test_strict_policy_accepts_only_complete_all_caught_efficacy() -> None:
    report = _passing_report()
    policy = _verifier_policy(report)

    decision = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )

    assert report.semantic_state is (ControlEfficacySemanticState.all_evaluated_applicable_caught)
    assert report.threat_scope_state is ThreatScopeSemanticState.all_applicable_challenged
    assert decision.exit_code == 0
    assert decision.outcome is GateOutcome.pass_
    assert "verifier_profile=control-efficacy/test-verifier" in decision.message
    assert f"verifier_policy_sha256={_POLICY_SHA256}" in decision.message
    assert f"verifier_scope_sha256={_SCOPE_SHA256}" in decision.message


def test_successful_efficacy_records_distinguish_strict_from_advisory() -> None:
    report = _passing_report()
    policy = _verifier_policy(report)

    strict = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )
    advisory = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=False,
    )

    assert strict.outcome is GateOutcome.pass_
    assert advisory.outcome is GateOutcome.pass_
    assert strict.model_dump()["efficacy_evidence"] == "present"
    assert advisory.model_dump()["efficacy_evidence"] == "present"
    assert strict.model_dump()["efficacy_verification"] == "strict"
    assert advisory.model_dump()["efficacy_verification"] == "advisory"
    assert strict.model_dump()["efficacy_required"] is True
    assert advisory.model_dump()["efficacy_required"] is True
    assert "efficacy_verification=strict" in strict.message
    assert "efficacy_verification=advisory" in advisory.message
    assert strict.message != advisory.message


def test_ci_command_defaults_to_strict_efficacy_for_reports(tmp_path: Path) -> None:
    report_path = write_control_efficacy_report(
        _passing_report(),
        tmp_path / "efficacy",
    ).report

    strict = _RUNNER.invoke(
        app,
        ["ci", "gate", str(report_path)],
        terminal_width=240,
    )
    advisory = _RUNNER.invoke(
        app,
        ["ci", "gate", str(report_path), "--allow-advisory-efficacy"],
        terminal_width=240,
    )

    assert strict.exit_code == 2, strict.output
    assert "separate verifier-owned efficacy policy" in " ".join(strict.output.split())
    assert advisory.exit_code == 0, advisory.output
    assert "ci gate pass: control-efficacy-report" in advisory.output


def test_ci_packet_efficacy_is_required_by_default_with_migration_opt_out(
    tmp_path: Path,
) -> None:
    packet = _packet_without_efficacy()
    packet_path = tmp_path / "packet.json"
    write_evidence_packet(packet, packet_path)
    files = expected_scaffold_files()
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    config_path = policy_dir / CONFIG_FILENAME
    config_path.write_bytes(files[CONFIG_FILENAME])
    (policy_dir / THREAT_MANIFEST_FILENAME).write_bytes(files[THREAT_MANIFEST_FILENAME])

    default = _RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path)],
        terminal_width=240,
    )
    required = _RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path), "--require-efficacy"],
        terminal_width=240,
    )
    policy_required = _RUNNER.invoke(
        app,
        ["ci", "gate", str(packet_path), "--efficacy-policy", str(config_path)],
        terminal_width=240,
    )
    migration = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--allow-missing-efficacy-for-migration",
        ],
        terminal_width=240,
    )

    for result in (default, required, policy_required):
        normalized = _plain_cli_output(result.output)
        assert result.exit_code == 2, result.output
        assert f"evidence-packet {packet.packet_id}" in normalized
        assert "has no control-efficacy evidence" in normalized
        assert "required by the default evidence-packet gate" in normalized
        assert "options require a control-efficacy report or evidence packet" not in normalized
    assert migration.exit_code == 0, migration.output
    migration_output = _plain_cli_output(migration.output)
    assert "efficacy_evidence=absent" in migration_output
    assert "efficacy_verification=not_requested" in migration_output
    assert "policy_profile=non-assurance-migration" in migration_output


def test_ci_migration_absent_efficacy_json_is_explicitly_not_verified(
    tmp_path: Path,
) -> None:
    packet_path = tmp_path / "packet.json"
    write_evidence_packet(_packet_without_efficacy(), packet_path)

    result = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--allow-missing-efficacy-for-migration",
            "--format",
            "json",
        ],
        terminal_width=240,
    )

    assert result.exit_code == 0, result.output
    decision = json.loads(result.output)
    assert decision["efficacy_evidence"] == "absent"
    assert decision["efficacy_verification"] == "not_requested"
    assert decision["efficacy_required"] is False


def test_migration_override_rejects_non_packet_and_present_efficacy() -> None:
    report = _passing_report()
    efficacy_packet = _packet(report, _permissive_profile(report))

    non_packet = gate_artifact(
        _passing_evaluation(),
        allow_missing_efficacy_for_migration=True,
    )
    already_present = gate_evidence_packet(
        efficacy_packet,
        allow_missing_efficacy_for_migration=True,
    )

    assert non_packet.exit_code == 2
    assert non_packet.outcome is GateOutcome.invalid
    assert "valid only for an evidence packet without" in non_packet.message
    assert already_present.exit_code == 2
    assert already_present.outcome is GateOutcome.invalid
    assert "already carries control-efficacy evidence" in already_present.message


def test_ci_migration_override_rejects_packet_with_existing_efficacy(
    tmp_path: Path,
) -> None:
    report = _passing_report()
    packet_path = tmp_path / "packet.json"
    write_evidence_packet(_packet(report, _permissive_profile(report)), packet_path)

    result = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--allow-missing-efficacy-for-migration",
        ],
        terminal_width=240,
    )

    assert result.exit_code == 2
    assert "already carries control-efficacy evidence" in _plain_cli_output(result.output)


def test_ci_release_profile_requires_policy_and_rejects_non_packet(tmp_path: Path) -> None:
    report_path = write_control_efficacy_report(
        _passing_report(),
        tmp_path / "efficacy",
    ).report

    without_policy = _RUNNER.invoke(
        app,
        ["ci", "gate", str(report_path), "--release-profile"],
        terminal_width=240,
    )
    assert without_policy.exit_code == 2
    assert "--release-profile requires --efficacy-policy" in _plain_cli_output(
        without_policy.output
    )

    files = expected_scaffold_files()
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_path = policy_dir / CONFIG_FILENAME
    policy_path.write_bytes(files[CONFIG_FILENAME])
    (policy_dir / THREAT_MANIFEST_FILENAME).write_bytes(files[THREAT_MANIFEST_FILENAME])
    non_packet = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(report_path),
            "--release-profile",
            "--efficacy-policy",
            str(policy_path),
        ],
        terminal_width=240,
    )
    assert non_packet.exit_code == 2
    assert "--release-profile requires an evidence packet" in _plain_cli_output(non_packet.output)


@pytest.mark.parametrize(
    "weakening_flag",
    (
        "--allow-missing-efficacy-for-migration",
        "--allow-advisory-efficacy",
        "--allow-sensitivity-non-verdict",
        "--allow-legacy-unbound-comparison",
    ),
)
def test_ci_release_profile_rejects_weakening_flags(
    tmp_path: Path,
    weakening_flag: str,
) -> None:
    files = expected_scaffold_files()
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_path = policy_dir / CONFIG_FILENAME
    policy_path.write_bytes(files[CONFIG_FILENAME])
    (policy_dir / THREAT_MANIFEST_FILENAME).write_bytes(files[THREAT_MANIFEST_FILENAME])
    packet_path = tmp_path / "packet.json"
    write_evidence_packet(_packet_without_efficacy(), packet_path)

    result = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--release-profile",
            "--efficacy-policy",
            str(policy_path),
            weakening_flag,
        ],
        terminal_width=500,
    )

    assert result.exit_code == 2
    normalized = _plain_cli_output(result.output)
    assert "--release-profile" in normalized
    assert weakening_flag in normalized


def test_ci_release_profile_requires_present_strict_efficacy(tmp_path: Path) -> None:
    files = expected_scaffold_files()
    policy_dir = tmp_path / "policy"
    policy_dir.mkdir()
    policy_path = policy_dir / CONFIG_FILENAME
    policy_path.write_bytes(files[CONFIG_FILENAME])
    (policy_dir / THREAT_MANIFEST_FILENAME).write_bytes(files[THREAT_MANIFEST_FILENAME])
    packet_path = tmp_path / "packet.json"
    write_evidence_packet(_packet_without_efficacy(), packet_path)

    result = _RUNNER.invoke(
        app,
        [
            "ci",
            "gate",
            str(packet_path),
            "--release-profile",
            "--efficacy-policy",
            str(policy_path),
        ],
        terminal_width=240,
    )

    normalized = _plain_cli_output(result.output)
    assert result.exit_code == 2
    assert "has no control-efficacy evidence" in normalized
    assert "required by the default evidence-packet gate" in normalized
    assert "policy_profile=release" in normalized


def test_yaml_policy_loader_pins_config_catalog_and_threat_scope(tmp_path: Path) -> None:
    files = expected_scaffold_files()
    config_path = tmp_path / CONFIG_FILENAME
    manifest_path = tmp_path / THREAT_MANIFEST_FILENAME
    config_path.write_bytes(files[CONFIG_FILENAME])
    manifest_path.write_bytes(files[THREAT_MANIFEST_FILENAME])

    policy = load_control_efficacy_verifier_policy(config_path)
    manifest = load_threat_applicability_manifest(manifest_path)

    assert policy.expected_selected_operator_ids == (_DROP_OPERATOR,)
    assert policy.profile.required_operators == (_DROP_OPERATOR,)
    assert policy.source_sha256 == sha256(files[CONFIG_FILENAME]).hexdigest()
    assert policy.expected_threat_manifest_digest == manifest.manifest_digest
    assert policy.scope_source_sha256 == sha256(files[THREAT_MANIFEST_FILENAME]).hexdigest()
    assert policy.expected_catalog == build_core_catalog()
    assert policy.expected_threat_scope == VerifierThreatScopeProjection.from_manifest(manifest)


def test_json_policy_loader_is_profile_only_and_advisory_compatible(
    tmp_path: Path,
) -> None:
    report = _passing_report()
    profile = _permissive_profile(report)
    payload = (json.dumps(profile.model_dump(mode="json"), sort_keys=True) + "\n").encode("utf-8")
    path = tmp_path / "efficacy-profile.json"
    path.write_bytes(payload)

    policy = load_control_efficacy_verifier_policy(path)
    advisory = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=False,
    )
    strict = gate_artifact(
        report,
        verifier_efficacy_policy=policy,
        strict_efficacy=True,
    )

    assert policy.expected_selected_operator_ids == report.required_operator_ids
    assert policy.source_sha256 == sha256(payload).hexdigest()
    assert policy.expected_threat_manifest_digest is None
    assert policy.scope_source_sha256 is None
    assert policy.expected_catalog == build_core_catalog()
    assert policy.expected_threat_scope is None
    assert advisory.outcome is GateOutcome.pass_
    assert strict.exit_code == 2
    assert strict.outcome is GateOutcome.invalid


def test_policy_loader_rejects_unsupported_and_wrapped_profile_formats(
    tmp_path: Path,
) -> None:
    profile = ControlEfficacyGateProfile(
        required_catalog="core/v1",
        required_operators=(_DROP_OPERATOR,),
    )
    unsupported = tmp_path / "policy.toml"
    unsupported.write_text("required_catalog = 'core/v1'\n", encoding="utf-8")
    wrapped = tmp_path / "policy.json"
    wrapped.write_text(
        json.dumps({"control_efficacy": profile.model_dump(mode="json")}),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"\.json, \.yaml, or \.yml"):
        load_control_efficacy_verifier_policy(unsupported)
    with pytest.raises(ValueError):
        load_control_efficacy_verifier_policy(wrapped)


def _passing_report() -> ControlEfficacyReport:
    execution = _campaign(operator_ids=(_DROP_OPERATOR,))
    return build_control_efficacy_report(
        execution.campaign,
        execution.catalog,
        _complete_manifest(execution),
        required_operator_ids=(_DROP_OPERATOR,),
    )


def _report_with_claimed_manifest_digest(
    report: ControlEfficacyReport,
    manifest_digest: str,
) -> ControlEfficacyReport:
    payload = report.model_dump(mode="json", exclude={"report_digest"})
    payload["threat_manifest_digest"] = manifest_digest
    return ControlEfficacyReport.build(**payload)


def _manifest_with_present_controls(
    manifest: ThreatApplicabilityManifest,
    present_control_ids: tuple[str, ...],
) -> ThreatApplicabilityManifest:
    return ThreatApplicabilityManifest.build(
        threat_source=manifest.threat_source,
        present_control_ids=present_control_ids,
        items=manifest.items,
        limitations=manifest.limitations,
    )


def _passing_evaluation() -> EvaluationSummary:
    return EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id="strict-efficacy-test-runset",
        runset_digest="c" * 64,
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        state=GateState.pass_,
        findings=(),
    )


def _packet_without_efficacy() -> Any:
    return build_evidence_packet(
        _passing_evaluation(),
        artifact_digests=(PacketArtifactDigest(role="evaluation-summary", sha256="e" * 64),),
    )


def _incomplete_report(case: str) -> ControlEfficacyReport:
    if case in {"optional-survivor", "invalid-optional-operator"}:
        execution = _campaign()
        optional_operator = next(
            entry.operator_id
            for entry in execution.campaign.operator_results
            if entry.operator_id != _DROP_OPERATOR
        )
        state = (
            MutationResultState.survived
            if case == "optional-survivor"
            else MutationResultState.invalid_subject
        )
        campaign = _replace_result_state(
            execution.campaign,
            operator_id=optional_operator,
            state=state,
        )
        manifest = _complete_manifest(execution)
    else:
        execution = _campaign(operator_ids=(_DROP_OPERATOR,))
        campaign = execution.campaign
        if case == "threat-gap":
            manifest = _complete_manifest(
                execution,
                extra_items=(
                    {
                        "threat_id": "declared-but-unchallenged",
                        "applicability": "applicable",
                        "critical": False,
                        "reviewed_at": "2026-08-08",
                    },
                ),
            )
        elif case == "unknown-scope":
            manifest = _complete_manifest(
                execution,
                extra_items=(
                    {
                        "threat_id": "unknown-scope",
                        "applicability": "unknown",
                        "critical": False,
                        "reviewed_at": "2026-08-08",
                    },
                ),
            )
        elif case == "unscoped-reference":
            manifest = _complete_manifest(
                execution,
                omitted_threat_ids=("material-claim-link-regression",),
            )
        elif case == "threat-not-evaluated":
            threat_ids = _selected_threat_ids(execution)
            manifest = _complete_manifest(
                execution,
                applicability_by_id={threat_id: "not_applicable" for threat_id in threat_ids},
            )
        else:
            raise AssertionError(f"unsupported strict efficacy case: {case}")
    return build_control_efficacy_report(
        campaign,
        execution.catalog,
        manifest,
        required_operator_ids=(_DROP_OPERATOR,),
    )


def _verifier_policy(
    report: ControlEfficacyReport,
    *,
    profile: ControlEfficacyGateProfile | None = None,
    pin_threat_scope: bool = True,
    threat_manifest: ThreatApplicabilityManifest | None = None,
) -> VerifierEfficacyPolicy:
    threat_scope = (
        None
        if not pin_threat_scope
        else (
            VerifierThreatScopeProjection.from_manifest(threat_manifest)
            if threat_manifest is not None
            else _threat_scope_projection_from_report(report)
        )
    )
    return VerifierEfficacyPolicy(
        profile=profile or _permissive_profile(report),
        expected_selected_operator_ids=report.selected_operator_ids,
        expected_catalog_digest=report.catalog_digest,
        source_sha256=_POLICY_SHA256,
        expected_threat_manifest_digest=(
            threat_scope.manifest_digest if threat_scope is not None else None
        ),
        scope_source_sha256=_SCOPE_SHA256 if pin_threat_scope else None,
        expected_catalog=build_core_catalog(),
        expected_threat_scope=threat_scope,
    )


def _threat_scope_projection_from_report(
    report: ControlEfficacyReport,
) -> VerifierThreatScopeProjection:
    return VerifierThreatScopeProjection(
        manifest_digest=report.threat_manifest_digest,
        present_control_ids=tuple(
            sorted(
                {
                    control_id
                    for outcome in report.operator_outcomes
                    for control_id in outcome.present_target_control_ids
                }
            )
        ),
        items=tuple(
            (item.threat_id, item.applicability, item.critical) for item in report.threat_coverage
        ),
    )


def _permissive_profile(
    report: ControlEfficacyReport,
    *,
    required_operators: tuple[str, ...] | None = None,
) -> ControlEfficacyGateProfile:
    return ControlEfficacyGateProfile(
        profile_id="control-efficacy/test-verifier",
        required_catalog=report.catalog_id,
        required_operators=required_operators or report.required_operator_ids,
        surviving_applicable_operator=GateEffect.ignore,
        critical_threat_uncovered=GateEffect.ignore,
        applicable_threat_uncovered=GateEffect.ignore,
        unknown_threat_applicability=GateEffect.ignore,
        unscoped_catalog_threat_reference=GateEffect.ignore,
    )


def _complete_manifest(
    execution: Any,
    *,
    omitted_threat_ids: tuple[str, ...] = (),
    applicability_by_id: dict[str, str] | None = None,
    extra_items: tuple[dict[str, object], ...] = (),
) -> ThreatApplicabilityManifest:
    omitted = set(omitted_threat_ids)
    applicability = applicability_by_id or {}
    items: list[dict[str, object]] = []
    for threat_id in _selected_threat_ids(execution):
        if threat_id in omitted:
            continue
        state = applicability.get(threat_id, "applicable")
        item: dict[str, object] = {
            "threat_id": threat_id,
            "applicability": state,
            "critical": False,
            "reviewed_at": "2026-08-08",
        }
        if state == "not_applicable":
            item.update(
                {
                    "rationale": "Synthetic strict-CI scope exclusion.",
                    "owner": "test-owner",
                }
            )
        items.append(item)
    items.extend(extra_items)
    items.sort(key=lambda item: str(item["threat_id"]))
    return ThreatApplicabilityManifest.build(
        threat_source={"name": "mitre-atlas", "version": "2026.06"},
        present_control_ids=_selected_control_ids(execution),
        items=tuple(items),
        limitations=("Synthetic strict-CI fixture scope only.",),
    )


def _selected_catalog_entries(execution: Any) -> tuple[Any, ...]:
    selected = {entry.operator_id for entry in execution.campaign.operator_results}
    return tuple(
        entry for entry in execution.catalog.operators if entry.descriptor.operator_id in selected
    )


def _selected_threat_ids(execution: Any) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                threat_id
                for entry in _selected_catalog_entries(execution)
                for threat_id in entry.threat_source_references
            }
        )
    )


def _selected_control_ids(execution: Any) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                control_id
                for entry in _selected_catalog_entries(execution)
                for control_id in (entry.descriptor.expected_detection_contract.target_control_ids)
            }
        )
    )


def _packet(
    report: ControlEfficacyReport,
    embedded_profile: ControlEfficacyGateProfile,
) -> Any:
    embedded_gate = evaluate_control_efficacy_gate(report, embedded_profile)
    return build_evidence_packet(
        _passing_evaluation(),
        control_efficacy=report,
        control_efficacy_gate_profile=embedded_profile,
        control_efficacy_gate=embedded_gate,
        artifact_digests=(
            PacketArtifactDigest(
                role="evaluation-summary",
                sha256="e" * 64,
            ),
            PacketArtifactDigest(
                role="control-efficacy-report",
                sha256="c" * 64,
            ),
            PacketArtifactDigest(
                role="control-efficacy-gate-profile",
                sha256="d" * 64,
            ),
        ),
    )
