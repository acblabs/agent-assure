from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from agent_assure.demo.common import (
    DemoError,
    ExpectedCommandResult,
    artifact_path,
    copy_example_resource,
    prepare_output_dir,
    run_cli_command,
    write_json,
)
from agent_assure.rag.sensitivity import SensitivityInputError, load_sensitivity_report
from agent_assure.schema.common import GateState
from agent_assure.schema.sensitivity import (
    DetectorTestStatus,
    EvidenceSensitivityGateEffect,
    EvidenceSensitivityObservedRelation,
    EvidenceSensitivityReasonCode,
    EvidenceSensitivityState,
    RAGSensitivityDecision,
    RAGSensitivityReport,
)
from agent_assure.sensitivity_contract import SENSITIVITY_HARNESS_NOTICE

EVIDENCE_SENSITIVITY_NOTICE = (
    f"{SENSITIVITY_HARNESS_NOTICE} This detector contract is not a causal guarantee "
    "or a real-model failure-prevalence estimate."
)


def run_evidence_sensitivity_demo(
    out_dir: Path,
    *,
    clean: bool,
) -> dict[str, object]:
    root = prepare_output_dir(out_dir, clean=clean)
    example_dir = copy_example_resource(
        "evidence_sensitivity",
        root / "example" / "evidence_sensitivity",
        owner_root=root,
    )
    responsive_dir = root / "responsive"
    inertial_dir = root / "evidence-inertial"
    summary_path = root / "demo-summary.json"
    common_args = [
        "--baseline-corpus",
        str(example_dir / "corpora" / "policy_a"),
        "--counterfactual-corpus",
        str(example_dir / "corpora" / "policy_b"),
        "--knowledge-contract",
        str(example_dir / "knowledge-contract.yaml"),
        "--expected-relation",
        "decision_flip",
    ]
    commands = (
        run_cli_command(
            name="responsive-sensitivity",
            args=[
                "rag",
                "sensitivity",
                "--suite",
                str(example_dir / "responsive_suite.yaml"),
                *common_args,
                "--out",
                str(responsive_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        ),
        run_cli_command(
            name="evidence-inertial-sensitivity",
            args=[
                "rag",
                "sensitivity",
                "--suite",
                str(example_dir / "evidence_inertial_suite.yaml"),
                *common_args,
                "--out",
                str(inertial_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        ),
    )
    responsive = _load_report(responsive_dir / "evidence-sensitivity.json")
    inertial = _load_report(inertial_dir / "evidence-sensitivity.json")
    summary = _build_summary(
        root=root,
        responsive=responsive,
        inertial=inertial,
        commands=commands,
    )
    _assert_success_summary(summary, root=root)
    write_json(summary_path, summary)
    return summary


def render_evidence_sensitivity_text(summary: dict[str, object]) -> str:
    experiments = cast(dict[str, Any], summary["experiments"])
    responsive = cast(dict[str, Any], experiments["responsive"])
    inertial = cast(dict[str, Any], experiments["evidence_inertial"])
    artifacts = cast(dict[str, str], summary["artifacts"])
    return "\n".join(
        (
            "agent-assure controlled evidence sensitivity demo",
            "",
            EVIDENCE_SENSITIVITY_NOTICE,
            "",
            "Authoritative corpus substitution:",
            "  Policy A expected decision: approve",
            "  Policy B expected decision: deny",
            "",
            "Responsive synthetic subject:",
            f"  observed relation: {responsive['observed_relation']}",
            f"  state: {responsive['state']}",
            f"  gate effect: {responsive['gate_effect']}",
            "",
            "Intentionally evidence-inertial synthetic subject:",
            f"  decisions: {inertial['baseline_decision']} -> "
            f"{inertial['counterfactual_decision']}",
            f"  retrieval and citation prerequisites: {inertial['evidence_prerequisites']}",
            f"  ordinary arm evaluations: {inertial['arm_evaluations']}",
            f"  decision inertia: {str(inertial['decision_inertia']).lower()}",
            f"  state: {inertial['state']}",
            f"  gate effect: {inertial['gate_effect']}",
            "",
            "Artifacts:",
            f"  {artifacts['summary']}",
            f"  {artifacts['responsive_report']}",
            f"  {artifacts['inertial_report']}",
            f"  {artifacts['inertial_markdown']}",
            f"  {artifacts['inertial_html']}",
            "",
            "Demo result:",
            "  success: citations pass while controlled sensitivity blocks inertia",
        )
    )


def _build_summary(
    *,
    root: Path,
    responsive: RAGSensitivityReport,
    inertial: RAGSensitivityReport,
    commands: tuple[ExpectedCommandResult, ExpectedCommandResult],
) -> dict[str, object]:
    expected_behavior_observed = (
        _responsive_contract_met(responsive)
        and _inertial_contract_met(inertial)
        and commands[0].actual_exit_code == 0
        and commands[1].actual_exit_code == 1
        and all(item.matched for item in commands)
    )
    return {
        "demo": "evidence-sensitivity",
        "status": "success" if expected_behavior_observed else "failure",
        "notice": EVIDENCE_SENSITIVITY_NOTICE,
        "underlying_exit_code": commands[1].actual_exit_code,
        "expected_behavior_observed": expected_behavior_observed,
        "experiments": {
            "responsive": _experiment_summary(responsive),
            "evidence_inertial": _experiment_summary(inertial),
        },
        "artifacts": {
            "summary": artifact_path(root / "demo-summary.json", root=root),
            "responsive_report": artifact_path(
                root / "responsive" / "evidence-sensitivity.json",
                root=root,
            ),
            "responsive_markdown": artifact_path(
                root / "responsive" / "evidence-sensitivity.md",
                root=root,
            ),
            "responsive_html": artifact_path(
                root / "responsive" / "evidence-sensitivity.html",
                root=root,
            ),
            "inertial_report": artifact_path(
                root / "evidence-inertial" / "evidence-sensitivity.json",
                root=root,
            ),
            "inertial_markdown": artifact_path(
                root / "evidence-inertial" / "evidence-sensitivity.md",
                root=root,
            ),
            "inertial_html": artifact_path(
                root / "evidence-inertial" / "evidence-sensitivity.html",
                root=root,
            ),
        },
        "commands": [item.model_dump(root=root) for item in commands],
    }


def _experiment_summary(report: RAGSensitivityReport) -> dict[str, object]:
    evidence_prerequisites = (
        "pass"
        if all(
            (
                report.baseline_arm.retrieval_succeeded,
                report.counterfactual_arm.retrieval_succeeded,
                report.baseline_arm.governing_evidence_supported,
                report.counterfactual_arm.governing_evidence_supported,
                report.baseline_arm.evidence_link_present,
                report.counterfactual_arm.evidence_link_present,
            )
        )
        else "fail"
    )
    arm_evaluations = (
        "pass"
        if report.baseline_arm.evaluation_state is GateState.pass_
        and report.counterfactual_arm.evaluation_state is GateState.pass_
        else "fail"
    )
    return {
        "state": report.state.value,
        "gate_effect": report.gate_effect.value,
        "expected_relation": report.expected_relation.value,
        "observed_relation": report.observed_relation.value,
        "endpoint_value": report.endpoint_value,
        "baseline_decision": report.baseline_arm.decision.value,
        "counterfactual_decision": report.counterfactual_arm.decision.value,
        "evidence_prerequisites": evidence_prerequisites,
        "arm_evaluations": arm_evaluations,
        "decision_inertia": report.decision_inertia_finding.detected,
        "reason_codes": [item.value for item in report.reason_codes],
        "detector_test_status": report.detector_test_status.value,
        "verdict_bearing": report.verdict_bearing,
    }


def _responsive_contract_met(report: RAGSensitivityReport) -> bool:
    return (
        report.state is EvidenceSensitivityState.responsive
        and report.gate_effect is EvidenceSensitivityGateEffect.pass_
        and report.endpoint_value is True
        and report.observed_relation is EvidenceSensitivityObservedRelation.decision_flip
        and report.baseline_arm.decision is RAGSensitivityDecision.approve
        and report.counterfactual_arm.decision is RAGSensitivityDecision.deny
        and _shared_prerequisites_met(report)
        and not report.decision_inertia_finding.detected
        and report.detector_test_status is DetectorTestStatus.synthetic_detector_contract_test
    )


def _inertial_contract_met(report: RAGSensitivityReport) -> bool:
    return (
        report.state is EvidenceSensitivityState.evidence_insensitive
        and report.gate_effect is EvidenceSensitivityGateEffect.block
        and report.endpoint_value is False
        and report.observed_relation is EvidenceSensitivityObservedRelation.decision_same
        and report.baseline_arm.decision is RAGSensitivityDecision.approve
        and report.counterfactual_arm.decision is RAGSensitivityDecision.approve
        and _shared_prerequisites_met(report)
        and report.decision_inertia_finding.detected
        and report.reason_codes == (EvidenceSensitivityReasonCode.expected_response_missing,)
        and report.detector_test_status is DetectorTestStatus.synthetic_detector_contract_test
    )


def _shared_prerequisites_met(report: RAGSensitivityReport) -> bool:
    return (
        report.protocol.controlled_difference_manifest.only_declared_differences
        and report.baseline_arm.evaluation_state is GateState.pass_
        and report.counterfactual_arm.evaluation_state is GateState.pass_
        and report.baseline_arm.retrieval_succeeded
        and report.counterfactual_arm.retrieval_succeeded
        and report.baseline_arm.governing_evidence_supported
        and report.counterfactual_arm.governing_evidence_supported
        and report.baseline_arm.evidence_link_present
        and report.counterfactual_arm.evidence_link_present
    )


def _assert_success_summary(summary: dict[str, object], *, root: Path) -> None:
    if summary["status"] != "success":
        raise DemoError("evidence-sensitivity demo did not reproduce its detector contract")
    artifacts = cast(dict[str, str], summary["artifacts"])
    for name, relative_path in artifacts.items():
        if not relative_path:
            raise DemoError(f"evidence-sensitivity demo omitted artifact path: {name}")
        if name != "summary" and not (root / relative_path).is_file():
            raise DemoError(f"evidence-sensitivity demo artifact is missing: {relative_path}")


def _load_report(path: Path) -> RAGSensitivityReport:
    try:
        return load_sensitivity_report(path)
    except SensitivityInputError as exc:
        raise DemoError("evidence-sensitivity demo produced an invalid report") from exc


__all__ = [
    "EVIDENCE_SENSITIVITY_NOTICE",
    "render_evidence_sensitivity_text",
    "run_evidence_sensitivity_demo",
]
