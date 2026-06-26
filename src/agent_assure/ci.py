from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Literal

from agent_assure.compare.runsets import ComparisonReport, InvalidComparisonError, compare_runsets
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import load_compiled_suite
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
from agent_assure.reporting.environment import (
    attach_comparison_environment,
    attach_evaluation_environment,
    build_release_manifest,
    environment_with_dependency_inventory,
    release_artifact,
    write_release_manifest,
)
from agent_assure.reporting.json_report import write_comparison_json, write_evaluation_json
from agent_assure.reporting.markdown import write_comparison_markdown, write_evaluation_markdown
from agent_assure.reporting.packet import (
    build_evidence_packet,
    packet_artifact_digest,
    write_evidence_packet,
    write_evidence_packet_markdown,
)
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import load_json

GateArtifact = EvaluationSummary | ComparisonSummary | EvidencePacket
ReportMode = Literal["full", "fail-fast"]


@dataclass(frozen=True)
class GateDecision:
    exit_code: int
    message: str
    reason_code: ReasonCode | None = None
    artifact_kind: str = ""
    artifact_path: str = ""
    validator: str = "agent_assure.ci"

    def model_dump(self) -> dict[str, object]:
        return {
            "exit_code": self.exit_code,
            "message": self.message,
            "reason_code": self.reason_code.value if self.reason_code is not None else None,
            "artifact_kind": self.artifact_kind,
            "artifact_path": self.artifact_path,
            "validator": self.validator,
        }


@dataclass(frozen=True)
class CiRunResult:
    decision: GateDecision
    report_paths: tuple[Path, ...]
    packet_path: Path
    diagnostics_path: Path | None = None


def load_gate_artifact(path: Path) -> GateArtifact:
    payload = load_json(path)
    artifact_kind = payload.get("artifact_kind")
    if artifact_kind == "evaluation-summary":
        return EvaluationSummary.model_validate(payload)
    if artifact_kind == "comparison-summary":
        return ComparisonSummary.model_validate(payload)
    if artifact_kind == "evidence-packet":
        return EvidencePacket.model_validate(payload)
    raise ValueError(
        "CI gate expects artifact_kind evaluation-summary, comparison-summary, "
        f"or evidence-packet; got {artifact_kind!r}"
    )


def gate_artifact(
    artifact: GateArtifact,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    if isinstance(artifact, EvaluationSummary):
        return gate_evaluation_summary(
            artifact,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    if isinstance(artifact, ComparisonSummary):
        return gate_comparison_summary(
            artifact,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    return gate_evidence_packet(
        artifact,
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
    )


def gate_evaluation_summary(
    summary: EvaluationSummary,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    decision = _decision_for_state(
        summary.state,
        subject=f"evaluation-summary {summary.runset_id}",
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
    )
    if decision.exit_code:
        finding = summary.findings[0] if summary.findings else None
        return GateDecision(
            exit_code=decision.exit_code,
            message=decision.message,
            reason_code=finding.reason_code if finding is not None else ReasonCode.POLICY_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    return decision


def gate_comparison_summary(
    summary: ComparisonSummary,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    if (
        summary.classification is ComparisonClassification.invalid_comparison
        or summary.fixture_equivalence_state is GateState.fail
    ):
        return GateDecision(
            exit_code=2,
            message=(
                "ci gate invalid: comparison-summary "
                f"{summary.baseline_runset_id}->{summary.candidate_runset_id} "
                "has invalid fixture equivalence"
            ),
            reason_code=ReasonCode.FIXTURE_EQUIVALENCE_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    if summary.classification in {
        ComparisonClassification.new_failure,
        ComparisonClassification.persistent_failure,
    }:
        return GateDecision(
            exit_code=1,
            message=(
                "ci gate fail: comparison-summary "
                f"{summary.baseline_runset_id}->{summary.candidate_runset_id} "
                f"classification={summary.classification.value}"
            ),
            reason_code=ReasonCode.POLICY_FAILED,
            artifact_kind=summary.artifact_kind,
        )
    return _decision_for_state(
        summary.candidate_state,
        subject=(
            "comparison-summary "
            f"{summary.baseline_runset_id}->{summary.candidate_runset_id}"
        ),
        fail_on_warn=fail_on_warn,
        fail_on_not_evaluated=fail_on_not_evaluated,
    )


def gate_evidence_packet(
    packet: EvidencePacket,
    *,
    fail_on_warn: bool = False,
    fail_on_not_evaluated: bool = False,
) -> GateDecision:
    decisions = [
        gate_evaluation_summary(
            packet.evaluation,
            fail_on_warn=fail_on_warn,
            fail_on_not_evaluated=fail_on_not_evaluated,
        )
    ]
    if packet.comparison is not None:
        decisions.append(
            gate_comparison_summary(
                packet.comparison,
                fail_on_warn=fail_on_warn,
                fail_on_not_evaluated=fail_on_not_evaluated,
            )
        )
    for exit_code in (2, 1):
        decision = next(
            (candidate for candidate in decisions if candidate.exit_code == exit_code),
            None,
        )
        if decision is not None:
            return GateDecision(
                exit_code=exit_code,
                message=f"{decision.message}; evidence-packet={packet.packet_id}",
                reason_code=decision.reason_code,
                artifact_kind=packet.artifact_kind,
            )
    return GateDecision(exit_code=0, message=f"ci gate pass: evidence-packet {packet.packet_id}")


def run_ci(
    candidate_runset_path: Path,
    *,
    suite_path: Path,
    out_dir: Path,
    baseline_runset_path: Path | None = None,
    report_mode: ReportMode = "full",
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    today: date | None = None,
    project_root: Path | None = None,
) -> CiRunResult:
    root = (project_root or Path.cwd()).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    environment = environment_with_dependency_inventory(root, out_dir)
    suite = load_compiled_suite(suite_path)
    candidate = _load_runset(candidate_runset_path)
    candidate_report = attach_evaluation_environment(
        evaluate_runset(
            suite,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today or date.today(),
        ),
        environment,
    )
    if report_mode == "fail-fast":
        candidate_report = _fail_fast_evaluation_report(candidate_report)
    report_paths = list(_write_evaluation_outputs(candidate_report, out_dir))
    decision = gate_evaluation_summary(candidate_report.candidate_vs_expectations)
    comparison_summary: ComparisonSummary | None = None
    comparison_paths: tuple[Path, ...] = ()

    if not (report_mode == "fail-fast" and decision.exit_code) and baseline_runset_path is not None:
        baseline = _load_runset(baseline_runset_path)
        comparison_report = _compare_for_ci(
            suite=suite,
            baseline=baseline,
            candidate=candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today or date.today(),
        )
        comparison_report = attach_comparison_environment(comparison_report, environment)
        comparison_paths = _write_comparison_outputs(comparison_report, out_dir)
        report_paths.extend(comparison_paths)
        comparison_summary = comparison_report.comparison_summary
        decision = gate_comparison_summary(comparison_summary)

    packet_path, packet_markdown_path, manifest_path = _write_ci_packet(
        out_dir=out_dir,
        environment=environment,
        evaluation_summary_path=out_dir / "evaluation-summary.json",
        comparison_summary_path=(out_dir / "comparison-summary.json") if comparison_paths else None,
        evaluation_summary=candidate_report.candidate_vs_expectations,
        comparison_summary=comparison_summary,
        suite_path=suite_path,
        candidate_runset_path=candidate_runset_path,
        baseline_runset_path=baseline_runset_path,
        project_root=root,
    )
    report_paths.extend(
        (
            packet_path,
            packet_markdown_path,
            manifest_path,
            out_dir / "dependency-inventory.json",
        )
    )
    diagnostics_path = None
    if decision.exit_code:
        reason_code = decision.reason_code
        if reason_code is ReasonCode.POLICY_FAILED and candidate_report.failed_controls:
            reason_code = candidate_report.failed_controls[0].reason_code
        diagnostics_path = out_dir / "ci-diagnostics.json"
        decision = GateDecision(
            exit_code=decision.exit_code,
            message=decision.message,
            reason_code=reason_code,
            artifact_kind=decision.artifact_kind,
            artifact_path=str(packet_path),
            validator=decision.validator,
        )
        write_diagnostics(decision, diagnostics_path, report_paths=tuple(report_paths))
    return CiRunResult(
        decision=decision,
        report_paths=tuple(report_paths),
        packet_path=packet_path,
        diagnostics_path=diagnostics_path,
    )


def write_diagnostics(
    decision: GateDecision,
    path: Path,
    *,
    report_paths: tuple[Path, ...] = (),
) -> None:
    payload = decision.model_dump()
    payload["report_paths"] = [str(report_path) for report_path in report_paths]
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _decision_for_state(
    state: GateState,
    *,
    subject: str,
    fail_on_warn: bool,
    fail_on_not_evaluated: bool,
) -> GateDecision:
    if state is GateState.fail:
        return GateDecision(exit_code=1, message=f"ci gate fail: {subject} state=fail")
    if state is GateState.warn and fail_on_warn:
        return GateDecision(exit_code=1, message=f"ci gate fail: {subject} state=warn")
    if state is GateState.not_evaluated and fail_on_not_evaluated:
        return GateDecision(
            exit_code=1,
            message=f"ci gate fail: {subject} state=not_evaluated",
        )
    return GateDecision(exit_code=0, message=f"ci gate pass: {subject} state={state.value}")


def _load_runset(path: Path) -> RunSet:
    return RunSet.model_validate(load_json(path))


def _compare_for_ci(
    *,
    suite: CompiledSuite,
    baseline: RunSet,
    candidate: RunSet,
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    today: date,
) -> ComparisonReport:
    try:
        return compare_runsets(
            suite,
            baseline,
            candidate,
            gate_profile=gate_profile,
            waivers=waivers,
            today=today,
        )
    except InvalidComparisonError as exc:
        if exc.report is None:
            raise
        return exc.report


def _fail_fast_evaluation_report(
    report: EvaluationReport,
) -> EvaluationReport:
    first = next((finding for finding in report.failed_controls), None)
    if first is None:
        return report
    summary = report.candidate_vs_expectations.model_copy(update={"findings": (first,)})
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": (first,),
            "warning_controls": (),
        }
    )


def _write_evaluation_outputs(report: EvaluationReport, out_dir: Path) -> tuple[Path, ...]:
    report_json, summary_json = write_evaluation_json(report, out_dir)
    report_md = write_evaluation_markdown(report, out_dir)
    return report_json, summary_json, report_md


def _write_comparison_outputs(report: ComparisonReport, out_dir: Path) -> tuple[Path, ...]:
    report_json, summary_json = write_comparison_json(report, out_dir)
    report_md = write_comparison_markdown(report, out_dir)
    return report_json, summary_json, report_md


def _write_ci_packet(
    *,
    out_dir: Path,
    environment: EnvironmentInfo,
    evaluation_summary_path: Path,
    comparison_summary_path: Path | None,
    evaluation_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary | None,
    suite_path: Path,
    candidate_runset_path: Path,
    baseline_runset_path: Path | None,
    project_root: Path,
) -> tuple[Path, Path, Path]:
    artifact_paths = [
        release_artifact("compiled-suite", suite_path, project_root=project_root),
        release_artifact("candidate-runset", candidate_runset_path, project_root=project_root),
        release_artifact("evaluation-summary", evaluation_summary_path, project_root=project_root),
        release_artifact(
            "dependency-inventory",
            out_dir / "dependency-inventory.json",
            project_root=project_root,
        ),
    ]
    packet_digests = [packet_artifact_digest("evaluation-summary", evaluation_summary_path)]
    if baseline_runset_path is not None:
        artifact_paths.append(
            release_artifact("baseline-runset", baseline_runset_path, project_root=project_root)
        )
    if comparison_summary_path is not None and comparison_summary is not None:
        artifact_paths.append(
            release_artifact(
                "comparison-summary",
                comparison_summary_path,
                project_root=project_root,
            )
        )
        packet_digests.append(packet_artifact_digest("comparison-summary", comparison_summary_path))
    manifest = build_release_manifest(tuple(artifact_paths), environment=environment)
    manifest_path = out_dir / "release-artifact-manifest.json"
    write_release_manifest(manifest, manifest_path)
    packet = build_evidence_packet(
        evaluation_summary,
        comparison=comparison_summary,
        environment=environment,
        release_manifest=manifest,
        artifact_digests=tuple(packet_digests),
    )
    packet_path = out_dir / "evidence-packet.json"
    packet_markdown_path = out_dir / "evidence-packet.md"
    write_evidence_packet(packet, packet_path)
    write_evidence_packet_markdown(packet, packet_markdown_path)
    return packet_path, packet_markdown_path, manifest_path
