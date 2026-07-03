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
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet

EDGE_CASE_ID = "shared-source-multi-claim"
MISSING_CLAIM_ID = "claim-duration"


def run_flagship_demo(out_dir: Path, *, clean: bool) -> dict[str, object]:
    root = prepare_output_dir(out_dir, clean=clean)
    example_dir = copy_example_resource(
        "prior_auth_synthetic",
        root / "example" / "prior_auth_synthetic",
        owner_root=root,
    )
    compiled_path = root / "prior-auth.compiled.json"
    manifest_path = root / "prior-auth.fixture-manifest.json"
    baseline_runset_path = root / "baseline.runset.json"
    candidate_runset_path = root / "candidate-evidence-normalization.runset.json"
    baseline_report_dir = root / "baseline-report"
    candidate_report_dir = root / "evidence-report"
    comparison_report_dir = root / "comparison-report"
    ci_report_dir = root / "ci-report"
    evidence_diff_path = root / "evidence-diff.html"
    summary_path = root / "demo-summary.json"

    suite_yaml = example_dir / "suite.yaml"
    baseline_variant = example_dir / "variants" / "baseline.yaml"
    candidate_variant = example_dir / "variants" / "candidate_evidence_normalization.yaml"

    command_results: list[ExpectedCommandResult] = []
    command_results.append(
        run_cli_command(
            name="compile-suite",
            args=[
                "suite",
                "compile",
                str(suite_yaml),
                "--out",
                str(compiled_path),
                "--manifest",
                str(manifest_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="run-baseline",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(baseline_variant),
                "--manifest",
                str(manifest_path),
                "--out",
                str(baseline_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="run-candidate",
            args=[
                "suite",
                "run",
                str(compiled_path),
                "--variant",
                str(candidate_variant),
                "--manifest",
                str(manifest_path),
                "--out",
                str(candidate_runset_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="evaluate-baseline",
            args=[
                "evaluate",
                str(baseline_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(baseline_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="evaluate-candidate",
            args=[
                "evaluate",
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(candidate_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="compare-runs",
            args=[
                "compare",
                str(baseline_runset_path),
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--out-dir",
                str(comparison_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="ci-report",
            args=[
                "ci",
                str(candidate_runset_path),
                "--suite",
                str(compiled_path),
                "--baseline",
                str(baseline_runset_path),
                "--out-dir",
                str(ci_report_dir),
            ],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    packet_path = ci_report_dir / "evidence-packet.json"
    command_results.append(
        run_cli_command(
            name="ci-gate-packet",
            args=["ci", "gate", str(packet_path)],
            out_dir=root,
            expected_exit_codes={1},
            cwd=root,
        )
    )
    command_results.append(
        run_cli_command(
            name="diff-render",
            args=[
                "diff",
                "render",
                "--baseline",
                str(baseline_runset_path),
                "--candidate",
                str(candidate_runset_path),
                "--comparison",
                str(comparison_report_dir / "comparison-summary.json"),
                "--packet",
                str(packet_path),
                "--out",
                str(evidence_diff_path),
            ],
            out_dir=root,
            expected_exit_codes={0},
            cwd=root,
        )
    )

    summary = _build_summary(
        root=root,
        baseline_runset_path=baseline_runset_path,
        candidate_runset_path=candidate_runset_path,
        baseline_summary_path=baseline_report_dir / "evaluation-summary.json",
        candidate_summary_path=candidate_report_dir / "evaluation-summary.json",
        comparison_summary_path=comparison_report_dir / "comparison-summary.json",
        packet_path=packet_path,
        evidence_diff_path=evidence_diff_path,
        command_results=tuple(command_results),
    )
    _assert_success_summary(summary, root=root)
    write_json(summary_path, summary)
    return summary


def render_flagship_text(summary: dict[str, object]) -> str:
    visible = cast(dict[str, Any], summary["visible_final_output"])
    baseline = cast(dict[str, Any], visible["baseline"])
    candidate = cast(dict[str, Any], visible["candidate"])
    process = cast(dict[str, Any], summary["process_regression"])
    artifacts = cast(dict[str, Any], summary["artifacts"])
    missing_links = cast(list[str], process["missing_evidence_links"])
    reason_codes = cast(list[str], summary["blocking_reason_codes"])
    return "\n".join(
        (
            "agent-assure flagship demo",
            "",
            "Final visible output:",
            f"  case: {visible['case_id']}",
            (
                "  baseline:  "
                f"recommendation={baseline['recommendation']}; outcome={baseline['outcome']}"
            ),
            (
                "  candidate: "
                f"recommendation={candidate['recommendation']}; outcome={candidate['outcome']}"
            ),
            f"  decision fields: {summary['output_equivalence']}",
            "",
            "Process assurance:",
            f"  missing evidence link: {', '.join(missing_links)}",
            f"  reason: {', '.join(reason_codes)}",
            f"  fixture equivalence: {process['fixture_equivalence']}",
            f"  classification: {process['classification']}",
            "",
            "CI gate:",
            "  blocked as expected",
            "",
            "Artifacts:",
            f"  {artifacts['summary']}",
            f"  {artifacts['baseline_report']}",
            f"  {artifacts['candidate_report']}",
            f"  {artifacts['comparison_report']}",
            f"  {artifacts['evidence_packet']}",
            f"  {artifacts['evidence_diff_html']}",
            "",
            "Demo result:",
            "  success: matching decision fields, process regression caught",
        )
    )


def _build_summary(
    *,
    root: Path,
    baseline_runset_path: Path,
    candidate_runset_path: Path,
    baseline_summary_path: Path,
    candidate_summary_path: Path,
    comparison_summary_path: Path,
    packet_path: Path,
    evidence_diff_path: Path,
    command_results: tuple[ExpectedCommandResult, ...],
) -> dict[str, object]:
    baseline_runset = _load_runset(baseline_runset_path)
    candidate_runset = _load_runset(candidate_runset_path)
    baseline_summary = _load_evaluation_summary(baseline_summary_path)
    candidate_summary = _load_evaluation_summary(candidate_summary_path)
    comparison_summary = _load_comparison_summary(comparison_summary_path)
    packet = _load_packet(packet_path)
    baseline_run = _run_by_case(baseline_runset, EDGE_CASE_ID)
    candidate_run = _run_by_case(candidate_runset, EDGE_CASE_ID)
    blocking_reason_codes = sorted(
        {
            finding.reason_code.value
            for finding in candidate_summary.findings
            if finding.state is GateState.fail
        }
    )
    missing_links = sorted(
        _claim_id_from_target(finding.target)
        for finding in candidate_summary.findings
        if finding.reason_code is ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
        and finding.target.startswith("claim:")
    )
    expected_regression_caught = _expected_regression_caught(
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        comparison_summary=comparison_summary,
        baseline_run=baseline_run,
        candidate_run=candidate_run,
        blocking_reason_codes=blocking_reason_codes,
        missing_links=missing_links,
        command_results=command_results,
    )
    return {
        "demo": "flagship",
        "status": "success" if expected_regression_caught else "failure",
        "underlying_exit_code": _underlying_exit_code(tuple(command_results)),
        "output_equivalence": (
            "preserved"
            if _visible_output(baseline_run) == _visible_output(candidate_run)
            else "changed"
        ),
        "expected_regression_caught": expected_regression_caught,
        "blocking_reason_codes": blocking_reason_codes,
        "visible_final_output": {
            "case_id": EDGE_CASE_ID,
            "baseline": {
                "recommendation": baseline_run.recommendation,
                "outcome": baseline_run.outcome,
            },
            "candidate": {
                "recommendation": candidate_run.recommendation,
                "outcome": candidate_run.outcome,
            },
        },
        "process_regression": {
            "missing_evidence_links": missing_links,
            "candidate_state": candidate_summary.state.value,
            "baseline_state": baseline_summary.state.value,
            "classification": comparison_summary.classification.value,
            "fixture_equivalence": comparison_summary.fixture_equivalence_state.value,
            "ci_blocked_as_expected": _command_exit(command_results, "ci-report") == 1,
            "packet_gate_blocked_as_expected": _command_exit(command_results, "ci-gate-packet")
            == 1,
        },
        "artifacts": {
            "summary": artifact_path(root / "demo-summary.json", root=root),
            "compiled_suite": artifact_path(root / "prior-auth.compiled.json", root=root),
            "fixture_manifest": artifact_path(root / "prior-auth.fixture-manifest.json", root=root),
            "baseline_runset": artifact_path(baseline_runset_path, root=root),
            "candidate_runset": artifact_path(candidate_runset_path, root=root),
            "baseline_report": artifact_path(
                root / "baseline-report" / "evaluation-report.md",
                root=root,
            ),
            "candidate_report": artifact_path(
                root / "evidence-report" / "evaluation-report.md",
                root=root,
            ),
            "comparison_report": artifact_path(
                root / "comparison-report" / "comparison-report.md",
                root=root,
            ),
            "evidence_packet": artifact_path(packet_path, root=root),
            "evidence_diff_html": artifact_path(evidence_diff_path, root=root),
        },
        "packet_id": packet.packet_id,
        "commands": [result.model_dump(root=root) for result in command_results],
    }


def _expected_regression_caught(
    *,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    baseline_run: AgentRunRecord,
    candidate_run: AgentRunRecord,
    blocking_reason_codes: list[str],
    missing_links: list[str],
    command_results: tuple[ExpectedCommandResult, ...],
) -> bool:
    return (
        baseline_summary.state is GateState.pass_
        and candidate_summary.state is GateState.fail
        and _visible_output(baseline_run) == _visible_output(candidate_run)
        and baseline_run.recommendation == candidate_run.recommendation == "approve"
        and baseline_run.outcome == candidate_run.outcome == "approve"
        and missing_links == [MISSING_CLAIM_ID]
        and blocking_reason_codes == [ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value]
        and comparison_summary.classification is ComparisonClassification.new_failure
        and comparison_summary.fixture_equivalence_state is GateState.pass_
        and _command_exit(command_results, "ci-report") == 1
        and _command_exit(command_results, "ci-gate-packet") == 1
        and all(result.matched for result in command_results)
    )


def _assert_success_summary(summary: dict[str, object], *, root: Path) -> None:
    if summary["status"] != "success":
        raise DemoError("flagship demo did not prove the expected same-output process regression")
    artifacts = cast(dict[str, str], summary["artifacts"])
    required_artifact_names = (
        "summary",
        "baseline_report",
        "candidate_report",
        "comparison_report",
        "evidence_packet",
        "evidence_diff_html",
    )
    for name in required_artifact_names:
        relative_path = artifacts[name]
        if not relative_path:
            raise DemoError(f"flagship demo summary omitted artifact path: {name}")
        if name == "summary":
            continue
        if not (root / relative_path).exists():
            raise DemoError(f"flagship demo artifact is missing: {relative_path}")


def _load_runset(path: Path) -> RunSet:
    return RunSet.model_validate_json(path.read_text(encoding="utf-8"))


def _load_evaluation_summary(path: Path) -> EvaluationSummary:
    return EvaluationSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_comparison_summary(path: Path) -> ComparisonSummary:
    return ComparisonSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_packet(path: Path) -> EvidencePacket:
    return EvidencePacket.model_validate_json(path.read_text(encoding="utf-8"))


def _run_by_case(runset: RunSet, case_id: str) -> AgentRunRecord:
    for run in runset.runs:
        if run.case_id == case_id:
            return run
    raise DemoError(f"expected case is missing from run set {runset.runset_id}: {case_id}")


def _visible_output(run: AgentRunRecord) -> tuple[str, str]:
    return run.recommendation, run.outcome


def _claim_id_from_target(target: str) -> str:
    return target.removeprefix("claim:")


def _command_exit(results: tuple[ExpectedCommandResult, ...], name: str) -> int | None:
    for result in results:
        if result.name == name:
            return result.actual_exit_code
    return None


def _underlying_exit_code(results: tuple[ExpectedCommandResult, ...]) -> int:
    for name in ("ci-gate-packet", "ci-report", "compare-runs", "evaluate-candidate"):
        exit_code = _command_exit(results, name)
        if exit_code is not None:
            return exit_code
    return 0
