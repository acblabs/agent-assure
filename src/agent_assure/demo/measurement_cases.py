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
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.packet import EvidencePacket
from agent_assure.schema.run import AgentRunRecord, RunSet

MEASUREMENT_CASES_NOTICE = (
    "This is a process-assurance fixture suite, not a benchmark against other tools."
)
MEASUREMENT_CASES_TITLE = "Process assurance cases"
_EXPECTED_CASE_IDS = (
    "same-output-missing-evidence",
    "same-output-provider-boundary",
    "same-output-human-review-bypassed",
    "same-output-redaction-state-changed",
    "same-output-retry-storm",
    "same-output-usage-cost-delta",
    "different-output-no-process-regression",
)
_BLOCKING_REASON_CODES = (
    ReasonCode.FORBIDDEN_PROVIDER.value,
    ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value,
    ReasonCode.RAW_SENSITIVE_CONTENT.value,
    ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT.value,
)


def run_measurement_cases_demo(out_dir: Path, *, clean: bool) -> dict[str, object]:
    root = prepare_output_dir(out_dir, clean=clean)
    example_dir = copy_example_resource(
        "process_measurement_cases",
        root / "example" / "process_measurement_cases",
        owner_root=root,
    )
    compiled_path = root / "process-measurement.compiled.json"
    manifest_path = root / "process-measurement.fixture-manifest.json"
    baseline_runset_path = root / "baseline.runset.json"
    candidate_runset_path = root / "candidate-process-regressions.runset.json"
    baseline_report_dir = root / "baseline-report"
    candidate_report_dir = root / "candidate-report"
    comparison_report_dir = root / "comparison-report"
    ci_report_dir = root / "ci-report"
    evidence_diff_path = root / "evidence-diff.html"
    summary_path = root / "demo-summary.json"

    suite_yaml = example_dir / "suite.yaml"
    baseline_variant = example_dir / "variants" / "baseline.yaml"
    candidate_variant = example_dir / "variants" / "candidate_process_regressions.yaml"

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
                "--title",
                MEASUREMENT_CASES_TITLE,
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


def render_measurement_cases_text(summary: dict[str, object]) -> str:
    artifacts = cast(dict[str, Any], summary["artifacts"])
    blocking_reason_codes = cast(list[str], summary["blocking_reason_codes"])
    advisory = cast(dict[str, Any], summary["advisory_observations"])
    raw_usage_delta = advisory.get("usage_delta")
    usage_delta = cast(dict[str, Any], raw_usage_delta) if isinstance(raw_usage_delta, dict) else {}
    return "\n".join(
        (
            "agent-assure measurement cases demo",
            "",
            MEASUREMENT_CASES_NOTICE,
            "",
            "Process assurance:",
            f"  baseline state: {summary['baseline_state']}",
            f"  candidate state: {summary['candidate_state']}",
            f"  classification: {summary['classification']}",
            f"  fixture equivalence: {summary['fixture_equivalence']}",
            f"  blocking reasons: {', '.join(blocking_reason_codes)}",
            "",
            "Observable process changes:",
            "  missing evidence link: same-output-missing-evidence",
            "  provider/model changed: same-output-provider-boundary",
            "  human review bypassed: same-output-human-review-bypassed",
            "  residual sensitive metadata: same-output-redaction-state-changed",
            f"  suite aggregate retry delta: {usage_delta.get('total_retries_delta')}",
            (
                "  suite aggregate declared cost delta micro-USD: "
                f"{usage_delta.get('estimated_cost_microusd_delta')}"
            ),
            "  different output, no process regression: different-output-no-process-regression",
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
            "  success: process regressions surfaced without benchmark claims",
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
    case_summaries = _case_summaries(
        baseline_runset,
        candidate_runset,
        candidate_summary,
    )
    blocking_reason_codes = sorted(
        {
            finding.reason_code.value
            for finding in candidate_summary.findings
            if finding.state is GateState.fail
        }
    )
    usage_delta = comparison_summary.usage_delta
    expected_regressions_caught = _expected_regressions_caught(
        baseline_summary=baseline_summary,
        candidate_summary=candidate_summary,
        comparison_summary=comparison_summary,
        case_summaries=case_summaries,
        blocking_reason_codes=blocking_reason_codes,
        command_results=command_results,
    )
    return {
        "demo": "measurement-cases",
        "status": "success" if expected_regressions_caught else "failure",
        "notice": MEASUREMENT_CASES_NOTICE,
        "underlying_exit_code": _underlying_exit_code(command_results),
        "expected_regressions_caught": expected_regressions_caught,
        "baseline_state": baseline_summary.state.value,
        "candidate_state": candidate_summary.state.value,
        "classification": comparison_summary.classification.value,
        "fixture_equivalence": comparison_summary.fixture_equivalence_state.value,
        "blocking_reason_codes": blocking_reason_codes,
        "cases": case_summaries,
        "advisory_observations": {
            "provider_boundary_changed_case": "same-output-provider-boundary",
            "retry_storm_case": "same-output-retry-storm",
            "usage_cost_delta_case": "same-output-usage-cost-delta",
            "different_output_no_process_regression_case": (
                "different-output-no-process-regression"
            ),
            "usage_delta": (
                usage_delta.model_dump(mode="json") if usage_delta is not None else None
            ),
        },
        "artifacts": {
            "summary": artifact_path(root / "demo-summary.json", root=root),
            "compiled_suite": artifact_path(root / "process-measurement.compiled.json", root=root),
            "fixture_manifest": artifact_path(
                root / "process-measurement.fixture-manifest.json",
                root=root,
            ),
            "baseline_runset": artifact_path(baseline_runset_path, root=root),
            "candidate_runset": artifact_path(candidate_runset_path, root=root),
            "baseline_report": artifact_path(
                root / "baseline-report" / "evaluation-report.md",
                root=root,
            ),
            "candidate_report": artifact_path(
                root / "candidate-report" / "evaluation-report.md",
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


def _case_summaries(
    baseline: RunSet,
    candidate: RunSet,
    candidate_summary: EvaluationSummary,
) -> list[dict[str, object]]:
    baseline_by_case = {run.case_id: run for run in baseline.runs}
    candidate_by_case = {run.case_id: run for run in candidate.runs}
    findings_by_case: dict[str, list[Finding]] = {}
    for finding in candidate_summary.findings:
        findings_by_case.setdefault(finding.case_id, []).append(finding)
    summaries: list[dict[str, object]] = []
    for case_id in _EXPECTED_CASE_IDS:
        base = baseline_by_case[case_id]
        cand = candidate_by_case[case_id]
        summaries.append(
            {
                "case_id": case_id,
                "visible_output": (
                    "preserved" if _visible_output(base) == _visible_output(cand) else "changed"
                ),
                "changed_process_fields": list(_changed_process_fields(base, cand)),
                "findings": [
                    {
                        "control_id": finding.control_id,
                        "reason_code": finding.reason_code.value,
                        "target": finding.target,
                    }
                    for finding in findings_by_case.get(case_id, ())
                ],
            }
        )
    return summaries


def _changed_process_fields(
    baseline: AgentRunRecord,
    candidate: AgentRunRecord,
) -> tuple[str, ...]:
    changed: list[str] = []
    if _linked_claims(baseline) != _linked_claims(candidate):
        changed.append("claim-evidence links")
    if (baseline.provider, baseline.model) != (candidate.provider, candidate.model):
        changed.append("provider/model")
    if _human_review_state(baseline) != _human_review_state(candidate):
        changed.append("human review")
    if _evidence_sources(baseline) != _evidence_sources(candidate):
        changed.append("evidence sources")
    if (
        baseline.attempt_count,
        baseline.retry_count,
        baseline.rate_limit_events,
        baseline.latency_ms,
    ) != (
        candidate.attempt_count,
        candidate.retry_count,
        candidate.rate_limit_events,
        candidate.latency_ms,
    ):
        changed.append("operational counters")
    if baseline.usage_summary != candidate.usage_summary:
        changed.append("measured usage")
    return tuple(changed)


def _expected_regressions_caught(
    *,
    baseline_summary: EvaluationSummary,
    candidate_summary: EvaluationSummary,
    comparison_summary: ComparisonSummary,
    case_summaries: list[dict[str, object]],
    blocking_reason_codes: list[str],
    command_results: tuple[ExpectedCommandResult, ...],
) -> bool:
    cases_by_id = {str(item["case_id"]): item for item in case_summaries}
    usage_delta = comparison_summary.usage_delta
    return (
        baseline_summary.state is GateState.pass_
        and candidate_summary.state is GateState.fail
        and comparison_summary.classification is ComparisonClassification.new_failure
        and comparison_summary.fixture_equivalence_state is GateState.pass_
        and blocking_reason_codes == sorted(_BLOCKING_REASON_CODES)
        and "claim-evidence links"
        in _case_changed_fields(cases_by_id, "same-output-missing-evidence")
        and _case_has_finding(
            cases_by_id,
            "same-output-missing-evidence",
            ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
            target="claim:claim-policy-support",
        )
        and _case_visible_output(cases_by_id, "same-output-human-review-bypassed")
        == "preserved"
        and "provider/model" in _case_changed_fields(cases_by_id, "same-output-provider-boundary")
        and "human review" in _case_changed_fields(cases_by_id, "same-output-provider-boundary")
        and _case_has_finding(
            cases_by_id,
            "same-output-provider-boundary",
            ReasonCode.FORBIDDEN_PROVIDER,
            target="provider:alternate-process-provider",
        )
        and "human review"
        in _case_changed_fields(cases_by_id, "same-output-human-review-bypassed")
        and _case_has_finding(
            cases_by_id,
            "same-output-human-review-bypassed",
            ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
            target="human_review_required",
        )
        and "evidence sources"
        in _case_changed_fields(cases_by_id, "same-output-redaction-state-changed")
        and _case_has_finding(
            cases_by_id,
            "same-output-redaction-state-changed",
            ReasonCode.RAW_SENSITIVE_CONTENT,
            target="evidence_refs[0].source_id",
        )
        and "operational counters" in _case_changed_fields(cases_by_id, "same-output-retry-storm")
        and "measured usage" in _case_changed_fields(cases_by_id, "same-output-usage-cost-delta")
        and _case_visible_output(cases_by_id, "different-output-no-process-regression")
        == "changed"
        and _case_changed_fields(cases_by_id, "different-output-no-process-regression") == []
        and usage_delta is not None
        and usage_delta.comparison_state == "observed"
        and (usage_delta.total_retries_delta or 0) > 0
        and (usage_delta.estimated_cost_microusd_delta or 0) > 0
        and _command_exit(command_results, "ci-report") == 1
        and _command_exit(command_results, "ci-gate-packet") == 1
        and all(result.matched for result in command_results)
    )


def _case_visible_output(cases_by_id: dict[str, dict[str, object]], case_id: str) -> str:
    return str(cases_by_id[case_id]["visible_output"])


def _case_changed_fields(cases_by_id: dict[str, dict[str, object]], case_id: str) -> list[str]:
    return cast(list[str], cases_by_id[case_id]["changed_process_fields"])


def _case_has_finding(
    cases_by_id: dict[str, dict[str, object]],
    case_id: str,
    reason_code: ReasonCode,
    *,
    target: str,
) -> bool:
    findings = cast(list[dict[str, str]], cases_by_id[case_id]["findings"])
    return any(
        finding.get("reason_code") == reason_code.value and finding.get("target") == target
        for finding in findings
    )


def _assert_success_summary(summary: dict[str, object], *, root: Path) -> None:
    if summary["status"] != "success":
        raise DemoError("measurement cases demo did not surface the expected process evidence")
    artifacts = cast(dict[str, str], summary["artifacts"])
    for name in (
        "summary",
        "baseline_report",
        "candidate_report",
        "comparison_report",
        "evidence_packet",
        "evidence_diff_html",
    ):
        relative_path = artifacts[name]
        if not relative_path:
            raise DemoError(f"measurement cases demo summary omitted artifact path: {name}")
        if name == "summary":
            continue
        if not (root / relative_path).exists():
            raise DemoError(f"measurement cases demo artifact is missing: {relative_path}")


def _load_runset(path: Path) -> RunSet:
    return RunSet.model_validate_json(path.read_text(encoding="utf-8"))


def _load_evaluation_summary(path: Path) -> EvaluationSummary:
    return EvaluationSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_comparison_summary(path: Path) -> ComparisonSummary:
    return ComparisonSummary.model_validate_json(path.read_text(encoding="utf-8"))


def _load_packet(path: Path) -> EvidencePacket:
    return EvidencePacket.model_validate_json(path.read_text(encoding="utf-8"))


def _visible_output(run: AgentRunRecord) -> tuple[str, str]:
    return run.recommendation, run.outcome


def _linked_claims(run: AgentRunRecord) -> tuple[tuple[str, str], ...]:
    return tuple(sorted((link.claim_id, link.evidence_ref_id) for link in run.claim_evidence_links))


def _evidence_sources(run: AgentRunRecord) -> tuple[str, ...]:
    return tuple(sorted(ref.source_id for ref in run.evidence_refs))


def _human_review_state(run: AgentRunRecord) -> tuple[bool, bool]:
    return run.human_review_required, run.human_review_performed


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
