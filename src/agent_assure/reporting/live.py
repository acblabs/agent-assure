from __future__ import annotations

import json
from pathlib import Path

from agent_assure.privacy.redaction import (
    PRESERVE_PACKET_KEYS,
    redact_artifact_payload,
)
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.schema.live import (
    LiveComparisonReport,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveTrajectoryReport,
)


def write_live_evaluation_json(report: LiveEvaluationReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-evaluation-report.json"
    _write_json(report.model_dump(mode="json"), path)
    return path


def write_live_comparison_json(report: LiveComparisonReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-comparison-report.json"
    _write_json(report.model_dump(mode="json"), path)
    return path


def write_live_drift_json(report: LiveDriftReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-drift-report.json"
    _write_json(report.model_dump(mode="json"), path)
    return path


def write_live_trajectory_json(report: LiveTrajectoryReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-trajectory-report.json"
    _write_json(report.model_dump(mode="json"), path)
    return path


def write_live_evaluation_markdown(report: LiveEvaluationReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-evaluation-report.md"
    path.write_text(render_live_evaluation_markdown(report), encoding="utf-8", newline="\n")
    return path


def write_live_comparison_markdown(report: LiveComparisonReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-comparison-report.md"
    path.write_text(render_live_comparison_markdown(report), encoding="utf-8", newline="\n")
    return path


def write_live_drift_markdown(report: LiveDriftReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-drift-report.md"
    path.write_text(render_live_drift_markdown(report), encoding="utf-8", newline="\n")
    return path


def write_live_trajectory_markdown(report: LiveTrajectoryReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "live-trajectory-report.md"
    path.write_text(render_live_trajectory_markdown(report), encoding="utf-8", newline="\n")
    return path


def render_live_evaluation_markdown(report: LiveEvaluationReport) -> str:
    lines = [
        "# Live Evaluation Report",
        "",
        "## Summary",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Run set: {markdown_code_span(report.runset_id)}",
        f"- Suite: {markdown_code_span(report.suite_id)} "
        f"version {markdown_code_span(report.suite_version)}",
        f"- Completion status: {markdown_code_span(report.completion_status)}",
        f"- Stop reasons: {markdown_code_span(', '.join(report.stop_reasons) or 'none')}",
        f"- Observations: `{report.overall.observations}`",
        f"- Expectation pass rate: `{report.overall.expectation_pass_rate.rate}`",
        f"- Cluster mean pass rate: `{report.overall.expectation_pass_rate.cluster_mean_rate}`",
        f"- Mean-cluster design effect: `{report.overall.expectation_pass_rate.design_effect}`",
        "- Largest-cluster sensitivity: "
        f"size=`{report.overall.expectation_pass_rate.largest_cluster_size}` "
        "design_effect="
        f"`{report.overall.expectation_pass_rate.largest_cluster_design_effect}` "
        "effective_n="
        f"`{report.overall.expectation_pass_rate.largest_cluster_effective_n}`",
        "- Confidence interval around "
        f"{markdown_code_span(report.overall.expectation_pass_rate.interval_center)} "
        f"(`{report.overall.expectation_pass_rate.interval_center_value}`): "
        f"`{report.overall.expectation_pass_rate.ci_lower}` to "
        f"`{report.overall.expectation_pass_rate.ci_upper}`",
        "",
        "## Provider And Model Groups",
        "",
    ]
    for group in report.groups:
        lines.extend(
            [
                f"- {markdown_code_span(group.group_id)} observations=`{group.observations}` "
                f"pass_rate=`{group.expectation_pass_rate.rate}` "
                f"cluster_mean=`{group.expectation_pass_rate.cluster_mean_rate}` "
                f"ci_center=`{group.expectation_pass_rate.interval_center}` "
                f"largest_cluster_size=`{group.expectation_pass_rate.largest_cluster_size}` "
                f"latency_p50_ms=`{group.latency_ms.p50 or 'not_evaluated'}` "
                f"cost_total_usd=`{group.estimated_cost_usd.total or 'not_evaluated'}`",
            ]
        )
    lines.extend(["", "## Observation Provenance", ""])
    for observation in report.observations:
        lines.append(
            f"- {markdown_code_span(observation.case_id)} "
            f"repetition=`{observation.repetition_index}` "
            f"tool_schema={markdown_code_span(observation.tool_schema_digest)} "
            f"policy_bundle={markdown_code_span(observation.policy_bundle_digest)}"
        )
    lines.extend(["", "## Reason-Code Rates", ""])
    if report.overall.reason_code_rates:
        lines.extend(
            f"- {markdown_code_span(rate.label)}: "
            f"`{rate.numerator}` / `{rate.denominator}` = `{rate.rate}`"
            for rate in report.overall.reason_code_rates
        )
    else:
        lines.append("No reason-code findings were observed.")
    lines.extend(["", "## Statistical Invariants", ""])
    if report.statistical_invariants:
        for invariant in report.statistical_invariants:
            lines.append(
                f"- {markdown_code_span(invariant.endpoint_id)} "
                f"{markdown_code_span(invariant.interpretation)} "
                f"{markdown_code_span(invariant.prerequisite_status)} "
                f"rate=`{invariant.rate}` clusters=`{invariant.cluster_count}` "
                f"method={markdown_code_span(invariant.analysis_method)}"
            )
            if invariant.rare_event_bound is not None:
                bound = invariant.rare_event_bound
                lines.append(
                    f"  - {markdown_code_span(bound.interval_sidedness)} "
                    f"{markdown_code_span(bound.confidence_level)} bound: "
                    f"events=`{bound.observed_events}` exposure=`{bound.exposure}` "
                    f"upper_rate=`{bound.upper_rate_bound}`"
                )
            if invariant.cluster_correlation is not None:
                correlation = invariant.cluster_correlation
                lines.append(
                    "  - cluster correlation: "
                    f"planned=`{correlation.planned_intraclass_correlation}` "
                    f"observed=`{correlation.observed_intraclass_correlation or 'not_evaluated'}` "
                    f"ci=`{correlation.ci_lower or 'not_evaluated'}`.."
                    f"`{correlation.ci_upper or 'not_evaluated'}` "
                    f"confirmatory_use=`{correlation.confirmatory_use}`"
                )
    else:
        lines.append("No advanced statistical endpoints were declared.")
    lines.extend(["", "## Observation Findings", ""])
    failing = [observation for observation in report.observations if observation.findings]
    if failing:
        for observation in failing:
            for finding in observation.findings:
                lines.append(
                    f"- {markdown_code_span(observation.case_id)} "
                    f"repetition=`{observation.repetition_index}` "
                    f"{markdown_code_span(finding.control_id)} "
                    f"{markdown_code_span(finding.reason_code.value)} "
                    f"{markdown_code_span(finding.state.value)}: "
                    f"{markdown_text(finding.message)}"
                )
    else:
        lines.append("No observation-level findings were emitted.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def render_live_comparison_markdown(report: LiveComparisonReport) -> str:
    lines = [
        "# Live Comparison Report",
        "",
        "## Summary",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Baseline run set: {markdown_code_span(report.baseline_runset_id)}",
        f"- Candidate run set: {markdown_code_span(report.candidate_runset_id)}",
        f"- Suite: {markdown_code_span(report.suite_id)} "
        f"version {markdown_code_span(report.suite_version)}",
        f"- Baseline group: {markdown_code_span(report.baseline_group_id)}",
        f"- Candidate group: {markdown_code_span(report.candidate_group_id)}",
        f"- Exploratory: {markdown_code_span(str(report.exploratory).lower())}",
        f"- Compared clusters: `{report.compared_clusters}`",
        f"- Effective sample size: `{report.effective_n}`",
        f"- Baseline pass rate: `{report.baseline_pass_rate.rate}`",
        f"- Candidate pass rate: `{report.candidate_pass_rate.rate}`",
        f"- Pass-rate difference: `{report.pass_rate_difference}`",
        f"- Difference interval: `{report.difference_ci_lower}` to "
        f"`{report.difference_ci_upper}`",
        f"- Non-inferiority margin: `{report.non_inferiority_margin}`",
        "",
        "## Operational Deltas",
        "",
        f"- p50 latency difference ms: `{report.latency_p50_difference_ms or 'not_evaluated'}`",
        f"- total cost difference USD: `{report.cost_total_difference_usd or 'not_evaluated'}`",
        "",
        "## Randomization Tests",
        "",
    ]
    if report.randomization_tests:
        for test in report.randomization_tests:
            lines.append(
                f"- {markdown_code_span(test.endpoint_id)} "
                f"{markdown_code_span(test.analysis_method)} "
                f"{markdown_code_span(test.prerequisite_status)} "
                f"p=`{test.p_value or 'not_evaluated'}` "
                f"adjusted_p=`{test.adjusted_p_value or 'not_evaluated'}` "
                f"clusters=`{test.compared_clusters}` resamples=`{test.resamples}`"
            )
    else:
        lines.append("No paired randomization test was declared.")
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {markdown_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def render_live_drift_markdown(report: LiveDriftReport) -> str:
    lines = [
        "# Live Drift Report",
        "",
        "## Summary",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Monitoring status: {markdown_code_span(report.monitoring_status)}",
        f"- Interpretation: {markdown_code_span(report.interpretation)}",
        f"- Suite: {markdown_code_span(report.suite_id)} "
        f"version {markdown_code_span(report.suite_version)}",
        f"- Protocol: {markdown_code_span(report.protocol_id or 'not_evaluated')}",
        f"- Drift plan: {markdown_code_span(report.drift_plan_id or 'default')}",
        f"- Ordering variable: {markdown_code_span(report.ordering_variable)}",
        "- Observation window: "
        f"{markdown_code_span(report.observation_window_start_utc or 'unknown')} to "
        f"{markdown_code_span(report.observation_window_end_utc or 'unknown')}",
        "",
        "## Comparability",
        "",
        f"- Status: {markdown_code_span(report.comparability.status)}",
        f"- Windows: `{report.comparability.compared_windows}`",
        f"- Suite matches: {markdown_code_span(str(report.comparability.suite_matches).lower())}",
        f"- Baseline mode matches: "
        f"{markdown_code_span(str(report.comparability.baseline_mode_matches).lower())}",
        f"- Analysis method matches: "
        f"{markdown_code_span(str(report.comparability.analysis_method_matches).lower())}",
        f"- Protocol digest matches: "
        f"{markdown_code_span(str(report.comparability.protocol_digest_matches).lower())}",
        f"- Material fields match: "
        f"{markdown_code_span(str(report.comparability.material_fields_match).lower())}",
        f"- Tool-schema digest matches: "
        f"{markdown_code_span(str(report.comparability.tool_schema_digest_matches).lower())}",
        f"- Policy-bundle digest matches: "
        f"{markdown_code_span(str(report.comparability.policy_bundle_digest_matches).lower())}",
        "",
        "## Windows",
        "",
    ]
    for window in report.windows:
        lines.append(
            f"- {markdown_code_span(window.window_id)} "
            f"runset={markdown_code_span(window.runset_id)} "
            f"observations=`{window.observations}` "
            f"included=`{window.included_observations}` "
            f"excluded=`{window.excluded_observations}` "
            f"start={markdown_code_span(window.observation_window_start_utc or 'unknown')} "
            f"end={markdown_code_span(window.observation_window_end_utc or 'unknown')} "
            "provider_version_unknown="
            f"{markdown_code_span(str(window.provider_version_unknown).lower())}"
        )
    lines.extend(["", "## Metric Diagnostics", ""])
    for diagnostic in report.diagnostics:
        lines.append(
            f"- {markdown_code_span(diagnostic.label)} "
            f"metric={markdown_code_span(diagnostic.metric)} "
            f"{markdown_code_span(diagnostic.interpretation)} "
            f"{markdown_code_span(diagnostic.prerequisite_status)} "
            f"windows=`{diagnostic.windows}` missing=`{diagnostic.missing_windows}` "
            f"first=`{diagnostic.first_value or 'not_evaluated'}` "
            f"last=`{diagnostic.last_value or 'not_evaluated'}` "
            f"slope=`{diagnostic.slope_per_window or 'not_evaluated'}` "
            f"max_step=`{diagnostic.max_step_change or 'not_evaluated'}` "
            f"stationarity={markdown_code_span(diagnostic.stationarity_signal)} "
            f"dependence={markdown_code_span(diagnostic.dependence_signal)}"
        )
        if diagnostic.state_estimate is not None:
            estimate = diagnostic.state_estimate
            lines.append(
                f"  - {markdown_code_span(estimate.state_name)} level="
                f"`{estimate.latest_level or 'not_evaluated'}` drift="
                f"`{estimate.latest_drift_per_window or 'not_evaluated'}` "
                f"alpha=`{estimate.smoothing_alpha}`"
            )
        for reason in diagnostic.review_reasons:
            lines.append(f"  - review signal: {markdown_text(reason)}")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(limitation)}" for limitation in report.limitations)
    if report.comparability.failures:
        lines.extend(["", "## Comparability Failures", ""])
        lines.extend(f"- {markdown_text(failure)}" for failure in report.comparability.failures)
    return "\n".join(lines) + "\n"


def render_live_trajectory_markdown(report: LiveTrajectoryReport) -> str:
    lines = [
        "# Live Trajectory Report",
        "",
        "## Summary",
        "",
        f"- State: {markdown_code_span(report.state.value)}",
        f"- Trajectory status: {markdown_code_span(report.trajectory_status)}",
        f"- Interpretation: {markdown_code_span(report.interpretation)}",
        f"- Run set: {markdown_code_span(report.runset_id)}",
        f"- Suite: {markdown_code_span(report.suite_id)} "
        f"version {markdown_code_span(report.suite_version)}",
        f"- Protocol: {markdown_code_span(report.protocol_id or 'not_evaluated')}",
        f"- Trajectory plan: {markdown_code_span(report.trajectory_plan_id or 'default')}",
        f"- Observations: `{report.observations}`",
        f"- Included: `{report.included_observations}`",
        f"- Excluded: `{report.excluded_observations}`",
        f"- Transition assumption: {markdown_code_span(report.transition_assumption)} "
        f"{markdown_code_span(report.transition_assumption_status)}",
        "",
        "## Paths",
        "",
    ]
    for path in report.paths:
        lines.append(
            f"- {markdown_code_span(path.case_id)} repetition=`{path.repetition_index}` "
            f"terminal={markdown_code_span(path.terminal_state)} "
            f"transitions=`{path.transition_count}` "
            f"states={markdown_code_span(' -> '.join(path.states))} "
            f"tools=`{path.tool_count}` claims=`{path.claim_count}` "
            f"links=`{path.claim_evidence_link_count}` "
            f"review_required={markdown_code_span(str(path.human_review_required).lower())} "
            f"review_performed={markdown_code_span(str(path.human_review_performed).lower())}"
        )
    lines.extend(["", "## Transition Summary", ""])
    for transition in report.transitions:
        lines.append(
            f"- {markdown_code_span(transition.from_state)} -> "
            f"{markdown_code_span(transition.to_state)} "
            f"count=`{transition.count}` from_state_count=`{transition.from_state_count}` "
            f"frequency=`{transition.conditional_frequency}` "
            f"{markdown_code_span(transition.prerequisite_status)}"
        )
    lines.extend(["", "## Trajectory Invariants", ""])
    for invariant in report.invariants:
        lines.append(
            f"- {markdown_code_span(invariant.invariant_id)} "
            f"{markdown_code_span(invariant.category)} "
            f"{markdown_code_span(invariant.prerequisite_status)} "
            f"state={markdown_code_span(invariant.state.value)} affected="
            f"`{invariant.affected_observations}` / `{invariant.evaluated_observations}`"
        )
    lines.extend(["", "## History-Dependent Checks", ""])
    for check in report.history_dependent_checks:
        lines.append(
            f"- {markdown_code_span(check.check_id)} "
            f"{markdown_code_span(check.prerequisite_status)} "
            f"affected=`{check.affected_observations}` dependency="
            f"{markdown_text(check.dependency)}"
        )
    lines.extend(["", "## Operational Event Processes", ""])
    for process in report.event_processes:
        lines.append(
            f"- {markdown_code_span(process.event_type)} events=`{process.observed_events}` "
            f"exposure=`{process.exposure}` rate=`{process.event_rate}` "
            f"{markdown_code_span(process.prerequisite_status)} "
            f"burst={markdown_code_span(process.burst_signal)} "
            f"max_window_count=`{process.max_events_in_burst_window}` "
            f"timestamped=`{process.timestamped_events}` "
            f"missing_timestamps=`{process.missing_timestamp_events}`"
        )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {markdown_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def _write_json(payload: dict[str, object], path: Path) -> None:
    path.write_text(
        json.dumps(
            redact_artifact_payload(payload, preserve_keys=PRESERVE_PACKET_KEYS),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
