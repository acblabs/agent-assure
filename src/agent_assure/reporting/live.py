from __future__ import annotations

import json
from pathlib import Path

from agent_assure.privacy.redaction import (
    PRESERVE_PACKET_KEYS,
    redact_artifact_payload,
    redact_text,
)
from agent_assure.schema.live import LiveComparisonReport, LiveDriftReport, LiveEvaluationReport


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


def render_live_evaluation_markdown(report: LiveEvaluationReport) -> str:
    lines = [
        "# Live Evaluation Report",
        "",
        "## Summary",
        "",
        f"- State: `{report.state.value}`",
        f"- Run set: `{report.runset_id}`",
        f"- Suite: `{report.suite_id}` version `{report.suite_version}`",
        f"- Completion status: `{report.completion_status}`",
        f"- Stop reasons: `{', '.join(report.stop_reasons) or 'none'}`",
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
        f"`{report.overall.expectation_pass_rate.interval_center}` "
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
                f"- `{redact_text(group.group_id)}` observations=`{group.observations}` "
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
            f"- `{observation.case_id}` repetition=`{observation.repetition_index}` "
            f"tool_schema=`{observation.tool_schema_digest}` "
            f"policy_bundle=`{observation.policy_bundle_digest}`"
        )
    lines.extend(["", "## Reason-Code Rates", ""])
    if report.overall.reason_code_rates:
        lines.extend(
            f"- `{rate.label}`: `{rate.numerator}` / `{rate.denominator}` = `{rate.rate}`"
            for rate in report.overall.reason_code_rates
        )
    else:
        lines.append("No reason-code findings were observed.")
    lines.extend(["", "## Statistical Invariants", ""])
    if report.statistical_invariants:
        for invariant in report.statistical_invariants:
            lines.append(
                f"- `{redact_text(invariant.endpoint_id)}` "
                f"`{invariant.interpretation}` `{invariant.prerequisite_status}` "
                f"rate=`{invariant.rate}` clusters=`{invariant.cluster_count}` "
                f"method=`{invariant.analysis_method}`"
            )
            if invariant.rare_event_bound is not None:
                bound = invariant.rare_event_bound
                lines.append(
                    f"  - upper `{bound.confidence_level}` bound: "
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
                    f"- `{observation.case_id}` repetition=`{observation.repetition_index}` "
                    f"`{finding.control_id}` `{finding.reason_code.value}` "
                    f"`{finding.state.value}`: {redact_text(finding.message)}"
                )
    else:
        lines.append("No observation-level findings were emitted.")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def render_live_comparison_markdown(report: LiveComparisonReport) -> str:
    lines = [
        "# Live Comparison Report",
        "",
        "## Summary",
        "",
        f"- State: `{report.state.value}`",
        f"- Baseline run set: `{report.baseline_runset_id}`",
        f"- Candidate run set: `{report.candidate_runset_id}`",
        f"- Suite: `{report.suite_id}` version `{report.suite_version}`",
        f"- Baseline group: `{redact_text(report.baseline_group_id)}`",
        f"- Candidate group: `{redact_text(report.candidate_group_id)}`",
        f"- Exploratory: `{str(report.exploratory).lower()}`",
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
                f"- `{redact_text(test.endpoint_id)}` `{test.analysis_method}` "
                f"`{test.prerequisite_status}` p=`{test.p_value or 'not_evaluated'}` "
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
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def render_live_drift_markdown(report: LiveDriftReport) -> str:
    lines = [
        "# Live Drift Report",
        "",
        "## Summary",
        "",
        f"- State: `{report.state.value}`",
        f"- Monitoring status: `{report.monitoring_status}`",
        f"- Interpretation: `{report.interpretation}`",
        f"- Suite: `{report.suite_id}` version `{report.suite_version}`",
        f"- Protocol: `{report.protocol_id or 'not_evaluated'}`",
        f"- Drift plan: `{redact_text(report.drift_plan_id or 'default')}`",
        f"- Ordering variable: `{report.ordering_variable}`",
        f"- Observation window: `{report.observation_window_start_utc or 'unknown'}` to "
        f"`{report.observation_window_end_utc or 'unknown'}`",
        "",
        "## Comparability",
        "",
        f"- Status: `{report.comparability.status}`",
        f"- Windows: `{report.comparability.compared_windows}`",
        f"- Suite matches: `{str(report.comparability.suite_matches).lower()}`",
        f"- Baseline mode matches: "
        f"`{str(report.comparability.baseline_mode_matches).lower()}`",
        f"- Analysis method matches: "
        f"`{str(report.comparability.analysis_method_matches).lower()}`",
        f"- Protocol digest matches: "
        f"`{str(report.comparability.protocol_digest_matches).lower()}`",
        f"- Material fields match: "
        f"`{str(report.comparability.material_fields_match).lower()}`",
        f"- Tool-schema digest matches: "
        f"`{str(report.comparability.tool_schema_digest_matches).lower()}`",
        f"- Policy-bundle digest matches: "
        f"`{str(report.comparability.policy_bundle_digest_matches).lower()}`",
        "",
        "## Windows",
        "",
    ]
    for window in report.windows:
        lines.append(
            f"- `{window.window_id}` runset=`{window.runset_id}` "
            f"observations=`{window.observations}` "
            f"included=`{window.included_observations}` "
            f"excluded=`{window.excluded_observations}` "
            f"start=`{window.observation_window_start_utc or 'unknown'}` "
            f"end=`{window.observation_window_end_utc or 'unknown'}` "
            f"provider_version_unknown=`{str(window.provider_version_unknown).lower()}`"
        )
    lines.extend(["", "## Metric Diagnostics", ""])
    for diagnostic in report.diagnostics:
        lines.append(
            f"- `{diagnostic.label}` metric=`{diagnostic.metric}` "
            f"`{diagnostic.interpretation}` `{diagnostic.prerequisite_status}` "
            f"windows=`{diagnostic.windows}` missing=`{diagnostic.missing_windows}` "
            f"first=`{diagnostic.first_value or 'not_evaluated'}` "
            f"last=`{diagnostic.last_value or 'not_evaluated'}` "
            f"slope=`{diagnostic.slope_per_window or 'not_evaluated'}` "
            f"max_step=`{diagnostic.max_step_change or 'not_evaluated'}` "
            f"stationarity=`{diagnostic.stationarity_signal}` "
            f"dependence=`{diagnostic.dependence_signal}`"
        )
        if diagnostic.state_estimate is not None:
            estimate = diagnostic.state_estimate
            lines.append(
                f"  - `{estimate.state_name}` level="
                f"`{estimate.latest_level or 'not_evaluated'}` drift="
                f"`{estimate.latest_drift_per_window or 'not_evaluated'}` "
                f"alpha=`{estimate.smoothing_alpha}`"
            )
        for reason in diagnostic.review_reasons:
            lines.append(f"  - review signal: {redact_text(reason)}")
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    if report.comparability.failures:
        lines.extend(["", "## Comparability Failures", ""])
        lines.extend(f"- {redact_text(failure)}" for failure in report.comparability.failures)
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
