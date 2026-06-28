from __future__ import annotations

import json
from pathlib import Path

from agent_assure.privacy.redaction import (
    PRESERVE_PACKET_KEYS,
    redact_artifact_payload,
    redact_text,
)
from agent_assure.schema.live import LiveComparisonReport, LiveEvaluationReport


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
        "## Limitations",
        "",
    ]
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
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
