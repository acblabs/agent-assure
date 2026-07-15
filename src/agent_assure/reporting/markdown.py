from __future__ import annotations

from pathlib import Path

from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.privacy.redaction import redact_text
from agent_assure.reporting.usage import prefixed_usage_summary_lines, usage_summary_lines
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.evaluation import Finding
from agent_assure.usage.aggregation import format_usage_delta


def render_evaluation_markdown(report: EvaluationReport) -> str:
    summary = report.candidate_vs_expectations
    lines = [
        "# Evaluation Report",
        "",
        "## Candidate vs Expectations",
        "",
        f"- State: `{summary.state.value}`",
        f"- Run set: `{report.runset_id}`",
        f"- Suite: `{report.suite_id}` version `{report.suite_version}`",
        f"- Gate profile: `{report.gate_profile}`",
        "",
        "## Why the Candidate Passed or Failed",
        "",
    ]
    if summary.state is GateState.pass_:
        lines.append(
            "The candidate satisfies the compiled expectations and deterministic controls "
            "evaluated for this fixture suite."
        )
    else:
        lines.extend(_finding_lines(summary.findings))
    lines.extend(
        [
            "",
            "## Failed Controls",
            "",
        ]
    )
    lines.extend(_finding_lines(report.failed_controls) or ["No blocking controls failed."])
    lines.extend(
        [
            "",
            "## Warning Controls",
            "",
        ]
    )
    lines.extend(_finding_lines(report.warning_controls) or ["No warning controls were emitted."])
    lines.extend(
        [
            "",
            "## Not-Evaluated Capabilities",
            "",
        ]
    )
    lines.extend(
        f"- `{capability.capability_id}`: `{capability.state.value}` - "
        f"{redact_text(capability.reason)}"
        for capability in report.not_evaluated_capabilities
    )
    lines.extend(
        [
            "",
            "## Metrics",
            "",
            f"- Total cases: `{report.metrics.total_cases}`",
            f"- Evaluated cases: `{report.metrics.evaluated_cases}`",
            f"- Unevaluated cases: `{report.metrics.unevaluated_cases}`",
            f"- Passed cases: `{report.metrics.passed_cases}`",
            f"- Failed cases: `{report.metrics.failed_cases}`",
            f"- Blocking findings: `{report.metrics.blocking_findings}`",
            f"- Global blocking findings: `{report.metrics.global_blocking_findings}`",
            f"- Warning findings: `{report.metrics.warning_findings}`",
            "",
            "Warn-only and waived case findings do not count as failed cases. "
            "Gate-profile-filtered fail findings count as failed cases and warning controls. "
            "Passed, failed, and unevaluated cases partition total cases. "
            "Global gate failures are reported separately from case pass/fail counts.",
            "",
            "## Measured Usage",
            "",
        ]
    )
    lines.extend(usage_summary_lines(report.usage_summary))
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def write_evaluation_markdown(report: EvaluationReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "evaluation-report.md"
    path.write_text(render_evaluation_markdown(report), encoding="utf-8", newline="\n")
    return path


def render_comparison_markdown(report: ComparisonReport) -> str:
    summary = report.comparison_summary
    lines = [
        "# Comparison Report",
        "",
        "## Candidate vs Expectations",
        "",
        f"- State: `{report.candidate_vs_expectations.state.value}`",
        f"- Candidate run set: `{summary.candidate_runset_id}`",
        f"- Suite: `{report.suite_id}` version `{report.suite_version}`",
        f"- Classification: `{summary.classification.value}`",
        "",
        "## Why the Candidate Passed or Failed",
        "",
    ]
    lines.extend(f"- {redact_text(line)}" for line in report.verdict_explanations)
    lines.extend(
        [
            "",
            "## Fixture-Equivalence Result",
            "",
            f"- State: `{report.fixture_equivalence.state.value}`",
        ]
    )
    lines.extend(
        _finding_lines(report.fixture_equivalence.findings)
        or ["Baseline and candidate runs reference equivalent fixture material."]
    )
    lines.extend(
        [
            "",
            "## Baseline vs Expectations",
            "",
            f"- State: `{report.baseline_vs_expectations.state.value}`",
            f"- Baseline run set: `{summary.baseline_runset_id}`",
        ]
    )
    lines.extend(_finding_lines(report.baseline_vs_expectations.findings) or ["No findings."])
    lines.extend(
        [
            "",
            "## Baseline-to-Candidate Control Changes",
            "",
        ]
    )
    if report.control_changes:
        lines.extend(
            (
                f"- `{change.classification.value}` `{change.case_id}` "
                f"`{change.control_id}` `{change.reason_code.value}` "
                f"`{redact_text(change.target)}`: {redact_text(change.message)}"
            )
            for change in report.control_changes
        )
    else:
        lines.append("No verdict-bearing control changes were found.")
    if report.behavioral_changes:
        lines.append("")
        lines.append(f"{_behavioral_change_heading(report)}:")
        lines.extend(
            (
                f"- `{change.case_id}` `{change.field}`: "
                f"`{redact_text(change.baseline_value)}` -> "
                f"`{redact_text(change.candidate_value)}`"
            )
            for change in report.behavioral_changes
        )
    lines.extend(
        [
            "",
            "## Provenance Changes",
            "",
        ]
    )
    if report.provenance_changes:
        lines.extend(
            (
                f"- `{change.case_id}` `{change.field}`: "
                f"`{redact_text(change.baseline_value or '<unset>')}` -> "
                f"`{redact_text(change.candidate_value or '<unset>')}`"
            )
            for change in report.provenance_changes
        )
    else:
        lines.append("No provenance changes were found.")
    lines.extend(
        [
            "",
            "## Measured Usage",
            "",
        ]
    )
    lines.extend(_comparison_usage_lines(report))
    lines.extend(
        [
            "",
            "## Not-Evaluated Capabilities",
            "",
        ]
    )
    lines.extend(
        f"- `{capability.capability_id}`: `{capability.state.value}` - "
        f"{redact_text(capability.reason)}"
        for capability in report.not_evaluated_capabilities
    )
    lines.extend(
        [
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def write_comparison_markdown(report: ComparisonReport, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "comparison-report.md"
    path.write_text(render_comparison_markdown(report), encoding="utf-8", newline="\n")
    return path


def _behavioral_change_heading(report: ComparisonReport) -> str:
    if (
        report.comparison_summary.classification
        is ComparisonClassification.allowed_behavioral_change
        or report.comparison_summary.classification
        is ComparisonClassification.allowed_behavioral_and_provenance_change
    ):
        return "Behavioral record changes (non-blocking under current gates)"
    if report.comparison_summary.classification is ComparisonClassification.unchanged:
        return "No comparison changes"
    return "Behavioral record changes"


def _finding_lines(findings: tuple[Finding, ...]) -> list[str]:
    return [
        (
            f"- `{finding.case_id}` `{finding.control_id}` `{redact_text(finding.target)}` "
            f"`{finding.reason_code.value}` "
            f"`{finding.state.value}`: {redact_text(finding.message)}"
        )
        for finding in findings
    ]


def _comparison_usage_lines(report: ComparisonReport) -> list[str]:
    lines = []
    lines.extend(prefixed_usage_summary_lines("Baseline", report.baseline_usage_summary))
    lines.extend(prefixed_usage_summary_lines("Candidate", report.candidate_usage_summary))
    if report.usage_delta is None:
        lines.append("- Usage delta: `not_observed`")
    else:
        lines.append(f"- {redact_text(format_usage_delta(report.usage_delta))}")
    return lines
