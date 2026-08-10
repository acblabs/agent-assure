from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
    read_file_bounded,
)
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.schema.efficacy import (
    ControlEfficacyGateDecision,
    ControlEfficacyGateProfile,
    ControlEfficacyReport,
    ExactRate,
    derive_control_efficacy_gate_decision,
)

CONTROL_EFFICACY_REPORT_FILENAME = "control-efficacy-report.json"
CONTROL_EFFICACY_MARKDOWN_FILENAME = "control-efficacy-report.md"
MAX_RENDERED_EFFICACY_MARKDOWN_CHARS = 1024 * 1024
MAX_RENDERED_EFFICACY_LIST_ITEMS = 128
MAX_RENDERED_EFFICACY_TEXT_CHARS = 2048


@dataclass(frozen=True)
class ControlEfficacyArtifactPaths:
    report: Path
    markdown: Path


def write_control_efficacy_report(
    report: ControlEfficacyReport,
    out_dir: Path,
    *,
    gate_decision: ControlEfficacyGateDecision | None = None,
    gate_profile: ControlEfficacyGateProfile | None = None,
) -> ControlEfficacyArtifactPaths:
    """Atomically write the validated report and its deterministic review view."""
    _validate_gate_arguments(gate_profile=gate_profile, gate_decision=gate_decision)
    # Re-validation before persistence protects callers which bypassed normal
    # construction through Pydantic's low-level model_construct API.
    report = ControlEfficacyReport.model_validate(report.model_dump(mode="json"))
    payload = report.model_dump(mode="json")
    rendered = render_control_efficacy_markdown(
        report,
        gate_decision=gate_decision,
        gate_profile=gate_profile,
    )
    report_path = out_dir / CONTROL_EFFICACY_REPORT_FILENAME
    markdown_path = out_dir / CONTROL_EFFICACY_MARKDOWN_FILENAME
    write_text_atomic(
        report_path,
        json.dumps(
            payload,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
        )
        + "\n",
    )
    write_text_atomic(markdown_path, rendered)
    return ControlEfficacyArtifactPaths(report=report_path, markdown=markdown_path)


def load_control_efficacy_report(path: Path) -> ControlEfficacyReport:
    contents = read_file_bounded(
        path,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="control-efficacy report",
    )
    payload = load_json_bytes_bounded(
        contents.data,
        label="control-efficacy report",
    )
    return ControlEfficacyReport.model_validate(payload)


def render_control_efficacy_markdown(
    report: ControlEfficacyReport,
    *,
    gate_decision: ControlEfficacyGateDecision | None = None,
    gate_profile: ControlEfficacyGateProfile | None = None,
) -> str:
    """Render a bounded deterministic view without inventing decimal scores."""
    _validate_gate_arguments(gate_profile=gate_profile, gate_decision=gate_decision)
    report = ControlEfficacyReport.model_validate(report.model_dump(mode="json"))
    if gate_decision is not None:
        if gate_profile is None:
            raise ValueError("gate profile and decision must be supplied together")
        gate_profile = ControlEfficacyGateProfile.model_validate(
            gate_profile.model_dump(mode="json")
        )
        gate_decision = ControlEfficacyGateDecision.model_validate(
            gate_decision.model_dump(mode="json")
        )
        _validate_gate_decision_report_binding(report, gate_profile, gate_decision)
    lines = [
        "# Control Efficacy Report",
        "",
        "## Claim Boundary",
        "",
        *(f"- {_bounded_markdown_text(limitation)}" for limitation in report.limitations),
        "",
        "## Evidence Identity",
        "",
        f"- Report digest: {markdown_code_span(report.report_digest)}",
        f"- Campaign digest: {markdown_code_span(report.campaign_digest)}",
        f"- Catalog: {markdown_code_span(report.catalog_id)}",
        f"- Catalog digest: {markdown_code_span(report.catalog_digest)}",
        f"- Threat manifest digest: {markdown_code_span(report.threat_manifest_digest)}",
        "",
        "## Semantic Evidence State",
        "",
        f"- Control efficacy: {markdown_code_span(report.semantic_state.value)}",
        f"- Threat scope: {markdown_code_span(report.threat_scope_state.value)}",
        "- These semantic states are computed independently of gate-profile effects.",
        "",
        "## Exact Catalog Metrics",
        "",
        "- Catalog detector kill ratio (`catalog_kill_rate`): "
        f"{_rate_text(report.catalog_kill_rate)}",
        f"- Canonical catalog operators: `{len(report.canonical_operator_ids)}`",
        f"- Canonical invariant families: `{len(report.canonical_invariant_families)}`",
        f"- Selected operators: `{len(report.selected_operator_ids)}`",
        f"- Completed selected operators: `{len(report.operator_outcomes)}`",
        f"- Pending selected operators: `{len(report.pending_operator_ids)}`",
        f"- Applicable operators: `{report.applicable_operator_count}`",
        f"- Caught: `{report.caught_operator_count}`",
        f"- Survived: `{report.survived_operator_count}`",
        f"- Inapplicable: `{report.inapplicable_operator_count}`",
        f"- Invalid operator: `{report.invalid_operator_count}`",
        f"- Invalid subject: `{report.invalid_subject_count}`",
        f"- Execution error: `{report.execution_error_count}`",
        f"- Required survivors: `{report.required_survivor_count}`",
        f"- Critical survivors: `{report.critical_survivor_count}`",
        *_gate_decision_lines(gate_decision),
        "",
        "## Independence Strata",
        "",
        "| Independence class | Independent coverage eligible | Caught | Survived | "
        "Inapplicable | Invalid operator | Invalid subject | Execution error | Kill rate |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for stratum in report.kill_rate_by_independence_class:
        counts = stratum.state_counts
        eligible = "yes" if stratum.independent_challenge_eligible else "no"
        lines.append(
            f"| {markdown_code_span(stratum.stratum)} | {eligible} | {counts.caught} | "
            f"{counts.survived} | {counts.inapplicable} | {counts.invalid_operator} | "
            f"{counts.invalid_subject} | {counts.execution_error} | "
            f"{_rate_text(stratum.kill_rate)} |"
        )

    lines.extend(
        [
            "",
            "## Invariant-Family Strata",
            "",
            "| Invariant family | Caught | Survived | Inapplicable | Invalid operator | "
            "Invalid subject | Execution error | Kill rate |",
            "|---|---:|---:|---:|---:|---:|---:|---|",
        ]
    )
    for stratum in report.kill_rate_by_invariant_family:
        counts = stratum.state_counts
        lines.append(
            f"| {markdown_code_span(stratum.stratum)} | {counts.caught} | "
            f"{counts.survived} | {counts.inapplicable} | {counts.invalid_operator} | "
            f"{counts.invalid_subject} | {counts.execution_error} | "
            f"{_rate_text(stratum.kill_rate)} |"
        )

    lines.extend(
        [
            "",
            "## Threat Applicability and Challenge Coverage",
            "",
            f"- Applicable threat categories: `{report.applicable_threat_category_count}`",
            f"- Challenged threat categories: `{report.challenged_threat_category_count}`",
            "- Independently challenged threat categories: "
            f"`{report.independently_challenged_threat_category_count}`",
            f"- Challenge rate: {_rate_text(report.threat_challenge_rate)}",
            f"- Independent challenge rate: {_rate_text(report.independent_threat_challenge_rate)}",
            f"- Critical uncovered threats: `{report.critical_uncovered_threat_count}`",
            f"- Unknown applicability: `{report.unknown_applicability_count}`",
            f"- Catalog threat references absent from manifest: "
            f"`{report.unscoped_catalog_threat_count}`",
            "- Critical uncovered threat IDs: "
            + _code_list_or_none(report.critical_uncovered_threat_ids),
            "- Unknown-applicability threat IDs: "
            + _code_list_or_none(report.unknown_applicability_threat_ids),
            "- Catalog threat IDs absent from manifest: "
            + _code_list_or_none(report.unscoped_catalog_threat_ids),
            "",
            "## Operator Outcomes",
            "",
            "| Operator | State | Applicability | Invariant family | Independence class | "
            "Required | Critical applicable threat |",
            "|---|---|---|---|---|---:|---:|",
        ]
    )
    for outcome in report.operator_outcomes:
        lines.append(
            f"| {markdown_code_span(outcome.operator_id)} | "
            f"{markdown_code_span(outcome.state.value)} | "
            f"{markdown_code_span(outcome.applicability.value)} | "
            f"{markdown_code_span(outcome.invariant_family)} | "
            f"{markdown_code_span(outcome.independence_class.value)} | "
            f"{'yes' if outcome.required else 'no'} | "
            f"{'yes' if outcome.critical_threat_ids else 'no'} |"
        )

    return _bounded_markdown(lines, report_digest=report.report_digest)


def _rate_text(rate: ExactRate) -> str:
    return f"`{rate.numerator}/{rate.denominator}` ({markdown_code_span(rate.state.value)})"


def _code_list_or_none(values: tuple[str, ...]) -> str:
    if not values:
        return "`none`"
    visible = values[:MAX_RENDERED_EFFICACY_LIST_ITEMS]
    rendered = ", ".join(markdown_code_span(value) for value in visible)
    omitted = len(values) - len(visible)
    if omitted:
        rendered += (
            f", _{omitted} additional IDs omitted from this bounded Markdown view; "
            "see the validated JSON report_"
        )
    return rendered


def _bounded_markdown_text(value: str) -> str:
    visible = value[:MAX_RENDERED_EFFICACY_TEXT_CHARS]
    rendered = markdown_text(visible)
    omitted = len(value) - len(visible)
    if omitted:
        rendered += (
            f" _[{omitted} characters omitted from this bounded Markdown view; "
            "see the validated JSON report]_"
        )
    return rendered


def _gate_decision_lines(
    gate_decision: ControlEfficacyGateDecision | None,
) -> tuple[str, ...]:
    if gate_decision is None:
        return ()
    lines = [
        "",
        "## Gate-Profile Decision",
        "",
        f"- Profile: {markdown_code_span(gate_decision.profile_id)}",
        f"- Decision: {markdown_code_span(gate_decision.state.value)}",
    ]
    if gate_decision.findings:
        lines.extend(
            "- "
            + markdown_code_span(finding.reason_code.value)
            + ": effect "
            + markdown_code_span(finding.effect.value)
            + "; operators "
            + _code_list_or_none(finding.operator_ids)
            + "; threats "
            + _code_list_or_none(finding.threat_ids)
            for finding in gate_decision.findings
        )
    else:
        lines.append("- No gate-profile rule was triggered.")
    return tuple(lines)


def _bounded_markdown(lines: list[str], *, report_digest: str) -> str:
    rendered = "\n".join(lines).rstrip() + "\n"
    if len(rendered) <= MAX_RENDERED_EFFICACY_MARKDOWN_CHARS:
        return rendered

    kept_count = len(lines)
    kept_character_count = sum(len(line) for line in lines)
    while kept_count:
        omitted_line_count = len(lines) - kept_count
        notice = [
            "",
            "## Bounded Markdown Notice",
            "",
            "- This reviewer view was truncated at a complete line; the validated JSON "
            "report remains authoritative.",
            f"- Omitted Markdown lines: `{omitted_line_count}`",
            f"- Authoritative report digest: {markdown_code_span(report_digest)}",
        ]
        candidate_character_count = (
            kept_character_count + sum(len(line) for line in notice) + kept_count + len(notice)
        )
        if candidate_character_count <= MAX_RENDERED_EFFICACY_MARKDOWN_CHARS:
            return "\n".join((*lines[:kept_count], *notice)).rstrip() + "\n"
        kept_count -= 1
        kept_character_count -= len(lines[kept_count])

    # The production limit is much larger than this fixed notice. This branch
    # keeps the helper total if a caller deliberately lowers the constant.
    return "# Control Efficacy Report\n\n_Bounded Markdown view truncated; see JSON._\n"[
        :MAX_RENDERED_EFFICACY_MARKDOWN_CHARS
    ]


def _validate_gate_arguments(
    *,
    gate_profile: ControlEfficacyGateProfile | None,
    gate_decision: ControlEfficacyGateDecision | None,
) -> None:
    if (gate_profile is None) != (gate_decision is None):
        raise ValueError("gate profile and decision must be supplied together")


def _validate_gate_decision_report_binding(
    report: ControlEfficacyReport,
    profile: ControlEfficacyGateProfile,
    decision: ControlEfficacyGateDecision,
) -> None:
    expected = derive_control_efficacy_gate_decision(report, profile)
    if decision != expected:
        raise ValueError("gate decision must exactly match the control-efficacy report and profile")
