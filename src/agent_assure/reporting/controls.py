from __future__ import annotations

import json
from pathlib import Path

from agent_assure.privacy.redaction import (
    PRESERVE_PACKET_KEYS,
    redact_artifact_payload,
)
from agent_assure.reporting.markdown_safety import markdown_code_span, markdown_text
from agent_assure.schema.controls import (
    ControlConditionEvaluation,
    ControlCoverageItem,
    ControlCoverageReport,
    ControlEvidenceRef,
)


def write_control_coverage_report(
    report: ControlCoverageReport,
    out_dir: Path,
) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "control-coverage-report.json"
    markdown_path = out_dir / "control-coverage-report.md"
    payload = redact_artifact_payload(
        report.model_dump(mode="json"),
        preserve_keys=PRESERVE_PACKET_KEYS,
    )
    ControlCoverageReport.model_validate(payload)
    json_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    markdown_path.write_text(
        render_control_coverage_markdown(report),
        encoding="utf-8",
        newline="\n",
    )
    return json_path, markdown_path


def render_control_coverage_markdown(report: ControlCoverageReport) -> str:
    lines = [
        "# Control Coverage Report",
        "",
        "## Claim Boundary",
        "",
    ]
    lines.extend(f"- {markdown_text(limitation)}" for limitation in report.limitations)
    lines.extend(
        [
            "",
            "## Framework Evidence Mapping",
            "",
            f"- Framework: {markdown_code_span(report.framework.value)}",
            f"- Framework version: {markdown_code_span(report.framework_version)}",
            f"- Mapping version: {markdown_code_span(report.mapping_version)}",
            f"- Mapping digest: {markdown_code_span(report.mapping_digest)}",
            f"- Evidence packet: {markdown_code_span(report.evidence_packet_id)}",
            f"- Evidence packet digest: {markdown_code_span(report.evidence_packet_digest)}",
            "",
            "## State Counts",
            "",
        ]
    )
    if report.coverage_state_counts:
        lines.extend(
            f"- {markdown_code_span(state)}: `{count}`"
            for state, count in sorted(report.coverage_state_counts.items())
        )
    else:
        lines.append("- No mapped items.")
    lines.extend(["", "## Mapped Items", ""])
    for item in report.items:
        lines.extend(_item_lines(item))
    return "\n".join(lines).rstrip() + "\n"


def _item_lines(item: ControlCoverageItem) -> list[str]:
    lines = [
        f"### {markdown_code_span(item.control_id)} {markdown_text(item.title)}",
        "",
        f"- State: {markdown_code_span(item.coverage_state.value)}",
    ]
    if item.mapping_strength is not None:
        lines.append(
            f"- Mapping strength: {markdown_code_span(item.mapping_strength.value)}"
        )
    if item.atlas_tactic_ids:
        lines.append("- ATLAS tactics: " + _code_list(item.atlas_tactic_ids))
    if item.atlas_technique_ids:
        lines.append("- ATLAS techniques: " + _code_list(item.atlas_technique_ids))
    lines.extend(["", "Evidence:"])
    if item.evidence_refs:
        lines.extend(f"- {_evidence_ref_line(ref)}" for ref in item.evidence_refs)
    else:
        lines.append("- `not_observed`")
    lines.extend(["", "Conditions:"])
    lines.extend(_condition_line(evaluation) for evaluation in item.condition_evaluations)
    if item.limitations:
        lines.extend(["", "Limitations:"])
        lines.extend(f"- {markdown_text(limitation)}" for limitation in item.limitations)
    lines.append("")
    return lines


def _condition_line(evaluation: ControlConditionEvaluation) -> str:
    observed = "observed" if evaluation.observed else "not_observed"
    condition = (
        f" condition {markdown_code_span(evaluation.condition)}"
        if evaluation.condition is not None
        else ""
    )
    return (
        f"- {markdown_code_span(evaluation.rule_id)} "
        f"{markdown_code_span(evaluation.signal)}{condition}: "
        f"{markdown_code_span(observed)} -> "
        f"{markdown_code_span(evaluation.coverage_state.value)}; "
        f"{markdown_text(evaluation.rationale)}"
    )


def _evidence_ref_line(ref: ControlEvidenceRef) -> str:
    parts = [
        markdown_code_span(ref.evidence_kind),
        markdown_code_span(ref.evidence_id),
        markdown_code_span(ref.field_path),
    ]
    if ref.evidence_digest:
        parts.append(markdown_code_span(ref.evidence_digest))
    return " ".join(parts) + f" - {markdown_text(ref.description)}"


def _code_list(values: tuple[str, ...]) -> str:
    return ", ".join(markdown_code_span(value) for value in values)
