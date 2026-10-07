from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
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
    _aggregate_condition_coverage_state,
    _project_control_coverage_limitations,
    _project_observed_evidence_refs,
    _validate_control_coverage_item_collections,
    _validate_control_coverage_review_contract,
)
from agent_assure.schema.validation import validate_loaded_artifact_payload


def write_control_coverage_report(
    report: ControlCoverageReport,
    out_dir: Path,
) -> tuple[Path, Path]:
    report = _validated_control_coverage_report(report)
    payload = redact_artifact_payload(
        report.model_dump(mode="json", warnings="error"),
        preserve_keys=PRESERVE_PACKET_KEYS,
    )
    validated = ControlCoverageReport.model_validate(payload)
    validate_loaded_artifact_payload(payload, "control-coverage-report")
    safe_payload = validated.model_dump(mode="json", warnings="error")
    if redact_artifact_payload(safe_payload, preserve_keys=PRESERVE_PACKET_KEYS) != safe_payload:
        raise ValueError("control coverage report could not be made privacy-safe")
    rendered = render_control_coverage_markdown(validated)
    json_text = json.dumps(safe_payload, indent=2, sort_keys=True) + "\n"
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "control-coverage-report.json"
    markdown_path = out_dir / "control-coverage-report.md"
    write_text_atomic(
        json_path,
        json_text,
    )
    write_text_atomic(
        markdown_path,
        rendered,
    )
    return json_path, markdown_path


def render_control_coverage_markdown(report: ControlCoverageReport) -> str:
    report = _validated_control_coverage_report(report)
    # Derive display-only totals from the typed source items. Normal construction
    # validates the persisted counter, while this keeps rendering trustworthy if
    # an internal caller bypasses validation with model_construct/model_copy.
    item_states = tuple(
        (
            item.control_id,
            _aggregate_condition_coverage_state(item.condition_evaluations),
        )
        for item in report.items
    )
    _validate_control_coverage_review_contract(
        report,
        item_states=item_states,
        validate_persisted_limitations=False,
    )
    coverage_state_counts = Counter(state.value for _control_id, state in item_states)
    limitations = _project_control_coverage_limitations(
        report.framework,
        report.limitations,
    )
    lines = [
        "# Control Coverage Report",
        "",
        "## Claim Boundary",
        "",
    ]
    lines.extend(f"- {markdown_text(limitation)}" for limitation in limitations)
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
    if coverage_state_counts:
        lines.extend(
            f"- {markdown_code_span(state)}: `{count}`"
            for state, count in sorted(coverage_state_counts.items())
        )
    else:
        lines.append("- No mapped items.")
    lines.extend(["", "## Mapped Items", ""])
    for item in report.items:
        lines.extend(_item_lines(item))
    return "\n".join(lines).rstrip() + "\n"


def _validated_control_coverage_report(
    report: ControlCoverageReport,
) -> ControlCoverageReport:
    payload = report.model_dump(mode="json", warnings="error")
    validated = ControlCoverageReport.model_validate(payload)
    validate_loaded_artifact_payload(payload, "control-coverage-report")
    return validated


def _item_lines(item: ControlCoverageItem) -> list[str]:
    _validate_control_coverage_item_collections(item)
    coverage_state = _aggregate_condition_coverage_state(item.condition_evaluations)
    evidence_refs = _project_observed_evidence_refs(item.condition_evaluations)
    lines = [
        f"### {markdown_code_span(item.control_id)} {markdown_text(item.title)}",
        "",
        f"- State: {markdown_code_span(coverage_state.value)}",
    ]
    if item.mapping_strength is not None:
        lines.append(f"- Mapping strength: {markdown_code_span(item.mapping_strength.value)}")
    if item.atlas_tactic_ids:
        lines.append("- ATLAS tactics: " + _code_list(item.atlas_tactic_ids))
    if item.atlas_technique_ids:
        lines.append("- ATLAS techniques: " + _code_list(item.atlas_technique_ids))
    lines.extend(["", "Evidence:"])
    if evidence_refs:
        lines.extend(f"- {_evidence_ref_line(ref)}" for ref in evidence_refs)
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
