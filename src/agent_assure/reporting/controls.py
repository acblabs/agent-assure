from __future__ import annotations

import json
from pathlib import Path

from agent_assure.privacy.redaction import (
    PRESERVE_PACKET_KEYS,
    redact_artifact_payload,
    redact_text,
)
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
    lines.extend(f"- {redact_text(limitation)}" for limitation in report.limitations)
    lines.extend(
        [
            "",
            "## Framework Evidence Mapping",
            "",
            f"- Framework: `{report.framework.value}`",
            f"- Framework version: `{redact_text(report.framework_version)}`",
            f"- Mapping version: `{redact_text(report.mapping_version)}`",
            f"- Mapping digest: `{report.mapping_digest}`",
            f"- Evidence packet: `{redact_text(report.evidence_packet_id)}`",
            f"- Evidence packet digest: `{report.evidence_packet_digest}`",
            "",
            "## State Counts",
            "",
        ]
    )
    if report.coverage_state_counts:
        lines.extend(
            f"- `{state}`: `{count}`"
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
        f"### `{redact_text(item.control_id)}` {redact_text(item.title)}",
        "",
        f"- State: `{item.coverage_state.value}`",
    ]
    if item.mapping_strength is not None:
        lines.append(f"- Mapping strength: `{item.mapping_strength.value}`")
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
        lines.extend(f"- {redact_text(limitation)}" for limitation in item.limitations)
    lines.append("")
    return lines


def _condition_line(evaluation: ControlConditionEvaluation) -> str:
    observed = "observed" if evaluation.observed else "not_observed"
    condition = (
        f" condition `{redact_text(evaluation.condition)}`"
        if evaluation.condition is not None
        else ""
    )
    return (
        f"- `{redact_text(evaluation.rule_id)}` `{evaluation.signal}`{condition}: "
        f"`{observed}` -> `{evaluation.coverage_state.value}`; "
        f"{redact_text(evaluation.rationale)}"
    )


def _evidence_ref_line(ref: ControlEvidenceRef) -> str:
    parts = [
        f"`{redact_text(ref.evidence_kind)}`",
        f"`{redact_text(ref.evidence_id)}`",
        f"`{redact_text(ref.field_path)}`",
    ]
    if ref.evidence_digest:
        parts.append(f"`{ref.evidence_digest}`")
    return " ".join(parts) + f" - {redact_text(ref.description)}"


def _code_list(values: tuple[str, ...]) -> str:
    return ", ".join(f"`{redact_text(value)}`" for value in values)
