from __future__ import annotations

import json
from pathlib import Path

from agent_assure.artifact_io import write_text_atomic
from agent_assure.compare.runsets import ComparisonReport
from agent_assure.evaluation.evaluator import EvaluationReport
from agent_assure.privacy.redaction import PRESERVE_PACKET_KEYS, redact_artifact_payload
from agent_assure.schema.validation import validate_loaded_artifact_payload


def write_evaluation_json(report: EvaluationReport, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "evaluation-report.json"
    summary_path = out_dir / "evaluation-summary.json"
    # Preserve model field order so machine reports lead with candidate vs expectations.
    write_text_atomic(
        report_path,
        json.dumps(
            redact_artifact_payload(
                report.model_dump(mode="json"),
                preserve_keys=PRESERVE_PACKET_KEYS,
            ),
            indent=2,
        )
        + "\n",
    )
    write_text_atomic(
        summary_path,
        json.dumps(
            redact_artifact_payload(
                report.candidate_vs_expectations.model_dump(mode="json"),
                preserve_keys=PRESERVE_PACKET_KEYS,
            ),
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return report_path, summary_path


def write_comparison_json(report: ComparisonReport, out_dir: Path) -> tuple[Path, Path]:
    report_payload = redact_artifact_payload(
        report.model_dump(mode="json"),
        preserve_keys=PRESERVE_PACKET_KEYS,
    )
    summary_payload = redact_artifact_payload(
        report.comparison_summary.model_dump(mode="json"),
        preserve_keys=PRESERVE_PACKET_KEYS,
    )
    validate_loaded_artifact_payload(report_payload, "comparison-report")
    validate_loaded_artifact_payload(summary_payload, "comparison-summary")
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "comparison-report.json"
    summary_path = out_dir / "comparison-summary.json"
    write_text_atomic(
        report_path,
        json.dumps(
            report_payload,
            indent=2,
        )
        + "\n",
    )
    write_text_atomic(
        summary_path,
        json.dumps(
            summary_payload,
            indent=2,
            sort_keys=True,
        )
        + "\n",
    )
    return report_path, summary_path
