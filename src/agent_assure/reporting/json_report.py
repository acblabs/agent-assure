from __future__ import annotations

import json
from pathlib import Path

from agent_assure.evaluation.evaluator import EvaluationReport


def write_evaluation_json(report: EvaluationReport, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / "evaluation-report.json"
    summary_path = out_dir / "evaluation-summary.json"
    # Preserve model field order so machine reports lead with candidate vs expectations.
    report_path.write_text(
        json.dumps(report.model_dump(mode="json"), indent=2) + "\n",
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(
            report.candidate_vs_expectations.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return report_path, summary_path
