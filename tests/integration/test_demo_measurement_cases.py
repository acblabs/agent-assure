from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from typer.testing import CliRunner

from agent_assure.cli.demo_cmd import _strict_exit_code
from agent_assure.cli.main import app
from agent_assure.demo.measurement_cases import (
    MEASUREMENT_CASES_NOTICE,
    render_measurement_cases_text,
)
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode

RUNNER = CliRunner()


def test_measurement_cases_demo_runs_offline_without_benchmark_claims(tmp_path: Path) -> None:
    out_dir = tmp_path / "measurement-cases"
    result = RUNNER.invoke(
        app,
        [
            "demo",
            "measurement-cases",
            "--out",
            str(out_dir),
            "--clean",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    summary = json.loads(result.output)
    assert summary == _json(out_dir / "demo-summary.json")
    assert summary["demo"] == "measurement-cases"
    assert summary["status"] == "success"
    assert summary["notice"] == MEASUREMENT_CASES_NOTICE
    assert summary["underlying_exit_code"] == 1
    assert summary["expected_regressions_caught"] is True
    assert summary["baseline_state"] == GateState.pass_.value
    assert summary["candidate_state"] == GateState.fail.value
    assert summary["classification"] == ComparisonClassification.new_failure.value
    assert summary["fixture_equivalence"] == GateState.pass_.value
    assert summary["blocking_reason_codes"] == [
        ReasonCode.FORBIDDEN_PROVIDER.value,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value,
        ReasonCode.RAW_SENSITIVE_CONTENT.value,
        ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT.value,
    ]

    cases = {
        str(case["case_id"]): cast(dict[str, Any], case)
        for case in cast(list[dict[str, Any]], summary["cases"])
    }
    assert cases["same-output-missing-evidence"]["visible_output"] == "preserved"
    assert "claim-evidence links" in cases["same-output-missing-evidence"][
        "changed_process_fields"
    ]
    assert _case_has_finding(
        cases,
        "same-output-missing-evidence",
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target="claim:claim-policy-support",
    )
    assert "provider/model" in cases["same-output-provider-boundary"][
        "changed_process_fields"
    ]
    assert "human review" in cases["same-output-provider-boundary"][
        "changed_process_fields"
    ]
    assert _case_has_finding(
        cases,
        "same-output-provider-boundary",
        ReasonCode.FORBIDDEN_PROVIDER,
        target="provider:alternate-process-provider",
    )
    assert "human review" in cases["same-output-human-review-bypassed"][
        "changed_process_fields"
    ]
    assert _case_has_finding(
        cases,
        "same-output-human-review-bypassed",
        ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
        target="human_review_required",
    )
    assert "evidence sources" in cases["same-output-redaction-state-changed"][
        "changed_process_fields"
    ]
    assert _case_has_finding(
        cases,
        "same-output-redaction-state-changed",
        ReasonCode.RAW_SENSITIVE_CONTENT,
        target="evidence_refs[0].source_id",
    )
    assert "operational counters" in cases["same-output-retry-storm"][
        "changed_process_fields"
    ]
    assert "measured usage" in cases["same-output-usage-cost-delta"][
        "changed_process_fields"
    ]
    assert cases["different-output-no-process-regression"]["visible_output"] == "changed"
    assert cases["different-output-no-process-regression"]["changed_process_fields"] == []

    advisory = cast(dict[str, Any], summary["advisory_observations"])
    usage_delta = cast(dict[str, Any], advisory["usage_delta"])
    assert usage_delta["comparison_state"] == "observed"
    assert usage_delta["total_retries_delta"] == 7
    assert usage_delta["estimated_cost_microusd_delta"] == 500

    command_exits = {
        command["name"]: command["actual_exit_code"]
        for command in cast(list[dict[str, Any]], summary["commands"])
    }
    assert command_exits == {
        "compile-suite": 0,
        "run-baseline": 0,
        "run-candidate": 0,
        "evaluate-baseline": 0,
        "evaluate-candidate": 1,
        "compare-runs": 1,
        "ci-report": 1,
        "ci-gate-packet": 1,
        "diff-render": 0,
    }
    assert _strict_exit_code(summary) == 1
    assert str(out_dir) not in json.dumps(summary)

    artifacts = cast(dict[str, str], summary["artifacts"])
    for artifact in artifacts.values():
        assert (out_dir / artifact).exists()

    rendered_text = render_measurement_cases_text(summary)
    assert MEASUREMENT_CASES_NOTICE in rendered_text
    assert "not a benchmark against other tools" in rendered_text
    assert "human review bypassed: same-output-human-review-bypassed" in rendered_text
    assert "suite aggregate retry delta: 7" in rendered_text

    html = (out_dir / artifacts["evidence_diff_html"]).read_text(encoding="utf-8")
    assert "Process assurance cases" in html
    assert "Measured usage delta" in html
    assert "provider/model" in html
    assert "alternate-process-provider" in html
    assert "operational counters" in html
    assert "retries=7" in html
    assert "cost_micro_usd=430" in html
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert ReasonCode.FORBIDDEN_PROVIDER.value in html
    assert ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT.value in html
    assert ReasonCode.RAW_SENSITIVE_CONTENT.value in html
    assert "<script" not in html.lower()
    assert "https://" not in html.lower()
    assert "http://" not in html.lower()


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _case_has_finding(
    cases: dict[str, dict[str, Any]],
    case_id: str,
    reason_code: ReasonCode,
    *,
    target: str,
) -> bool:
    findings = cast(list[dict[str, str]], cases[case_id]["findings"])
    return any(
        finding.get("reason_code") == reason_code.value and finding.get("target") == target
        for finding in findings
    )
