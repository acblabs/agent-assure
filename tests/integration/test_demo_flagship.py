from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

from typer.testing import CliRunner

from agent_assure.cli.demo_cmd import _strict_exit_code
from agent_assure.cli.main import app
from agent_assure.demo.flagship import render_flagship_text
from agent_assure.reporting.evidence_diff_html import THESIS_TITLE
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode

RUNNER = CliRunner()


def test_flagship_demo_exits_zero_on_expected_process_regression(tmp_path: Path) -> None:
    out_dir = tmp_path / "flagship"
    result = RUNNER.invoke(
        app,
        [
            "demo",
            "flagship",
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
    assert summary["demo"] == "flagship"
    assert summary["status"] == "success"
    assert summary["underlying_exit_code"] == 1
    assert summary["output_equivalence"] == "preserved"
    assert summary["expected_regression_caught"] is True
    assert summary["blocking_reason_codes"] == [
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value
    ]

    visible = cast(dict[str, Any], summary["visible_final_output"])
    assert visible["case_id"] == "shared-source-multi-claim"
    assert visible["baseline"] == {"outcome": "approve", "recommendation": "approve"}
    assert visible["candidate"] == {"outcome": "approve", "recommendation": "approve"}

    process = cast(dict[str, Any], summary["process_regression"])
    assert process["missing_evidence_links"] == ["claim-duration"]
    assert process["baseline_state"] == GateState.pass_.value
    assert process["candidate_state"] == GateState.fail.value
    assert process["classification"] == ComparisonClassification.new_failure.value
    assert process["fixture_equivalence"] == GateState.pass_.value
    assert process["ci_blocked_as_expected"] is True
    assert process["packet_gate_blocked_as_expected"] is True

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
    for command in cast(list[dict[str, Any]], summary["commands"]):
        command_argv = cast(list[str], command["command"])
        assert command_argv[0] == "<python>"
        assert not any(str(out_dir) in arg for arg in command_argv)

    artifacts = cast(dict[str, str], summary["artifacts"])
    for artifact in artifacts.values():
        assert (out_dir / artifact).exists()
    assert "case: shared-source-multi-claim" in render_flagship_text(summary)
    html = (out_dir / artifacts["evidence_diff_html"]).read_text(encoding="utf-8")
    assert THESIS_TITLE in html
    assert "Review Punchline" in html
    assert "claim-duration" in html
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value in html
    assert "<script" not in html.lower()
    assert "https://" not in html.lower()
    assert "http://" not in html.lower()


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload
