from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.schema.common import GateState, ReasonCode

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
RUNNER = CliRunner()


def test_evaluate_cli_writes_candidate_first_reports_for_passing_baseline(
    tmp_path: Path,
) -> None:
    compiled_path, runset_path = _write_inputs(tmp_path, BASELINE)
    out_dir = tmp_path / "reports"

    result = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(runset_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0
    report_text = (out_dir / "evaluation-report.json").read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["schema_version"] == "0.1.0"
    assert report["artifact_kind"] == "evaluation-report"
    assert report["candidate_vs_expectations"]["state"] == GateState.pass_.value
    assert report["environment"]["artifact_kind"] == "environment-info"
    assert report["environment"]["dependency_inventory_digest"]
    assert "python_executable" not in report["environment"]
    summary = json.loads((out_dir / "evaluation-summary.json").read_text(encoding="utf-8"))
    assert summary["environment"]["dependency_inventory_path"].endswith(
        "dependency-inventory.json"
    )
    assert (out_dir / "dependency-inventory.json").exists()
    manifest = json.loads(
        (out_dir / "release-artifact-manifest.json").read_text(encoding="utf-8")
    )
    assert {
        artifact["role"]
        for artifact in manifest["artifacts"]
    } == {
        "compiled-suite",
        "candidate-runset",
        "evaluation-report",
        "evaluation-summary",
        "dependency-inventory",
    }
    assert b"\r\n" not in (out_dir / "evaluation-report.json").read_bytes()
    assert b"\r\n" not in (out_dir / "evaluation-report.md").read_bytes()
    markdown = (out_dir / "evaluation-report.md").read_text(encoding="utf-8")
    assert markdown.index("## Candidate vs Expectations") < markdown.index(
        "## Why the Candidate Passed or Failed"
    )


def test_evaluate_cli_exits_nonzero_after_writing_failure_reports(tmp_path: Path) -> None:
    compiled_path, runset_path = _write_inputs(tmp_path, EVIDENCE_CANDIDATE)
    out_dir = tmp_path / "reports"

    result = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(runset_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 1
    summary = json.loads((out_dir / "evaluation-summary.json").read_text(encoding="utf-8"))
    assert summary["state"] == GateState.fail.value
    assert summary["findings"][0]["reason_code"] == ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE


def _write_inputs(tmp_path: Path, variant: Path) -> tuple[Path, Path]:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    compiled_path = tmp_path / "suite.compiled.json"
    runset_path = tmp_path / "runset.json"
    write_compiled_suite(compiled, compiled_path)
    write_runset(runset, runset_path)
    return compiled_path, runset_path
