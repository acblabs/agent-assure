from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.schema.common import ComparisonClassification, GateState
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.evaluation import EvaluationSummary

RUNNER = CliRunner()
SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)


def test_ci_gate_passes_and_fails_evaluation_summaries(tmp_path: Path) -> None:
    passing = tmp_path / "pass.json"
    failing = tmp_path / "fail.json"
    _write_json(
        passing,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="baseline",
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    _write_json(
        failing,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            state=GateState.fail,
        ).model_dump(mode="json"),
    )

    assert RUNNER.invoke(app, ["ci", "gate", str(passing)]).exit_code == 0
    assert RUNNER.invoke(app, ["ci", "gate", str(failing)]).exit_code == 1


def test_ci_gate_exits_two_for_invalid_comparison(tmp_path: Path) -> None:
    summary = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id="baseline",
        candidate_runset_id="candidate",
        classification=ComparisonClassification.invalid_comparison,
        fixture_equivalence_state=GateState.fail,
    )
    path = tmp_path / "comparison-summary.json"
    _write_json(path, summary.model_dump(mode="json"))

    result = RUNNER.invoke(app, ["ci", "gate", str(path)])

    assert result.exit_code == 2


def test_ci_command_writes_reports_packet_manifest_and_diagnostics(tmp_path: Path) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "ci-report"

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "full",
        ],
    )

    assert result.exit_code == 1, result.output
    assert (out_dir / "evaluation-report.json").exists()
    assert (out_dir / "comparison-report.json").exists()
    assert (out_dir / "evidence-packet.json").exists()
    assert (out_dir / "evidence-packet.md").exists()
    assert (out_dir / "release-artifact-manifest.json").exists()
    assert (out_dir / "dependency-inventory.json").exists()
    diagnostics = json.loads((out_dir / "ci-diagnostics.json").read_text(encoding="utf-8"))
    assert diagnostics["exit_code"] == 1
    assert diagnostics["reason_code"] == "MATERIAL_CLAIM_MISSING_EVIDENCE"
    assert diagnostics["artifact_path"].endswith("evidence-packet.json")
    packet = json.loads((out_dir / "evidence-packet.json").read_text(encoding="utf-8"))
    assert packet["environment"]["dependency_inventory_digest"]
    assert "python_executable" not in packet["environment"]
    assert packet["release_manifest"]["artifacts"]
    inventory = json.loads(
        (out_dir / "dependency-inventory.json").read_text(encoding="utf-8")
    )
    assert inventory["artifact_kind"] == "dependency-inventory"
    assert inventory["format"] == "agent-assure-dependency-inventory-v0.1"


def test_ci_fail_fast_stops_before_comparison_after_candidate_blocker(tmp_path: Path) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "ci-report"

    result = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(out_dir),
            "--report-mode",
            "fail-fast",
        ],
    )

    assert result.exit_code == 1, result.output
    assert (out_dir / "evaluation-summary.json").exists()
    assert not (out_dir / "comparison-summary.json").exists()
    summary = json.loads((out_dir / "evaluation-summary.json").read_text(encoding="utf-8"))
    assert len(summary["findings"]) == 1
    report = json.loads((out_dir / "evaluation-report.json").read_text(encoding="utf-8"))
    assert report["metrics"]["blocking_findings"] >= 1
    assert report["metrics"]["findings_by_reason"]["MATERIAL_CLAIM_MISSING_EVIDENCE"] == 1


def _write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8", newline="\n")


def _write_inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(EVIDENCE_CANDIDATE), SUITE.parent)
    compiled_path = tmp_path / "suite.compiled.json"
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    write_compiled_suite(compiled, compiled_path)
    write_runset(baseline, baseline_path)
    write_runset(candidate, candidate_path)
    return compiled_path, baseline_path, candidate_path
