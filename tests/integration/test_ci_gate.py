from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agent_assure.artifact_io import file_sha256
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


@pytest.mark.parametrize(
    "env_var",
    (
        "AGENT_ASSURE_DEMO_EXPECTED_FAILURE",
        "AGENT_ASSURE_DEMO_NETWORK_DISABLED",
    ),
)
def test_demo_markers_do_not_affect_core_commands(tmp_path: Path, env_var: str) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    env = {env_var: "1"}
    slug = env_var.lower()

    evaluate = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(tmp_path / f"evaluate-report-{slug}"),
        ],
        env=env,
    )
    compare = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(tmp_path / f"compare-report-{slug}"),
        ],
        env=env,
    )
    ci = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(tmp_path / f"ci-report-with-demo-env-{slug}"),
            "--report-mode",
            "full",
        ],
        env=env,
    )
    failing_summary = tmp_path / f"failing-summary-{slug}.json"
    _write_json(
        failing_summary,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            state=GateState.fail,
        ).model_dump(mode="json"),
    )
    gate = RUNNER.invoke(app, ["ci", "gate", str(failing_summary)], env=env)

    assert evaluate.exit_code == 1, evaluate.output
    assert compare.exit_code == 1, compare.output
    assert ci.exit_code == 1, ci.output
    assert gate.exit_code == 1, gate.output


def test_core_commands_accept_out_dir_outside_cwd(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    compiled_path, baseline_path, candidate_path = _write_inputs(workspace)
    lockfile = workspace / "requirements.lock"
    lockfile.write_text("agent-assure-test-lock\n", encoding="utf-8")
    _init_git_repo(workspace)
    out_root = tmp_path / "external-output"

    evaluate_out = out_root / "evaluate"
    evaluate = RUNNER.invoke(
        app,
        [
            "evaluate",
            str(baseline_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(evaluate_out),
        ],
    )

    compare_out = out_root / "compare"
    compare = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(compare_out),
        ],
    )

    ci_out = out_root / "ci"
    ci = RUNNER.invoke(
        app,
        [
            "ci",
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--baseline",
            str(baseline_path),
            "--out-dir",
            str(ci_out),
            "--report-mode",
            "full",
        ],
    )

    packet_summary = workspace / "evaluation-summary.json"
    packet_comparison = workspace / "comparison-summary.json"
    _write_json(
        packet_summary,
        EvaluationSummary(
            artifact_kind="evaluation-summary",
            runset_id="candidate",
            state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    _write_json(
        packet_comparison,
        ComparisonSummary(
            artifact_kind="comparison-summary",
            baseline_runset_id="baseline",
            candidate_runset_id="candidate",
            classification=ComparisonClassification.provenance_only_change,
            fixture_equivalence_state=GateState.pass_,
        ).model_dump(mode="json"),
    )
    packet_out = out_root / "packet" / "evidence-packet.json"
    packet = RUNNER.invoke(
        app,
        [
            "packet",
            "build",
            str(packet_summary),
            "--comparison",
            str(packet_comparison),
            "--out",
            str(packet_out),
        ],
    )

    assert evaluate.exit_code == 0, evaluate.output
    assert compare.exit_code == 1, compare.output
    assert ci.exit_code == 1, ci.output
    assert packet.exit_code == 0, packet.output
    for command_out in (evaluate_out, compare_out, ci_out, packet_out.parent):
        assert (command_out / "release-artifact-manifest.json").exists()
        manifest = json.loads(
            (command_out / "release-artifact-manifest.json").read_text(encoding="utf-8")
        )
        environment = manifest["environment"]
        assert environment["git_commit"]
        assert environment["lockfile_path"] == "requirements.lock"
        assert environment["lockfile_digest"] == file_sha256(lockfile)
        assert not Path(environment["dependency_inventory_path"]).is_absolute()
        assert all(not Path(artifact["path"]).is_absolute() for artifact in manifest["artifacts"])


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


def _init_git_repo(path: Path) -> None:
    commands = (
        ("init",),
        ("config", "user.email", "agent-assure@example.test"),
        ("config", "user.name", "Agent Assure Tests"),
        ("add", "."),
        ("commit", "-m", "test provenance root"),
    )
    for command in commands:
        try:
            subprocess.run(
                ("git", *command),
                cwd=path,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            pytest.skip("git is not available")
