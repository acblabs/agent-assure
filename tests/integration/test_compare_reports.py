from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite, write_runset
from agent_assure.schema.common import ComparisonClassification

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
RUNNER = CliRunner()


def test_compare_cli_writes_candidate_first_reports_for_regression(tmp_path: Path) -> None:
    compiled_path, baseline_path, candidate_path = _write_inputs(tmp_path)
    out_dir = tmp_path / "reports"

    result = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 1
    report_text = (out_dir / "comparison-report.json").read_text(encoding="utf-8")
    report = json.loads(report_text)
    assert report["schema_version"] == "0.1.0"
    assert report["artifact_kind"] == "comparison-report"
    assert report["environment"]["artifact_kind"] == "environment-info"
    assert report["environment"]["dependency_inventory_digest"]
    assert report["candidate_vs_expectations"]["environment"]["dependency_inventory_digest"]
    assert report["baseline_vs_expectations"]["environment"]["dependency_inventory_digest"]
    summary = json.loads((out_dir / "comparison-summary.json").read_text(encoding="utf-8"))
    assert summary["classification"] == ComparisonClassification.new_failure.value
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
        "baseline-runset",
        "candidate-runset",
        "comparison-report",
        "comparison-summary",
        "dependency-inventory",
    }
    assert b"\r\n" not in (out_dir / "comparison-report.json").read_bytes()
    assert b"\r\n" not in (out_dir / "comparison-report.md").read_bytes()
    markdown = (out_dir / "comparison-report.md").read_text(encoding="utf-8")
    assert markdown.index("## Candidate vs Expectations") < markdown.index(
        "## Why the Candidate Passed or Failed"
    )
    assert markdown.index("## Why the Candidate Passed or Failed") < markdown.index(
        "## Fixture-Equivalence Result"
    )
    assert markdown.index("## Fixture-Equivalence Result") < markdown.index(
        "## Baseline vs Expectations"
    )
    assert markdown.index("## Baseline vs Expectations") < markdown.index(
        "## Baseline-to-Candidate Control Changes"
    )
    assert markdown.index("## Baseline-to-Candidate Control Changes") < markdown.index(
        "## Provenance Changes"
    )
    assert "Behavioral record changes:" in markdown
    assert "Allowed behavioral record changes:" not in markdown


def test_compare_cli_exits_two_for_invalid_fixture_equivalence(tmp_path: Path) -> None:
    compiled_path, baseline_path, _ = _write_inputs(tmp_path)
    bad_candidate = _bad_fixture_digest(
        json.loads(baseline_path.read_text(encoding="utf-8"))
    )
    candidate_path = tmp_path / "bad-candidate.json"
    candidate_path.write_text(json.dumps(bad_candidate, indent=2) + "\n", encoding="utf-8")
    out_dir = tmp_path / "reports"

    result = RUNNER.invoke(
        app,
        [
            "compare",
            str(baseline_path),
            str(candidate_path),
            "--suite",
            str(compiled_path),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 2
    summary = json.loads((out_dir / "comparison-summary.json").read_text(encoding="utf-8"))
    assert summary["classification"] == ComparisonClassification.invalid_comparison.value
    assert summary["fixture_equivalence_state"] == "fail"
    assert summary["environment"]["dependency_inventory_digest"]
    report = json.loads((out_dir / "comparison-report.json").read_text(encoding="utf-8"))
    assert report["candidate_vs_expectations"]["state"] == "not_evaluated"
    assert report["environment"]["dependency_inventory_path"].endswith(
        "dependency-inventory.json"
    )
    assert report["behavioral_changes"] == []
    assert report["provenance_changes"] == []


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


def _bad_fixture_digest(payload: dict[str, object]) -> dict[str, object]:
    runs = payload["runs"]
    assert isinstance(runs, list)
    first = runs[0]
    assert isinstance(first, dict)
    provenance = first["provenance"]
    assert isinstance(provenance, dict)
    provenance["fixture_manifest_digest"] = "b" * 64
    payload["runset_id"] = f"{payload['runset_id']}-bad-fixture"
    return payload
