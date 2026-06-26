from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.main import app
from agent_assure.fixtures.loader import write_compiled_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
RUNNER = CliRunner()


def test_prior_auth_suite_compiles_offline() -> None:
    compiled = compile_suite(SUITE)
    assert compiled.suite_id == "prior-auth-synthetic"
    assert compiled.defaults.fixture_roots == ("fixtures/shared",)
    assert len(compiled.resolved_expectations) == 10
    expectations = {
        expectation.expectation_id: expectation for expectation in compiled.resolved_expectations
    }
    assert all(case.expectation_id in expectations for case in compiled.cases)
    assert all(expectations[case.expectation_id].case_id == case.case_id for case in compiled.cases)


def test_prior_auth_baseline_runs_offline() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    assert runset.suite_id == "prior-auth-synthetic"
    assert len(runset.runs) == 10
    assert {run.outcome for run in runset.runs} == {
        "approve",
        "deny",
        "escalate",
        "request_more_info",
    }


def test_suite_run_cli_checks_expected_compiled_suite_digest(tmp_path) -> None:  # type: ignore[no-untyped-def]
    compiled = compile_suite(SUITE)
    compiled_path = tmp_path / "compiled.json"
    write_compiled_suite(compiled, compiled_path)
    result = RUNNER.invoke(
        app,
        [
            "suite",
            "run",
            str(compiled_path),
            "--variant",
            str(BASELINE),
            "--suite-root",
            str(SUITE.parent),
            "--suite-digest",
            "0" * 64,
            "--out",
            str(tmp_path / "runset.json"),
        ],
    )
    assert result.exit_code != 0
    assert result.exception is not None
    assert "compiled suite digest mismatch" in str(result.exception)
