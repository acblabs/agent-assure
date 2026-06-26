from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from agent_assure.authoring.compiler import compile_suite
from agent_assure.cli.main import app
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.run import AgentRunRecord, RunSet

SUITE = Path("examples/expense_approval_minimal/suite.yaml")
BASELINE = Path("examples/expense_approval_minimal/variants/baseline.yaml")
CANDIDATE = Path("examples/expense_approval_minimal/variants/candidate_provider_policy.yaml")
RUNNER = CliRunner()


def test_expense_baseline_runs_as_independent_generic_suite() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(BASELINE), SUITE.parent)
    outcomes = {run.case_id: run.outcome for run in runset.runs}

    assert compiled.suite_id == "expense-approval-minimal"
    assert compiled.defaults.runner_id == "expense_approval.minimal"
    assert len(compiled.cases) == 3
    assert outcomes == {
        "exp-001": "approve",
        "exp-002": "request_receipt",
        "exp-003": "manual_review",
    }
    assert all("prior" not in run.pipeline_id for run in runset.runs)


def test_expense_provider_candidate_uses_same_fixtures_and_fails_control() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runs_by_case(run_suite(compiled, load_variant_config(BASELINE), SUITE.parent))
    candidate = _runs_by_case(run_suite(compiled, load_variant_config(CANDIDATE), SUITE.parent))

    assert (
        baseline["exp-003"].provenance.fixture_manifest_digest
        == candidate["exp-003"].provenance.fixture_manifest_digest
    )
    for case_id in ("exp-001", "exp-002"):
        assert candidate[case_id].outcome == baseline[case_id].outcome
        assert _claims(candidate[case_id]) == _claims(baseline[case_id])

    baseline_policy = baseline["exp-003"].policy_results[0]
    candidate_policy = candidate["exp-003"].policy_results[0]
    assert baseline["exp-003"].outcome == "manual_review"
    assert baseline_policy.state is GateState.fail
    assert baseline_policy.reason_codes == (ReasonCode.FORBIDDEN_PROVIDER,)
    assert candidate["exp-003"].outcome == "approve_without_review"
    assert candidate_policy.state is GateState.pass_


def test_expense_example_compiles_and_runs_through_cli(tmp_path: Path) -> None:
    compiled_path = tmp_path / "expense.compiled.json"
    manifest_path = tmp_path / "expense.fixtures.json"
    runset_path = tmp_path / "expense.baseline.json"

    compile_result = RUNNER.invoke(
        app,
        [
            "suite",
            "compile",
            str(SUITE),
            "--out",
            str(compiled_path),
            "--manifest",
            str(manifest_path),
        ]
    )
    assert compile_result.exit_code == 0

    run_result = RUNNER.invoke(
        app,
        [
            "suite",
            "run",
            str(compiled_path),
            "--variant",
            str(BASELINE),
            "--manifest",
            str(manifest_path),
            "--out",
            str(runset_path),
        ]
    )
    assert run_result.exit_code == 0
    runset = RunSet.model_validate_json(runset_path.read_text(encoding="utf-8"))
    assert runset.suite_id == "expense-approval-minimal"
    assert len(runset.runs) == 3


def _runs_by_case(runset: RunSet) -> dict[str, AgentRunRecord]:
    return {run.case_id: run for run in runset.runs}


def _claims(run: AgentRunRecord) -> set[str]:
    return {claim_id for ref in run.evidence_refs for claim_id in ref.claim_ids}
