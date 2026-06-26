from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import GateState, ReasonCode

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
SMOKE = Path("examples/prior_auth_synthetic/variants/candidate_smoke_fail.yaml")


def test_smoke_candidate_captures_in_process_failure_as_error_record() -> None:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(SMOKE), SUITE.parent)
    tool_failure = next(run for run in runset.runs if run.case_id == "tool-failure")
    assert tool_failure.recommendation == "error"
    assert tool_failure.outcome == "runtime_error"
    assert tool_failure.policy_results[0].state is GateState.fail
    assert tool_failure.policy_results[0].reason_codes == (ReasonCode.RUNTIME_FAILED,)
