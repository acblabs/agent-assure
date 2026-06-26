from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.run import AgentRunRecord

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
PROVIDER_CANDIDATE = Path("examples/prior_auth_synthetic/variants/candidate_provider_policy.yaml")


def test_provider_policy_candidate_lets_runtime_defaults_shadow_policy_bundle() -> None:
    compiled = compile_suite(SUITE)
    baseline_config = load_variant_config(BASELINE)
    candidate_config = load_variant_config(PROVIDER_CANDIDATE)
    baseline = _run_forbidden_provider(BASELINE)
    candidate = _run_forbidden_provider(PROVIDER_CANDIDATE)
    assert (
        baseline.provenance.fixture_manifest_digest
        == candidate.provenance.fixture_manifest_digest
    )
    assert baseline.outcome == "escalate"
    assert baseline_config.behavior.provider_policy_precedence == "policy_over_runtime"
    assert baseline.policy_results[0].state is GateState.fail
    assert baseline.policy_results[0].reason_codes == (ReasonCode.FORBIDDEN_PROVIDER,)
    assert candidate.outcome == "approve_without_review"
    assert candidate_config.behavior.provider_policy_precedence == "runtime_over_policy"
    assert candidate.policy_results[0].state is GateState.pass_
    assert candidate.provider == "unapproved-prior-auth-model"
    assert compiled.suite_id == "prior-auth-synthetic"


def _run_forbidden_provider(variant: Path) -> AgentRunRecord:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return next(run for run in runset.runs if run.case_id == "forbidden-provider")
