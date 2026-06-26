from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.run import AgentRunRecord

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)


def test_evidence_normalization_candidate_loses_secondary_claim_link() -> None:
    baseline = _shared_source_run(BASELINE)
    candidate = _shared_source_run(EVIDENCE_CANDIDATE)
    assert (
        baseline.provenance.fixture_manifest_digest
        == candidate.provenance.fixture_manifest_digest
    )
    assert baseline.recommendation == candidate.recommendation == "approve"
    assert baseline.outcome == candidate.outcome == "approve"
    baseline_claims = _claim_ids(baseline)
    candidate_claims = _claim_ids(candidate)
    assert baseline_claims == {"claim-duration", "claim-eligibility"}
    assert candidate_claims < baseline_claims
    assert "claim-duration" not in candidate_claims


def _shared_source_run(variant: Path) -> AgentRunRecord:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return next(run for run in runset.runs if run.case_id == "shared-source-multi-claim")


def _claim_ids(run: AgentRunRecord) -> set[str]:
    return {claim_id for ref in run.evidence_refs for claim_id in ref.claim_ids}
