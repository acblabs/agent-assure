from __future__ import annotations

from pathlib import Path

from agent_assure.authoring.compiler import compile_suite
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.suite import CompiledSuite

SUITE = Path("examples/prior_auth_synthetic/suite.yaml")
BASELINE = Path("examples/prior_auth_synthetic/variants/baseline.yaml")
EVIDENCE_CANDIDATE = Path(
    "examples/prior_auth_synthetic/variants/candidate_evidence_normalization.yaml"
)
EDGE_CASE_ID = "shared-source-multi-claim"


def test_evidence_normalization_candidate_loses_secondary_claim_link() -> None:
    baseline = _case_run(BASELINE, EDGE_CASE_ID)
    candidate = _case_run(EVIDENCE_CANDIDATE, EDGE_CASE_ID)
    assert (
        baseline.provenance.fixture_manifest_digest
        == candidate.provenance.fixture_manifest_digest
    )
    assert baseline.recommendation == candidate.recommendation == "approve"
    assert baseline.outcome == candidate.outcome == "approve"
    baseline_claims = _claim_ids(baseline)
    candidate_claims = _claim_ids(candidate)
    lost_claims = baseline_claims - candidate_claims
    assert baseline_claims == {"claim-duration", "claim-eligibility"}
    assert _ref_ids_are_unique(baseline)
    assert candidate_claims < baseline_claims
    assert len(lost_claims) == 1


def test_evidence_refactor_preserves_ordinary_one_source_claims() -> None:
    compiled = compile_suite(SUITE)
    baseline = _runset_by_case(BASELINE)
    candidate = _runset_by_case(EVIDENCE_CANDIDATE)
    ordinary_case_ids = _ordinary_evidence_case_ids(compiled)
    assert len(ordinary_case_ids) == 9

    for case_id in sorted(ordinary_case_ids):
        baseline_run = baseline[case_id]
        candidate_run = candidate[case_id]
        assert candidate_run.recommendation == baseline_run.recommendation
        assert candidate_run.outcome == baseline_run.outcome
        assert _evidence_claims_by_ref(candidate_run) == _evidence_claims_by_ref(baseline_run)


def test_evidence_refactor_violates_only_the_shared_source_material_claim() -> None:
    compiled = compile_suite(SUITE)
    candidate = _runset_by_case(EVIDENCE_CANDIDATE)
    expectations = {
        expectation.case_id: expectation for expectation in compiled.resolved_expectations
    }

    missing_material_claims = [
        (case_id, claim_id)
        for case_id, expectation in sorted(expectations.items())
        for claim_id in _missing_material_claims(candidate[case_id], expectation)
    ]

    assert len(missing_material_claims) == 1
    missing_case_id, missing_claim_id = missing_material_claims[0]
    assert missing_case_id == EDGE_CASE_ID
    assert missing_claim_id in {"claim-duration", "claim-eligibility"}


def test_evidence_refactor_has_no_case_id_branch_or_marker() -> None:
    variant = load_variant_config(EVIDENCE_CANDIDATE)
    source_paths = [
        Path("src/agent_assure/examples/prior_auth_synthetic/app.py"),
        Path("src/agent_assure/examples/prior_auth_synthetic/runner.py"),
    ]
    implementation_text = "\n".join(path.read_text(encoding="utf-8") for path in source_paths)

    assert variant.runner_id == "prior_auth.synthetic_evidence_refactor"
    assert variant.behavior.evidence_assembly == "association_preserving"
    assert variant.behavior.runtime_error_case is None
    assert EDGE_CASE_ID not in implementation_text
    assert "claim-duration" not in implementation_text
    assert "planted" not in implementation_text.lower()
    assert "intentional bug" not in implementation_text.lower()


def _case_run(variant: Path, case_id: str) -> AgentRunRecord:
    return _runset_by_case(variant)[case_id]


def _runset_by_case(variant: Path) -> dict[str, AgentRunRecord]:
    compiled = compile_suite(SUITE)
    runset = run_suite(compiled, load_variant_config(variant), SUITE.parent)
    return {run.case_id: run for run in runset.runs}


def _claim_ids(run: AgentRunRecord) -> set[str]:
    return {claim_id for ref in run.evidence_refs for claim_id in ref.claim_ids}


def _evidence_claims_by_ref(run: AgentRunRecord) -> dict[str, tuple[str, ...]]:
    return {ref.ref_id: ref.claim_ids for ref in run.evidence_refs}


def _missing_material_claims(run: AgentRunRecord, expectation: Expectation) -> tuple[str, ...]:
    evidence_refs = {item.ref_id for item in run.evidence_items}
    observed = {
        link.claim_id
        for link in run.claim_evidence_links
        if link.evidence_ref_id in evidence_refs
    }
    return tuple(
        claim_id for claim_id in expectation.material_claim_ids if claim_id not in observed
    )


def _ordinary_evidence_case_ids(compiled: CompiledSuite) -> set[str]:
    return {
        case.case_id
        for case in compiled.cases
        if case.case_id != EDGE_CASE_ID
        and "evidence-linking" not in case.tags
    }


def _ref_ids_are_unique(run: AgentRunRecord) -> bool:
    ref_ids = [ref.ref_id for ref in run.evidence_refs]
    return len(ref_ids) == len(set(ref_ids))
