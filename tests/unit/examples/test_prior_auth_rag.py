from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.compare.runsets import compare_runsets
from agent_assure.evaluation.evaluator import evaluate_runset
from agent_assure.examples.prior_auth_synthetic.rag import (
    RAG_BASELINE_VARIANT_ID,
    RAG_CORPUS_VERSION_SKEW_VARIANT_ID,
    RAG_RERANKER_REGRESSION_VARIANT_ID,
    retrieval_diff_summary,
    retrieval_output_payload,
    retrieve_for_variant,
)
from agent_assure.runner.fixture_runner import load_variant_config, run_suite
from agent_assure.schema.common import ComparisonClassification, GateState, ReasonCode

ROOT = Path(__file__).resolve().parents[3]
EXAMPLE = ROOT / "examples" / "prior_auth_synthetic"
SUITE = EXAMPLE / "rag_suite.yaml"
BASELINE_VARIANT = EXAMPLE / "variants" / "rag_baseline.yaml"
RERANKER_VARIANT = EXAMPLE / "variants" / "candidate_rag_reranker_regression.yaml"
SKEW_VARIANT = EXAMPLE / "variants" / "candidate_rag_corpus_version_skew.yaml"
REQUEST = EXAMPLE / "fixtures" / "rag" / "requests" / "rag-pt-duration.json"
RETRIEVAL_OUTPUTS = EXAMPLE / "fixtures" / "rag" / "retrieval_outputs"


def test_rag_retrieval_matches_committed_rank_fixtures() -> None:
    request = _request()
    baseline = retrieve_for_variant(EXAMPLE, request, variant_id=RAG_BASELINE_VARIANT_ID)
    reranker = retrieve_for_variant(
        EXAMPLE,
        request,
        variant_id=RAG_RERANKER_REGRESSION_VARIANT_ID,
    )
    skew = retrieve_for_variant(EXAMPLE, request, variant_id=RAG_CORPUS_VERSION_SKEW_VARIANT_ID)

    assert _jsonable(retrieval_output_payload(baseline)) == _json(
        RETRIEVAL_OUTPUTS / "rag-baseline.json"
    )
    assert _jsonable(retrieval_output_payload(reranker)) == _json(
        RETRIEVAL_OUTPUTS / "rag-reranker-drops-secondary-claim-source.json"
    )
    assert _jsonable(retrieval_output_payload(skew)) == _json(
        RETRIEVAL_OUTPUTS / "rag-corpus-version-skew.json"
    )
    assert baseline.corpus.retrieval_corpus_digest == reranker.corpus.retrieval_corpus_digest
    assert baseline.corpus.retrieval_corpus_digest != skew.corpus.retrieval_corpus_digest
    assert {item.chunk.content_digest for item in baseline.retrieved_chunks} == {
        "32de93ec681deeb1108a2355c3ce0caded976cd66ec554dfe8c5adc9ee7ddcfd",
        "39a52598fb2b7f5bbfc734a18d6ddd55a1e9c48da493cd10c65aceabcd44a782",
    }


def test_rag_retrieval_uses_fixture_pinned_as_of_date() -> None:
    request = _request()
    stale_request = copy.deepcopy(request)
    retrieval = stale_request["retrieval"]
    assert isinstance(retrieval, dict)
    retrieval["as_of_date"] = "2025-12-31"

    result = retrieve_for_variant(EXAMPLE, stale_request, variant_id=RAG_BASELINE_VARIANT_ID)

    assert result.retrieved_chunks == ()


def test_rag_retrieval_treats_expires_date_as_exclusive() -> None:
    request = _request()
    boundary_request = copy.deepcopy(request)
    retrieval = boundary_request["retrieval"]
    assert isinstance(retrieval, dict)
    retrieval["as_of_date"] = "2026-12-31"

    result = retrieve_for_variant(EXAMPLE, boundary_request, variant_id=RAG_BASELINE_VARIANT_ID)

    assert result.retrieved_chunks == ()


def test_rag_reranker_renumbers_results_after_filtering_top_hit() -> None:
    request = _request()
    top_drop_request = copy.deepcopy(request)
    retrieval = top_drop_request["retrieval"]
    assert isinstance(retrieval, dict)
    reranker_configs = retrieval["reranker_configs"]
    assert isinstance(reranker_configs, dict)
    reranker_configs["baseline"] = {
        "config_id": "drop-top-claim-source-v1",
        "drop_claim_ids": ["claim-eligibility"],
    }

    result = retrieve_for_variant(
        EXAMPLE,
        top_drop_request,
        variant_id=RAG_BASELINE_VARIANT_ID,
    )

    assert tuple((item.chunk.ref_id, item.rank) for item in result.retrieved_chunks) == (
        ("ref-rag-duration-limit", 1),
    )


def test_rag_retrieval_validates_fixture_dates() -> None:
    request = _request()
    malformed_request = copy.deepcopy(request)
    retrieval = malformed_request["retrieval"]
    assert isinstance(retrieval, dict)
    retrieval["as_of_date"] = "20260701"

    with pytest.raises(ValueError, match="ISO date"):
        retrieve_for_variant(EXAMPLE, malformed_request, variant_id=RAG_BASELINE_VARIANT_ID)


def test_rag_retrieval_rejects_invalid_score_threshold() -> None:
    request = _request()
    malformed_request = copy.deepcopy(request)
    retrieval = malformed_request["retrieval"]
    assert isinstance(retrieval, dict)
    retrieval["score_threshold"] = "1.5"

    with pytest.raises(ValueError, match="score_threshold"):
        retrieve_for_variant(EXAMPLE, malformed_request, variant_id=RAG_BASELINE_VARIANT_ID)


def test_rag_retrieval_rejects_invalid_chunk_date_range(tmp_path: Path) -> None:
    suite_root = tmp_path / "prior_auth_synthetic"
    shutil.copytree(EXAMPLE, suite_root)
    chunk_path = (
        suite_root
        / "fixtures"
        / "rag"
        / "policy_corpus"
        / "current"
        / "duration_limit.json"
    )
    chunk = _json(chunk_path)
    chunk["expires_date"] = chunk["effective_date"]
    chunk_path.write_text(
        json.dumps(chunk, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ValueError, match="expires_date must be after effective_date"):
        retrieve_for_variant(suite_root, _request(), variant_id=RAG_BASELINE_VARIANT_ID)


def test_rag_hero_candidate_preserves_decision_and_fails_material_claim_link() -> None:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE_VARIANT), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(RERANKER_VARIANT), SUITE.parent)
    baseline_report = evaluate_runset(compiled, baseline)
    candidate_report = evaluate_runset(compiled, candidate)
    comparison = compare_runsets(compiled, baseline, candidate)
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]

    assert baseline_report.candidate_vs_expectations.state is GateState.pass_
    assert candidate_report.candidate_vs_expectations.state is GateState.fail
    assert baseline_run.recommendation == candidate_run.recommendation == "approve"
    assert baseline_run.outcome == candidate_run.outcome == "approve"
    assert (
        baseline_run.provenance.retrieval_corpus_digest
        == candidate_run.provenance.retrieval_corpus_digest
    )
    assert candidate_report.candidate_vs_expectations.findings[0].reason_code is (
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE
    )
    assert candidate_report.candidate_vs_expectations.findings[0].target == "claim:claim-duration"
    assert comparison.comparison_summary.classification is ComparisonClassification.new_failure
    assert comparison.comparison_summary.fixture_equivalence_state is GateState.pass_


def test_rag_corpus_version_skew_is_provenance_only_when_evidence_stays_intact() -> None:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE_VARIANT), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(SKEW_VARIANT), SUITE.parent)
    candidate_report = evaluate_runset(compiled, candidate)
    comparison = compare_runsets(compiled, baseline, candidate)
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]

    assert candidate_report.candidate_vs_expectations.state is GateState.pass_
    assert baseline_run.recommendation == candidate_run.recommendation == "approve"
    assert baseline_run.outcome == candidate_run.outcome == "approve"
    assert (
        baseline_run.provenance.retrieval_corpus_digest
        != candidate_run.provenance.retrieval_corpus_digest
    )
    assert (
        comparison.comparison_summary.classification
        is ComparisonClassification.provenance_only_change
    )
    assert any(
        change.field == "retrieval_corpus_digest"
        for change in comparison.provenance_changes
    )


def test_rag_retrieval_diff_summary_is_json_first_and_deterministic() -> None:
    request = _request()
    baseline = retrieve_for_variant(EXAMPLE, request, variant_id=RAG_BASELINE_VARIANT_ID)
    reranker = retrieve_for_variant(
        EXAMPLE,
        request,
        variant_id=RAG_RERANKER_REGRESSION_VARIANT_ID,
    )

    summary = retrieval_diff_summary(baseline, reranker)

    assert summary["baseline_only_ref_ids"] == ("ref-rag-duration-limit",)
    assert summary["candidate_only_ref_ids"] == ()
    assert summary["shared_ref_ids"] == ("ref-rag-medical-necessity",)
    assert summary["retrieval_jaccard_bps"] == 5000
    assert summary["missing_required_source_ids"] == (
        "policy:acme-health:pt-coverage:duration-limit",
    )
    assert summary["corpus_digest_changed"] is False


def _request() -> dict[str, object]:
    payload = json.loads(REQUEST.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return {str(key): value for key, value in payload.items()}


def _json(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(payload, dict)
    return payload


def _jsonable(value: dict[str, object]) -> dict[str, Any]:
    payload = json.loads(json.dumps(value, sort_keys=True))
    assert isinstance(payload, dict)
    return payload
