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
    CounterfactualFamilyEvaluation,
    _int_sequence,
    _string_tuple,
    evaluate_counterfactual_families,
    load_counterfactual_query_families,
    normalize_query,
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
COUNTERFACTUAL_FAMILIES = (
    EXAMPLE / "fixtures" / "rag" / "counterfactual_query_families.json"
)
COUNTERFACTUAL_FAMILY_ID = "rag-pt-duration-equivalent-v1"


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


def test_counterfactual_baseline_preserves_required_evidence_across_query_variants() -> None:
    compiled = compile_suite(SUITE)
    evaluation = _counterfactual_family_evaluation(
        evaluate_counterfactual_families(
            EXAMPLE,
            variant_id=RAG_BASELINE_VARIANT_ID,
            compiled_suite=compiled,
            canonical_decision_matches_family_expectation=True,
        ),
        COUNTERFACTUAL_FAMILY_ID,
    )
    report = evaluation.report_payload()
    variant_payloads = report["variants"]
    assert isinstance(variant_payloads, tuple)

    assert report["query_family_id"] == COUNTERFACTUAL_FAMILY_ID
    assert report["variants_evaluated"] == 4
    assert report["expected_decision"] == {
        "allowed_outcomes": ("approve",),
        "expected_recommendation": "approve",
    }
    assert report["decision_measurement_scope"] == "canonical_case_only"
    assert report["canonical_decision_matches_family_expectation"] is True
    assert report["preserved_required_ref_support"] is True
    assert report["preserved_required_source_support"] is True
    assert report["preserved_material_claim_support"] is True
    assert report["escalated_variants"] == ()
    assert report["reference_retrieval_ref_ids"] == (
        "ref-rag-medical-necessity",
        "ref-rag-duration-limit",
    )
    assert set(report["retrieval_jaccard_bps_by_variant"].values()) == {10000}
    assert set(report["required_ref_coverage_bps_by_variant"].values()) == {10000}
    assert set(report["required_ref_support_preserved_by_variant"].values()) == {True}
    assert set(report["required_source_support_preserved_by_variant"].values()) == {True}
    assert set(
        report["required_material_claim_support_preserved_by_variant"].values()
    ) == {True}
    assert set(report["missing_refs_by_variant"].values()) == {()}
    assert len(
        {
            item["query_digest"]
            for item in variant_payloads
            if isinstance(item, dict)
        }
    ) == 4
    assert "query_digest" in json.dumps(report, sort_keys=True)
    assert "Does this member qualify" not in json.dumps(report, sort_keys=True)
    assert "three months of PT" not in json.dumps(report, sort_keys=True)


def test_counterfactual_candidate_preserves_decision_but_loses_material_support() -> None:
    compiled = compile_suite(SUITE)
    baseline = run_suite(compiled, load_variant_config(BASELINE_VARIANT), SUITE.parent)
    candidate = run_suite(compiled, load_variant_config(RERANKER_VARIANT), SUITE.parent)
    baseline_run = baseline.runs[0]
    candidate_run = candidate.runs[0]
    decision_preserved = (
        baseline_run.recommendation == candidate_run.recommendation == "approve"
        and baseline_run.outcome == candidate_run.outcome == "approve"
    )

    evaluation = _counterfactual_family_evaluation(
        evaluate_counterfactual_families(
            EXAMPLE,
            variant_id=RAG_RERANKER_REGRESSION_VARIANT_ID,
            compiled_suite=compiled,
            canonical_decision_matches_family_expectation=decision_preserved,
        ),
        COUNTERFACTUAL_FAMILY_ID,
    )
    report = evaluation.report_payload()

    assert report["canonical_decision_matches_family_expectation"] is True
    assert report["preserved_required_ref_support"] is True
    assert report["preserved_required_source_support"] is False
    assert report["preserved_material_claim_support"] is False
    assert report["escalated_variants"] == (
        "rag-pt-duration-three-months-pt",
    )
    assert report["retrieval_jaccard_bps_by_variant"] == {
        "rag-pt-duration-twelve-weeks": 10000,
        "rag-pt-duration-three-months-pt": 5000,
        "rag-pt-duration-extended-rehab": 10000,
        "rag-pt-duration-noisy-typo": 10000,
    }
    assert set(report["required_ref_coverage_bps_by_variant"].values()) == {10000}
    assert report["required_source_support_preserved_by_variant"] == {
        "rag-pt-duration-twelve-weeks": True,
        "rag-pt-duration-three-months-pt": False,
        "rag-pt-duration-extended-rehab": True,
        "rag-pt-duration-noisy-typo": True,
    }
    assert report["required_material_claim_support_preserved_by_variant"] == {
        "rag-pt-duration-twelve-weeks": True,
        "rag-pt-duration-three-months-pt": False,
        "rag-pt-duration-extended-rehab": True,
        "rag-pt-duration-noisy-typo": True,
    }
    assert set(report["missing_refs_by_variant"].values()) == {()}
    assert set(report["missing_material_claim_ids_by_variant"].values()) == {
        (),
        ("claim-duration",)
    }
    assert set(report["missing_source_ids_by_variant"].values()) == {
        (),
        ("policy:acme-health:pt-coverage:duration-limit",)
    }
    assert "Can this patient receive three months" not in json.dumps(report, sort_keys=True)
    assert "physcial therapy" not in json.dumps(report, sort_keys=True)


def test_counterfactual_fixtures_require_committed_query_vector_keys(
    tmp_path: Path,
) -> None:
    compiled = compile_suite(SUITE)
    fixture_root = tmp_path / "fixtures" / "rag"
    fixture_root.mkdir(parents=True)
    payload = _json(COUNTERFACTUAL_FAMILIES)
    families = payload["families"]
    assert isinstance(families, list)
    family = families[0]
    assert isinstance(family, dict)
    variants = family["variants"]
    assert isinstance(variants, list)
    variant = variants[0]
    assert isinstance(variant, dict)
    del variant["query_vector_key"]
    (fixture_root / "counterfactual_query_families.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        TypeError,
        match=r"families\[0\].*rag-pt-duration-equivalent-v1.*query_vector_key",
    ):
        load_counterfactual_query_families(tmp_path, compiled_suite=compiled)


def test_counterfactual_loader_inherits_and_validates_suite_expectations(
    tmp_path: Path,
) -> None:
    compiled = compile_suite(SUITE)
    fixture_root = tmp_path / "fixtures" / "rag"
    fixture_root.mkdir(parents=True)
    payload = _json(COUNTERFACTUAL_FAMILIES)
    families = payload["families"]
    assert isinstance(families, list)
    family = families[0]
    assert isinstance(family, dict)
    family["required_material_claim_ids"] = ["claim-eligibility"]
    (fixture_root / "counterfactual_query_families.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        ValueError,
        match=r"families\[0\].*rag-pt-duration-equivalent-v1.*required_material_claim_ids",
    ):
        load_counterfactual_query_families(tmp_path, compiled_suite=compiled)


def test_counterfactual_loader_rejects_boolean_drift_threshold(
    tmp_path: Path,
) -> None:
    compiled = compile_suite(SUITE)
    fixture_root = tmp_path / "fixtures" / "rag"
    fixture_root.mkdir(parents=True)
    payload = _json(COUNTERFACTUAL_FAMILIES)
    families = payload["families"]
    assert isinstance(families, list)
    family = families[0]
    assert isinstance(family, dict)
    family["allowed_retrieval_drift_bps"] = True
    (fixture_root / "counterfactual_query_families.json").write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(
        TypeError,
        match=r"families\[0\].*rag-pt-duration-equivalent-v1.*allowed_retrieval_drift_bps",
    ):
        load_counterfactual_query_families(tmp_path, compiled_suite=compiled)


def test_counterfactual_loader_requires_compiled_suite_for_inherited_expectations() -> None:
    with pytest.raises(
        TypeError,
        match=r"families\[0\].*rag-pt-duration-equivalent-v1.*compiled_suite",
    ):
        load_counterfactual_query_families(EXAMPLE)


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


def test_rag_retrieval_rejects_boolean_top_k() -> None:
    request = _request()
    malformed_request = copy.deepcopy(request)
    retrieval = malformed_request["retrieval"]
    assert isinstance(retrieval, dict)
    retrieval["top_k"] = True

    with pytest.raises(TypeError, match="top_k"):
        retrieve_for_variant(EXAMPLE, malformed_request, variant_id=RAG_BASELINE_VARIANT_ID)


def test_rag_vector_integer_sequence_rejects_bool() -> None:
    with pytest.raises(TypeError, match="vectors.demo"):
        _int_sequence((1, True, 3), "vectors.demo")


def test_rag_string_tuple_rejects_non_string_members() -> None:
    with pytest.raises(TypeError, match="retrieval.required_source_ids"):
        _string_tuple(("policy-source", 1), "retrieval.required_source_ids")


def test_rag_query_normalization_returns_nfc() -> None:
    assert normalize_query("Cafe\u0301   POLICY") == "caf\u00e9 policy"


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


def _counterfactual_family_evaluation(
    evaluations: tuple[CounterfactualFamilyEvaluation, ...],
    query_family_id: str,
) -> CounterfactualFamilyEvaluation:
    for evaluation in evaluations:
        if evaluation.query_family_id == query_family_id:
            return evaluation
    raise AssertionError(f"missing counterfactual family evaluation: {query_family_id}")
