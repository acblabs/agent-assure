from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.runner.evidence import EvidenceAssociation
from agent_assure.runner.fixture_values import required_string
from agent_assure.schema.common import decimal_string
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.suite import CompiledSuite

RAG_BASELINE_VARIANT_ID = "rag-baseline"
RAG_RERANKER_REGRESSION_VARIANT_ID = "rag-reranker-drops-secondary-claim-source"
RAG_CORPUS_VERSION_SKEW_VARIANT_ID = "rag-corpus-version-skew"

_FIXTURE_ROOT = Path("fixtures/rag")
_CURRENT_CORPUS_MANIFEST = "corpus_manifest.json"
_SKEWED_CORPUS_MANIFEST = "corpus_manifest_skewed.json"
_COUNTERFACTUAL_FAMILIES = "counterfactual_query_families.json"
_SCORE_QUANTUM = Decimal("0.000001")
_NORMALIZED_QUERY_PATTERN = re.compile(r"\s+")
_ISO_DATE_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}")
_FILE_DIGEST_CHUNK_BYTES = 65536

RagVariantMode = Literal["baseline", "reranker_drops_secondary_claim_source", "corpus_version_skew"]


class RagFixtureError(ValueError):
    """Raised when committed RAG fixture metadata does not match artifact bytes."""


@dataclass(frozen=True)
class PolicyChunk:
    chunk_id: str
    ref_id: str
    source_id: str
    section: str
    section_type: str
    payer: str
    policy_domain: str
    effective_date: str
    expires_date: str | None
    claim_ids: tuple[str, ...]
    safe_summary: str
    vector_key: str
    content_digest: str


@dataclass(frozen=True)
class RetrievedChunk:
    chunk: PolicyChunk
    rank: int
    score: str


@dataclass(frozen=True)
class VectorStore:
    dimensions: int
    scale: int
    vectors: dict[str, tuple[int, ...]]
    cached_vectors_sha256: str
    vector_manifest_digest: str


@dataclass(frozen=True)
class PolicyCorpus:
    corpus_id: str
    corpus_version: str
    retrieval_corpus_digest: str
    chunking_config_digest: str
    vector_manifest_digest: str
    chunks: tuple[PolicyChunk, ...]
    vectors: VectorStore


@dataclass(frozen=True)
class RerankerConfig:
    config_id: str
    drop_claim_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class RetrievalResult:
    variant_mode: RagVariantMode
    corpus: PolicyCorpus
    normalized_query_digest: str
    retrieval_config_digest: str
    retrieved_chunks: tuple[RetrievedChunk, ...]
    required_source_ids: tuple[str, ...]

    @property
    def retrieved_ref_ids(self) -> tuple[str, ...]:
        return tuple(item.chunk.ref_id for item in self.retrieved_chunks)

    @property
    def retrieved_source_ids(self) -> tuple[str, ...]:
        return tuple(item.chunk.source_id for item in self.retrieved_chunks)


@dataclass(frozen=True)
class CounterfactualQueryVariant:
    query_variant_id: str
    query: str
    query_vector_key: str


@dataclass(frozen=True)
class CounterfactualQueryFamily:
    query_family_id: str
    canonical_case_id: str
    source_fixture_id: str
    expected_recommendation: str | None
    allowed_outcomes: tuple[str, ...]
    required_evidence_refs: tuple[str, ...]
    required_material_claim_ids: tuple[str, ...]
    required_source_ids: tuple[str, ...]
    allowed_retrieval_drift_bps: int
    variants: tuple[CounterfactualQueryVariant, ...]


@dataclass(frozen=True)
class CounterfactualVariantEvaluation:
    query_variant_id: str
    query_digest: str
    retrieved_ref_ids: tuple[str, ...]
    retrieved_source_ids: tuple[str, ...]
    retrieved_material_claim_ids: tuple[str, ...]
    missing_required_evidence_refs: tuple[str, ...]
    missing_required_source_ids: tuple[str, ...]
    missing_required_material_claim_ids: tuple[str, ...]
    retrieval_jaccard_bps: int
    required_ref_coverage_bps: int
    lowest_required_score: str | None
    retrieval_drift_exceeded: bool
    escalated: bool

    @property
    def preserved_required_ref_support(self) -> bool:
        return not self.missing_required_evidence_refs

    @property
    def preserved_required_source_support(self) -> bool:
        return not self.missing_required_source_ids

    @property
    def preserved_required_material_claim_support(self) -> bool:
        return not self.missing_required_material_claim_ids

    def report_payload(self) -> dict[str, object]:
        return {
            "query_variant_id": self.query_variant_id,
            "query_digest": self.query_digest,
            "retrieved_ref_ids": self.retrieved_ref_ids,
            "retrieved_source_ids": self.retrieved_source_ids,
            "retrieved_material_claim_ids": self.retrieved_material_claim_ids,
            "missing_required_evidence_refs": self.missing_required_evidence_refs,
            "missing_required_source_ids": self.missing_required_source_ids,
            "missing_required_material_claim_ids": self.missing_required_material_claim_ids,
            "retrieval_jaccard_bps": self.retrieval_jaccard_bps,
            "required_ref_coverage_bps": self.required_ref_coverage_bps,
            "preserved_required_ref_support": self.preserved_required_ref_support,
            "preserved_required_source_support": self.preserved_required_source_support,
            "preserved_required_material_claim_support": (
                self.preserved_required_material_claim_support
            ),
            "lowest_required_score": self.lowest_required_score,
            "retrieval_drift_exceeded": self.retrieval_drift_exceeded,
            "escalated": self.escalated,
        }


@dataclass(frozen=True)
class CounterfactualFamilyEvaluation:
    query_family_id: str
    canonical_case_id: str
    expected_recommendation: str | None
    allowed_outcomes: tuple[str, ...]
    required_evidence_refs: tuple[str, ...]
    required_material_claim_ids: tuple[str, ...]
    required_source_ids: tuple[str, ...]
    allowed_retrieval_drift_bps: int
    reference_variant_id: str
    reference_query_digest: str
    reference_retrieval_ref_ids: tuple[str, ...]
    canonical_decision_matches_family_expectation: bool | None
    variant_evaluations: tuple[CounterfactualVariantEvaluation, ...]

    @property
    def variants_evaluated(self) -> int:
        return len(self.variant_evaluations)

    @property
    def preserved_required_ref_support(self) -> bool:
        return all(
            item.preserved_required_ref_support
            for item in self.variant_evaluations
        )

    @property
    def preserved_required_source_support(self) -> bool:
        return all(
            item.preserved_required_source_support
            for item in self.variant_evaluations
        )

    @property
    def preserved_material_claim_support(self) -> bool:
        return all(
            item.preserved_required_material_claim_support
            for item in self.variant_evaluations
        )

    @property
    def escalated_variants(self) -> tuple[str, ...]:
        return tuple(
            item.query_variant_id
            for item in self.variant_evaluations
            if item.escalated
        )

    def report_payload(self) -> dict[str, object]:
        return {
            "query_family_id": self.query_family_id,
            "canonical_case_id": self.canonical_case_id,
            "variants_evaluated": self.variants_evaluated,
            "expected_decision": {
                "expected_recommendation": self.expected_recommendation,
                "allowed_outcomes": self.allowed_outcomes,
            },
            "decision_measurement_scope": "canonical_case_only",
            "decision_fields_evaluated": (
                self.canonical_decision_matches_family_expectation is not None
            ),
            "canonical_decision_matches_family_expectation": (
                self.canonical_decision_matches_family_expectation
            ),
            "preserved_required_ref_support": self.preserved_required_ref_support,
            "preserved_required_source_support": self.preserved_required_source_support,
            "preserved_material_claim_support": self.preserved_material_claim_support,
            "reference_variant_id": self.reference_variant_id,
            "reference_query_digest": self.reference_query_digest,
            "reference_retrieval_ref_ids": self.reference_retrieval_ref_ids,
            "required_evidence_refs": self.required_evidence_refs,
            "required_material_claim_ids": self.required_material_claim_ids,
            "required_source_ids": self.required_source_ids,
            "allowed_retrieval_drift_bps": self.allowed_retrieval_drift_bps,
            "missing_refs_by_variant": {
                item.query_variant_id: item.missing_required_evidence_refs
                for item in self.variant_evaluations
            },
            "missing_material_claim_ids_by_variant": {
                item.query_variant_id: item.missing_required_material_claim_ids
                for item in self.variant_evaluations
            },
            "missing_source_ids_by_variant": {
                item.query_variant_id: item.missing_required_source_ids
                for item in self.variant_evaluations
            },
            "retrieval_jaccard_bps_by_variant": {
                item.query_variant_id: item.retrieval_jaccard_bps
                for item in self.variant_evaluations
            },
            "required_ref_coverage_bps_by_variant": {
                item.query_variant_id: item.required_ref_coverage_bps
                for item in self.variant_evaluations
            },
            "required_ref_support_preserved_by_variant": {
                item.query_variant_id: item.preserved_required_ref_support
                for item in self.variant_evaluations
            },
            "required_source_support_preserved_by_variant": {
                item.query_variant_id: item.preserved_required_source_support
                for item in self.variant_evaluations
            },
            "required_material_claim_support_preserved_by_variant": {
                item.query_variant_id: item.preserved_required_material_claim_support
                for item in self.variant_evaluations
            },
            "lowest_score_variant": _lowest_score_variant(self.variant_evaluations),
            "escalated_variants": self.escalated_variants,
            "variants": tuple(item.report_payload() for item in self.variant_evaluations),
        }


def rag_mode_for_variant(variant_id: str) -> RagVariantMode:
    if variant_id == RAG_BASELINE_VARIANT_ID:
        return "baseline"
    if variant_id == RAG_RERANKER_REGRESSION_VARIANT_ID:
        return "reranker_drops_secondary_claim_source"
    if variant_id == RAG_CORPUS_VERSION_SKEW_VARIANT_ID:
        return "corpus_version_skew"
    raise ValueError(f"unknown prior-auth RAG variant_id: {variant_id}")


def retrieve_for_variant(
    suite_root: Path,
    request: dict[str, object],
    *,
    variant_id: str,
) -> RetrievalResult:
    mode = rag_mode_for_variant(variant_id)
    corpus = load_policy_corpus(suite_root, manifest_name=_manifest_name_for_mode(mode))
    return retrieve_policy_chunks(corpus, request, variant_mode=mode)


def load_policy_corpus(
    suite_root: Path,
    *,
    manifest_name: str = _CURRENT_CORPUS_MANIFEST,
) -> PolicyCorpus:
    fixture_root = suite_root / _FIXTURE_ROOT
    manifest_path = fixture_root / manifest_name
    manifest = _read_json_object(manifest_path)

    vector_manifest_path = fixture_root / _string(manifest, "vector_manifest_path")
    vector_manifest_digest = _file_sha256(vector_manifest_path)
    _assert_digest(
        observed=vector_manifest_digest,
        expected=_string(manifest, "vector_manifest_digest"),
        label=f"{manifest_name}:vector_manifest_digest",
    )

    vector_manifest = _read_json_object(vector_manifest_path)
    vectors = _load_vectors(fixture_root, vector_manifest, vector_manifest_digest)
    chunking_config = _mapping(manifest.get("chunking_config"), "chunking_config")
    chunking_config_digest = sha256_hexdigest(chunking_config)
    _assert_digest(
        observed=chunking_config_digest,
        expected=_string(manifest, "chunking_config_digest"),
        label=f"{manifest_name}:chunking_config_digest",
    )

    chunks = _load_manifest_chunks(fixture_root, manifest)
    retrieval_corpus_digest = _retrieval_corpus_digest(
        corpus_id=_string(manifest, "corpus_id"),
        corpus_version=_string(manifest, "corpus_version"),
        chunking_config_digest=chunking_config_digest,
        chunks=chunks,
    )
    _assert_digest(
        observed=retrieval_corpus_digest,
        expected=_string(manifest, "retrieval_corpus_digest"),
        label=f"{manifest_name}:retrieval_corpus_digest",
    )
    return PolicyCorpus(
        corpus_id=_string(manifest, "corpus_id"),
        corpus_version=_string(manifest, "corpus_version"),
        retrieval_corpus_digest=retrieval_corpus_digest,
        chunking_config_digest=chunking_config_digest,
        vector_manifest_digest=vector_manifest_digest,
        chunks=chunks,
        vectors=vectors,
    )


def retrieve_policy_chunks(
    corpus: PolicyCorpus,
    request: dict[str, object],
    *,
    variant_mode: RagVariantMode,
) -> RetrievalResult:
    retrieval_request = _mapping(request.get("retrieval"), "retrieval")
    query_key = _string(retrieval_request, "query_vector_key")
    query = _string(retrieval_request, "query")
    normalized_query = normalize_query(query)
    normalized_query_digest = sha256_hexdigest(normalized_query)
    query_vector = _vector_for(corpus.vectors, query_key)
    filters = _mapping(retrieval_request.get("filters"), "retrieval.filters")
    as_of_date = _date_string(retrieval_request, "as_of_date")
    top_k = _positive_int(retrieval_request.get("top_k"), "retrieval.top_k")
    threshold = _score_threshold(retrieval_request.get("score_threshold"))
    required_source_ids = _string_tuple(
        retrieval_request.get("required_source_ids", ()),
        "retrieval.required_source_ids",
    )
    reranker_config = _reranker_config(
        retrieval_request,
        variant_mode,
        query_vector_key=query_key,
    )

    scored: list[RetrievedChunk] = []
    for chunk in corpus.chunks:
        if not _chunk_matches_filters(chunk, filters, as_of_date=as_of_date):
            continue
        chunk_vector = _vector_for(corpus.vectors, chunk.vector_key)
        score = _quantized_cosine(query_vector, chunk_vector)
        if Decimal(score) < threshold:
            continue
        scored.append(RetrievedChunk(chunk=chunk, rank=0, score=score))

    ranked = tuple(
        RetrievedChunk(chunk=item.chunk, rank=index + 1, score=item.score)
        for index, item in enumerate(
            sorted(
                scored,
                key=lambda item: (
                    -Decimal(item.score),
                    item.chunk.content_digest,
                    item.chunk.ref_id,
                ),
            )[:top_k]
        )
    )
    # The synthetic demo perturbation runs after top_k so dropped support shrinks
    # the observed result set instead of backfilling from lower-ranked chunks.
    ranked = _apply_reranker(ranked, reranker_config)
    retrieval_config_digest = sha256_hexdigest(
        {
            "filters": filters,
            "reranker": {
                "config_id": reranker_config.config_id,
                "drop_claim_ids": reranker_config.drop_claim_ids,
            },
            "score_threshold": decimal_string(threshold),
            "top_k": top_k,
        }
    )
    return RetrievalResult(
        variant_mode=variant_mode,
        corpus=corpus,
        normalized_query_digest=normalized_query_digest,
        retrieval_config_digest=retrieval_config_digest,
        retrieved_chunks=ranked,
        required_source_ids=required_source_ids,
    )


def evidence_from_retrieval(result: RetrievalResult) -> tuple[EvidenceAssociation, ...]:
    return tuple(
        EvidenceAssociation(
            ref_id=item.chunk.ref_id,
            source_id=item.chunk.source_id,
            content_digest=item.chunk.content_digest,
            claim_ids=item.chunk.claim_ids,
        )
        for item in result.retrieved_chunks
    )


def retrieval_diff_summary(
    baseline: RetrievalResult,
    candidate: RetrievalResult,
) -> dict[str, object]:
    baseline_ref_ids = baseline.retrieved_ref_ids
    candidate_ref_ids = candidate.retrieved_ref_ids
    baseline_set = set(baseline_ref_ids)
    candidate_set = set(candidate_ref_ids)
    shared_ref_ids = tuple(sorted(baseline_set & candidate_set))
    rank_changes = []
    baseline_ranks = {item.chunk.ref_id: item.rank for item in baseline.retrieved_chunks}
    candidate_ranks = {item.chunk.ref_id: item.rank for item in candidate.retrieved_chunks}
    for ref_id in shared_ref_ids:
        baseline_rank = baseline_ranks[ref_id]
        candidate_rank = candidate_ranks[ref_id]
        if baseline_rank != candidate_rank:
            rank_changes.append(
                {
                    "ref_id": ref_id,
                    "baseline_rank": baseline_rank,
                    "candidate_rank": candidate_rank,
                }
            )
    missing_required = _missing(baseline.required_source_ids, candidate.retrieved_source_ids)
    jaccard_bps = _jaccard_bps(baseline_set, candidate_set)
    vector_manifest_digest: str | dict[str, str]
    if baseline.corpus.vector_manifest_digest == candidate.corpus.vector_manifest_digest:
        vector_manifest_digest = baseline.corpus.vector_manifest_digest
    else:
        vector_manifest_digest = {
            "baseline": baseline.corpus.vector_manifest_digest,
            "candidate": candidate.corpus.vector_manifest_digest,
        }
    retrieval_config_digest: str | dict[str, str]
    if baseline.retrieval_config_digest == candidate.retrieval_config_digest:
        retrieval_config_digest = baseline.retrieval_config_digest
    else:
        retrieval_config_digest = {
            "baseline": baseline.retrieval_config_digest,
            "candidate": candidate.retrieval_config_digest,
        }
    return {
        "baseline_only_ref_ids": tuple(sorted(baseline_set - candidate_set)),
        "candidate_only_ref_ids": tuple(sorted(candidate_set - baseline_set)),
        "shared_ref_ids": shared_ref_ids,
        "retrieval_jaccard_bps": jaccard_bps,
        "rank_changes": tuple(rank_changes),
        "missing_required_source_ids": missing_required,
        "corpus_digest_changed": (
            baseline.corpus.retrieval_corpus_digest
            != candidate.corpus.retrieval_corpus_digest
        ),
        "baseline_retrieval_corpus_digest": baseline.corpus.retrieval_corpus_digest,
        "candidate_retrieval_corpus_digest": candidate.corpus.retrieval_corpus_digest,
        "vector_manifest_digest": vector_manifest_digest,
        "retrieval_config_digest": retrieval_config_digest,
    }


def retrieval_output_payload(result: RetrievalResult) -> dict[str, object]:
    return {
        "variant_mode": result.variant_mode,
        "retrieval_corpus_digest": result.corpus.retrieval_corpus_digest,
        "corpus_version": result.corpus.corpus_version,
        "normalized_query_digest": result.normalized_query_digest,
        "retrieval_config_digest": result.retrieval_config_digest,
        "retrieved_chunks": tuple(
            {
                "rank": item.rank,
                "score": item.score,
                "ref_id": item.chunk.ref_id,
                "source_id": item.chunk.source_id,
                "chunk_digest": item.chunk.content_digest,
                "claim_ids": item.chunk.claim_ids,
            }
            for item in result.retrieved_chunks
        ),
    }


def load_counterfactual_query_families(
    suite_root: Path,
    *,
    fixture_name: str = _COUNTERFACTUAL_FAMILIES,
    compiled_suite: CompiledSuite | None = None,
) -> tuple[CounterfactualQueryFamily, ...]:
    """Load fixture-authored metamorphic RAG query families.

    The Sprint 8 fixture keeps case-level decision and material-claim
    expectations single-sourced in ``rag_suite.yaml`` whenever ``compiled_suite``
    is supplied; family JSON should only declare the RAG-specific query variants
    and source-ID requirements.
    """
    payload = _read_json_object(suite_root / _FIXTURE_ROOT / fixture_name)
    schema_version = _string(payload, "schema_version")
    if schema_version != "counterfactual-rag-family-v1":
        raise ValueError(f"unsupported counterfactual family schema: {schema_version}")
    families = tuple(
        _load_counterfactual_family_with_context(
            item,
            index,
            compiled_suite=compiled_suite,
        )
        for index, item in enumerate(_sequence(payload.get("families"), "families"))
    )
    if not families:
        raise ValueError("counterfactual fixture must define at least one family")
    return families


def evaluate_counterfactual_families(
    suite_root: Path,
    *,
    variant_id: str,
    compiled_suite: CompiledSuite | None = None,
    canonical_decision_matches_family_expectation: bool | None = None,
    reference_variant_id: str = RAG_BASELINE_VARIANT_ID,
    fixture_name: str = _COUNTERFACTUAL_FAMILIES,
) -> tuple[CounterfactualFamilyEvaluation, ...]:
    return tuple(
        evaluate_counterfactual_family(
            suite_root,
            family,
            variant_id=variant_id,
            canonical_decision_matches_family_expectation=(
                canonical_decision_matches_family_expectation
            ),
            reference_variant_id=reference_variant_id,
        )
        for family in load_counterfactual_query_families(
            suite_root,
            fixture_name=fixture_name,
            compiled_suite=compiled_suite,
        )
    )


def evaluate_counterfactual_family(
    suite_root: Path,
    family: CounterfactualQueryFamily,
    *,
    variant_id: str,
    canonical_decision_matches_family_expectation: bool | None = None,
    reference_variant_id: str = RAG_BASELINE_VARIANT_ID,
) -> CounterfactualFamilyEvaluation:
    source_request = _counterfactual_source_request(suite_root, family)
    reference_mode = rag_mode_for_variant(reference_variant_id)
    reference_manifest_name = _manifest_name_for_mode(reference_mode)
    reference_corpus = load_policy_corpus(
        suite_root,
        manifest_name=reference_manifest_name,
    )
    reference_retrieval = retrieve_policy_chunks(
        reference_corpus,
        source_request,
        variant_mode=reference_mode,
    )
    variant_mode = rag_mode_for_variant(variant_id)
    variant_manifest_name = _manifest_name_for_mode(variant_mode)
    variant_corpus = (
        reference_corpus
        if variant_manifest_name == reference_manifest_name
        else load_policy_corpus(
            suite_root,
            manifest_name=variant_manifest_name,
        )
    )
    return CounterfactualFamilyEvaluation(
        query_family_id=family.query_family_id,
        canonical_case_id=family.canonical_case_id,
        expected_recommendation=family.expected_recommendation,
        allowed_outcomes=family.allowed_outcomes,
        required_evidence_refs=family.required_evidence_refs,
        required_material_claim_ids=family.required_material_claim_ids,
        required_source_ids=family.required_source_ids,
        allowed_retrieval_drift_bps=family.allowed_retrieval_drift_bps,
        reference_variant_id=reference_variant_id,
        reference_query_digest=reference_retrieval.normalized_query_digest,
        reference_retrieval_ref_ids=reference_retrieval.retrieved_ref_ids,
        canonical_decision_matches_family_expectation=(
            canonical_decision_matches_family_expectation
        ),
        variant_evaluations=tuple(
            _evaluate_counterfactual_variant(
                family,
                source_request,
                variant,
                reference_retrieval=reference_retrieval,
                variant_corpus=variant_corpus,
                variant_mode=variant_mode,
            )
            for variant in family.variants
        ),
    )


def normalize_query(query: str) -> str:
    folded = unicodedata.normalize("NFC", query.casefold())
    return _NORMALIZED_QUERY_PATTERN.sub(" ", folded).strip()


def _manifest_name_for_mode(mode: RagVariantMode) -> str:
    return (
        _SKEWED_CORPUS_MANIFEST
        if mode == "corpus_version_skew"
        else _CURRENT_CORPUS_MANIFEST
    )


def _load_counterfactual_family_with_context(
    payload: object,
    index: int,
    *,
    compiled_suite: CompiledSuite | None,
) -> CounterfactualQueryFamily:
    try:
        return _counterfactual_family_from_payload(
            payload,
            index,
            compiled_suite=compiled_suite,
        )
    except (TypeError, ValueError) as exc:
        context = _counterfactual_family_context(payload, index)
        message = f"counterfactual {context}: {exc}"
        if isinstance(exc, TypeError):
            raise TypeError(message) from exc
        raise ValueError(message) from exc


def _counterfactual_family_context(payload: object, index: int) -> str:
    if isinstance(payload, dict):
        query_family_id = payload.get("query_family_id")
        if isinstance(query_family_id, str) and query_family_id:
            return f"families[{index}] query_family_id={query_family_id!r}"
    return f"families[{index}]"


def _counterfactual_family_from_payload(
    payload: object,
    index: int,
    *,
    compiled_suite: CompiledSuite | None,
) -> CounterfactualQueryFamily:
    mapping = _mapping(payload, f"families[{index}]")
    canonical_case_id = _string(mapping, "canonical_case_id")
    expectation = (
        _expectation_for_case(compiled_suite, canonical_case_id)
        if compiled_suite is not None
        else None
    )
    expected_recommendation = _optional_string(mapping.get("expected_recommendation"))
    if expectation is not None:
        expected_recommendation = _field_or_expectation_string(
            observed=expected_recommendation,
            expected=expectation.expected_recommendation,
            field_name="expected_recommendation",
            case_id=canonical_case_id,
        )
    if expected_recommendation is None and expectation is None:
        raise TypeError(
            "expected_recommendation must be declared in the family fixture or "
            "inherited by passing compiled_suite"
        )

    allowed_outcomes = _optional_string_tuple(mapping.get("allowed_outcomes"))
    if expectation is not None:
        expected_allowed_outcomes = (
            expectation.allowed_outcomes
            if expectation.allowed_outcomes
            else (
                ()
                if expectation.expected_recommendation is None
                else (expectation.expected_recommendation,)
            )
        )
        allowed_outcomes = _field_or_expectation_tuple(
            observed=allowed_outcomes,
            expected=expected_allowed_outcomes,
            field_name="allowed_outcomes",
            case_id=canonical_case_id,
        )
    if allowed_outcomes is None:
        allowed_outcomes = (
            (expected_recommendation,)
            if expected_recommendation is not None
            else ()
        )

    required_evidence_refs = _optional_string_tuple(mapping.get("required_evidence_refs"))
    if expectation is not None:
        required_evidence_refs = _field_or_expectation_tuple(
            observed=required_evidence_refs,
            expected=expectation.required_evidence_refs,
            field_name="required_evidence_refs",
            case_id=canonical_case_id,
        )
    required_material_claim_ids = _optional_string_tuple(
        mapping.get("required_material_claim_ids")
    )
    if expectation is not None:
        required_material_claim_ids = _field_or_expectation_tuple(
            observed=required_material_claim_ids,
            expected=expectation.material_claim_ids,
            field_name="required_material_claim_ids",
            case_id=canonical_case_id,
        )

    variants = tuple(
        _counterfactual_variant_from_payload(item, variant_index)
        for variant_index, item in enumerate(_sequence(mapping.get("variants"), "variants"))
    )
    if not variants:
        raise ValueError("counterfactual family must define at least one variant")
    variant_ids = tuple(item.query_variant_id for item in variants)
    if len(set(variant_ids)) != len(variant_ids):
        raise ValueError("counterfactual query_variant_id values must be unique")
    return CounterfactualQueryFamily(
        query_family_id=_string(mapping, "query_family_id"),
        canonical_case_id=canonical_case_id,
        source_fixture_id=_string(mapping, "source_fixture_id"),
        expected_recommendation=expected_recommendation,
        allowed_outcomes=allowed_outcomes,
        required_evidence_refs=required_evidence_refs or (),
        required_material_claim_ids=required_material_claim_ids or (),
        required_source_ids=_string_tuple(
            mapping.get("required_source_ids", ()),
            "required_source_ids",
        ),
        allowed_retrieval_drift_bps=_basis_points(
            mapping.get("allowed_retrieval_drift_bps", 0),
            "allowed_retrieval_drift_bps",
        ),
        variants=variants,
    )


def _counterfactual_variant_from_payload(
    payload: object,
    index: int,
) -> CounterfactualQueryVariant:
    mapping = _mapping(payload, f"variants[{index}]")
    return CounterfactualQueryVariant(
        query_variant_id=_string(mapping, "query_variant_id"),
        query=_string(mapping, "query"),
        query_vector_key=_string(mapping, "query_vector_key"),
    )


def _counterfactual_source_request(
    suite_root: Path,
    family: CounterfactualQueryFamily,
) -> dict[str, object]:
    request = _read_json_object(
        suite_root / _FIXTURE_ROOT / "requests" / f"{family.source_fixture_id}.json"
    )
    case_id = _string(request, "case_id")
    if case_id != family.canonical_case_id:
        raise ValueError(
            "counterfactual source request case_id does not match canonical_case_id: "
            f"{case_id!r} != {family.canonical_case_id!r}"
        )
    return request


def _expectation_for_case(compiled_suite: CompiledSuite, case_id: str) -> Expectation:
    for expectation in compiled_suite.resolved_expectations:
        if expectation.case_id == case_id:
            return expectation
    raise ValueError(f"counterfactual canonical_case_id not found in suite: {case_id}")


def _field_or_expectation_string(
    *,
    observed: str | None,
    expected: str | None,
    field_name: str,
    case_id: str,
) -> str | None:
    if observed is not None and expected is not None and observed != expected:
        raise ValueError(
            f"counterfactual {field_name} for {case_id!r} does not match suite expectation"
        )
    return expected if expected is not None else observed


def _field_or_expectation_tuple(
    *,
    observed: tuple[str, ...] | None,
    expected: tuple[str, ...],
    field_name: str,
    case_id: str,
) -> tuple[str, ...]:
    if observed is not None and observed != expected:
        raise ValueError(
            f"counterfactual {field_name} for {case_id!r} does not match suite expectation"
        )
    return expected


def _evaluate_counterfactual_variant(
    family: CounterfactualQueryFamily,
    source_request: dict[str, object],
    variant: CounterfactualQueryVariant,
    *,
    reference_retrieval: RetrievalResult,
    variant_corpus: PolicyCorpus,
    variant_mode: RagVariantMode,
) -> CounterfactualVariantEvaluation:
    request = _request_with_counterfactual_query(source_request, variant)
    retrieval = retrieve_policy_chunks(
        variant_corpus,
        request,
        variant_mode=variant_mode,
    )
    retrieved_ref_ids = retrieval.retrieved_ref_ids
    retrieved_source_ids = retrieval.retrieved_source_ids
    retrieved_material_claim_ids = tuple(
        sorted(
            {
                claim_id
                for item in retrieval.retrieved_chunks
                for claim_id in item.chunk.claim_ids
            }
        )
    )
    missing_refs = _missing(family.required_evidence_refs, retrieved_ref_ids)
    missing_sources = _missing(family.required_source_ids, retrieved_source_ids)
    missing_material_claim_ids = _missing(
        family.required_material_claim_ids,
        retrieved_material_claim_ids,
    )
    retrieval_jaccard_bps = _jaccard_bps(
        set(reference_retrieval.retrieved_ref_ids),
        set(retrieved_ref_ids),
    )
    required_ref_coverage_bps = _coverage_bps(
        family.required_evidence_refs,
        retrieved_ref_ids,
    )
    # Basis-point ratios floor fractional values, making drift thresholds
    # slightly conservative at exact boundaries.
    retrieval_drift_exceeded = 10000 - retrieval_jaccard_bps > family.allowed_retrieval_drift_bps
    escalated = bool(
        missing_refs
        or missing_sources
        or missing_material_claim_ids
        or retrieval_drift_exceeded
    )
    return CounterfactualVariantEvaluation(
        query_variant_id=variant.query_variant_id,
        query_digest=retrieval.normalized_query_digest,
        retrieved_ref_ids=retrieved_ref_ids,
        retrieved_source_ids=retrieved_source_ids,
        retrieved_material_claim_ids=retrieved_material_claim_ids,
        missing_required_evidence_refs=missing_refs,
        missing_required_source_ids=missing_sources,
        missing_required_material_claim_ids=missing_material_claim_ids,
        retrieval_jaccard_bps=retrieval_jaccard_bps,
        required_ref_coverage_bps=required_ref_coverage_bps,
        lowest_required_score=_lowest_required_score(retrieval, family.required_evidence_refs),
        retrieval_drift_exceeded=retrieval_drift_exceeded,
        escalated=escalated,
    )


def _request_with_counterfactual_query(
    request: dict[str, object],
    variant: CounterfactualQueryVariant,
) -> dict[str, object]:
    updated = dict(request)
    retrieval = _mapping(updated.get("retrieval"), "retrieval")
    retrieval["query"] = variant.query
    retrieval["query_vector_key"] = variant.query_vector_key
    updated["retrieval"] = retrieval
    return updated


def _missing(required: tuple[str, ...], observed: tuple[str, ...]) -> tuple[str, ...]:
    observed_set = set(observed)
    return tuple(item for item in required if item not in observed_set)


def _jaccard_bps(left: set[str], right: set[str]) -> int:
    union = left | right
    if not union:
        return 10000
    return int(Decimal(len(left & right) * 10000) / Decimal(len(union)))


def _coverage_bps(required: tuple[str, ...], observed: tuple[str, ...]) -> int:
    required_set = set(required)
    if not required_set:
        return 10000
    return int(Decimal(len(required_set & set(observed)) * 10000) / Decimal(len(required_set)))


def _lowest_required_score(
    retrieval: RetrievalResult,
    required_evidence_refs: tuple[str, ...],
) -> str | None:
    required_refs = set(required_evidence_refs)
    scores = tuple(
        item.score
        for item in retrieval.retrieved_chunks
        if item.chunk.ref_id in required_refs
    )
    if not scores:
        return None
    return min(scores, key=Decimal)


def _lowest_score_variant(
    variants: tuple[CounterfactualVariantEvaluation, ...],
) -> dict[str, object] | None:
    scored = tuple(
        (Decimal(item.lowest_required_score), item)
        for item in variants
        if item.lowest_required_score is not None
    )
    if not scored:
        return None
    # The variant ID tie-breaker keeps reports deterministic when scores match.
    _, lowest = min(scored, key=lambda item: (item[0], item[1].query_variant_id))
    return {
        "query_variant_id": lowest.query_variant_id,
        "lowest_required_score": lowest.lowest_required_score,
    }


def _reranker_config(
    retrieval_request: dict[str, object],
    mode: RagVariantMode,
    *,
    query_vector_key: str,
) -> RerankerConfig:
    raw_configs = retrieval_request.get("reranker_configs", {})
    configs = _mapping(raw_configs, "retrieval.reranker_configs")
    raw_config = configs.get(mode)
    if raw_config is None:
        return RerankerConfig(config_id="none")
    config = _mapping(raw_config, f"retrieval.reranker_configs.{mode}")
    drop_claim_ids = _string_tuple(config.get("drop_claim_ids", ()), "drop_claim_ids")
    keyed_drops = _mapping(
        config.get("drop_claim_ids_by_query_vector_key", {}),
        "drop_claim_ids_by_query_vector_key",
    )
    keyed_drop_claim_ids = _string_tuple(
        keyed_drops.get(query_vector_key, ()),
        f"drop_claim_ids_by_query_vector_key.{query_vector_key}",
    )
    return RerankerConfig(
        config_id=_string(config, "config_id"),
        drop_claim_ids=tuple(dict.fromkeys((*drop_claim_ids, *keyed_drop_claim_ids))),
    )


def _apply_reranker(
    ranked: tuple[RetrievedChunk, ...],
    config: RerankerConfig,
) -> tuple[RetrievedChunk, ...]:
    if not config.drop_claim_ids:
        return ranked
    drop_claim_ids = set(config.drop_claim_ids)
    filtered = tuple(
        item
        for item in ranked
        if not drop_claim_ids.intersection(item.chunk.claim_ids)
    )
    return tuple(
        RetrievedChunk(chunk=item.chunk, rank=index + 1, score=item.score)
        for index, item in enumerate(filtered)
    )


def _load_manifest_chunks(
    fixture_root: Path,
    manifest: dict[str, object],
) -> tuple[PolicyChunk, ...]:
    chunks: list[PolicyChunk] = []
    for entry in _sequence(manifest.get("chunks"), "chunks"):
        entry_map = _mapping(entry, "chunks[]")
        chunk_path = fixture_root / _string(entry_map, "path")
        payload = _read_json_object(chunk_path)
        chunk = _chunk_from_payload(payload)
        for field_name in ("chunk_id", "ref_id", "source_id"):
            expected = _string(entry_map, field_name)
            observed = getattr(chunk, field_name)
            if observed != expected:
                raise ValueError(
                    f"chunk manifest {field_name} mismatch for {chunk_path}: "
                    f"{observed!r} != {expected!r}"
                )
        _assert_digest(
            observed=chunk.content_digest,
            expected=_string(entry_map, "content_digest"),
            label=f"{chunk_path}:content_digest",
        )
        chunks.append(chunk)
    return tuple(sorted(chunks, key=lambda chunk: chunk.content_digest))


def _chunk_from_payload(payload: dict[str, object]) -> PolicyChunk:
    effective_date = _date_string(payload, "effective_date")
    expires_date = _optional_date_string(payload.get("expires_date"), "expires_date")
    if expires_date is not None and expires_date <= effective_date:
        raise ValueError("expires_date must be after effective_date")
    return PolicyChunk(
        chunk_id=required_string(payload, "chunk_id"),
        ref_id=required_string(payload, "ref_id"),
        source_id=required_string(payload, "source_id"),
        section=required_string(payload, "section"),
        section_type=required_string(payload, "section_type"),
        payer=required_string(payload, "payer"),
        policy_domain=required_string(payload, "policy_domain"),
        effective_date=effective_date,
        expires_date=expires_date,
        claim_ids=_string_tuple(payload.get("claim_ids", ()), "claim_ids"),
        safe_summary=required_string(payload, "safe_summary"),
        vector_key=required_string(payload, "vector_key"),
        content_digest=sha256_hexdigest(payload),
    )


def _load_vectors(
    fixture_root: Path,
    vector_manifest: dict[str, object],
    vector_manifest_digest: str,
) -> VectorStore:
    vector_path = fixture_root / _string(vector_manifest, "cached_vectors_path")
    cached_vectors_sha256 = _file_sha256(vector_path)
    _assert_digest(
        observed=cached_vectors_sha256,
        expected=_string(vector_manifest, "cached_vectors_sha256"),
        label=f"{vector_path}:cached_vectors_sha256",
    )
    payload = _read_json_object(vector_path)
    dimensions = _positive_int(payload.get("dimensions"), "dimensions")
    scale = _positive_int(payload.get("scale"), "scale")
    vectors_payload = _mapping(payload.get("vectors"), "vectors")
    vectors: dict[str, tuple[int, ...]] = {}
    for key, value in vectors_payload.items():
        vector = tuple(_int_sequence(value, f"vectors.{key}"))
        if len(vector) != dimensions:
            raise ValueError(f"vector {key!r} has dimension {len(vector)}, expected {dimensions}")
        vectors[str(key)] = vector
    manifest_dimensions = _positive_int(vector_manifest.get("dimensions"), "dimensions")
    if manifest_dimensions != dimensions:
        raise ValueError("vector manifest dimensions do not match cached vectors")
    return VectorStore(
        dimensions=dimensions,
        scale=scale,
        vectors=vectors,
        cached_vectors_sha256=cached_vectors_sha256,
        vector_manifest_digest=vector_manifest_digest,
    )


def _retrieval_corpus_digest(
    *,
    corpus_id: str,
    corpus_version: str,
    chunking_config_digest: str,
    chunks: tuple[PolicyChunk, ...],
) -> str:
    return sha256_hexdigest(
        {
            "corpus_id": corpus_id,
            "corpus_version": corpus_version,
            "chunking_config_digest": chunking_config_digest,
            "chunks": tuple(
                {
                    "chunk_id": chunk.chunk_id,
                    "ref_id": chunk.ref_id,
                    "source_id": chunk.source_id,
                    "content_digest": chunk.content_digest,
                }
                for chunk in sorted(chunks, key=lambda item: item.content_digest)
            ),
        }
    )


def _chunk_matches_filters(
    chunk: PolicyChunk,
    filters: dict[str, object],
    *,
    as_of_date: str,
) -> bool:
    expected_fields = ("payer", "policy_domain", "section_type")
    if any(
        getattr(chunk, field_name) != _string(filters, field_name)
        for field_name in expected_fields
    ):
        return False
    if chunk.effective_date > as_of_date:
        return False
    return chunk.expires_date is None or chunk.expires_date > as_of_date


def _quantized_cosine(left: tuple[int, ...], right: tuple[int, ...]) -> str:
    left_norm_sq = Decimal(sum(value * value for value in left))
    right_norm_sq = Decimal(sum(value * value for value in right))
    if left_norm_sq == 0 or right_norm_sq == 0:
        return "0.000000"
    numerator = Decimal(sum(a * b for a, b in zip(left, right, strict=True)))
    with localcontext() as context:
        context.prec = 64
        score = (numerator / (left_norm_sq.sqrt() * right_norm_sq.sqrt())).quantize(
            _SCORE_QUANTUM
        )
    return decimal_string(score)


def _vector_for(store: VectorStore, key: str) -> tuple[int, ...]:
    try:
        return store.vectors[key]
    except KeyError as exc:
        raise ValueError(f"cached vector is missing: {key}") from exc


def _file_sha256(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(_FILE_DIGEST_CHUNK_BYTES), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_json_object(path: Path) -> dict[str, object]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return {str(key): value for key, value in payload.items()}


def _assert_digest(*, observed: str, expected: str, label: str) -> None:
    if observed != expected:
        raise RagFixtureError(
            f"{label} digest mismatch: observed {observed}, expected {expected}"
        )


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(f"{label} must be a mapping")
    return {str(key): item for key, item in value.items()}


def _sequence(value: object, label: str) -> tuple[object, ...]:
    if not isinstance(value, list | tuple):
        raise TypeError(f"{label} must be a sequence")
    return tuple(value)


def _string(mapping: dict[str, object], key: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value:
        raise TypeError(f"{key} must be a non-empty string")
    return value


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value:
        raise TypeError("optional string field must be a non-empty string when present")
    return value


def _date_string(mapping: dict[str, object], key: str) -> str:
    value = _string(mapping, key)
    _validate_iso_date(value, key)
    return value


def _optional_date_string(value: object, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise TypeError(f"{label} must be a string or null")
    _validate_iso_date(value, label)
    return value


def _validate_iso_date(value: str, label: str) -> None:
    if _ISO_DATE_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{label} must be an ISO date in YYYY-MM-DD format")
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an ISO date in YYYY-MM-DD format") from exc


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    result: list[str] = []
    for item in _sequence(value, label):
        if not isinstance(item, str) or not item:
            raise TypeError(f"{label} must contain non-empty strings")
        result.append(item)
    return tuple(result)


def _optional_string_tuple(value: object) -> tuple[str, ...] | None:
    if value is None:
        return None
    return _string_tuple(value, "optional string sequence")


def _positive_int(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise TypeError(f"{label} must be a positive integer")
    return value


def _basis_points(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0 or value > 10000:
        raise TypeError(f"{label} must be an integer from 0 to 10000")
    return value


def _score_threshold(value: object) -> Decimal:
    if not isinstance(value, str):
        raise TypeError("retrieval.score_threshold must be a string")
    try:
        threshold = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError("retrieval.score_threshold must be a decimal string") from exc
    if not threshold.is_finite() or threshold < 0 or threshold > 1:
        raise ValueError("retrieval.score_threshold must be between 0 and 1")
    return threshold


def _int_sequence(value: object, label: str) -> tuple[int, ...]:
    result: list[int] = []
    for item in _sequence(value, label):
        if isinstance(item, bool) or not isinstance(item, int):
            raise TypeError(f"{label} must contain integers")
        result.append(item)
    return tuple(result)
