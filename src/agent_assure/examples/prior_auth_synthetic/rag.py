from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import date
from decimal import Decimal, InvalidOperation, localcontext
from pathlib import Path
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.runner.evidence import EvidenceAssociation
from agent_assure.runner.fixture_values import required_string
from agent_assure.schema.common import decimal_string

RAG_BASELINE_VARIANT_ID = "rag-baseline"
RAG_RERANKER_REGRESSION_VARIANT_ID = "rag-reranker-drops-secondary-claim-source"
RAG_CORPUS_VERSION_SKEW_VARIANT_ID = "rag-corpus-version-skew"

_FIXTURE_ROOT = Path("fixtures/rag")
_CURRENT_CORPUS_MANIFEST = "corpus_manifest.json"
_SKEWED_CORPUS_MANIFEST = "corpus_manifest_skewed.json"
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
    manifest_name = (
        _SKEWED_CORPUS_MANIFEST
        if mode == "corpus_version_skew"
        else _CURRENT_CORPUS_MANIFEST
    )
    corpus = load_policy_corpus(suite_root, manifest_name=manifest_name)
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
    reranker_config = _reranker_config(retrieval_request, variant_mode)

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
    union_ref_ids = baseline_set | candidate_set
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
    candidate_sources = set(candidate.retrieved_source_ids)
    missing_required = tuple(
        source_id
        for source_id in baseline.required_source_ids
        if source_id not in candidate_sources
    )
    jaccard_bps = 10000 if not union_ref_ids else int(
        Decimal(len(shared_ref_ids) * 10000) / Decimal(len(union_ref_ids))
    )
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


def normalize_query(query: str) -> str:
    return _NORMALIZED_QUERY_PATTERN.sub(" ", query.casefold()).strip()


def _reranker_config(
    retrieval_request: dict[str, object],
    mode: RagVariantMode,
) -> RerankerConfig:
    raw_configs = retrieval_request.get("reranker_configs", {})
    configs = _mapping(raw_configs, "retrieval.reranker_configs")
    raw_config = configs.get(mode)
    if raw_config is None:
        return RerankerConfig(config_id="none")
    config = _mapping(raw_config, f"retrieval.reranker_configs.{mode}")
    return RerankerConfig(
        config_id=_string(config, "config_id"),
        drop_claim_ids=_string_tuple(config.get("drop_claim_ids", ()), "drop_claim_ids"),
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
    return tuple(str(item) for item in _sequence(value, label))


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or value <= 0:
        raise TypeError(f"{label} must be a positive integer")
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
        if not isinstance(item, int):
            raise TypeError(f"{label} must contain integers")
        result.append(item)
    return tuple(result)
