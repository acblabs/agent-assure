from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, cast

import pytest
import yaml
from pydantic import ValidationError

from agent_assure.schema.benchmark import (
    ProcessEquivalenceBenchmark,
    ProcessEquivalenceBenchmarkCase,
    ProcessEquivalenceBenchmarkManifest,
)
from agent_assure.schema.sensitivity import (
    RAGSensitivityCorpusManifest,
    RAGSensitivityDocumentPayload,
    RAGSensitivityKnowledgeContract,
    knowledge_contract_case_authority_bindings,
)
from agent_assure.schema.study import RealModelStudyManifest

ROOT = Path(__file__).resolve().parents[3]
BENCHMARK_PATH = ROOT / "examples" / "process_equivalence_benchmark_v0_2" / "benchmark.json"
AUTHORITY_INDEX_PATH = BENCHMARK_PATH.with_name("authority-contract.json")
STUDY_TEMPLATE_PATH = ROOT / "docs" / "templates" / "real_model_study_manifest.yaml"
CASE_FIELDS = {
    "authority_contract_id",
    "baseline_expected_decision",
    "case_id",
    "counterfactual_expected_decision",
    "expected_relation",
    "input_digest",
    "query_family_id",
    "source_digest",
    "task_id",
}


def _payload() -> dict[str, Any]:
    loaded = json.loads(BENCHMARK_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _authority_index() -> dict[str, Any]:
    loaded = json.loads(AUTHORITY_INDEX_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def test_committed_v02_benchmark_is_exact_self_digested_input_manifest() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())

    assert ProcessEquivalenceBenchmark is ProcessEquivalenceBenchmarkManifest
    assert benchmark.benchmark_version == "0.2.0"
    assert benchmark.data_classification == "non_sensitive"
    assert benchmark.content_representation == "identity_and_digest_bindings_only"
    assert benchmark.real_model_measurement_compatible is True
    assert tuple(case.canonical_key for case in benchmark.cases) == tuple(
        sorted(case.canonical_key for case in benchmark.cases)
    )
    assert len({case.case_id for case in benchmark.cases}) == len(benchmark.cases)
    assert len(benchmark.cases) == 168
    assert len({case.input_digest for case in benchmark.cases}) == 168
    assert len({case.query_family_id for case in benchmark.cases}) == 4
    source_counts = Counter(case.source_digest for case in benchmark.cases)
    assert len(source_counts) == 4
    assert set(source_counts.values()) == {42}
    assert Counter(
        (
            case.expected_relation,
            case.baseline_expected_decision,
            case.counterfactual_expected_decision,
        )
        for case in benchmark.cases
    ) == Counter(
        {
            ("decision_flip", "approve", "deny"): 42,
            ("decision_flip", "deny", "approve"): 42,
            ("decision_invariant", "approve", "approve"): 42,
            ("decision_invariant", "deny", "deny"): 42,
        }
    )

    rebuilt = ProcessEquivalenceBenchmarkManifest.build(
        benchmark_id=benchmark.benchmark_id,
        cases=benchmark.cases,
    )
    assert rebuilt == benchmark


def test_committed_v02_corpora_are_self_digested_and_bind_exact_document_bytes() -> None:
    benchmark_root = BENCHMARK_PATH.parent
    manifests: dict[str, RAGSensitivityCorpusManifest] = {}
    decisions: list[str] = []
    content_digests: set[str] = set()
    source_ids: set[str] = set()

    for manifest_path in sorted((benchmark_root / "corpora").glob("*/*/corpus-manifest.json")):
        manifest = RAGSensitivityCorpusManifest.model_validate_json(manifest_path.read_bytes())
        rebuilt = RAGSensitivityCorpusManifest.build(
            corpus_id=manifest.corpus_id,
            corpus_version=manifest.corpus_version,
            query_family_id=manifest.query_family_id,
            retrieval_algorithm_id=manifest.retrieval_algorithm_id,
            retrieval_algorithm_version=manifest.retrieval_algorithm_version,
            top_k=manifest.top_k,
            documents=manifest.documents,
        )
        assert rebuilt == manifest
        assert manifest.corpus_digest not in manifests
        manifests[manifest.corpus_digest] = manifest

        assert len(manifest.documents) == 1
        descriptor = manifest.documents[0]
        document_path = manifest_path.parent / descriptor.path
        document_bytes = document_path.read_bytes()
        assert descriptor.content_digest == hashlib.sha256(document_bytes).hexdigest()
        content_digests.add(descriptor.content_digest)
        payload = RAGSensitivityDocumentPayload.model_validate_json(document_bytes)
        assert payload.source_id == descriptor.source_id
        source_ids.add(payload.source_id)
        decisions.append(payload.governing_decision.value)

    assert len(manifests) == 336
    assert len(content_digests) == 336
    assert len(source_ids) == 168
    assert Counter(decisions) == Counter({"approve": 168, "deny": 168})


def test_committed_v02_benchmark_resolves_exact_executable_contracts_and_inputs() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    benchmark_root = BENCHMARK_PATH.parent
    authority_index = _authority_index()
    rows = cast(list[dict[str, Any]], authority_index["contracts"])
    assert authority_index["authority_contract_index_version"] == "2.0.0"
    assert authority_index["task_id"] == "synthetic-benefit-eligibility"
    contract_ids = [cast(str, row["authority_contract_id"]) for row in rows]
    assert contract_ids == sorted(contract_ids)
    assert len(contract_ids) == len(set(contract_ids))
    assert set(contract_ids) == {case.authority_contract_id for case in benchmark.cases}
    assert len({case.input_digest for case in benchmark.cases}) == 168
    assert Counter(case.source_digest for case in benchmark.cases) == Counter(
        {cast(str, row["knowledge_contract_sha256"]): 42 for row in rows}
    )

    corpus_digests: set[str] = set()
    governing_content_digests: set[str] = set()
    governing_source_ids: set[str] = set()
    governing_ref_ids: set[str] = set()
    claim_ids: set[str] = set()

    for row in rows:
        authority_contract_id = cast(str, row["authority_contract_id"])
        cases = tuple(
            case for case in benchmark.cases if case.authority_contract_id == authority_contract_id
        )
        assert len(cases) == 42
        indexed_bindings = {
            cast(str, item["case_id"]): item
            for item in cast(list[dict[str, Any]], row["case_bindings"])
        }
        assert tuple(indexed_bindings) == tuple(sorted(indexed_bindings))
        assert set(indexed_bindings) == {case.case_id for case in cases}
        contract_path = benchmark_root / "knowledge-contracts" / f"{authority_contract_id}.json"
        assert (
            row["knowledge_contract_path"] == contract_path.relative_to(benchmark_root).as_posix()
        )
        contract_bytes = contract_path.read_bytes()
        source_digest = hashlib.sha256(contract_bytes).hexdigest()
        assert row["knowledge_contract_sha256"] == source_digest
        assert {case.source_digest for case in cases} == {source_digest}

        contract = RAGSensitivityKnowledgeContract.model_validate_json(contract_bytes)
        rebuilt_contract = RAGSensitivityKnowledgeContract.build(
            expected_response_relation=contract.expected_response_relation,
            case_id=contract.case_id,
            query_family_id=contract.query_family_id,
            assignments=contract.assignments,
            case_authority_bindings=contract.case_authority_bindings,
            limitations=contract.limitations,
        )
        assert rebuilt_contract == contract
        assert row["knowledge_contract_digest"] == contract.knowledge_contract_digest
        assert row["expected_relation"] == contract.expected_response_relation.value
        assert row["query_family_id"] == contract.query_family_id

        bindings = {
            binding.case_id: binding
            for binding in knowledge_contract_case_authority_bindings(contract)
        }
        assert set(bindings) == {case.case_id for case in cases}
        for case in cases:
            input_path = benchmark_root / "inputs" / f"{case.case_id}.json"
            assert input_path.is_file()
            input_bytes = input_path.read_bytes()
            assert case.input_digest == hashlib.sha256(input_bytes).hexdigest()
            input_payload = json.loads(input_bytes)
            assert input_payload["case_id"] == case.case_id
            assert set(input_payload) == {"case_id", "eligibility_score"}
            assert case.query_family_id == contract.query_family_id
            binding = bindings[case.case_id]
            indexed_binding = indexed_bindings[case.case_id]
            assert binding.expected_relation is not None
            assert binding.expected_relation.value == case.expected_relation
            assert (
                case.baseline_expected_decision,
                case.counterfactual_expected_decision,
            ) == (
                indexed_binding["baseline_expected_decision"],
                indexed_binding["counterfactual_expected_decision"],
            )

            assignments = {
                assignment.corpus_digest: assignment for assignment in binding.assignments
            }
            assert len(assignments) == 2
            assert len({item.governing_source_id for item in binding.assignments}) == 1
            assert len({item.governing_ref_id for item in binding.assignments}) == 1
            assert len({item.claim_id for item in binding.assignments}) == 1
            governing_source_ids.update(item.governing_source_id for item in binding.assignments)
            governing_ref_ids.update(item.governing_ref_id for item in binding.assignments)
            claim_ids.update(item.claim_id for item in binding.assignments)

            for role in ("baseline", "counterfactual"):
                manifest_path = benchmark_root / cast(
                    str,
                    indexed_binding[f"{role}_corpus_manifest_path"],
                )
                manifest = RAGSensitivityCorpusManifest.model_validate_json(
                    manifest_path.read_bytes()
                )
                assert manifest.corpus_digest == indexed_binding[f"{role}_corpus_digest"]
                corpus_digests.add(manifest.corpus_digest)
                assignment = assignments[manifest.corpus_digest]
                assert (
                    assignment.expected_decision.value
                    == indexed_binding[f"{role}_expected_decision"]
                )
                assert (
                    assignment.governing_content_digest
                    == indexed_binding[f"{role}_governing_content_digest"]
                    == manifest.documents[0].content_digest
                )
                governing_content_digests.add(assignment.governing_content_digest)
                document_path = manifest_path.parent / manifest.documents[0].path
                payload = RAGSensitivityDocumentPayload.model_validate_json(
                    document_path.read_bytes()
                )
                assert (
                    assignment.governing_source_id,
                    assignment.governing_ref_id,
                    assignment.expected_decision,
                    assignment.expected_outcome,
                ) == (
                    payload.source_id,
                    payload.ref_id,
                    payload.governing_decision,
                    payload.governing_outcome,
                )

    assert len(corpus_digests) == 336
    assert len(governing_content_digests) == 336
    assert len(governing_source_ids) == 168
    assert len(governing_ref_ids) == 168
    assert len(claim_ids) == 168


def test_committed_v02_visible_scores_do_not_determine_relation_or_direction() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    paths_by_score: dict[int, set[tuple[str, str]]] = {}

    for case in benchmark.cases:
        input_path = BENCHMARK_PATH.parent / "inputs" / f"{case.case_id}.json"
        input_payload = json.loads(input_path.read_bytes())
        score = cast(int, input_payload["eligibility_score"])
        paths_by_score.setdefault(score, set()).add(
            (
                case.baseline_expected_decision,
                case.counterfactual_expected_decision,
            )
        )

    all_paths = {
        ("approve", "approve"),
        ("approve", "deny"),
        ("deny", "approve"),
        ("deny", "deny"),
    }
    assert set(paths_by_score) == set(range(50, 92))
    assert all(paths == all_paths for paths in paths_by_score.values())


def test_real_model_study_template_exactly_covers_the_canonical_four_strata() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    loaded = yaml.safe_load(STUDY_TEMPLATE_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    manifest = RealModelStudyManifest.build(**loaded)

    assert (
        manifest.benchmark_id,
        manifest.benchmark_version,
        manifest.benchmark_digest,
    ) == (
        benchmark.benchmark_id,
        benchmark.benchmark_version,
        benchmark.benchmark_digest,
    )
    assert len(manifest.conditions) == 4
    assert manifest.primary_endpoint == "direct_same_decision_inertia"
    assert manifest.hypothesis_decision_rule.minimum_independent_clusters == 42
    assert (
        manifest.hypothesis_decision_rule.multiplicity_family_scope
        == "target_task_model_conditions_only"
    )
    assert manifest.hypothesis_decision_rule.sampling_frame == "finite_frozen_conformance_frame"
    assert "alpha 0.025 per target" in (
        manifest.hypothesis_decision_rule.decision_boundary_rationale
    )
    independence = manifest.hypothesis_decision_rule.independence_justification
    assert independence.status == "unresolved_authoring_placeholder"
    assert "UNRESOLVED AUTHORING PLACEHOLDER" in independence.independence_basis
    assert "semantic" in independence.dependence_risks_and_mitigations
    assert all(condition.justification.count(".") >= 2 for condition in manifest.conditions)
    assert manifest.hypothesis_decision_rule.target_task_model_conditions == tuple(
        condition.condition_id
        for condition in manifest.conditions
        if condition.analysis_role == "inertia_estimand"
    )
    assert manifest.hypothesis_decision_rule.negative_control_conditions == tuple(
        condition.condition_id
        for condition in manifest.conditions
        if condition.analysis_role == "invariant_negative_control"
    )
    assert (
        manifest.hypothesis_decision_rule.invariant_control_gate
        == "zero_observed_unexpected_arm_changes"
    )

    benchmark_by_case = {case.case_id: case for case in benchmark.cases}
    covered: set[str] = set()
    observed_strata: set[tuple[str, str, str]] = set()
    contract_id_by_condition = {
        f"{contract_id.removesuffix('-v1')}-condition": contract_id
        for contract_id in (
            "approve-invariant-v1",
            "approve-to-deny-v1",
            "deny-invariant-v1",
            "deny-to-approve-v1",
        )
    }
    template_conditions = cast(list[dict[str, Any]], loaded["conditions"])
    assert all(
        "execution_origin" in item and "analysis_role" in item for item in template_conditions
    )

    for condition in manifest.conditions:
        frame = set(condition.benchmark_case_ids)
        assert len(frame) == 42
        assert covered.isdisjoint(frame)
        covered.update(frame)
        assert condition.planned_pairs == 42
        assert condition.planned_independent_clusters == 42
        cases = tuple(benchmark_by_case[case_id] for case_id in frame)
        strata = {
            (
                case.expected_relation,
                case.baseline_expected_decision,
                case.counterfactual_expected_decision,
            )
            for case in cases
        }
        assert len(strata) == 1
        observed_strata.update(strata)
        assert tuple(sorted({case.task_id for case in cases})) == condition.task_ids

        contract_id = contract_id_by_condition[condition.condition_id]
        assert {case.authority_contract_id for case in cases} == {contract_id}
        contract_path = BENCHMARK_PATH.parent / "knowledge-contracts" / f"{contract_id}.json"
        contract = RAGSensitivityKnowledgeContract.model_validate_json(contract_path.read_bytes())
        assert condition.knowledge_contract_digest == contract.knowledge_contract_digest

    assert covered == set(benchmark_by_case)
    assert observed_strata == {
        ("decision_flip", "approve", "deny"),
        ("decision_flip", "deny", "approve"),
        ("decision_invariant", "approve", "approve"),
        ("decision_invariant", "deny", "deny"),
    }


def test_case_descriptor_has_only_machine_id_and_digest_bindings() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())

    assert set(ProcessEquivalenceBenchmarkCase.model_fields) == CASE_FIELDS
    assert all(set(case.model_dump(mode="json")) == CASE_FIELDS for case in benchmark.cases)
    manifest_fields = set(ProcessEquivalenceBenchmarkManifest.model_fields)
    assert not manifest_fields & {
        "completion",
        "judge",
        "observations",
        "outputs",
        "prompt",
        "results",
        "score",
    }


@pytest.mark.parametrize(
    ("field_name", "value"),
    (
        ("task_id", "human readable task"),
        ("authority_contract_id", "authority\N{EM DASH}contract"),
        ("query_family_id", "family?"),
        ("case_id", "case#1"),
    ),
)
def test_case_descriptor_rejects_non_machine_safe_identifiers(
    field_name: str,
    value: str,
) -> None:
    payload = cast(dict[str, Any], _payload()["cases"][0])
    payload[field_name] = value

    with pytest.raises(ValidationError, match=field_name):
        ProcessEquivalenceBenchmarkCase.model_validate(payload)


@pytest.mark.parametrize("field_name", ("source_digest", "input_digest"))
def test_case_descriptor_requires_sha256_shaped_digests(field_name: str) -> None:
    payload = cast(dict[str, Any], _payload()["cases"][0])
    payload[field_name] = "not-a-digest"

    with pytest.raises(ValidationError, match=field_name):
        ProcessEquivalenceBenchmarkCase.model_validate(payload)


@pytest.mark.parametrize("field_name", ("prompt", "completion", "llm_judge", "result"))
def test_case_descriptor_rejects_raw_or_result_bearing_extensions(field_name: str) -> None:
    payload = cast(dict[str, Any], _payload()["cases"][0])
    payload[field_name] = "must not be persisted"

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ProcessEquivalenceBenchmarkCase.model_validate(payload)


@pytest.mark.parametrize("field_name", ("observations", "results", "scores"))
def test_benchmark_manifest_rejects_measurement_claim_extensions(field_name: str) -> None:
    payload = _payload()
    payload[field_name] = []

    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        ProcessEquivalenceBenchmarkManifest.model_validate(payload)


def test_benchmark_rejects_noncanonical_case_order() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())

    with pytest.raises(ValidationError, match="canonical identity ordering"):
        ProcessEquivalenceBenchmarkManifest.build(
            benchmark_id=benchmark.benchmark_id,
            cases=tuple(reversed(benchmark.cases)),
        )


def test_benchmark_rejects_duplicate_exact_cases() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())

    with pytest.raises(ValidationError, match="benchmark cases must be unique"):
        ProcessEquivalenceBenchmarkManifest.build(
            benchmark_id=benchmark.benchmark_id,
            cases=(benchmark.cases[0], benchmark.cases[0]),
        )


def test_benchmark_rejects_globally_ambiguous_case_ids() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    first, second = benchmark.cases[:2]
    duplicate_id = ProcessEquivalenceBenchmarkCase(
        task_id=second.task_id,
        authority_contract_id="second-authority-contract",
        query_family_id=second.query_family_id,
        case_id=first.case_id,
        expected_relation=second.expected_relation,
        baseline_expected_decision=second.baseline_expected_decision,
        counterfactual_expected_decision=second.counterfactual_expected_decision,
        source_digest=second.source_digest,
        input_digest=second.input_digest,
    )
    cases = tuple(sorted((first, duplicate_id), key=lambda case: case.canonical_key))

    with pytest.raises(ValidationError, match="case IDs must be globally unique"):
        ProcessEquivalenceBenchmarkManifest.build(
            benchmark_id=benchmark.benchmark_id,
            cases=cases,
        )


def test_benchmark_rejects_duplicate_exact_inputs_across_distinct_cases() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    first, second = benchmark.cases[:2]
    duplicate_input = ProcessEquivalenceBenchmarkCase.model_validate(
        {
            **second.model_dump(mode="json"),
            "input_digest": first.input_digest,
        }
    )
    cases = tuple(
        duplicate_input if case.case_id == second.case_id else case for case in benchmark.cases
    )

    with pytest.raises(ValidationError, match="input digests must be globally unique"):
        ProcessEquivalenceBenchmarkManifest.build(
            benchmark_id=benchmark.benchmark_id,
            cases=cases,
        )


def test_benchmark_requires_both_decision_invariant_control_directions() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    forward_flip = next(
        case
        for case in benchmark.cases
        if (
            case.baseline_expected_decision,
            case.counterfactual_expected_decision,
        )
        == ("approve", "deny")
    )
    reverse_flip = next(
        case
        for case in benchmark.cases
        if (
            case.baseline_expected_decision,
            case.counterfactual_expected_decision,
        )
        == ("deny", "approve")
    )
    one_sided_controls = tuple(
        case
        for case in benchmark.cases
        if (
            case.baseline_expected_decision,
            case.counterfactual_expected_decision,
        )
        == ("approve", "approve")
    )[:2]
    cases = tuple(
        sorted(
            (forward_flip, reverse_flip, *one_sided_controls),
            key=lambda case: case.canonical_key,
        )
    )

    with pytest.raises(
        ValidationError,
        match="both directional decision-invariant control paths",
    ):
        ProcessEquivalenceBenchmarkManifest.build(
            benchmark_id=benchmark.benchmark_id,
            cases=cases,
        )


def test_benchmark_digest_rejects_structurally_valid_tampering() -> None:
    payload = _payload()
    cases = cast(list[dict[str, Any]], payload["cases"])
    cases[0]["input_digest"] = "f" * 64

    with pytest.raises(ValidationError, match="benchmark_digest"):
        ProcessEquivalenceBenchmarkManifest.model_validate(payload)


def test_benchmark_case_rejects_a_relation_that_contradicts_expected_decisions() -> None:
    payload = cast(dict[str, Any], _payload()["cases"][0])
    payload["expected_relation"] = (
        "decision_flip"
        if payload["expected_relation"] == "decision_invariant"
        else "decision_invariant"
    )

    with pytest.raises(ValidationError, match="expected relation contradicts"):
        ProcessEquivalenceBenchmarkCase.model_validate(payload)


def test_benchmark_is_not_the_detector_reproduction_index() -> None:
    benchmark = ProcessEquivalenceBenchmarkManifest.model_validate(_payload())
    payload = benchmark.model_dump(mode="json")

    assert benchmark.artifact_kind == "process-equivalence-benchmark"
    assert not {"replay", "source_closure", "stratum"} & set(payload)
    assert all(
        not ({"replay", "source_closure", "stratum"} & set(case)) for case in payload["cases"]
    )
