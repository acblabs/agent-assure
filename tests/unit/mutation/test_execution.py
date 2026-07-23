from __future__ import annotations

import json
from collections.abc import Callable, Iterator, Mapping
from copy import deepcopy
from typing import cast

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.evaluation.evaluator import EvaluationReport, evaluate_runset
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation import catalog as mutation_catalog
from agent_assure.mutation import execution as mutation_execution
from agent_assure.mutation.catalog import (
    CatalogIntegrityError,
    RegisteredOperator,
    resolve_operator,
)
from agent_assure.mutation.execution import (
    MutationEvaluatorBinding,
    MutationExecution,
    execute_mutation,
)
from agent_assure.mutation.operators import MutationTarget, PayloadChange
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import assert_runset_payload_safe_for_persistence
from agent_assure.schema.common import MAX_LABEL_CHARS, GateState, ReasonCode
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.expectation import Expectation
from agent_assure.schema.mutation import (
    ASSURANCE_MUTATION_METHOD_ID,
    RFC8785_SAFE_INTEGER_MAX,
    EvidenceEvaluationBasis,
    EvidenceState,
    MutationResultState,
    ObservedFinding,
    PrerequisiteState,
)
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    EvidenceItem,
    RunSet,
)
from agent_assure.schema.suite import CompiledSuite, SuiteCase, SuiteDefaults

_GENERATED_AT = "2026-07-20T00:00:00Z"


class _TypeSensitiveMapping(Mapping[str, object]):
    """Legal Mapping whose equality intentionally requires the same wrapper type."""

    def __init__(self, payload: Mapping[str, object]) -> None:
        self._payload = dict(payload)

    def __getitem__(self, key: str) -> object:
        return self._payload[key]

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, _TypeSensitiveMapping) and self._payload == other._payload


_OPERATOR_CASES = (
    (
        "drop-material-evidence-link",
        ("/runs/0/claim_evidence_links",),
        "material_claims_have_evidence",
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    ),
    (
        "bypass-required-human-review",
        (
            "/runs/0/human_review_performed",
            "/runs/0/human_review_required",
        ),
        "human_review_required",
        ReasonCode.REQUIRED_HUMAN_REVIEW_ABSENT,
    ),
    (
        "inject-forbidden-tool",
        ("/runs/0/tools",),
        "tool_allowlist",
        ReasonCode.FORBIDDEN_TOOL,
    ),
)


@pytest.mark.parametrize(
    ("operator_id", "expected_paths", "expected_control", "expected_reason"),
    _OPERATOR_CASES,
)
def test_registered_operator_is_caught_only_by_its_normative_detector(
    operator_id: str,
    expected_paths: tuple[str, ...],
    expected_control: str,
    expected_reason: ReasonCode,
) -> None:
    suite, source_payload = _fixture()
    source_before = deepcopy(source_payload)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id=operator_id,
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.caught
    assert execution.result.changed_paths == expected_paths
    assert execution.result.source_digest == sha256_hexdigest(source_payload)
    assert execution.mutated_payload is not None
    assert execution.result.mutated_digest == sha256_hexdigest(execution.mutated_payload)
    assert source_payload == source_before
    assert _different_pointers(source_payload, execution.mutated_payload) == set(expected_paths)
    assert execution.result.matched_finding_ids
    assert execution.result.expected_finding_target_digest is not None
    observed_ids = tuple(finding.finding_id for finding in execution.result.observed_findings)
    assert len(observed_ids) == len(set(observed_ids))
    assert {
        (finding.control_id, finding.reason_code)
        for finding in execution.result.observed_findings
        if finding.finding_id in execution.result.matched_finding_ids
    } == {(expected_control, expected_reason)}
    assert {
        finding.target_digest
        for finding in execution.result.observed_findings
        if finding.finding_id in execution.result.matched_finding_ids
    } == {execution.result.expected_finding_target_digest}
    assert execution.evidence_descriptor.result.state is EvidenceState.supported
    assert execution.evidence_descriptor.result.verdict_bearing is True
    assert execution.evidence_descriptor.prerequisites.state is PrerequisiteState.satisfied


def test_type_sensitive_mapping_does_not_spuriously_fail_immutability() -> None:
    suite, source_payload = _fixture()

    execution = execute_mutation(
        suite,
        _TypeSensitiveMapping(source_payload),
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.caught
    assert execution.mutated_payload is not None


def test_operator_that_mutates_working_source_is_invalid(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source_payload = _fixture()
    source_before = deepcopy(source_payload)
    registered = resolve_operator("drop-material-evidence-link")
    assert registered is not None

    def mutating_resolver(
        compiled: CompiledSuite,
        subject: RunSet,
        payload: Mapping[str, object],
    ) -> tuple[MutationTarget, ...]:
        targets = registered.resolve_targets(compiled, subject, payload)
        runs = cast(list[dict[str, object]], payload["runs"])
        runs[0]["input_summary"] = "operator-mutated-working-source"
        return targets

    invalid = RegisteredOperator(
        descriptor=registered.descriptor,
        resolve_targets=mutating_resolver,
        limitations=registered.limitations,
    )
    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        lambda _operator_id: invalid,
    )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == "operator_mutated_source"
    assert execution.mutated_payload is None
    assert source_payload == source_before


@pytest.mark.parametrize(
    ("operator_id", "_expected_paths", "expected_control", "expected_reason"),
    _OPERATOR_CASES,
)
def test_deliberately_weakened_normative_control_produces_survived(
    operator_id: str,
    _expected_paths: tuple[str, ...],
    expected_control: str,
    expected_reason: ReasonCode,
) -> None:
    suite, source_payload = _fixture()

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id=operator_id,
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(_without_detector(expected_control, expected_reason)),
    )

    assert execution.result.state is MutationResultState.survived
    assert execution.result.mutated_digest is not None
    assert execution.result.expected_finding_target_digest is not None
    assert execution.mutated_payload is not None
    assert execution.result.matched_finding_ids == ()
    assert execution.evidence_descriptor.result.state is EvidenceState.contradicted
    assert execution.evidence_descriptor.result.verdict_bearing is True
    assert execution.result.evaluator_method_id == "assurance-mutation/test-evaluator/v1"
    assert execution.result.evaluator_implementation_version == "1.0.0"
    assert execution.result.evaluator_implementation_digest == "e" * 64
    assert execution.result.evaluator_evaluation_basis is EvidenceEvaluationBasis.deterministic
    assert execution.result.evaluator_protocol_digest is None
    assert execution.result.evaluator_population_id == "deterministic-fixture-v1"
    assert execution.evidence_descriptor.method.method_id == execution.result.evaluator_method_id
    assert (
        execution.evidence_descriptor.method.implementation_digest
        == execution.result.evaluator_implementation_digest
    )
    assert (
        execution.evidence_descriptor.method.evaluation_basis
        is execution.result.evaluator_evaluation_basis
    )
    assert execution.evidence_descriptor.scope.population_id == (
        execution.result.evaluator_population_id
    )


def test_custom_evaluator_requires_explicit_non_builtin_identity() -> None:
    suite, source_payload = _fixture()
    evaluator = _without_detector(
        "material_claims_have_evidence",
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    )
    common = {
        "operator_id": "drop-material-evidence-link",
        "seed": 17,
        "generated_at": _GENERATED_AT,
    }

    with pytest.raises(TypeError, match="unexpected keyword argument 'evaluator'"):
        execute_mutation(suite, source_payload, evaluator=evaluator, **common)  # type: ignore[call-arg]

    built_in = mutation_execution._built_in_evaluator_binding()
    spoofed_method = MutationEvaluatorBinding(
        evaluator=evaluator,
        method_id=built_in.method_id,
        implementation_version="1.0.0",
        implementation_digest="e" * 64,
        evaluation_basis=EvidenceEvaluationBasis.deterministic,
        protocol_digest=None,
        population_id="deterministic-fixture-v1",
    )
    spoofed_digest = MutationEvaluatorBinding(
        evaluator=evaluator,
        method_id="assurance-mutation/spoof/v1",
        implementation_version="1.0.0",
        implementation_digest=built_in.implementation_digest,
        evaluation_basis=EvidenceEvaluationBasis.deterministic,
        protocol_digest=None,
        population_id="deterministic-fixture-v1",
    )

    for binding in (spoofed_method, spoofed_digest):
        with pytest.raises(ValueError, match="cannot reuse built-in evaluator identity"):
            execute_mutation(
                suite,
                source_payload,
                evaluator_binding=binding,
                **common,
            )


def test_built_in_evaluator_identity_binds_runtime_dependency_versions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    mutation_execution._built_in_evaluator_binding.cache_clear()
    monkeypatch.setattr(
        mutation_execution,
        "distribution_version",
        lambda distribution: f"1.0.0-{distribution}",
    )
    first = mutation_execution._built_in_evaluator_binding().implementation_digest

    mutation_execution._built_in_evaluator_binding.cache_clear()
    monkeypatch.setattr(
        mutation_execution,
        "distribution_version",
        lambda distribution: f"2.0.0-{distribution}",
    )
    second = mutation_execution._built_in_evaluator_binding().implementation_digest
    mutation_execution._built_in_evaluator_binding.cache_clear()

    assert first != second


@pytest.mark.parametrize(
    "relative_path",
    (
        "agent_assure/schema/__init__.py",
        "schemas/v0.5.0/run-set.schema.json",
    ),
)
def test_built_in_evaluator_identity_binds_executed_code_and_schema_bytes(
    monkeypatch: pytest.MonkeyPatch,
    relative_path: str,
) -> None:
    original_read = mutation_catalog._read_packaged_component
    mutation_execution._built_in_evaluator_binding.cache_clear()
    first = mutation_execution._built_in_evaluator_binding().implementation_digest

    def changed_component(path: str) -> bytes:
        source = original_read(path)
        return source + b"\n# identity regression sentinel\n" if path == relative_path else source

    mutation_execution._built_in_evaluator_binding.cache_clear()
    monkeypatch.setattr(mutation_catalog, "_read_packaged_component", changed_component)
    try:
        second = mutation_execution._built_in_evaluator_binding().implementation_digest
    finally:
        mutation_execution._built_in_evaluator_binding.cache_clear()

    assert first != second


def test_custom_evaluator_basis_and_scope_are_preserved_in_evidence() -> None:
    suite, source_payload = _fixture()
    protocol_digest = "f" * 64
    binding = MutationEvaluatorBinding(
        evaluator=_without_detector(
            "material_claims_have_evidence",
            ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ),
        method_id="assurance-mutation/test-stochastic-evaluator/v1",
        implementation_version="1.0.0",
        implementation_digest="e" * 64,
        evaluation_basis=EvidenceEvaluationBasis.stochastic,
        protocol_digest=protocol_digest,
        population_id="held-out-population-v1",
    )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=binding,
    )

    assert execution.result.state is MutationResultState.survived
    assert execution.evidence_descriptor.method.evaluation_basis is (
        EvidenceEvaluationBasis.stochastic
    )
    assert execution.evidence_descriptor.scope.protocol_digest == protocol_digest
    assert execution.evidence_descriptor.scope.population_id == "held-out-population-v1"


def test_stochastic_evaluator_requires_protocol_identity() -> None:
    with pytest.raises(ValueError, match="require a protocol digest"):
        MutationEvaluatorBinding(
            evaluator=evaluate_runset,
            method_id="assurance-mutation/test-stochastic-evaluator/v1",
            implementation_version="1.0.0",
            implementation_digest="e" * 64,
            evaluation_basis=EvidenceEvaluationBasis.stochastic,
            protocol_digest=None,
            population_id="held-out-population-v1",
        )


def test_custom_evaluator_cannot_bypass_runset_compatibility() -> None:
    suite, source_payload = _fixture()
    source_payload["suite_digest"] = "f" * 64
    calls = 0

    def evaluator(_suite: CompiledSuite, _subject: RunSet) -> EvaluationReport:
        nonlocal calls
        calls += 1
        raise AssertionError("incompatible input must not reach a custom evaluator")

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(evaluator),
    )

    assert calls == 0
    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == "suite_binding_mismatch"


def test_custom_evaluator_report_must_bind_to_the_evaluated_runset() -> None:
    suite, source_payload = _fixture()

    def wrong_report(bound_suite: CompiledSuite, subject: RunSet) -> EvaluationReport:
        report = evaluate_runset(bound_suite, subject)
        return report.model_copy(update={"runset_id": "another-runset"})

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(wrong_report),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "source_evaluation_error"


def test_custom_evaluator_cannot_reuse_stale_report_for_mutated_content() -> None:
    suite, source_payload = _fixture()
    cached_report: EvaluationReport | None = None

    def stale_report(bound_suite: CompiledSuite, subject: RunSet) -> EvaluationReport:
        nonlocal cached_report
        if cached_report is None:
            cached_report = evaluate_runset(bound_suite, subject)
        return cached_report

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(stale_report),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "candidate_evaluation_error"
    assert execution.mutated_payload is None


def test_unmet_precondition_produces_inapplicable_without_persisting_a_mutation() -> None:
    suite, source_payload = _fixture(required_human_review=False)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="bypass-required-human-review",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.inapplicable
    assert execution.result.diagnostic_code == "preconditions_unmet"
    assert execution.result.mutated_digest is None
    assert execution.result.changed_paths == ()
    assert execution.mutated_payload is None
    assert execution.evidence_descriptor.result.state is EvidenceState.prerequisites_unmet
    assert execution.evidence_descriptor.result.verdict_bearing is False
    assert execution.evidence_descriptor.prerequisites.state is PrerequisiteState.unmet
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.satisfied,
        "operator-valid": PrerequisiteState.satisfied,
        "operator-applicable": PrerequisiteState.unmet,
        "mutation-execution-completed": PrerequisiteState.not_evaluated,
    }


@pytest.mark.parametrize("record_shape", ("excluded", "duplicate"))
def test_unevaluable_record_cannot_produce_verdict_bearing_survived(
    record_shape: str,
) -> None:
    suite, source_payload = _fixture()
    runs = cast(list[dict[str, object]], source_payload["runs"])
    if record_shape == "excluded":
        runs[0]["observation_status"] = "excluded"
        runs[0]["exclusion_reason"] = "synthetic exclusion"
    else:
        duplicate = deepcopy(runs[0])
        duplicate["run_id"] = "run-case-a-duplicate"
        runs.append(duplicate)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.inapplicable
    assert execution.result.diagnostic_code == "preconditions_unmet"
    assert execution.evidence_descriptor.result.verdict_bearing is False
    assert execution.mutated_payload is None


def test_execution_rejects_operator_targeting_an_excluded_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source_payload = _fixture()
    runs = cast(list[dict[str, object]], source_payload["runs"])
    runs[0]["observation_status"] = "excluded"
    runs[0]["exclusion_reason"] = "synthetic exclusion"
    registered = resolve_operator("drop-material-evidence-link")
    assert registered is not None

    invalid = RegisteredOperator(
        descriptor=registered.descriptor,
        resolve_targets=lambda *_args: (
            MutationTarget(
                identity="excluded-observation",
                expected_finding_target="claim:claim-case-a",
                changes=(PayloadChange(path="/runs/0/claim_evidence_links", value=[]),),
            ),
        ),
        limitations=registered.limitations,
    )
    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        lambda _operator_id: invalid,
    )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == "operator_target_not_evaluable"
    assert execution.evidence_descriptor.result.verdict_bearing is False
    assert execution.mutated_payload is None


def test_prohibited_substitute_produces_invalid_operator_and_is_privacy_minimized() -> None:
    suite, source_payload = _fixture()
    sensitive_message = "patient name: Synthetic Adversarial Person"

    def substitute_evaluator(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(compiled, subject)
        if subject.runs[0].human_review_required:
            return report
        substitute = _finding(
            finding_id="finding-prohibited-runtime-substitute",
            control_id="runtime_success_required",
            reason_code=ReasonCode.RUNTIME_FAILED,
            target=subject.runs[0].run_id,
            message=sensitive_message,
        )
        return _report_with_findings(report, (substitute,), failed_controls=(substitute,))

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="bypass-required-human-review",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(substitute_evaluator),
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == "confounded_operator_output"
    assert execution.mutated_payload is None
    assert tuple(
        (finding.control_id, finding.reason_code) for finding in execution.result.observed_findings
    ) == (("runtime_success_required", ReasonCode.RUNTIME_FAILED),)
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_message not in persisted
    assert "message" not in ObservedFinding.model_fields
    assert "target" not in ObservedFinding.model_fields
    assert "case_id" not in ObservedFinding.model_fields
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.satisfied,
        "operator-valid": PrerequisiteState.unmet,
        "operator-applicable": PrerequisiteState.satisfied,
        "mutation-execution-completed": PrerequisiteState.not_evaluated,
    }


def test_conflicting_evaluator_finding_ids_return_semantic_invalid_operator_result() -> None:
    suite, source_payload = _fixture()

    def conflicting_evaluator(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(compiled, subject)
        normative = next(
            (
                finding
                for finding in report.candidate_vs_expectations.findings
                if finding.control_id == "material_claims_have_evidence"
            ),
            None,
        )
        if normative is None:
            return report
        conflicting = normative.model_copy(
            update={
                "control_id": "runtime_success_required",
                "reason_code": ReasonCode.RUNTIME_FAILED,
                "target": subject.runs[0].run_id,
            }
        )
        return _report_with_findings(
            report,
            (normative, conflicting),
            failed_controls=(normative,),
        )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(conflicting_evaluator),
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == "confounded_operator_output"
    assert len(execution.result.observed_findings) == 1
    assert execution.result.matched_finding_ids == ()
    assert execution.mutated_payload is None


def test_malformed_subject_produces_invalid_subject() -> None:
    suite, source_payload = _fixture()
    source_payload.pop("runs")

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == "subject_schema_invalid"
    assert execution.result.mutated_digest is None
    assert execution.mutated_payload is None
    assert execution.evidence_descriptor.result.state is EvidenceState.prerequisites_unmet
    assert execution.evidence_descriptor.prerequisites.state is PrerequisiteState.unmet
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.unmet,
        "operator-valid": PrerequisiteState.satisfied,
        "operator-applicable": PrerequisiteState.not_evaluated,
        "mutation-execution-completed": PrerequisiteState.not_evaluated,
    }


def test_schema_valid_noncanonical_subject_has_no_fabricated_digest() -> None:
    suite, source_payload = _fixture()
    runs = cast(list[dict[str, object]], source_payload["runs"])
    runs[0]["input_summary"] = "Cafe\u0301"

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == "subject_not_canonical"
    assert execution.result.source_digest is None
    assert execution.evidence_descriptor.subject.digest is None
    assert execution.evidence_descriptor.result.verdict_bearing is False


def test_schema_valid_unsupported_runset_version_is_invalid_subject() -> None:
    suite, source_payload = _fixture()
    source_payload = cast(dict[str, object], _legacy_v043_value(source_payload))

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == "unsupported_subject_schema"
    assert execution.evidence_descriptor.result.verdict_bearing is False


@pytest.mark.parametrize("seed", (-1, RFC8785_SAFE_INTEGER_MAX + 1))
def test_seed_outside_canonical_integer_domain_is_rejected_before_execution(
    seed: int,
) -> None:
    suite, source_payload = _fixture()

    with pytest.raises(ValueError, match="mutation seed must be between"):
        execute_mutation(
            suite,
            source_payload,
            operator_id="unknown-requested-operator",
            seed=seed,
            generated_at=_GENERATED_AT,
        )


@pytest.mark.parametrize(
    ("mutation", "expected_code"),
    (
        ("suite", "suite_binding_mismatch"),
        ("privacy", "privacy_profile_incompatible"),
        ("fixture", "fixture_binding_mismatch"),
    ),
)
def test_subject_compatibility_failures_have_specific_safe_diagnostics(
    mutation: str,
    expected_code: str,
) -> None:
    suite, source_payload = _fixture()
    if mutation == "suite":
        source_payload["suite_id"] = "different-suite"
    elif mutation == "privacy":
        source_payload["privacy_profile_id"] = "external/privacy/v9"
        source_payload["privacy_profile_digest"] = "f" * 64
    else:
        runs = cast(list[dict[str, object]], source_payload["runs"])
        provenance = cast(dict[str, object], runs[0]["provenance"])
        provenance["fixture_manifest_digest"] = "d" * 64

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == expected_code
    assert execution.mutated_payload is None
    persisted = json.dumps(execution.result.model_dump(mode="json"), sort_keys=True)
    assert "different-suite" not in persisted
    assert "external/privacy/v9" not in persisted


def test_untyped_evaluator_value_error_is_an_execution_error() -> None:
    suite, source_payload = _fixture()

    def failing_evaluator(
        _suite: CompiledSuite,
        _subject: RunSet,
    ) -> EvaluationReport:
        raise ValueError("unexpected evaluator value failure")

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(failing_evaluator),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "source_evaluation_error"
    assert execution.mutated_payload is None


def test_catalog_integrity_failure_is_privacy_safe_execution_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source_payload = _fixture()

    def fail_catalog(_operator_id: str) -> RegisteredOperator | None:
        raise CatalogIntegrityError("sensitive local package path")

    monkeypatch.setattr(mutation_execution, "resolve_operator", fail_catalog)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "catalog_integrity_error"
    assert execution.result.evaluator_implementation_digest != "0" * 64
    assert (
        execution.evidence_descriptor.method.implementation_digest
        == execution.result.evaluator_implementation_digest
    )
    assert execution.result.provenance.implementation_components == ()
    assert execution.result.provenance.target_controls == ()
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.not_evaluated,
        "operator-valid": PrerequisiteState.unmet,
        "operator-applicable": PrerequisiteState.not_evaluated,
        "mutation-execution-completed": PrerequisiteState.unmet,
    }
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert "sensitive local package path" not in persisted


def test_evaluator_component_read_failure_is_structured_and_privacy_safe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source_payload = _fixture()
    sensitive_error = "C:/private/build/package/component.py"

    def fail_component_read(_relative_path: str) -> bytes:
        raise OSError(sensitive_error)

    mutation_execution._built_in_evaluator_binding.cache_clear()
    mutation_catalog._operator_catalog.cache_clear()
    monkeypatch.setattr(mutation_catalog, "_read_packaged_component", fail_component_read)
    try:
        execution = execute_mutation(
            suite,
            source_payload,
            operator_id="drop-material-evidence-link",
            seed=17,
            generated_at=_GENERATED_AT,
        )
    finally:
        mutation_execution._built_in_evaluator_binding.cache_clear()
        mutation_catalog._operator_catalog.cache_clear()

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "catalog_integrity_error"
    assert execution.result.source_digest is None
    assert execution.result.evaluator_method_id == ASSURANCE_MUTATION_METHOD_ID
    assert execution.result.evaluator_implementation_digest == "0" * 64
    assert execution.evidence_descriptor.subject.digest is None
    assert execution.evidence_descriptor.result.state is EvidenceState.error
    assert execution.evidence_descriptor.result.verdict_bearing is False
    assert execution.mutated_payload is None
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_error not in persisted


def test_unknown_operator_provenance_does_not_invent_control_or_release_facts() -> None:
    suite, source_payload = _fixture()

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="unknown-requested-operator",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    provenance = execution.result.provenance
    assert provenance.implementation_digest == "0" * 64
    assert provenance.implementation_components == ()
    assert provenance.introduced_at_commit is None
    assert provenance.introduced_in_release is None
    assert provenance.target_controls == ()
    assert execution.result.independence_class.value == "unknown"
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.not_evaluated,
        "operator-valid": PrerequisiteState.unmet,
        "operator-applicable": PrerequisiteState.not_evaluated,
        "mutation-execution-completed": PrerequisiteState.not_evaluated,
    }


def test_sensitive_unknown_operator_identity_is_replaced_not_persisted() -> None:
    suite, source_payload = _fixture()
    sensitive_operator = "sk-proj-" + ("A" * 24)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id=sensitive_operator,
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.operator_id == "unknown-operator"
    assert execution.result.provenance.operator_id == "unknown-operator"
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_operator not in persisted


def test_privacy_unsafe_subject_is_rejected_without_echoing_sensitive_content() -> None:
    suite, source_payload = _fixture()
    sensitive_value = "patient name: Synthetic Privacy Boundary"
    runs = cast(list[dict[str, object]], source_payload["runs"])
    runs[0]["run_id"] = sensitive_value

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_value not in persisted


def test_sensitive_redactable_source_field_is_rejected_without_digest_rewrite() -> None:
    suite, source_payload = _fixture()
    sensitive_value = "Bearer abcdefghijklmnopqrstuvwxyz123456"
    runs = cast(list[dict[str, object]], source_payload["runs"])
    runs[0]["input_summary"] = sensitive_value
    source_before = deepcopy(source_payload)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_subject
    assert execution.result.diagnostic_code == "subject_privacy_violation"
    assert execution.result.source_digest is None
    assert execution.mutated_payload is None
    assert source_payload == source_before
    assert source_payload["suite_digest"] == compiled_suite_digest(suite)
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_value not in persisted


def test_sensitive_candidate_field_is_rejected_as_invalid_operator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    suite, source_payload = _fixture()
    source_before = deepcopy(source_payload)
    sensitive_tool = "sk-proj-" + ("B" * 24)
    registered = resolve_operator("inject-forbidden-tool")
    assert registered is not None

    def sensitive_target_resolver(
        _suite: CompiledSuite,
        _subject: RunSet,
        payload: Mapping[str, object],
    ) -> tuple[MutationTarget, ...]:
        runs = cast(list[dict[str, object]], payload["runs"])
        tools = cast(list[object], runs[0]["tools"])
        return (
            MutationTarget(
                identity="candidate-sensitive-tool",
                expected_finding_target="tool:candidate-sensitive-tool",
                changes=(
                    PayloadChange(
                        path="/runs/0/tools",
                        value=[*tools, sensitive_tool],
                    ),
                ),
            ),
        )

    privacy_unsafe_operator = RegisteredOperator(
        descriptor=registered.descriptor,
        resolve_targets=sensitive_target_resolver,
        limitations=registered.limitations,
    )

    def resolve_privacy_unsafe_operator(operator_id: str) -> RegisteredOperator | None:
        if operator_id == registered.descriptor.operator_id:
            return privacy_unsafe_operator
        return None

    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        resolve_privacy_unsafe_operator,
    )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="inject-forbidden-tool",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == "operator_output_privacy_violation"
    assert execution.mutated_payload is None
    assert source_payload == source_before
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_tool not in persisted


@pytest.mark.parametrize(
    ("failure_kind", "expected_code"),
    (
        ("invalid-path", "operator_output_path_invalid"),
        ("undeclared-path", "operator_output_path_undeclared"),
        ("application", "operator_output_application_error"),
        ("schema", "operator_output_schema_invalid"),
        ("noncanonical", "operator_output_not_canonical"),
        ("noop", "operator_output_noop"),
    ),
)
def test_invalid_operator_output_diagnostics_preserve_failure_stage(
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
    expected_code: str,
) -> None:
    suite, source_payload = _fixture()
    registered = resolve_operator("drop-material-evidence-link")
    assert registered is not None
    runs = cast(list[dict[str, object]], source_payload["runs"])
    current_links = deepcopy(runs[0]["claim_evidence_links"])
    if failure_kind == "invalid-path":
        change = PayloadChange(path="not-a-json-pointer", value=[])
    elif failure_kind == "undeclared-path":
        change = PayloadChange(path="/runs/0/input_summary", value="changed")
    elif failure_kind == "application":
        change = PayloadChange(path="/runs/99/claim_evidence_links", value=[])
    elif failure_kind == "schema":
        change = PayloadChange(path="/runs/0/claim_evidence_links", value="not-an-array")
    elif failure_kind == "noncanonical":
        links = cast(list[dict[str, object]], current_links)
        links[0]["claim_id"] = "Cafe\u0301"
        change = PayloadChange(path="/runs/0/claim_evidence_links", value=links)
    else:
        change = PayloadChange(
            path="/runs/0/claim_evidence_links",
            value=current_links,
        )

    def invalid_resolver(
        _suite: CompiledSuite,
        _subject: RunSet,
        _payload: Mapping[str, object],
    ) -> tuple[MutationTarget, ...]:
        return (
            MutationTarget(
                identity=f"invalid-output-{failure_kind}",
                expected_finding_target="claim:claim-case-a",
                changes=(change,),
            ),
        )

    invalid = RegisteredOperator(
        descriptor=registered.descriptor,
        resolve_targets=invalid_resolver,
        limitations=registered.limitations,
    )
    monkeypatch.setattr(
        mutation_execution,
        "resolve_operator",
        lambda _operator_id: invalid,
    )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.invalid_operator
    assert execution.result.diagnostic_code == expected_code
    assert execution.evidence_descriptor.result.verdict_bearing is False
    assert execution.mutated_payload is None


def test_unexpected_evaluator_failure_produces_bounded_execution_error() -> None:
    suite, source_payload = _fixture()
    sensitive_error = "Bearer abcdefghijklmnopqrstuvwxyz123456"

    def failing_evaluator(
        _suite: CompiledSuite,
        _subject: RunSet,
    ) -> EvaluationReport:
        raise RuntimeError(sensitive_error)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="inject-forbidden-tool",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(failing_evaluator),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "source_evaluation_error"
    assert execution.result.mutated_digest is None
    assert execution.mutated_payload is None
    assert execution.evidence_descriptor.result.state is EvidenceState.error
    assert execution.evidence_descriptor.prerequisites.state is PrerequisiteState.unmet
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.satisfied,
        "operator-valid": PrerequisiteState.satisfied,
        "operator-applicable": PrerequisiteState.not_evaluated,
        "mutation-execution-completed": PrerequisiteState.unmet,
    }
    persisted = json.dumps(
        {
            "result": execution.result.model_dump(mode="json"),
            "evidence": execution.evidence_descriptor.model_dump(mode="json"),
        },
        sort_keys=True,
    )
    assert sensitive_error not in persisted


def test_candidate_evaluator_failure_does_not_persist_partial_mutation() -> None:
    suite, source_payload = _fixture()

    def candidate_failing_evaluator(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        if subject.runs[0].human_review_required:
            return evaluate_runset(compiled, subject)
        raise RuntimeError("bounded candidate evaluator failure")

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="bypass-required-human-review",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(candidate_failing_evaluator),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "candidate_evaluation_error"
    assert execution.result.mutated_digest is None
    assert execution.result.changed_paths == ()
    assert execution.mutated_payload is None
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.satisfied,
        "operator-valid": PrerequisiteState.satisfied,
        "operator-applicable": PrerequisiteState.satisfied,
        "mutation-execution-completed": PrerequisiteState.unmet,
    }


def test_invalid_finding_projection_returns_privacy_safe_execution_error() -> None:
    suite, source_payload = _fixture()

    def evaluator_with_unpersistable_finding(
        compiled: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(compiled, subject)
        normative = next(
            (
                finding
                for finding in report.candidate_vs_expectations.findings
                if finding.control_id == "material_claims_have_evidence"
            ),
            None,
        )
        if normative is None:
            return report
        forged = normative.model_copy(update={"finding_id": "x" * (MAX_LABEL_CHARS + 1)})
        return _report_with_findings(
            report,
            (forged,),
            failed_controls=(forged,),
        )

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=17,
        generated_at=_GENERATED_AT,
        evaluator_binding=_bound_evaluator(evaluator_with_unpersistable_finding),
    )

    assert execution.result.state is MutationResultState.execution_error
    assert execution.result.diagnostic_code == "result_construction_error"
    assert execution.result.observed_findings == ()
    assert execution.result.mutated_digest is None
    assert execution.mutated_payload is None
    assert execution.evidence_descriptor.result.state is EvidenceState.error
    assert _prerequisite_states(execution) == {
        "subject-valid": PrerequisiteState.satisfied,
        "operator-valid": PrerequisiteState.satisfied,
        "operator-applicable": PrerequisiteState.satisfied,
        "mutation-execution-completed": PrerequisiteState.unmet,
    }


def test_same_source_operator_and_seed_produce_identical_bytes_and_result_digest() -> None:
    suite, source_payload = _fixture(second_applicable_run=True)

    first = execute_mutation(
        suite,
        source_payload,
        operator_id="drop-material-evidence-link",
        seed=7331,
        generated_at=_GENERATED_AT,
    )
    second = execute_mutation(
        suite,
        deepcopy(source_payload),
        operator_id="drop-material-evidence-link",
        seed=7331,
        generated_at=_GENERATED_AT,
    )

    assert first.result.state is MutationResultState.caught
    assert second.result.state is MutationResultState.caught
    assert first.mutated_payload is not None
    assert second.mutated_payload is not None
    assert canonical_bytes(first.mutated_payload) == canonical_bytes(second.mutated_payload)
    assert first.result.result_digest == second.result.result_digest
    assert first.evidence_descriptor.evidence_digest == second.evidence_descriptor.evidence_digest


@settings(max_examples=32, deadline=None)
@given(
    recommendation=st.sampled_from(("approve", "deny", "manual-review")),
    outcome=st.sampled_from(("approved", "denied", "escalated")),
    latency_ms=st.integers(min_value=0, max_value=1_000_000),
    attempt_count=st.integers(min_value=1, max_value=20),
    retry_count=st.integers(min_value=0, max_value=19),
)
def test_property_undeclared_fields_remain_unchanged(
    recommendation: str,
    outcome: str,
    latency_ms: int,
    attempt_count: int,
    retry_count: int,
) -> None:
    suite, source_payload = _fixture(
        run_updates={
            "recommendation": recommendation,
            "outcome": outcome,
            "latency_ms": latency_ms,
            "attempt_count": attempt_count,
            "retry_count": retry_count,
        }
    )
    source_before = deepcopy(source_payload)

    execution = execute_mutation(
        suite,
        source_payload,
        operator_id="bypass-required-human-review",
        seed=42,
        generated_at=_GENERATED_AT,
    )

    assert execution.result.state is MutationResultState.caught
    assert execution.mutated_payload is not None
    assert source_payload == source_before
    assert _different_pointers(source_payload, execution.mutated_payload) == {
        "/runs/0/human_review_performed",
        "/runs/0/human_review_required",
    }
    assert_runset_payload_safe_for_persistence(execution.mutated_payload)


def _without_detector(
    control_id: str,
    reason_code: ReasonCode,
) -> Callable[[CompiledSuite, RunSet], EvaluationReport]:
    def evaluate_without_detector(
        suite: CompiledSuite,
        subject: RunSet,
    ) -> EvaluationReport:
        report = evaluate_runset(suite, subject)
        findings = tuple(
            finding
            for finding in report.candidate_vs_expectations.findings
            if not (finding.control_id == control_id and finding.reason_code is reason_code)
        )
        failed_controls = tuple(
            finding
            for finding in report.failed_controls
            if not (finding.control_id == control_id and finding.reason_code is reason_code)
        )
        return _report_with_findings(
            report,
            findings,
            failed_controls=failed_controls,
        )

    return evaluate_without_detector


def _bound_evaluator(
    evaluator: Callable[[CompiledSuite, RunSet], EvaluationReport],
) -> MutationEvaluatorBinding:
    return MutationEvaluatorBinding(
        evaluator=evaluator,
        method_id="assurance-mutation/test-evaluator/v1",
        implementation_version="1.0.0",
        implementation_digest="e" * 64,
        evaluation_basis=EvidenceEvaluationBasis.deterministic,
        protocol_digest=None,
        population_id="deterministic-fixture-v1",
    )


def _report_with_findings(
    report: EvaluationReport,
    findings: tuple[Finding, ...],
    *,
    failed_controls: tuple[Finding, ...],
) -> EvaluationReport:
    summary = report.candidate_vs_expectations.model_copy(
        update={"findings": findings},
    )
    return report.model_copy(
        update={
            "candidate_vs_expectations": summary,
            "failed_controls": failed_controls,
        }
    )


def _finding(
    *,
    finding_id: str,
    control_id: str,
    reason_code: ReasonCode,
    target: str,
    message: str,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        case_id="case-a",
        control_id=control_id,
        target=target,
        state=GateState.fail,
        reason_code=reason_code,
        message=message,
    )


def _fixture(
    *,
    required_human_review: bool = True,
    second_applicable_run: bool = False,
    run_updates: Mapping[str, object] | None = None,
) -> tuple[CompiledSuite, dict[str, object]]:
    case_ids = ("case-a", "case-b") if second_applicable_run else ("case-a",)
    expectations = tuple(
        Expectation(
            expectation_id=f"expectation-{case_id}",
            case_id=case_id,
            material_claim_ids=(f"claim-{case_id}",),
            forbidden_tools=(f"blocked-tool-{case_id}",),
            required_human_review=required_human_review,
        )
        for case_id in case_ids
    )
    suite = CompiledSuite(
        suite_id="mutation-execution-test-suite",
        suite_version="1.0.0",
        defaults=SuiteDefaults(
            runner_id="mutation.execution.tests",
            allowed_tools=("safe-tool",),
        ),
        cases=tuple(
            SuiteCase(
                case_id=expectation.case_id,
                title=f"Mutation execution case {expectation.case_id}",
                expectation_id=expectation.expectation_id,
            )
            for expectation in expectations
        ),
        resolved_expectations=expectations,
        source_digest="a" * 64,
    )
    fixture_digest = "c" * 64
    runs = tuple(
        _run(
            case_id,
            fixture_digest=fixture_digest,
            required_human_review=required_human_review,
            run_updates=run_updates if index == 0 else None,
        )
        for index, case_id in enumerate(case_ids)
    )
    runset = RunSet(
        runset_id="mutation-execution-test-runset",
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        suite_digest=compiled_suite_digest(suite),
        fixture_manifest_digest=fixture_digest,
        runs=runs,
    )
    return suite, cast(dict[str, object], runset.model_dump(mode="json"))


def _run(
    case_id: str,
    *,
    fixture_digest: str,
    required_human_review: bool,
    run_updates: Mapping[str, object] | None,
) -> AgentRunRecord:
    claim_id = f"claim-{case_id}"
    evidence_ref = f"evidence-{case_id}"
    payload: dict[str, object] = {
        "run_id": f"run-{case_id}",
        "case_id": case_id,
        "pipeline_id": "mutation-execution-test-pipeline",
        "recommendation": "approve",
        "outcome": "approved",
        "input_summary": "synthetic input",
        "output_summary": "synthetic output",
        "tools": ("safe-tool",),
        "evidence_items": (
            EvidenceItem(
                ref_id=evidence_ref,
                source_id=f"source-{case_id}",
                content_digest="d" * 64,
            ),
        ),
        "claim_evidence_links": (
            ClaimEvidenceLink(
                claim_id=claim_id,
                evidence_ref_id=evidence_ref,
            ),
        ),
        "human_review_required": required_human_review,
        "human_review_performed": required_human_review,
        "provenance": Provenance(fixture_manifest_digest=fixture_digest),
    }
    if run_updates is not None:
        payload.update(run_updates)
    return AgentRunRecord.model_validate(payload)


def _different_pointers(left: object, right: object, pointer: str = "") -> set[str]:
    if isinstance(left, Mapping) and isinstance(right, Mapping):
        if set(left) != set(right):
            return {pointer or "/"}
        differences: set[str] = set()
        for key in sorted(left, key=str):
            child = f"{pointer}/{_escape_pointer_part(str(key))}"
            differences.update(_different_pointers(left[key], right[key], child))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        if len(left) != len(right):
            return {pointer or "/"}
        differences = set()
        for index, (left_item, right_item) in enumerate(zip(left, right, strict=True)):
            differences.update(_different_pointers(left_item, right_item, f"{pointer}/{index}"))
        return differences
    return set() if left == right else {pointer or "/"}


def _prerequisite_states(
    execution: MutationExecution,
) -> dict[str, PrerequisiteState]:
    for check in execution.evidence_descriptor.prerequisites.checks:
        expected_reason_codes = (
            (ReasonCode.NOT_EVALUATED,) if check.state is PrerequisiteState.not_evaluated else ()
        )
        assert check.reason_codes == expected_reason_codes
    return {
        check.check_id: check.state for check in execution.evidence_descriptor.prerequisites.checks
    }


def _escape_pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _legacy_v043_value(value: object) -> object:
    if isinstance(value, dict):
        return {
            str(key): ("0.4.3" if key == "schema_version" else _legacy_v043_value(nested))
            for key, nested in value.items()
            if key not in {"privacy_profile_id", "privacy_profile_digest"}
        }
    if isinstance(value, list):
        return [_legacy_v043_value(item) for item in value]
    return value
