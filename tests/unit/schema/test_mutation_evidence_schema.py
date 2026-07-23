from __future__ import annotations

import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.export import SCHEMA_MODELS
from agent_assure.schema.mutation import (
    ASSURANCE_MUTATION_METHOD_ID,
    ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS,
    RFC8785_SAFE_INTEGER_MAX,
    AssuranceEvidenceDescriptor,
    AssuranceMutationOperator,
    AssuranceMutationResult,
    AuthorshipRelationship,
    EvidenceDependency,
    EvidenceEvaluationBasis,
    EvidenceMethod,
    EvidencePrerequisites,
    EvidenceProducer,
    EvidenceResult,
    EvidenceScope,
    EvidenceState,
    EvidenceSubject,
    EvidenceValidity,
    ExpectedDetectionContract,
    FindingSelector,
    IndependenceClass,
    MutationResultState,
    ObservedFinding,
    OperatorAuthorship,
    OperatorImplementationComponent,
    OperatorOrigin,
    OperatorOriginKind,
    OperatorPrecondition,
    OperatorProvenance,
    PrerequisiteCheck,
    PrerequisiteState,
    RequiredFindingAlternatives,
    TargetControlProvenance,
    finding_target_digest,
    mutation_implementation_digest,
)
from agent_assure.schema.validation import validate_artifact_payload

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_FINDING_ID = "finding-00000000-0000-5000-8000-000000000001"
_FINDING_TARGET = "claim:claim-selected"
_FINDING_TARGET_DIGEST = finding_target_digest(_FINDING_TARGET)
ROOT = Path(__file__).resolve().parents[3]


def _satisfied_mutation_prerequisite_checks() -> tuple[PrerequisiteCheck, ...]:
    return tuple(
        PrerequisiteCheck(
            check_id=check_id,
            state=PrerequisiteState.satisfied,
        )
        for check_id in ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS
    )


def _detector_contract(**overrides: object) -> ExpectedDetectionContract:
    values: dict[str, object] = {
        "operator_id": "drop-material-evidence-link",
        "target_control_ids": ("material_claims_have_evidence",),
        "required_findings": RequiredFindingAlternatives(
            any_of=(
                FindingSelector(
                    control_id="material_claims_have_evidence",
                    reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                ),
            )
        ),
        "prohibited_substitutes": (
            FindingSelector(
                control_id="runtime_success_required",
                reason_code=ReasonCode.RUNTIME_FAILED,
            ),
        ),
        "expected_gate_effect": "block",
        "secondary_findings_allowed": True,
    }
    values.update(overrides)
    return ExpectedDetectionContract.build(**values)


def _provenance(
    *,
    operator_id: str = "drop-material-evidence-link",
    origin_kind: OperatorOriginKind = OperatorOriginKind.first_party,
) -> OperatorProvenance:
    operator_version = "1.0.0"
    components = (
        OperatorImplementationComponent(
            component_id="mutation.test-component",
            relative_path="agent_assure/mutation/operators.py",
            sha256=_DIGEST_A,
        ),
    )
    return OperatorProvenance(
        operator_id=operator_id,
        operator_version=operator_version,
        implementation_digest=mutation_implementation_digest(
            operator_id=operator_id,
            operator_version=operator_version,
            components=components,
        ),
        implementation_components=components,
        introduction_components=components,
        introduced_at_commit="git:uncommitted",
        introduced_in_release="0.6.0",
        origin=OperatorOrigin(
            kind=origin_kind,
            references=("docs/evidence_carrying_releases.md",),
        ),
        target_controls=(
            TargetControlProvenance(
                control_id="material_claims_have_evidence",
                first_seen_commit="git:" + ("1" * 40),
                digest_at_operator_creation=_DIGEST_B,
            ),
        ),
        authorship=OperatorAuthorship(
            relationship_to_control_author=AuthorshipRelationship.unknown,
        ),
    )


def _mutation_operator(**overrides: object) -> AssuranceMutationOperator:
    provenance = _provenance()
    values: dict[str, object] = {
        "operator_id": "drop-material-evidence-link",
        "operator_version": "1.0.0",
        "compatible_schema_versions": ("0.5.0", "0.6.0"),
        "preconditions": (
            OperatorPrecondition(
                precondition_id="fixture-mode",
                summary="The subject is a validated deterministic fixture RunSet.",
            ),
        ),
        "permitted_changed_paths": ("/runs/*/claim_evidence_links",),
        "privacy_classification": "synthetic_fixture_metadata",
        "provenance": provenance,
        "independence_class": IndependenceClass.first_party_postcontrol,
        "implementation_digest": provenance.implementation_digest,
        "expected_detection_contract": _detector_contract(),
    }
    values.update(overrides)
    return AssuranceMutationOperator.build(**values)


def _observed_finding() -> ObservedFinding:
    return ObservedFinding(
        finding_id=_FINDING_ID,
        control_id="material_claims_have_evidence",
        state=GateState.fail,
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        target_digest=_FINDING_TARGET_DIGEST,
    )


def _mutation_result(**overrides: object) -> AssuranceMutationResult:
    operator = _mutation_operator()
    values: dict[str, object] = {
        "source_digest": _DIGEST_A,
        "mutated_digest": _DIGEST_B,
        "operator_id": operator.operator_id,
        "operator_version": operator.operator_version,
        "operator_digest": operator.operator_digest,
        "implementation_digest": operator.implementation_digest,
        "expected_detection_contract_digest": (
            operator.expected_detection_contract.contract_digest
        ),
        "expected_finding_target_digest": _FINDING_TARGET_DIGEST,
        "evaluator_method_id": ASSURANCE_MUTATION_METHOD_ID,
        "evaluator_implementation_digest": _DIGEST_C,
        "evaluator_implementation_version": "1.0.0",
        "evaluator_evaluation_basis": EvidenceEvaluationBasis.deterministic,
        "evaluator_protocol_digest": None,
        "evaluator_population_id": "deterministic-fixture-v1",
        "seed": 7,
        "changed_paths": ("/runs/0/claim_evidence_links",),
        "observed_findings": (_observed_finding(),),
        "matched_finding_ids": (_FINDING_ID,),
        "state": MutationResultState.caught,
        "provenance": operator.provenance,
        "independence_class": operator.independence_class,
        "diagnostic_code": None,
        "limitations": ("Detection is scoped to this deterministic subject.",),
    }
    values.update(overrides)
    return AssuranceMutationResult.build(**values)


def _evidence_descriptor_values() -> dict[str, object]:
    return {
        "evidence_id": "ev-control-efficacy-001",
        "evidence_kind": "control_efficacy",
        "subject": EvidenceSubject(subject_type="run_set", digest=_DIGEST_A),
        "scope": EvidenceScope(
            suite_digest=_DIGEST_B,
            protocol_digest=None,
            population_id="deterministic-fixture-v1",
        ),
        "method": EvidenceMethod(
            method_id=ASSURANCE_MUTATION_METHOD_ID,
            implementation_digest=_DIGEST_C,
            implementation_version="1.0.0",
            evaluation_basis=EvidenceEvaluationBasis.deterministic,
        ),
        "result": EvidenceResult(
            state=EvidenceState.supported,
            verdict_bearing=True,
            reason_codes=(ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,),
            metrics={"matched_finding_count": 1},
        ),
        "prerequisites": EvidencePrerequisites(
            state=PrerequisiteState.satisfied,
            checks=_satisfied_mutation_prerequisite_checks(),
        ),
        "assumptions": ("The declared suite identifies the intended subject.",),
        "limitations": ("The finite operator does not represent every failure.",),
        "validity": EvidenceValidity(
            generated_at="2026-07-20T12:00:00Z",
            expires_at=None,
            invalidated_by=("suite_digest_change",),
        ),
        "dependencies": (
            EvidenceDependency(evidence_id="mutation-result-001", digest=_DIGEST_C),
        ),
        "producer": EvidenceProducer(name="agent-assure", version="0.6.0"),
    }


def test_nested_mutation_evidence_value_objects_are_deeply_immutable() -> None:
    descriptor = AssuranceEvidenceDescriptor.build(**_evidence_descriptor_values())

    with pytest.raises(ValidationError, match="frozen"):
        descriptor.method.method_id = "replacement"  # type: ignore[misc]
    with pytest.raises(TypeError):
        descriptor.result.metrics["matched_finding_count"] = 2  # type: ignore[index]

    assert descriptor.method.method_id == ASSURANCE_MUTATION_METHOD_ID
    assert descriptor.result.metrics["matched_finding_count"] == 1


def _evidence_descriptor(**overrides: object) -> AssuranceEvidenceDescriptor:
    values = _evidence_descriptor_values()
    values.update(overrides)
    return AssuranceEvidenceDescriptor.build(**values)


@pytest.mark.parametrize(
    ("artifact_kind", "factory"),
    (
        ("assurance-evidence-descriptor", _evidence_descriptor),
        ("assurance-mutation-operator", _mutation_operator),
        ("assurance-mutation-result", _mutation_result),
        ("expected-detection-contract", _detector_contract),
    ),
)
def test_new_artifacts_have_model_jsonschema_and_validation_parity(
    artifact_kind: str,
    factory: Callable[[], StrictModel],
) -> None:
    artifact = factory()
    payload = artifact.model_dump(mode="json")
    model = SCHEMA_MODELS[artifact_kind]

    assert model.model_validate(payload).model_dump(mode="json") == payload
    Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    assert validate_artifact_payload(payload, artifact_kind) == "pydantic+jsonschema"


@pytest.mark.parametrize(
    ("artifact_kind", "factory"),
    (
        ("assurance-evidence-descriptor", _evidence_descriptor),
        ("assurance-mutation-operator", _mutation_operator),
        ("assurance-mutation-result", _mutation_result),
        ("expected-detection-contract", _detector_contract),
    ),
)
def test_new_artifacts_reject_historical_schema_labels_in_both_validators(
    artifact_kind: str,
    factory: Callable[[], StrictModel],
) -> None:
    payload = factory().model_dump(mode="json")
    payload["schema_version"] = "0.5.0"
    model = SCHEMA_MODELS[artifact_kind]

    with pytest.raises(ValidationError):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)


@pytest.mark.parametrize(
    ("artifact_kind", "factory"),
    (
        ("assurance-evidence-descriptor", _evidence_descriptor),
        ("assurance-mutation-operator", _mutation_operator),
        ("assurance-mutation-result", _mutation_result),
        ("expected-detection-contract", _detector_contract),
    ),
)
@pytest.mark.parametrize(
    "identity_field",
    ("artifact_kind", "schema_version", "schema_name", "contract_id", "contract_version"),
)
def test_persisted_contract_identity_is_required_before_parsing(
    artifact_kind: str,
    factory: Callable[[], StrictModel],
    identity_field: str,
) -> None:
    payload = factory().model_dump(mode="json")
    del payload[identity_field]
    model = SCHEMA_MODELS[artifact_kind]

    with pytest.raises(ValidationError, match="explicit identity fields"):
        model.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(model.model_json_schema(mode="validation")).validate(payload)
    with pytest.raises(ValueError, match="explicit identity fields before parsing"):
        validate_artifact_payload(payload, artifact_kind)


def test_all_current_persisted_root_schemas_require_base_identity() -> None:
    for artifact_kind, model in SCHEMA_MODELS.items():
        schema = model.model_json_schema(mode="validation")
        required = set(schema.get("required", ()))
        assert {"artifact_kind", "schema_version"} <= required, artifact_kind


def test_policy_catalog_and_mutation_schema_have_no_fresh_import_cycle() -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from agent_assure.policies.catalog import BUILT_IN_POLICY_IDS; "
                "from agent_assure.schema.mutation import ExpectedDetectionContract; "
                "assert BUILT_IN_POLICY_IDS and ExpectedDetectionContract"
            ),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr


@pytest.mark.parametrize(
    "factory,digest_field",
    (
        (_evidence_descriptor, "evidence_digest"),
        (_mutation_operator, "operator_digest"),
        (_mutation_result, "result_digest"),
        (_detector_contract, "contract_digest"),
    ),
)
def test_self_digests_reject_tampering(
    factory: Callable[[], StrictModel],
    digest_field: str,
) -> None:
    payload = factory().model_dump(mode="json")
    payload[digest_field] = "0" * 64

    with pytest.raises(ValidationError, match="canonical artifact projection"):
        type(factory()).model_validate(payload)


def test_evidence_digest_is_independent_of_mapping_insertion_order() -> None:
    values = _evidence_descriptor_values()
    reversed_values = dict(reversed(tuple(values.items())))

    assert (
        AssuranceEvidenceDescriptor.build(**values).evidence_digest
        == AssuranceEvidenceDescriptor.build(**reversed_values).evidence_digest
    )


def test_llm_advisory_evidence_is_permanently_non_verdict_bearing() -> None:
    method = EvidenceMethod(
        method_id="llm-review/advisory/v1",
        implementation_digest=_DIGEST_A,
        implementation_version="1.0.0",
        evaluation_basis=EvidenceEvaluationBasis.llm_advisory,
    )

    with pytest.raises(
        ValidationError,
        match=ReasonCode.LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED.value,
    ):
        _evidence_descriptor(method=method)


def test_unmet_prerequisites_cannot_be_verdict_bearing() -> None:
    prerequisites = EvidencePrerequisites(
        state=PrerequisiteState.unmet,
        checks=(
            PrerequisiteCheck(
                check_id="subject-valid",
                state=PrerequisiteState.unmet,
                reason_codes=(ReasonCode.NOT_EVALUATED,),
            ),
        ),
    )

    with pytest.raises(ValidationError, match="cannot produce verdict-bearing"):
        _evidence_descriptor(prerequisites=prerequisites)


def test_satisfied_prerequisites_require_nonempty_checks_in_both_validators() -> None:
    payload = {"state": "satisfied", "checks": []}

    with pytest.raises(ValidationError, match="at least one explicit check"):
        EvidencePrerequisites.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            EvidencePrerequisites.model_json_schema(mode="validation")
        ).validate(payload)


def test_core_mutation_evidence_requires_exact_canonical_checks() -> None:
    incomplete = EvidencePrerequisites(
        state=PrerequisiteState.satisfied,
        checks=_satisfied_mutation_prerequisite_checks()[:-1],
    )
    with pytest.raises(ValidationError, match="exact canonical prerequisite checks"):
        _evidence_descriptor(prerequisites=incomplete)

    payload = _evidence_descriptor().model_dump(mode="json")
    payload["prerequisites"]["checks"].pop()
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(payload)

    duplicated = _satisfied_mutation_prerequisite_checks()
    duplicate_payload = _evidence_descriptor().model_dump(mode="json")
    duplicate_payload["prerequisites"]["checks"] = [
        duplicated[0].model_dump(mode="json"),
        duplicated[0].model_dump(mode="json"),
        duplicated[1].model_dump(mode="json"),
        duplicated[2].model_dump(mode="json"),
    ]
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(duplicate_payload)

    reordered = EvidencePrerequisites(
        state=PrerequisiteState.satisfied,
        checks=tuple(reversed(_satisfied_mutation_prerequisite_checks())),
    )
    with pytest.raises(ValidationError, match="exact canonical prerequisite checks"):
        _evidence_descriptor(prerequisites=reordered)

    reordered_payload = _evidence_descriptor().model_dump(mode="json")
    reordered_payload["prerequisites"]["checks"].reverse()
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(reordered_payload)


def test_unavailable_subject_digest_is_explicit_and_nonverdict_only() -> None:
    checks = tuple(
        PrerequisiteCheck(
            check_id=check_id,
            state=(
                PrerequisiteState.unmet
                if check_id == "subject-valid"
                else PrerequisiteState.not_evaluated
            ),
            reason_codes=(
                ()
                if check_id == "subject-valid"
                else (ReasonCode.NOT_EVALUATED,)
            ),
        )
        for check_id in ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS
    )
    descriptor = _evidence_descriptor(
        subject=EvidenceSubject(subject_type="run_set", digest=None),
        result=EvidenceResult(
            state=EvidenceState.prerequisites_unmet,
            verdict_bearing=False,
        ),
        prerequisites=EvidencePrerequisites(
            state=PrerequisiteState.unmet,
            checks=checks,
        ),
    )
    assert descriptor.subject.digest is None

    payload = descriptor.model_dump(mode="json")
    payload["result"]["verdict_bearing"] = True
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(payload)
    with pytest.raises(ValidationError, match="unavailable subject digest"):
        _evidence_descriptor(subject=EvidenceSubject(subject_type="run_set", digest=None))


def test_prerequisites_must_be_explicit_in_model_and_jsonschema() -> None:
    payload = _evidence_descriptor().model_dump(mode="json")
    del payload["prerequisites"]

    with pytest.raises(ValidationError):
        AssuranceEvidenceDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(payload)


def test_evidence_validity_rejects_invalid_or_unbounded_windows() -> None:
    with pytest.raises(ValidationError, match="valid RFC 3339 date-time"):
        EvidenceValidity(
            generated_at="2026-02-31T12:00:00Z",
            expires_at=None,
            invalidated_by=("suite_digest_change",),
        )
    with pytest.raises(ValidationError, match="expires_at cannot precede generated_at"):
        EvidenceValidity(
            generated_at="2026-07-20T12:00:00Z",
            expires_at="2026-07-20T11:59:59Z",
            invalidated_by=(),
        )
    with pytest.raises(ValidationError, match="requires expires_at"):
        EvidenceValidity(
            generated_at="2026-07-20T12:00:00Z",
            expires_at=None,
            invalidated_by=(),
        )
    with pytest.raises(ValidationError, match="must be unique"):
        EvidenceValidity(
            generated_at="2026-07-20T12:00:00Z",
            expires_at=None,
            invalidated_by=("suite_digest_change", "suite_digest_change"),
        )


def test_evidence_dependencies_must_have_unique_identities() -> None:
    dependencies = (
        EvidenceDependency(evidence_id="mutation-result-001", digest=_DIGEST_A),
        EvidenceDependency(evidence_id="mutation-result-001", digest=_DIGEST_B),
    )

    with pytest.raises(ValidationError, match="dependency IDs must be unique"):
        _evidence_descriptor(dependencies=dependencies)


def test_detector_contract_rejects_unknown_or_misdirected_controls() -> None:
    with pytest.raises(ValidationError, match="unknown controls"):
        _detector_contract(target_control_ids=("unknown_control",))

    misdirected = RequiredFindingAlternatives(
        any_of=(
            FindingSelector(
                control_id="tool_allowlist",
                reason_code=ReasonCode.FORBIDDEN_TOOL,
            ),
        )
    )
    with pytest.raises(ValidationError, match="must reference a target control"):
        _detector_contract(required_findings=misdirected)


def test_detector_contract_rejects_duplicate_or_prohibited_normative_selectors() -> None:
    selector = FindingSelector(
        control_id="material_claims_have_evidence",
        reason_code=ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    )
    with pytest.raises(ValidationError, match="alternatives must be unique"):
        RequiredFindingAlternatives(any_of=(selector, selector))
    with pytest.raises(ValidationError, match="must be disjoint"):
        _detector_contract(prohibited_substitutes=(selector,))


def test_operator_rejects_invalid_paths_or_identity_mismatches() -> None:
    with pytest.raises(ValidationError, match="String should match pattern"):
        _mutation_operator(permitted_changed_paths=("/runs/*/tools~2",))
    with pytest.raises(ValidationError, match="IDs must match"):
        _mutation_operator(provenance=_provenance(operator_id="different-operator"))


def test_operator_provenance_rejects_manifest_tampering_and_duplicate_ids() -> None:
    provenance = _provenance()
    payload = provenance.model_dump(mode="json")
    payload["implementation_digest"] = _DIGEST_B
    with pytest.raises(ValidationError, match="does not match its component manifest"):
        OperatorProvenance.model_validate(payload)

    duplicate_id_component = OperatorImplementationComponent(
        component_id=provenance.implementation_components[0].component_id,
        relative_path="agent_assure/mutation/paths.py",
        sha256=_DIGEST_B,
    )
    components = (*provenance.implementation_components, duplicate_id_component)
    payload = provenance.model_dump(mode="json")
    payload["implementation_components"] = [
        component.model_dump(mode="json") for component in components
    ]
    payload["implementation_digest"] = mutation_implementation_digest(
        operator_id=provenance.operator_id,
        operator_version=provenance.operator_version,
        components=components,
    )
    with pytest.raises(ValidationError, match="component IDs must be unique"):
        OperatorProvenance.model_validate(payload)


def test_unknown_operator_provenance_cannot_invent_release_or_control_facts() -> None:
    values: dict[str, object] = {
        "operator_id": "unknown-requested-operator",
        "operator_version": "0.0.0",
        "implementation_digest": "0" * 64,
        "implementation_components": (),
        "introduction_components": (),
        "introduced_at_commit": None,
        "introduced_in_release": None,
        "origin": OperatorOrigin(
            kind=OperatorOriginKind.unknown,
            references=("unresolved built-in operator identity",),
        ),
        "target_controls": (),
        "authorship": OperatorAuthorship(
            relationship_to_control_author=AuthorshipRelationship.unknown,
        ),
    }
    provenance = OperatorProvenance.model_validate(values)
    assert provenance.target_controls == ()
    assert provenance.introduced_at_commit is None

    values["introduced_in_release"] = "0.6.0"
    values["target_controls"] = (
        TargetControlProvenance(
            control_id="runtime_success_required",
            first_seen_commit="git:" + "1" * 40,
            digest_at_operator_creation=_DIGEST_A,
        ),
    )
    with pytest.raises(ValidationError, match="must not invent implementation facts"):
        OperatorProvenance.model_validate(values)


def test_operator_rejects_independence_claim_that_conflicts_with_origin() -> None:
    with pytest.raises(ValidationError, match="conflicts with declared operator origin"):
        _mutation_operator(independence_class=IndependenceClass.external_preexisting)


def test_execution_errors_are_valid_nonverdict_evidence_with_unmet_prerequisites() -> None:
    descriptor = _evidence_descriptor(
        result=EvidenceResult(
            state=EvidenceState.error,
            verdict_bearing=False,
        ),
        prerequisites=EvidencePrerequisites(
            state=PrerequisiteState.unmet,
            checks=tuple(
                PrerequisiteCheck(
                    check_id=check_id,
                    state=(
                        PrerequisiteState.unmet
                        if check_id == "mutation-execution-completed"
                        else PrerequisiteState.satisfied
                    ),
                )
                for check_id in ASSURANCE_MUTATION_PREREQUISITE_CHECK_IDS
            ),
        ),
    )

    assert descriptor.result.state is EvidenceState.error
    assert descriptor.result.verdict_bearing is False


def test_mutation_result_state_domain_is_exact() -> None:
    assert {item.value for item in MutationResultState} == {
        "caught",
        "survived",
        "inapplicable",
        "invalid_operator",
        "invalid_subject",
        "execution_error",
    }


def test_mutation_result_requires_bound_evaluator_identity() -> None:
    payload = _mutation_result().model_dump(mode="json")
    del payload["evaluator_method_id"]
    with pytest.raises(ValidationError):
        AssuranceMutationResult.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationResult.model_json_schema(mode="validation")
        ).validate(payload)

    payload = _mutation_result().model_dump(mode="json")
    payload["evaluator_implementation_digest"] = "0" * 64
    with pytest.raises(ValidationError, match="reserved for catalog bootstrap failures"):
        AssuranceMutationResult.model_validate(
            payload,
            context={"skip_self_digest": True},
        )
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationResult.model_json_schema(mode="validation")
        ).validate(payload)


def test_unavailable_evaluator_identity_is_limited_to_catalog_bootstrap_failure() -> None:
    result = _mutation_result(
        state=MutationResultState.execution_error,
        mutated_digest=None,
        changed_paths=(),
        observed_findings=(),
        matched_finding_ids=(),
        expected_finding_target_digest=None,
        evaluator_implementation_digest="0" * 64,
        diagnostic_code="catalog_integrity_error",
    )
    Draft202012Validator(
        AssuranceMutationResult.model_json_schema(mode="validation")
    ).validate(result.model_dump(mode="json"))

    for state, diagnostic_code in (
        (MutationResultState.invalid_subject, "catalog_integrity_error"),
        (MutationResultState.execution_error, "source_evaluation_error"),
    ):
        payload = result.model_dump(mode="json")
        payload["state"] = state.value
        payload["diagnostic_code"] = diagnostic_code
        with pytest.raises(ValidationError, match="reserved for catalog bootstrap failures"):
            AssuranceMutationResult.model_validate(
                payload,
                context={"skip_self_digest": True},
            )
        with pytest.raises(JsonSchemaValidationError):
            Draft202012Validator(
                AssuranceMutationResult.model_json_schema(mode="validation")
            ).validate(payload)


def test_mutation_seed_is_bounded_to_rfc8785_safe_integer_domain() -> None:
    assert _mutation_result(seed=RFC8785_SAFE_INTEGER_MAX).seed == RFC8785_SAFE_INTEGER_MAX
    with pytest.raises(ValidationError):
        _mutation_result(seed=RFC8785_SAFE_INTEGER_MAX + 1)

    payload = _mutation_result().model_dump(mode="json")
    payload["seed"] = RFC8785_SAFE_INTEGER_MAX + 1
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationResult.model_json_schema(mode="validation")
        ).validate(payload)


@pytest.mark.parametrize(
    "update",
    (
        {"state": "survived"},
        {"state": "inapplicable"},
        {"matched_finding_ids": []},
        {"independence_class": "external_preexisting"},
    ),
)
def test_mutation_result_jsonschema_enforces_state_and_provenance_rules(
    update: dict[str, object],
) -> None:
    payload = _mutation_result().model_dump(mode="json")
    payload.update(update)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationResult.model_json_schema(mode="validation")
        ).validate(payload)


def test_operator_provenance_jsonschema_rejects_known_facts_without_manifest() -> None:
    payload = _provenance().model_dump(mode="json")
    payload["implementation_components"] = []

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            OperatorProvenance.model_json_schema(mode="validation")
        ).validate(payload)


def test_caught_result_requires_observed_normative_match() -> None:
    with pytest.raises(ValidationError, match="must be present in observed findings"):
        _mutation_result(matched_finding_ids=("finding-missing",))
    with pytest.raises(ValidationError, match="requires a normative matched finding"):
        _mutation_result(matched_finding_ids=())


def test_mutated_results_bind_matches_to_a_privacy_minimized_target_digest() -> None:
    result = _mutation_result()

    assert result.expected_finding_target_digest == finding_target_digest(_FINDING_TARGET)
    assert result.observed_findings[0].target_digest == result.expected_finding_target_digest
    assert _FINDING_TARGET not in result.model_dump_json()

    with pytest.raises(ValidationError, match="require an expected target digest"):
        _mutation_result(expected_finding_target_digest=None)
    with pytest.raises(ValidationError, match="carry the expected target digest"):
        _mutation_result(
            observed_findings=(
                _observed_finding().model_copy(update={"target_digest": _DIGEST_C}),
            )
        )
    with pytest.raises(ValidationError, match="carry the expected target digest"):
        _mutation_result(
            observed_findings=(
                _observed_finding().model_copy(update={"target_digest": None}),
            )
        )


def test_finding_target_digest_has_a_stable_domain_separated_vector() -> None:
    assert finding_target_digest(_FINDING_TARGET) == (
        "53a78f37084baac5c9bc8d43bbef99e476bdc8a6959a56ba8cab5338768b1f10"
    )
    assert finding_target_digest(_FINDING_TARGET) != finding_target_digest(
        "tool:claim-selected"
    )
    with pytest.raises(TypeError, match="must be a string"):
        finding_target_digest(1)  # type: ignore[arg-type]


def test_nonmutation_result_cannot_claim_a_selected_target() -> None:
    result = _mutation_result(
        state=MutationResultState.inapplicable,
        mutated_digest=None,
        changed_paths=(),
        observed_findings=(),
        matched_finding_ids=(),
        expected_finding_target_digest=None,
    )
    assert result.expected_finding_target_digest is None

    with pytest.raises(ValidationError, match="cannot imply a selected target"):
        _mutation_result(
            state=MutationResultState.inapplicable,
            mutated_digest=None,
            changed_paths=(),
            observed_findings=(),
            matched_finding_ids=(),
        )


def test_nonmutation_result_cannot_claim_changed_subject_or_normative_match() -> None:
    with pytest.raises(ValidationError, match="cannot imply a persisted mutation"):
        _mutation_result(state=MutationResultState.inapplicable)
    with pytest.raises(ValidationError, match="only caught"):
        _mutation_result(state=MutationResultState.survived)


def test_mutation_result_rejects_duplicate_observed_finding_identities() -> None:
    with pytest.raises(ValidationError, match="observed finding IDs must be unique"):
        _mutation_result(observed_findings=(_observed_finding(), _observed_finding()))


@pytest.mark.parametrize(
    "pointer",
    (
        "/",
        "/runs/0/claim_evidence_links",
        "/runs/0/a~1b/~0",
        "/runs/0/*suffix",
        "/runs/0/prefix*",
        "/runs/0/**",
        "/runs//value",
    ),
)
def test_exact_json_pointer_corpus_has_model_and_jsonschema_parity(pointer: str) -> None:
    result = _mutation_result(changed_paths=(pointer,))
    payload = result.model_dump(mode="json")

    AssuranceMutationResult.model_validate(payload)
    Draft202012Validator(
        AssuranceMutationResult.model_json_schema(mode="validation")
    ).validate(payload)


@pytest.mark.parametrize(
    "pointer",
    (
        "",
        "runs/0",
        "#/runs/0",
        "/runs/~",
        "/runs/~2",
        "/runs/0/a/b~",
        "/runs/*/claim_evidence_links",
    ),
)
def test_invalid_exact_json_pointer_corpus_is_rejected_by_both_validators(
    pointer: str,
) -> None:
    payload = _mutation_result().model_dump(mode="json")
    payload["changed_paths"] = [pointer]

    with pytest.raises(ValidationError):
        AssuranceMutationResult.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationResult.model_json_schema(mode="validation")
        ).validate(payload)


@pytest.mark.parametrize(
    "pointer",
    (
        "/",
        "/runs/*/claim_evidence_links",
        "/runs/0/a~1b/~0",
        "/runs//value",
    ),
)
def test_json_pointer_template_corpus_has_model_and_jsonschema_parity(pointer: str) -> None:
    operator = _mutation_operator(permitted_changed_paths=(pointer,))
    payload = operator.model_dump(mode="json")

    AssuranceMutationOperator.model_validate(payload)
    Draft202012Validator(
        AssuranceMutationOperator.model_json_schema(mode="validation")
    ).validate(payload)


@pytest.mark.parametrize(
    "pointer",
    ("", "runs/*", "#/runs/*", "/runs/~", "/runs/~2", "/runs/*/field~"),
)
def test_invalid_json_pointer_template_corpus_is_rejected_by_both_validators(
    pointer: str,
) -> None:
    payload = _mutation_operator().model_dump(mode="json")
    payload["permitted_changed_paths"] = [pointer]

    with pytest.raises(ValidationError):
        AssuranceMutationOperator.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceMutationOperator.model_json_schema(mode="validation")
        ).validate(payload)


def test_bounded_summary_limits_are_shared_by_model_and_jsonschema() -> None:
    payload = _evidence_descriptor().model_dump(mode="json")
    payload["limitations"] = ["x" * 8193]

    with pytest.raises(ValidationError):
        AssuranceEvidenceDescriptor.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(
            AssuranceEvidenceDescriptor.model_json_schema(mode="validation")
        ).validate(payload)
