from __future__ import annotations

import re
import sys
from collections import Counter
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import date
from functools import lru_cache, partial
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as distribution_version
from typing import cast

from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from agent_assure import __version__
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.canonical.jcs import canonical_bytes
from agent_assure.canonical.normalize import digest_projection
from agent_assure.evaluation.evaluator import (
    EvaluationReport,
    RunSetCompatibilityError,
    evaluate_runset,
    validate_runset_compatibility,
)
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.mutation.catalog import (
    CatalogIntegrityError,
    RegisteredOperator,
    built_in_evaluator_implementation_components,
    resolve_operator,
)
from agent_assure.mutation.detection import assess_expected_detection
from agent_assure.mutation.operators import SYNTHETIC_SENSITIVE_SUMMARY, MutationTarget
from agent_assure.mutation.paths import (
    apply_payload_changes,
    parse_json_pointer,
    paths_are_permitted,
    structural_changed_paths,
)
from agent_assure.mutation.selection import select_target
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, GateProfile, Waiver
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.privacy.redaction import assert_runset_payload_safe_for_persistence
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.schema.common import (
    PACKAGE_RELEASE_VERSION_PATTERN,
    ExecutionMode,
    ReasonCode,
)
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.mutation import (
    ASSURANCE_MUTATION_METHOD_ID,
    HUMAN_REVIEW_SUFFICIENCY_CHECK_ID,
    HUMAN_REVIEW_SUFFICIENCY_LIMITATION,
    RFC8785_SAFE_INTEGER_MAX,
    STOCHASTIC_SUFFICIENCY_CHECK_ID,
    STOCHASTIC_SUFFICIENCY_LIMITATION,
    AssuranceEvidenceDescriptor,
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
    IndependenceClass,
    MutationPrivacyClassification,
    MutationResultState,
    ObservedFinding,
    OperatorAuthorship,
    OperatorOrigin,
    OperatorOriginKind,
    OperatorProvenance,
    PrerequisiteCheck,
    PrerequisiteState,
    finding_target_digest,
)
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import validate_artifact_payload

MutationEvaluator = Callable[[CompiledSuite, RunSet], EvaluationReport]
_MACHINE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
_PACKAGE_RELEASE_VERSION = re.compile(PACKAGE_RELEASE_VERSION_PATTERN)
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_UNKNOWN_DIGEST = "0" * 64
_EVALUATOR_MANIFEST_CONTRACT = "AssuranceMutationEvaluatorManifest/v1"
_EVALUATOR_RUNTIME_DISTRIBUTIONS = ("jsonschema", "pydantic", "PyYAML", "rfc8785")
_GATE_PROFILE_CONTRACT = "AssuranceMutationGateProfile/v1"
_WAIVER_SET_CONTRACT = "AssuranceMutationWaiverSet/v1"


@dataclass(frozen=True)
class MutationEvaluatorBinding:
    """Callable evaluator plus explicit implementation, method, and scope identity."""

    evaluator: MutationEvaluator
    method_id: str
    implementation_version: str
    implementation_digest: str
    evaluation_basis: EvidenceEvaluationBasis
    protocol_digest: str | None
    population_id: str
    gate_profile_id: str
    gate_profile_digest: str
    waiver_set_digest: str
    evaluation_date: str

    def __post_init__(self) -> None:
        if not callable(self.evaluator):
            raise TypeError("mutation evaluator must be callable")
        if _MACHINE_ID.fullmatch(self.method_id) is None:
            raise ValueError("mutation evaluator method_id must be a machine identifier")
        if _PACKAGE_RELEASE_VERSION.fullmatch(self.implementation_version) is None:
            raise ValueError("mutation evaluator implementation_version must be X.Y.Z or X.Y.ZrcN")
        if (
            _DIGEST.fullmatch(self.implementation_digest) is None
            or self.implementation_digest == _UNKNOWN_DIGEST
        ):
            raise ValueError("mutation evaluator implementation_digest must be non-zero SHA-256")
        if not isinstance(self.evaluation_basis, EvidenceEvaluationBasis):
            raise TypeError("mutation evaluator evaluation_basis must be an enum value")
        if self.protocol_digest is not None and (
            _DIGEST.fullmatch(self.protocol_digest) is None
            or self.protocol_digest == _UNKNOWN_DIGEST
        ):
            raise ValueError("mutation evaluator protocol_digest must be non-zero SHA-256")
        if (
            self.evaluation_basis
            in {
                EvidenceEvaluationBasis.stochastic,
                EvidenceEvaluationBasis.human_reviewed,
            }
            and self.protocol_digest is None
        ):
            raise ValueError("stochastic and human-reviewed evaluators require a protocol digest")
        if _MACHINE_ID.fullmatch(self.population_id) is None:
            raise ValueError("mutation evaluator population_id must be a machine identifier")
        if _MACHINE_ID.fullmatch(self.gate_profile_id) is None:
            raise ValueError("mutation evaluator gate_profile_id must be a machine identifier")
        for label, digest in (
            ("gate_profile_digest", self.gate_profile_digest),
            ("waiver_set_digest", self.waiver_set_digest),
        ):
            if _DIGEST.fullmatch(digest) is None or digest == _UNKNOWN_DIGEST:
                raise ValueError(f"mutation evaluator {label} must be non-zero SHA-256")
        try:
            date.fromisoformat(self.evaluation_date)
        except ValueError as exc:
            raise ValueError("mutation evaluator evaluation_date must use YYYY-MM-DD") from exc


class MutationSubjectValidationError(ValueError):
    """A RunSet payload could not establish the evaluator's canonical projection."""


def validated_runset_projection(
    payload: Mapping[str, object],
) -> tuple[RunSet, dict[str, object]]:
    """Validate a RunSet and return the exact projection hashed by evaluators.

    JSON Schema permits omission of some defaulted fields. Evaluators hash the
    validated model projection, so mutation selection, persistence, and result
    identity must use that same representation rather than the pre-projection
    input dictionary.
    """
    source = dict(payload)
    try:
        validate_artifact_payload(source, "run-set")
        subject = RunSet.model_validate(source)
        projected = cast(dict[str, object], subject.model_dump(mode="json"))
        validate_artifact_payload(projected, "run-set")
    except (JsonSchemaValidationError, RecursionError, TypeError, ValueError) as exc:
        raise MutationSubjectValidationError(
            "RunSet payload failed canonical validation and projection"
        ) from exc
    return subject, projected


@dataclass(frozen=True)
class MutationExecution:
    result: AssuranceMutationResult
    evidence_descriptor: AssuranceEvidenceDescriptor
    mutated_payload: dict[str, object] | None
    suite_digest: str
    generated_at: str


@lru_cache(maxsize=1)
def _built_in_evaluator_binding() -> MutationEvaluatorBinding:
    try:
        components = built_in_evaluator_implementation_components()
        implementation_digest = sha256_hexdigest(
            {
                "contract_id": _EVALUATOR_MANIFEST_CONTRACT,
                "method_id": ASSURANCE_MUTATION_METHOD_ID,
                "implementation_version": __version__,
                "components": [component.model_dump(mode="json") for component in components],
                "runtime": _evaluator_runtime_manifest(),
            }
        )
        return MutationEvaluatorBinding(
            evaluator=evaluate_runset,
            method_id=ASSURANCE_MUTATION_METHOD_ID,
            implementation_version=__version__,
            implementation_digest=implementation_digest,
            evaluation_basis=EvidenceEvaluationBasis.deterministic,
            protocol_digest=None,
            population_id="deterministic-fixture-v1",
            gate_profile_id=DEFAULT_GATE_PROFILE.profile_id,
            gate_profile_digest=mutation_gate_profile_digest(DEFAULT_GATE_PROFILE),
            waiver_set_digest=mutation_waiver_set_digest(()),
            # Execution always replaces this template value with its explicit
            # evaluation date before invoking the evaluator.
            evaluation_date="1970-01-01",
        )
    except CatalogIntegrityError:
        raise
    except Exception as exc:
        raise CatalogIntegrityError(
            "the built-in evaluator identity could not be constructed"
        ) from exc


def mutation_gate_profile_digest(gate_profile: GateProfile) -> str:
    """Return the canonical identity of the complete active gate profile."""
    projection = gate_profile.model_dump(mode="json")
    projection["fail_severities"] = sorted(set(projection["fail_severities"]))
    projection["fail_reason_codes"] = sorted(set(projection["fail_reason_codes"]))
    return sha256_hexdigest(
        {
            "contract_id": _GATE_PROFILE_CONTRACT,
            "gate_profile": projection,
        }
    )


def mutation_waiver_set_digest(waivers: tuple[Waiver, ...]) -> str:
    """Return the order-independent canonical identity of the explicit waiver set."""
    serialized = [waiver.model_dump(mode="json") for waiver in waivers]
    serialized.sort(key=lambda item: canonical_bytes(digest_projection(item)))
    return sha256_hexdigest(
        {
            "contract_id": _WAIVER_SET_CONTRACT,
            "waivers": serialized,
        }
    )


def _configured_built_in_evaluator_binding(
    *,
    gate_profile: GateProfile,
    waivers: tuple[Waiver, ...],
    evaluation_date: date,
) -> MutationEvaluatorBinding:
    template = _built_in_evaluator_binding()
    evaluator = partial(
        evaluate_runset,
        gate_profile=gate_profile,
        waivers=waivers,
        today=evaluation_date,
    )
    return replace(
        template,
        evaluator=evaluator,
        gate_profile_id=gate_profile.profile_id,
        gate_profile_digest=mutation_gate_profile_digest(gate_profile),
        waiver_set_digest=mutation_waiver_set_digest(waivers),
        evaluation_date=evaluation_date.isoformat(),
    )


def _evaluator_runtime_manifest() -> dict[str, object]:
    dependency_versions: dict[str, str] = {}
    for distribution in _EVALUATOR_RUNTIME_DISTRIBUTIONS:
        try:
            dependency_versions[distribution] = distribution_version(distribution)
        except PackageNotFoundError:
            dependency_versions[distribution] = "unavailable"
    return {
        "python_implementation": sys.implementation.name,
        "python_version": ".".join(str(part) for part in sys.version_info[:3]),
        "python_cache_tag": sys.implementation.cache_tag or "unavailable",
        "dependency_versions": dependency_versions,
    }


def execute_mutation(
    suite: CompiledSuite,
    source_payload: Mapping[str, object],
    *,
    operator_id: str,
    seed: int,
    generated_at: str,
    evaluator_binding: MutationEvaluatorBinding | None = None,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    evaluation_date: date | None = None,
) -> MutationExecution:
    """Apply and assess exactly one registered deterministic operator."""
    if seed < 0 or seed > RFC8785_SAFE_INTEGER_MAX:
        raise ValueError(f"mutation seed must be between 0 and {RFC8785_SAFE_INTEGER_MAX}")
    input_source = deepcopy(dict(source_payload))
    source_digest: str | None = None
    try:
        resolved_evaluation_date = evaluation_date or date.fromisoformat(generated_at[:10])
    except ValueError as exc:
        raise ValueError("generated_at must begin with a valid YYYY-MM-DD date") from exc
    try:
        built_in_binding = _configured_built_in_evaluator_binding(
            gate_profile=gate_profile,
            waivers=waivers,
            evaluation_date=resolved_evaluation_date,
        )
        if evaluator_binding is not None and (
            evaluator_binding.method_id == built_in_binding.method_id
            or evaluator_binding.implementation_digest == built_in_binding.implementation_digest
        ):
            result = _failure_result(
                state=MutationResultState.execution_error,
                operator=None,
                requested_operator_id=operator_id,
                source_digest=None,
                seed=seed,
                evaluator_binding=built_in_binding,
                diagnostic_code="evaluator_identity_conflict",
                limitations=("A custom evaluator cannot reuse the built-in evaluator identity.",),
            )
            return _execution_without_mutation(suite, result, generated_at=generated_at)
    except CatalogIntegrityError:
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=None,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=None,
            gate_configuration=(
                gate_profile.profile_id,
                mutation_gate_profile_digest(gate_profile),
                mutation_waiver_set_digest(waivers),
                resolved_evaluation_date.isoformat(),
            ),
            diagnostic_code="catalog_integrity_error",
            limitations=(
                "The built-in evaluator could not establish its packaged implementation identity.",
            ),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    binding = evaluator_binding or built_in_binding
    if binding.evaluation_basis is EvidenceEvaluationBasis.llm_advisory:
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=None,
            requested_operator_id=operator_id,
            source_digest=None,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="llm_advisory_not_supported",
            limitations=(ReasonCode.LLM_JUDGE_VERDICT_BEARING_NOT_SUPPORTED.value,),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    evaluator = binding.evaluator
    try:
        operator = resolve_operator(operator_id)
    except CatalogIntegrityError:
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=None,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="catalog_integrity_error",
            limitations=(
                "The built-in operator catalog could not establish its packaged identity.",
            ),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    if operator is None:
        result = _failure_result(
            state=MutationResultState.invalid_operator,
            operator=None,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="unknown_operator",
            limitations=("The requested operator is not in the built-in deterministic catalog.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        subject, canonical_source = validated_runset_projection(input_source)
    except MutationSubjectValidationError:
        result = _failure_result(
            state=MutationResultState.invalid_subject,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="subject_schema_invalid",
            limitations=("The source failed bounded RunSet schema validation.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        assert_runset_payload_safe_for_persistence(input_source)
        assert_runset_payload_safe_for_persistence(canonical_source)
    except ValueError:
        result = _failure_result(
            state=MutationResultState.invalid_subject,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=None,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="subject_privacy_violation",
            limitations=("The source failed the bound privacy-detector profile.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    source_digest = _safe_digest(canonical_source)
    if source_digest is None:
        result = _failure_result(
            state=MutationResultState.invalid_subject,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=None,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="subject_not_canonical",
            limitations=("The source could not be represented by canonical JSON.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    if subject.schema_version not in operator.descriptor.compatible_schema_versions:
        result = _failure_result(
            state=MutationResultState.invalid_subject,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="unsupported_subject_schema",
            limitations=(
                "The operator does not declare compatibility with the subject schema version.",
            ),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    if subject.execution_mode is not ExecutionMode.fixture:
        result = _failure_result(
            state=MutationResultState.inapplicable,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="fixture_mode_required",
            limitations=(
                "The initial deterministic operators apply only to fixture-mode RunSets.",
            ),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        validate_runset_compatibility(suite, subject)
        source_report = _validate_evaluator_report_binding(
            evaluator(suite, subject),
            suite=suite,
            runset=subject,
            gate_profile_id=binding.gate_profile_id,
        )
    except RunSetCompatibilityError as exc:
        result = _failure_result(
            state=MutationResultState.invalid_subject,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code=exc.diagnostic_code,
            limitations=("The source is incompatible with the selected evaluation context.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    except Exception as exc:
        exception_class, debug_reference = _safe_internal_diagnostic(
            "source_evaluation_error",
            exc,
        )
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="source_evaluation_error",
            diagnostic_exception_class=exception_class,
            local_debug_reference=debug_reference,
            limitations=("Source evaluation ended with a bounded internal execution error.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        source_snapshot = deepcopy(canonical_source)
        targets = operator.resolve_targets(suite, subject, canonical_source)
    except Exception as exc:
        exception_class, debug_reference = _safe_internal_diagnostic(
            "operator_applicability_error",
            exc,
        )
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="operator_applicability_error",
            diagnostic_exception_class=exception_class,
            local_debug_reference=debug_reference,
            limitations=("Operator applicability ended with a bounded internal error.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    if canonical_source != source_snapshot:
        result = _failure_result(
            state=MutationResultState.invalid_operator,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="operator_mutated_source",
            limitations=("The operator changed its immutable source working copy.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        target = select_target(
            targets,
            source_digest=source_digest,
            operator_id=operator.descriptor.operator_id,
            operator_version=operator.descriptor.operator_version,
            seed=seed,
        )
    except Exception as exc:
        exception_class, debug_reference = _safe_internal_diagnostic(
            "operator_applicability_error",
            exc,
        )
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="operator_applicability_error",
            diagnostic_exception_class=exception_class,
            local_debug_reference=debug_reference,
            limitations=("Operator applicability ended with a bounded internal error.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    if target is None:
        result = _failure_result(
            state=MutationResultState.inapplicable,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="preconditions_unmet",
            limitations=("No subject location satisfied every declared operator precondition.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        target = target.materialized(canonical_source)
    except Exception:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_application_error",
            limitation="The selected operator target could not be materialized.",
        )
    if canonical_source != source_snapshot:
        result = _failure_result(
            state=MutationResultState.invalid_operator,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="operator_mutated_source",
            limitations=("The operator changed its immutable source working copy.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        declared_paths = tuple(sorted(change.path for change in target.changes))
        permitted_paths = paths_are_permitted(
            declared_paths,
            operator.descriptor.permitted_changed_paths,
        )
    except (TypeError, ValueError):
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_path_invalid",
            limitation="The operator proposed an invalid changed-path contract.",
        )
    if not permitted_paths:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_path_undeclared",
            limitation="The operator proposed a changed path outside its declaration.",
        )
    try:
        candidate_payload = apply_payload_changes(canonical_source, target.changes)
    except (TypeError, ValueError):
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_application_error",
            limitation="The operator changes could not be applied to the validated source.",
        )
    try:
        candidate, projected_candidate = validated_runset_projection(candidate_payload)
    except MutationSubjectValidationError:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_schema_invalid",
            limitation="The operator output failed bounded RunSet schema validation.",
        )
    if projected_candidate != candidate_payload:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_not_canonical",
            limitation=("The operator output did not preserve the canonical RunSet projection."),
        )
    candidate_payload = projected_candidate
    try:
        changed_paths = structural_changed_paths(canonical_source, candidate_payload)
        actual_paths_permitted = paths_are_permitted(
            changed_paths,
            operator.descriptor.permitted_changed_paths,
        )
    except (TypeError, ValueError):
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_path_invalid",
            limitation="The operator produced an invalid changed path.",
        )
    if not actual_paths_permitted:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_path_undeclared",
            limitation="The operator changed a path outside its declaration.",
        )
    if not changed_paths:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_noop",
            limitation="The operator did not change the canonical subject.",
        )
    target_evaluable = _target_observation_is_evaluable(subject, changed_paths)
    if target_evaluable is False:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_target_not_evaluable",
            limitation=(
                "The operator selected an excluded or non-singleton observation that the "
                "evaluator cannot score."
            ),
        )
    try:
        assert_runset_payload_safe_for_persistence(candidate_payload)
    except ValueError:
        if not _is_exact_synthetic_privacy_challenge(
            operator,
            target,
            changed_paths,
            candidate_payload,
        ):
            return _invalid_operator_output_execution(
                suite,
                operator=operator,
                requested_operator_id=operator_id,
                source_digest=source_digest,
                seed=seed,
                evaluator_binding=binding,
                generated_at=generated_at,
                diagnostic_code="operator_output_privacy_violation",
                limitation="The operator output failed the bound privacy-detector profile.",
            )
    try:
        mutated_digest = sha256_hexdigest(candidate_payload)
    except (TypeError, ValueError):
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_not_canonical",
            limitation="The operator output could not be represented by canonical JSON.",
        )
    if mutated_digest == source_digest:
        return _invalid_operator_output_execution(
            suite,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            generated_at=generated_at,
            diagnostic_code="operator_output_noop",
            limitation="The operator did not change the canonical subject.",
        )

    try:
        validate_runset_compatibility(suite, candidate)
        candidate_report = _validate_evaluator_report_binding(
            evaluator(suite, candidate),
            suite=suite,
            runset=candidate,
            gate_profile_id=binding.gate_profile_id,
        )
    except RunSetCompatibilityError:
        result = _failure_result(
            state=MutationResultState.invalid_operator,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="invalid_operator_evaluation",
            limitations=("The validated mutation could not satisfy evaluation bindings.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)
    except Exception as exc:
        exception_class, debug_reference = _safe_internal_diagnostic(
            "candidate_evaluation_error",
            exc,
        )
        result = _failure_result(
            state=MutationResultState.execution_error,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="candidate_evaluation_error",
            diagnostic_exception_class=exception_class,
            local_debug_reference=debug_reference,
            limitations=("Candidate evaluation ended with a bounded internal execution error.",),
        )
        return _execution_without_mutation(suite, result, generated_at=generated_at)

    try:
        assessment = assess_expected_detection(
            source_report,
            candidate_report,
            operator.descriptor.expected_detection_contract,
            expected_target=target.expected_finding_target,
        )
        if assessment.state == MutationResultState.invalid_operator.value:
            result = _failure_result(
                state=MutationResultState.invalid_operator,
                operator=operator,
                requested_operator_id=operator_id,
                source_digest=source_digest,
                seed=seed,
                evaluator_binding=binding,
                diagnostic_code="confounded_operator_output",
                limitations=assessment.limitations,
                observed_findings=_project_findings(assessment.observed_findings),
            )
            return _execution_without_mutation(suite, result, generated_at=generated_at)

        result_state = MutationResultState(assessment.state)
        result_limitations = {
            *operator.limitations,
            *assessment.limitations,
        }
        basis_limitation = _basis_sufficiency_limitation(binding.evaluation_basis)
        if basis_limitation is not None:
            result_limitations.add(basis_limitation)
        result = AssuranceMutationResult.build(
            source_digest=source_digest,
            mutated_digest=mutated_digest,
            operator_id=operator.descriptor.operator_id,
            operator_version=operator.descriptor.operator_version,
            operator_digest=operator.descriptor.operator_digest,
            implementation_digest=operator.descriptor.implementation_digest,
            expected_detection_contract_digest=(
                operator.descriptor.expected_detection_contract.contract_digest
            ),
            expected_finding_target_digest=finding_target_digest(target.expected_finding_target),
            evaluator_method_id=binding.method_id,
            evaluator_implementation_digest=binding.implementation_digest,
            evaluator_implementation_version=binding.implementation_version,
            evaluator_evaluation_basis=binding.evaluation_basis,
            evaluator_protocol_digest=binding.protocol_digest,
            evaluator_population_id=binding.population_id,
            gate_profile_id=binding.gate_profile_id,
            gate_profile_digest=binding.gate_profile_digest,
            waiver_set_digest=binding.waiver_set_digest,
            evaluation_date=binding.evaluation_date,
            seed=seed,
            changed_paths=changed_paths,
            observed_findings=_project_findings(assessment.observed_findings),
            matched_finding_ids=assessment.matched_finding_ids,
            state=result_state,
            provenance=operator.descriptor.provenance,
            independence_class=operator.descriptor.independence_class,
            diagnostic_code=None,
            limitations=tuple(sorted(result_limitations)),
        )
        descriptor = build_evidence_descriptor(
            result,
            suite_digest=compiled_suite_digest(suite),
            generated_at=generated_at,
        )
    except Exception as exc:
        exception_class, debug_reference = _safe_internal_diagnostic(
            "result_construction_error",
            exc,
        )
        failure = _failure_result(
            state=MutationResultState.execution_error,
            operator=operator,
            requested_operator_id=operator_id,
            source_digest=source_digest,
            seed=seed,
            evaluator_binding=binding,
            diagnostic_code="result_construction_error",
            diagnostic_exception_class=exception_class,
            local_debug_reference=debug_reference,
            limitations=("Result construction ended with a bounded internal execution error.",),
        )
        return _execution_without_mutation(
            suite,
            failure,
            generated_at=generated_at,
        )
    return MutationExecution(
        result=result,
        evidence_descriptor=descriptor,
        mutated_payload=candidate_payload,
        suite_digest=compiled_suite_digest(suite),
        generated_at=generated_at,
    )


def _execution_without_mutation(
    suite: CompiledSuite,
    result: AssuranceMutationResult,
    *,
    generated_at: str,
) -> MutationExecution:
    suite_digest = compiled_suite_digest(suite)
    return MutationExecution(
        result=result,
        evidence_descriptor=build_evidence_descriptor(
            result,
            suite_digest=suite_digest,
            generated_at=generated_at,
        ),
        mutated_payload=None,
        suite_digest=suite_digest,
        generated_at=generated_at,
    )


def _invalid_operator_output_execution(
    suite: CompiledSuite,
    *,
    operator: RegisteredOperator,
    requested_operator_id: str,
    source_digest: str,
    seed: int,
    evaluator_binding: MutationEvaluatorBinding,
    generated_at: str,
    diagnostic_code: str,
    limitation: str,
) -> MutationExecution:
    result = _failure_result(
        state=MutationResultState.invalid_operator,
        operator=operator,
        requested_operator_id=requested_operator_id,
        source_digest=source_digest,
        seed=seed,
        evaluator_binding=evaluator_binding,
        diagnostic_code=diagnostic_code,
        limitations=(limitation,),
    )
    return _execution_without_mutation(suite, result, generated_at=generated_at)


def _target_observation_is_evaluable(
    subject: RunSet,
    changed_paths: tuple[str, ...],
) -> bool | None:
    run_indices: set[int] = set()
    for path in changed_paths:
        parts = parse_json_pointer(path)
        if len(parts) < 2 or parts[0] != "runs":
            return None
        index_token = parts[1]
        if not index_token.isdigit() or (len(index_token) > 1 and index_token.startswith("0")):
            return None
        run_indices.add(int(index_token))
    if len(run_indices) != 1:
        return False
    run_index = next(iter(run_indices))
    if run_index >= len(subject.runs):
        return None
    run = subject.runs[run_index]
    case_counts = Counter(item.case_id for item in subject.runs)
    return run.observation_status == "included" and case_counts[run.case_id] == 1


def _is_exact_synthetic_privacy_challenge(
    operator: RegisteredOperator,
    target: MutationTarget,
    changed_paths: tuple[str, ...],
    candidate_payload: Mapping[str, object],
) -> bool:
    """Permit only the catalog's fixed, clearly synthetic redaction sentinel.

    Source validation remains fail-closed. This exception is evaluated only
    after the candidate privacy scan reports the deliberately injected marker,
    and it binds the exact operator identity, contract, path, and value.
    """
    descriptor = operator.descriptor
    if (
        descriptor.operator_id != "inject-synthetic-sensitive-summary"
        or descriptor.privacy_classification
        is not MutationPrivacyClassification.synthetic_fixture_sensitive_marker
        or target.expected_finding_target != "output_summary"
        or len(target.changes) != 1
        or target.changes[0].value != SYNTHETIC_SENSITIVE_SUMMARY
        or changed_paths != (target.changes[0].path,)
        or not contains_sensitive_value(SYNTHETIC_SENSITIVE_SUMMARY)
    ):
        return False
    contract = descriptor.expected_detection_contract
    required = contract.required_findings.any_of
    if (
        contract.target_control_ids != ("redaction_required",)
        or len(required) != 1
        or required[0].control_id != "redaction_required"
        or required[0].reason_code is not ReasonCode.RAW_SENSITIVE_CONTENT
        or required[0].target is not None
    ):
        return False
    parts = parse_json_pointer(target.changes[0].path)
    if (
        len(parts) != 3
        or parts[0] != "runs"
        or not parts[1].isdigit()
        or (len(parts[1]) > 1 and parts[1].startswith("0"))
        or parts[2] != "output_summary"
    ):
        return False
    runs = candidate_payload.get("runs")
    if not isinstance(runs, list):
        return False
    run_index = int(parts[1])
    if run_index >= len(runs):
        return False
    run_payload = runs[run_index]
    if not isinstance(run_payload, Mapping):
        return False
    output_summary = run_payload.get("output_summary")
    if not isinstance(output_summary, str) or output_summary != SYNTHETIC_SENSITIVE_SUMMARY:
        return False

    privacy_probe = deepcopy(dict(candidate_payload))
    probe_runs = privacy_probe.get("runs")
    if not isinstance(probe_runs, list) or run_index >= len(probe_runs):
        return False
    probe_run = probe_runs[run_index]
    if not isinstance(probe_run, dict):
        return False
    probe_run["output_summary"] = ""
    try:
        assert_runset_payload_safe_for_persistence(privacy_probe)
    except ValueError:
        return False
    return True


def _failure_result(
    *,
    state: MutationResultState,
    operator: RegisteredOperator | None,
    requested_operator_id: str,
    source_digest: str | None,
    seed: int,
    evaluator_binding: MutationEvaluatorBinding | None,
    gate_configuration: tuple[str, str, str, str] | None = None,
    diagnostic_code: str,
    limitations: tuple[str, ...],
    diagnostic_exception_class: str | None = None,
    local_debug_reference: str | None = None,
    observed_findings: tuple[ObservedFinding, ...] = (),
) -> AssuranceMutationResult:
    if operator is None:
        operator_id = (
            requested_operator_id
            if _MACHINE_ID.fullmatch(requested_operator_id)
            and not contains_sensitive_value(requested_operator_id)
            else "unknown-operator"
        )
        operator_version = "0.0.0"
        operator_digest = _UNKNOWN_DIGEST
        implementation_digest = _UNKNOWN_DIGEST
        detector_digest = _UNKNOWN_DIGEST
        independence_class = IndependenceClass.unknown
        provenance = _unknown_provenance(operator_id)
    else:
        descriptor = operator.descriptor
        operator_id = descriptor.operator_id
        operator_version = descriptor.operator_version
        operator_digest = descriptor.operator_digest
        implementation_digest = descriptor.implementation_digest
        detector_digest = descriptor.expected_detection_contract.contract_digest
        independence_class = descriptor.independence_class
        provenance = descriptor.provenance
        limitations = tuple(sorted(set((*operator.limitations, *limitations))))
    evaluator_method_id: str
    evaluator_implementation_digest: str
    evaluator_implementation_version: str
    evaluator_evaluation_basis: EvidenceEvaluationBasis
    evaluator_protocol_digest: str | None
    evaluator_population_id: str
    gate_profile_id: str
    gate_profile_digest: str
    waiver_set_digest: str
    evaluation_date: str
    if evaluator_binding is None:
        if not (
            state is MutationResultState.execution_error
            and diagnostic_code == "catalog_integrity_error"
        ):
            raise ValueError(
                "unavailable evaluator identity is reserved for catalog bootstrap failures"
            )
        evaluator_method_id = ASSURANCE_MUTATION_METHOD_ID
        evaluator_implementation_digest = _UNKNOWN_DIGEST
        evaluator_implementation_version = __version__
        evaluator_evaluation_basis = EvidenceEvaluationBasis.deterministic
        evaluator_protocol_digest = None
        evaluator_population_id = "deterministic-fixture-v1"
        if gate_configuration is None:
            raise ValueError(
                "catalog bootstrap failures require explicit gate configuration identity"
            )
        (
            gate_profile_id,
            gate_profile_digest,
            waiver_set_digest,
            evaluation_date,
        ) = gate_configuration
    else:
        evaluator_method_id = evaluator_binding.method_id
        evaluator_implementation_digest = evaluator_binding.implementation_digest
        evaluator_implementation_version = evaluator_binding.implementation_version
        evaluator_evaluation_basis = evaluator_binding.evaluation_basis
        evaluator_protocol_digest = evaluator_binding.protocol_digest
        evaluator_population_id = evaluator_binding.population_id
        gate_profile_id = evaluator_binding.gate_profile_id
        gate_profile_digest = evaluator_binding.gate_profile_digest
        waiver_set_digest = evaluator_binding.waiver_set_digest
        evaluation_date = evaluator_binding.evaluation_date
    return AssuranceMutationResult.build(
        source_digest=source_digest,
        mutated_digest=None,
        operator_id=operator_id,
        operator_version=operator_version,
        operator_digest=operator_digest,
        implementation_digest=implementation_digest,
        expected_detection_contract_digest=detector_digest,
        evaluator_method_id=evaluator_method_id,
        evaluator_implementation_digest=evaluator_implementation_digest,
        evaluator_implementation_version=evaluator_implementation_version,
        evaluator_evaluation_basis=evaluator_evaluation_basis,
        evaluator_protocol_digest=evaluator_protocol_digest,
        evaluator_population_id=evaluator_population_id,
        gate_profile_id=gate_profile_id,
        gate_profile_digest=gate_profile_digest,
        waiver_set_digest=waiver_set_digest,
        evaluation_date=evaluation_date,
        seed=seed,
        changed_paths=(),
        observed_findings=observed_findings,
        matched_finding_ids=(),
        state=state,
        provenance=provenance,
        independence_class=independence_class,
        diagnostic_code=diagnostic_code,
        diagnostic_exception_class=diagnostic_exception_class,
        local_debug_reference=local_debug_reference,
        limitations=limitations,
    )


def _unknown_provenance(operator_id: str) -> OperatorProvenance:
    return OperatorProvenance(
        operator_id=operator_id,
        operator_version="0.0.0",
        implementation_digest=_UNKNOWN_DIGEST,
        implementation_components=(),
        introduction_components=(),
        introduced_at_commit=None,
        introduced_in_release=None,
        origin=OperatorOrigin(
            kind=OperatorOriginKind.unknown,
            references=("unresolved built-in operator identity",),
        ),
        target_controls=(),
        authorship=OperatorAuthorship(
            relationship_to_control_author=AuthorshipRelationship.unknown,
        ),
    )


def _project_findings(findings: tuple[Finding, ...]) -> tuple[ObservedFinding, ...]:
    return tuple(
        ObservedFinding(
            finding_id=finding.finding_id,
            control_id=finding.control_id,
            state=finding.state,
            reason_code=finding.reason_code,
            target_digest=finding_target_digest(finding.target),
        )
        for finding in findings
    )


def _validate_evaluator_report_binding(
    report: EvaluationReport,
    *,
    suite: CompiledSuite,
    runset: RunSet,
    gate_profile_id: str,
) -> EvaluationReport:
    if not isinstance(report, EvaluationReport):
        raise TypeError("mutation evaluator must return an EvaluationReport")
    report = EvaluationReport.model_validate(report.model_dump(mode="json"))
    if (
        report.runset_id != runset.runset_id
        or report.candidate_vs_expectations.runset_id != runset.runset_id
    ):
        raise ValueError("mutation evaluator report is bound to a different RunSet")
    expected_runset_digest = sha256_hexdigest(runset.model_dump(mode="json"))
    if report.runset_digest != expected_runset_digest:
        raise ValueError("mutation evaluator report is bound to different RunSet content")
    if report.suite_id != suite.suite_id or report.suite_version != suite.suite_version:
        raise ValueError("mutation evaluator report is bound to a different compiled suite")
    if report.gate_profile != gate_profile_id:
        raise ValueError("mutation evaluator report is bound to a different gate profile")
    return report


def build_evidence_descriptor(
    result: AssuranceMutationResult,
    *,
    suite_digest: str,
    generated_at: str,
) -> AssuranceEvidenceDescriptor:
    state = result.state
    basis_sufficiency_check_id = _basis_sufficiency_check_id(result.evaluator_evaluation_basis)
    completed_assessment = state in {
        MutationResultState.caught,
        MutationResultState.survived,
    }
    basis_sufficiency_unavailable = completed_assessment and basis_sufficiency_check_id is not None
    prerequisite_state = (
        PrerequisiteState.satisfied
        if completed_assessment and not basis_sufficiency_unavailable
        else PrerequisiteState.unmet
    )
    evidence_state = (
        EvidenceState.supported
        if state is MutationResultState.caught
        else EvidenceState.contradicted
    )
    verdict_bearing = completed_assessment and not basis_sufficiency_unavailable
    if basis_sufficiency_unavailable:
        evidence_state = EvidenceState.prerequisites_unmet
    elif state is MutationResultState.inapplicable:
        evidence_state = EvidenceState.prerequisites_unmet
    elif state is MutationResultState.invalid_operator:
        evidence_state = EvidenceState.prerequisites_unmet
    elif state is MutationResultState.invalid_subject:
        evidence_state = EvidenceState.prerequisites_unmet
    elif state is MutationResultState.execution_error:
        evidence_state = EvidenceState.error
    checks = _prerequisite_checks(result)
    reason_codes = tuple(
        sorted(
            {finding.reason_code for finding in result.observed_findings},
            key=lambda reason: reason.value,
        )
    )
    return AssuranceEvidenceDescriptor.build(
        evidence_id=f"ev-control-efficacy-{result.result_digest[:24]}",
        evidence_kind="control_efficacy",
        subject=EvidenceSubject(
            subject_type="run_set",
            digest=result.source_digest,
        ),
        scope=EvidenceScope(
            suite_digest=suite_digest,
            protocol_digest=result.evaluator_protocol_digest,
            population_id=result.evaluator_population_id,
            gate_profile_id=result.gate_profile_id,
            gate_profile_digest=result.gate_profile_digest,
            waiver_set_digest=result.waiver_set_digest,
            evaluation_date=result.evaluation_date,
        ),
        method=EvidenceMethod(
            method_id=result.evaluator_method_id,
            implementation_digest=result.evaluator_implementation_digest,
            implementation_version=result.evaluator_implementation_version,
            evaluation_basis=result.evaluator_evaluation_basis,
        ),
        result=EvidenceResult(
            state=evidence_state,
            verdict_bearing=verdict_bearing,
            reason_codes=reason_codes,
            metrics={
                "observed_finding_count": len(result.observed_findings),
                "matched_finding_count": len(result.matched_finding_ids),
            },
        ),
        prerequisites=EvidencePrerequisites(
            state=prerequisite_state,
            checks=checks,
        ),
        assumptions=(
            "When validated, the compiled suite and RunSet bindings identify the intended "
            "deterministic subject.",
            "The bound evaluator implementation provides the declared target controls.",
        ),
        limitations=result.limitations,
        validity=EvidenceValidity(
            generated_at=generated_at,
            expires_at=None,
            invalidated_by=(
                "canonicalization_component_digest_change",
                "evaluator_or_gate_component_digest_change",
                "evaluation_date_change",
                "expected_detection_contract_digest_change",
                "gate_profile_digest_change",
                "mutation_dispatch_component_digest_change",
                "mutation_schema_or_validation_component_digest_change",
                "operator_implementation_manifest_digest_change",
                "privacy_component_digest_change",
                "suite_digest_change",
                "target_control_component_digest_change",
                "waiver_set_digest_change",
            ),
        ),
        dependencies=(
            EvidenceDependency(
                evidence_id=f"mutation-result-{result.result_digest[:24]}",
                digest=result.result_digest,
            ),
        ),
        producer=EvidenceProducer(
            name="agent-assure",
            version=__version__,
        ),
    )


def _prerequisite_checks(
    result: AssuranceMutationResult,
) -> tuple[PrerequisiteCheck, ...]:
    check_ids = (
        "subject-valid",
        "operator-valid",
        "operator-applicable",
        "mutation-execution-completed",
    )
    states = {check_id: PrerequisiteState.not_evaluated for check_id in check_ids}
    state = result.state
    if state in {MutationResultState.caught, MutationResultState.survived}:
        states = {check_id: PrerequisiteState.satisfied for check_id in check_ids}
    elif state is MutationResultState.invalid_subject:
        states["operator-valid"] = PrerequisiteState.satisfied
        states["subject-valid"] = PrerequisiteState.unmet
    elif state is MutationResultState.invalid_operator:
        states["operator-valid"] = PrerequisiteState.unmet
        if result.diagnostic_code != "unknown_operator":
            states["subject-valid"] = PrerequisiteState.satisfied
        if result.diagnostic_code in {
            "confounded_operator_output",
            "invalid_operator_evaluation",
            "operator_output_application_error",
            "operator_output_noop",
            "operator_output_not_canonical",
            "operator_output_path_invalid",
            "operator_output_path_undeclared",
            "operator_output_privacy_violation",
            "operator_output_schema_invalid",
            "operator_target_not_evaluable",
        }:
            states["operator-applicable"] = PrerequisiteState.satisfied
    elif state is MutationResultState.inapplicable:
        states["subject-valid"] = PrerequisiteState.satisfied
        states["operator-valid"] = PrerequisiteState.satisfied
        states["operator-applicable"] = PrerequisiteState.unmet
    elif state is MutationResultState.execution_error:
        if result.diagnostic_code == "catalog_integrity_error":
            states["operator-valid"] = PrerequisiteState.unmet
        else:
            states["subject-valid"] = PrerequisiteState.satisfied
            states["operator-valid"] = PrerequisiteState.satisfied
            if result.diagnostic_code in {
                "candidate_evaluation_error",
                "result_construction_error",
            }:
                states["operator-applicable"] = PrerequisiteState.satisfied
        states["mutation-execution-completed"] = PrerequisiteState.unmet
    checks = tuple(
        PrerequisiteCheck(
            check_id=check_id,
            state=states[check_id],
            reason_codes=(
                (ReasonCode.NOT_EVALUATED,)
                if states[check_id] is PrerequisiteState.not_evaluated
                else ()
            ),
        )
        for check_id in check_ids
    )
    basis_check_id = _basis_sufficiency_check_id(result.evaluator_evaluation_basis)
    if basis_check_id is None:
        return checks
    basis_state = (
        PrerequisiteState.unmet
        if state in {MutationResultState.caught, MutationResultState.survived}
        else PrerequisiteState.not_evaluated
    )
    return (
        *checks,
        PrerequisiteCheck(
            check_id=basis_check_id,
            state=basis_state,
            reason_codes=(
                (ReasonCode.NOT_EVALUATED,)
                if basis_state is PrerequisiteState.not_evaluated
                else ()
            ),
        ),
    )


def _basis_sufficiency_check_id(
    basis: EvidenceEvaluationBasis,
) -> str | None:
    if basis is EvidenceEvaluationBasis.stochastic:
        return STOCHASTIC_SUFFICIENCY_CHECK_ID
    if basis is EvidenceEvaluationBasis.human_reviewed:
        return HUMAN_REVIEW_SUFFICIENCY_CHECK_ID
    return None


def _basis_sufficiency_limitation(basis: EvidenceEvaluationBasis) -> str | None:
    if basis is EvidenceEvaluationBasis.stochastic:
        return STOCHASTIC_SUFFICIENCY_LIMITATION
    if basis is EvidenceEvaluationBasis.human_reviewed:
        return HUMAN_REVIEW_SUFFICIENCY_LIMITATION
    return None


def _safe_internal_diagnostic(
    diagnostic_code: str,
    exc: BaseException,
) -> tuple[str, str]:
    diagnostic = safe_error(
        diagnostic_code,
        "Mutation execution ended with a bounded internal error.",
        exc,
    )
    exception_class = diagnostic.exception_class
    if _MACHINE_ID.fullmatch(exception_class) is None or contains_sensitive_value(exception_class):
        exception_class = "InternalError"
    return exception_class, diagnostic.local_debug_reference


def _safe_digest(payload: Mapping[str, object]) -> str | None:
    try:
        return sha256_hexdigest(payload)
    except (TypeError, ValueError):
        return None
