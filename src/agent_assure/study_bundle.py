"""Closed-directory verification and exact replay for real-model studies."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, TypeVar

from pydantic import BaseModel

from agent_assure.io_limits import (
    MAX_ARTIFACT_JSON_BYTES,
    load_json_bytes_bounded,
    open_directory_at,
)
from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.rooted_io import PinnedDirectoryFile
from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.run import RunSet
from agent_assure.schema.stochastic_sensitivity import (
    RepeatedEvidenceSensitivityProtocol,
)
from agent_assure.schema.study import (
    RealModelStudyManifest,
    RealModelStudyReport,
    StudyExecutionOrigin,
    StudyExecutionReviewReceipt,
    StudyHypothesisClassification,
    StudyInferenceScope,
    StudyObservedExecutionProvenance,
    StudyRegistrationMethod,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study_artifact_serialization import published_model_json_bytes
from agent_assure.study_execution_review import validate_study_execution_review
from agent_assure.study_limits import (
    MAX_STUDY_BUNDLE_FILES,
    MAX_STUDY_BUNDLE_TOTAL_BYTES,
    MAX_STUDY_RUNSET_JSON_BYTES,
)
from agent_assure.study_method_review import validate_study_statistical_method_review
from agent_assure.study_registration import validate_study_registration

if TYPE_CHECKING:
    from agent_assure.study.analysis import StudyConditionEvidence

STUDY_BUNDLE_BASE_FILENAMES = (
    "real-model-study-manifest.json",
    "process-equivalence-benchmark.json",
    "study-registration-record.json",
    "study-registration-review.json",
    "real-model-study-report.json",
    "real-model-study-report.md",
)
STUDY_EXECUTION_REVIEW_FILENAME = "study-execution-review.json"
STUDY_STATISTICAL_METHOD_REVIEW_FILENAME = "study-statistical-method-review.json"
_ModelT = TypeVar("_ModelT", bound=BaseModel)
_VALIDATED_STUDY_BUNDLE_MARKER = object()


@dataclass(frozen=True, slots=True, init=False)
class ValidatedStudyBundle:
    """Models issued only after a pinned, exact-inventory replay succeeds.

    Factory-only construction prevents a bare self-authored report from being
    accidentally promoted to release-readiness evidence. It is not a security
    boundary against Python code already executing inside this module's trust
    boundary.
    """

    manifest: RealModelStudyManifest
    benchmark: ProcessEquivalenceBenchmarkManifest
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol]
    evidence: Mapping[str, StudyConditionEvidence | None]
    report: RealModelStudyReport
    registration_review_receipt: StudyRegistrationReviewReceipt
    statistical_method_review_receipt: StudyStatisticalMethodReviewReceipt | None
    execution_review_receipt: StudyExecutionReviewReceipt | None
    registration_record_sha256: str
    registration_evidence_verified: bool
    statistical_method_review_verified: bool
    execution_review_verified: bool
    file_count: int
    total_bytes: int
    _verification_marker: object = field(repr=False, compare=False)

    def __new__(cls) -> ValidatedStudyBundle:
        raise TypeError(
            "ValidatedStudyBundle instances are issued only by load_and_validate_study_bundle"
        )

    @property
    def is_mechanically_verified(self) -> bool:
        return getattr(self, "_verification_marker", None) is _VALIDATED_STUDY_BUNDLE_MARKER

    @property
    def is_publication_ready(self) -> bool:
        """Return trusted confirmatory eligibility after exact bundle replay."""

        return bool(
            self.is_mechanically_verified
            and self.registration_evidence_verified
            and self.statistical_method_review_verified
            and self.statistical_method_review_receipt is not None
            and self.execution_review_verified
            and self.execution_review_receipt is not None
            and self.registration_record_sha256 == self.manifest.registration.evidence_digest
            and self.manifest.registration.method
            in {
                StudyRegistrationMethod.version_control_commit,
                StudyRegistrationMethod.append_only_registry,
            }
            and self.report.protocol_valid
            and self.report.statistical_sufficiency_satisfied
            and self.report.invariant_controls_satisfied
            and self.report.hypothesis_classification
            is not StudyHypothesisClassification.not_measured
            and self.manifest.hypothesis_decision_rule.inference_scope
            is StudyInferenceScope.confirmatory_independent_clusters
            and all(
                binding.execution_origin is StudyExecutionOrigin.real_provider
                and result.observed_execution_provenance is not None
                and result.observed_execution_provenance.observed_origin
                is StudyExecutionOrigin.real_provider
                and result.operational_summary.latency_reported_records
                == result.operational_summary.run_records
                for binding, result in zip(
                    self.manifest.conditions,
                    self.report.conditions,
                    strict=True,
                )
            )
        )

    @property
    def is_scoped_descriptive_publication_ready(self) -> bool:
        """Return eligibility to publish only fixed-frame descriptive findings.

        This deliberately does not satisfy the Sprint 7 confirmatory checkpoint.
        It exists so an honest downscope has a machine-readable, replayed output
        path without being relabeled as independent-cluster evidence.
        """

        return bool(
            self.is_mechanically_verified
            and self.registration_evidence_verified
            and self.statistical_method_review_verified
            and self.statistical_method_review_receipt is not None
            and self.execution_review_verified
            and self.execution_review_receipt is not None
            and self.registration_record_sha256 == self.manifest.registration.evidence_digest
            and self.manifest.registration.method
            in {
                StudyRegistrationMethod.version_control_commit,
                StudyRegistrationMethod.append_only_registry,
            }
            and self.manifest.hypothesis_decision_rule.inference_scope
            is StudyInferenceScope.fixed_frame_descriptive_conformance
            and self.report.protocol_valid
            and self.report.statistical_sufficiency_satisfied
            and self.report.invariant_controls_satisfied
            and self.report.hypothesis_classification is StudyHypothesisClassification.not_measured
            and all(
                binding.execution_origin is StudyExecutionOrigin.real_provider
                and result.observed_execution_provenance is not None
                and result.observed_execution_provenance.observed_origin
                is StudyExecutionOrigin.real_provider
                and result.operational_summary.latency_reported_records
                == result.operational_summary.run_records
                for binding, result in zip(
                    self.manifest.conditions,
                    self.report.conditions,
                    strict=True,
                )
            )
        )

    @classmethod
    def _from_verified_bytes(
        cls,
        *,
        manifest: RealModelStudyManifest,
        benchmark: ProcessEquivalenceBenchmarkManifest,
        protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol],
        evidence: Mapping[str, StudyConditionEvidence | None],
        report: RealModelStudyReport,
        registration_review_receipt: StudyRegistrationReviewReceipt,
        statistical_method_review_receipt: StudyStatisticalMethodReviewReceipt | None = None,
        execution_review_receipt: StudyExecutionReviewReceipt | None = None,
        registration_record_sha256: str,
        registration_evidence_verified: bool,
        statistical_method_review_verified: bool = False,
        execution_review_verified: bool = False,
        file_count: int,
        total_bytes: int,
    ) -> ValidatedStudyBundle:
        instance = object.__new__(cls)
        object.__setattr__(instance, "manifest", manifest)
        object.__setattr__(instance, "benchmark", benchmark)
        object.__setattr__(
            instance,
            "protocols",
            MappingProxyType(dict(protocols)),
        )
        object.__setattr__(
            instance,
            "evidence",
            MappingProxyType(dict(evidence)),
        )
        object.__setattr__(instance, "report", report)
        object.__setattr__(
            instance,
            "registration_review_receipt",
            registration_review_receipt,
        )
        object.__setattr__(
            instance,
            "statistical_method_review_receipt",
            statistical_method_review_receipt,
        )
        object.__setattr__(
            instance,
            "execution_review_receipt",
            execution_review_receipt,
        )
        object.__setattr__(
            instance,
            "registration_record_sha256",
            registration_record_sha256,
        )
        object.__setattr__(
            instance,
            "registration_evidence_verified",
            registration_evidence_verified,
        )
        object.__setattr__(
            instance,
            "statistical_method_review_verified",
            statistical_method_review_verified,
        )
        object.__setattr__(
            instance,
            "execution_review_verified",
            execution_review_verified,
        )
        object.__setattr__(instance, "file_count", file_count)
        object.__setattr__(instance, "total_bytes", total_bytes)
        object.__setattr__(
            instance,
            "_verification_marker",
            _VALIDATED_STUDY_BUNDLE_MARKER,
        )
        return instance


def load_and_validate_study_bundle(path: Path) -> ValidatedStudyBundle:
    """Load a closed study directory and replay its report from pinned bytes."""

    # Delay imports across the study/reporting facade until this module has
    # finished defining its factory-issued result type. The readiness facade
    # intentionally imports that type, so eager imports here form a cycle.
    from agent_assure.reporting.study import render_real_model_study_markdown
    from agent_assure.study.analysis import (
        StudyConditionEvidence,
        analyze_real_model_study,
    )

    with (
        open_directory_at(path, ".", label="real-model study bundle") as bundle,
        ExitStack() as opened_stack,
    ):
        initial_entries = bundle.entry_names(
            max_entries=MAX_STUDY_BUNDLE_FILES,
            label="real-model study bundle",
        )
        if len({name.casefold() for name in initial_entries}) != len(initial_entries):
            raise ValueError("real-model study bundle contains case-colliding paths")
        initial_entry_set = set(initial_entries)
        opened_files: list[PinnedDirectoryFile] = []
        opened_names: set[str] = set()
        total_bytes = 0

        def read_child(
            name: str,
            *,
            label: str,
            max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
        ) -> bytes:
            nonlocal total_bytes
            if name in opened_names:
                raise ValueError("real-model study bundle file was requested more than once")
            remaining = MAX_STUDY_BUNDLE_TOTAL_BYTES - total_bytes
            if remaining <= 0:
                raise ValueError("real-model study bundle exceeds maximum supported size")
            opened = opened_stack.enter_context(
                bundle.open_file_bounded(
                    name,
                    max_bytes=min(max_bytes, remaining),
                    label=label,
                    require_single_link=True,
                )
            )
            opened_files.append(opened)
            opened_names.add(name)
            total_bytes += opened.contents.size
            return opened.contents.data

        manifest_bytes = read_child(
            "real-model-study-manifest.json",
            label="real-model study manifest",
        )
        manifest = _load_canonical_model(
            manifest_bytes,
            RealModelStudyManifest,
            label="real-model study manifest",
        )
        expected_entries = list(STUDY_BUNDLE_BASE_FILENAMES)
        has_execution_review = STUDY_EXECUTION_REVIEW_FILENAME in initial_entry_set
        if has_execution_review:
            expected_entries.append(STUDY_EXECUTION_REVIEW_FILENAME)
        has_statistical_method_review = (
            STUDY_STATISTICAL_METHOD_REVIEW_FILENAME in initial_entry_set
        )
        if has_statistical_method_review:
            expected_entries.append(STUDY_STATISTICAL_METHOD_REVIEW_FILENAME)
        execution_presence: list[bool] = []
        provenance_presence: list[bool] = []
        for index, _binding in enumerate(manifest.conditions):
            registered_name, execution_names = _condition_filenames(index)
            expected_entries.append(registered_name)
            source_names = execution_names[:3]
            source_present = tuple(name in initial_entry_set for name in source_names)
            provenance_present = execution_names[3] in initial_entry_set
            if any(source_present) and not all(source_present):
                raise ValueError("real-model study condition evidence inventory is incomplete")
            executed = all(source_present)
            if provenance_present and not executed:
                raise ValueError("observed execution provenance requires complete source evidence")
            execution_presence.append(executed)
            provenance_presence.append(provenance_present)
            if executed:
                expected_entries.extend(source_names)
                if provenance_present:
                    expected_entries.append(execution_names[3])
        _require_exact_inventory(initial_entries, expected_entries)

        benchmark_bytes = read_child(
            "process-equivalence-benchmark.json",
            label="real-model study benchmark",
        )
        benchmark = _load_canonical_model(
            benchmark_bytes,
            ProcessEquivalenceBenchmarkManifest,
            label="real-model study benchmark",
        )
        registration_record_bytes = read_child(
            "study-registration-record.json",
            label="study registration record",
        )
        registration_review_receipt = _load_canonical_model(
            read_child(
                "study-registration-review.json",
                label="study registration review receipt",
            ),
            StudyRegistrationReviewReceipt,
            label="study registration review receipt",
        )
        registration = validate_study_registration(
            manifest=manifest,
            registration_record_bytes=registration_record_bytes,
            review_receipt=registration_review_receipt,
        )
        report_bytes = read_child(
            "real-model-study-report.json",
            label="real-model study report",
        )
        report = _load_canonical_model(
            report_bytes,
            RealModelStudyReport,
            label="real-model study report",
        )
        markdown_bytes = read_child(
            "real-model-study-report.md",
            label="real-model study Markdown report",
        )
        try:
            markdown_text = markdown_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("real-model study Markdown must be valid UTF-8") from exc
        assert_persisted_payload_safe(
            {"content": markdown_text},
            owner="real-model study Markdown report",
        )

        protocols: dict[str, RepeatedEvidenceSensitivityProtocol] = {}
        evidence: dict[str, StudyConditionEvidence | None] = {}
        registered_protocol_bytes: dict[str, bytes] = {}
        baseline_runset_bytes: dict[str, bytes] = {}
        counterfactual_runset_bytes: dict[str, bytes] = {}
        for index, (binding, executed, has_provenance) in enumerate(
            zip(
                manifest.conditions,
                execution_presence,
                provenance_presence,
                strict=True,
            )
        ):
            registered_name, execution_names = _condition_filenames(index)
            registered_bytes = read_child(
                registered_name,
                label="registered study condition protocol",
            )
            registered_protocol_bytes[binding.condition_id] = registered_bytes
            protocols[binding.condition_id] = _load_canonical_model(
                registered_bytes,
                RepeatedEvidenceSensitivityProtocol,
                label="registered study condition protocol",
            )
            if not executed:
                evidence[binding.condition_id] = None
                continue
            (
                source_protocol_name,
                baseline_name,
                counterfactual_name,
                provenance_name,
            ) = execution_names
            baseline_bytes = read_child(
                baseline_name,
                label="baseline study source RunSet",
                max_bytes=MAX_STUDY_RUNSET_JSON_BYTES,
            )
            counterfactual_bytes = read_child(
                counterfactual_name,
                label="counterfactual study source RunSet",
                max_bytes=MAX_STUDY_RUNSET_JSON_BYTES,
            )
            baseline_runset_bytes[binding.condition_id] = baseline_bytes
            counterfactual_runset_bytes[binding.condition_id] = counterfactual_bytes
            evidence[binding.condition_id] = StudyConditionEvidence(
                protocol=_load_canonical_model(
                    read_child(
                        source_protocol_name,
                        label="source study condition protocol",
                    ),
                    RepeatedEvidenceSensitivityProtocol,
                    label="source study condition protocol",
                ),
                baseline_runset=_load_canonical_model(
                    baseline_bytes,
                    RunSet,
                    label="baseline study source RunSet",
                    max_bytes=MAX_STUDY_RUNSET_JSON_BYTES,
                ),
                counterfactual_runset=_load_canonical_model(
                    counterfactual_bytes,
                    RunSet,
                    label="counterfactual study source RunSet",
                    max_bytes=MAX_STUDY_RUNSET_JSON_BYTES,
                ),
                observed_execution_provenance=(
                    _load_canonical_model(
                        read_child(
                            provenance_name,
                            label="observed study execution provenance",
                        ),
                        StudyObservedExecutionProvenance,
                        label="observed study execution provenance",
                    )
                    if has_provenance
                    else None
                ),
            )

        statistical_method_review_receipt = None
        statistical_method_review_verified = False
        if has_statistical_method_review:
            statistical_method_review_receipt = _load_canonical_model(
                read_child(
                    STUDY_STATISTICAL_METHOD_REVIEW_FILENAME,
                    label="study statistical-method review receipt",
                ),
                StudyStatisticalMethodReviewReceipt,
                label="study statistical-method review receipt",
            )
            validate_study_statistical_method_review(
                manifest=manifest,
                benchmark=benchmark,
                protocols=protocols,
                review_receipt=statistical_method_review_receipt,
                manifest_bytes=manifest_bytes,
                benchmark_bytes=benchmark_bytes,
                registered_protocol_bytes=registered_protocol_bytes,
            )
            statistical_method_review_verified = True

        recomputed = analyze_real_model_study(
            manifest=manifest,
            benchmark=benchmark,
            protocols=protocols,
            evidence=evidence,
        )
        if recomputed != report:
            raise ValueError(
                "real-model study report does not exactly replay from bundled evidence"
            )
        expected_markdown = render_real_model_study_markdown(recomputed).encode("utf-8")
        if markdown_bytes != expected_markdown:
            raise ValueError("real-model study Markdown does not match the recomputed report")

        execution_review_receipt = None
        execution_review_verified = False
        if has_execution_review:
            execution_review_receipt = _load_canonical_model(
                read_child(
                    STUDY_EXECUTION_REVIEW_FILENAME,
                    label="study execution review receipt",
                ),
                StudyExecutionReviewReceipt,
                label="study execution review receipt",
            )
            validate_study_execution_review(
                manifest=manifest,
                benchmark=benchmark,
                protocols=protocols,
                report=report,
                evidence=evidence,
                review_receipt=execution_review_receipt,
                manifest_bytes=manifest_bytes,
                report_bytes=report_bytes,
                baseline_runset_bytes=baseline_runset_bytes,
                counterfactual_runset_bytes=counterfactual_runset_bytes,
            )
            execution_review_verified = True

        for opened in opened_files:
            opened.revalidate()
        final_entries = bundle.entry_names(
            max_entries=MAX_STUDY_BUNDLE_FILES,
            label="real-model study bundle",
        )
        _require_exact_inventory(final_entries, expected_entries)

    return ValidatedStudyBundle._from_verified_bytes(
        manifest=manifest,
        benchmark=benchmark,
        protocols=protocols,
        evidence=evidence,
        report=report,
        registration_review_receipt=registration.review_receipt,
        statistical_method_review_receipt=statistical_method_review_receipt,
        execution_review_receipt=execution_review_receipt,
        registration_record_sha256=registration.record_sha256,
        registration_evidence_verified=True,
        statistical_method_review_verified=statistical_method_review_verified,
        execution_review_verified=execution_review_verified,
        file_count=len(expected_entries),
        total_bytes=total_bytes,
    )


def _condition_filenames(index: int) -> tuple[str, tuple[str, str, str, str]]:
    prefix = f"condition-{index:03d}"
    return (
        f"{prefix}.registered.protocol.json",
        (
            f"{prefix}.source.protocol.json",
            f"{prefix}.baseline.source.runset.json",
            f"{prefix}.counterfactual.source.runset.json",
            f"{prefix}.observed-execution-provenance.json",
        ),
    )


def _require_exact_inventory(
    observed: Sequence[str],
    expected: Sequence[str],
) -> None:
    if (
        len(observed) != len(expected)
        or len({name.casefold() for name in expected}) != len(expected)
        or set(observed) != set(expected)
    ):
        raise ValueError("real-model study bundle inventory does not match its manifest")


def _load_canonical_model(
    data: bytes,
    model_type: type[_ModelT],
    *,
    label: str,
    max_bytes: int = MAX_ARTIFACT_JSON_BYTES,
) -> _ModelT:
    payload = load_json_bytes_bounded(
        data,
        max_bytes=max_bytes,
        label=label,
    )
    assert_persisted_payload_safe(payload, owner=label)
    model = model_type.model_validate(payload)
    if data != published_model_json_bytes(model):
        raise ValueError(f"{label} is not in the canonical published JSON form")
    return model


__all__ = [
    "MAX_STUDY_BUNDLE_FILES",
    "MAX_STUDY_BUNDLE_TOTAL_BYTES",
    "MAX_STUDY_RUNSET_JSON_BYTES",
    "STUDY_BUNDLE_BASE_FILENAMES",
    "STUDY_EXECUTION_REVIEW_FILENAME",
    "STUDY_STATISTICAL_METHOD_REVIEW_FILENAME",
    "ValidatedStudyBundle",
    "load_and_validate_study_bundle",
]
