"""Fail-closed preflight for preregistered real-provider study dispatch."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_CEILING, Decimal

from agent_assure.schema.benchmark import ProcessEquivalenceBenchmarkManifest
from agent_assure.schema.stochastic_sensitivity import RepeatedEvidenceSensitivityProtocol
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyExecutionOrigin,
    StudyRegistrationReviewReceipt,
    StudyStatisticalMethodReviewReceipt,
)
from agent_assure.study_method_review import validate_study_statistical_method_review
from agent_assure.timestamps import parse_rfc3339_timestamp

_VALIDATED_STUDY_DISPATCH_SEAL = object()


@dataclass(frozen=True, slots=True)
class StudyDispatchPreflightEvidence:
    """Exact preregistration evidence required before a provider can be called.

    This is an in-memory input contract, not another persisted attestation. The
    two existing review receipts remain the human-reviewed artifacts.
    """

    manifest_bytes: bytes
    benchmark_bytes: bytes
    registration_record_bytes: bytes
    registration_review_receipt: StudyRegistrationReviewReceipt
    independence_audit_artifact_bytes: bytes
    statistical_method_review_receipt: StudyStatisticalMethodReviewReceipt
    protocols: Mapping[str, RepeatedEvidenceSensitivityProtocol]
    registered_protocol_bytes: Mapping[str, bytes]


@dataclass(frozen=True, slots=True)
class _ValidatedStudyDispatchCapability:
    study_manifest_digest: str
    allowed_arm_bindings: frozenset[tuple[str, str]]
    manifest: RealModelStudyManifest
    seal: object


class ValidatedStudyDispatchPreflight:
    """Opaque proof that exact preregistration inputs passed dispatch preflight."""

    __slots__ = ("_capability",)

    def __init__(self) -> None:
        raise TypeError("validated study dispatch proof is issued only by dispatch preflight")

    @property
    def study_manifest_digest(self) -> str:
        return self._capability.study_manifest_digest

    @property
    def allowed_arm_bindings(self) -> frozenset[tuple[str, str]]:
        return self._capability.allowed_arm_bindings

    _capability: _ValidatedStudyDispatchCapability


def require_real_provider_condition_dispatch(
    *,
    manifest: RealModelStudyManifest,
    condition_id: str,
    protocol: RepeatedEvidenceSensitivityProtocol,
) -> None:
    """Require prospective real-provider authorization for the selected condition."""

    matches = tuple(
        condition for condition in manifest.conditions if condition.condition_id == condition_id
    )
    if len(matches) != 1:
        raise ValueError("study dispatch condition is not uniquely declared by the manifest")
    binding = matches[0]
    if binding.execution_origin is not StudyExecutionOrigin.real_provider:
        raise ValueError(
            "study provider dispatch requires a condition preregistered as real_provider"
        )
    if binding.execution_attempt_id != protocol.execution_attempt_id:
        raise ValueError(
            "study provider dispatch attempt identity does not match the selected condition"
        )


def validate_study_dispatch_preflight(
    *,
    manifest: RealModelStudyManifest,
    benchmark: ProcessEquivalenceBenchmarkManifest,
    evidence: StudyDispatchPreflightEvidence,
) -> ValidatedStudyDispatchPreflight:
    """Replay every preregistration binding and require an open execution window."""

    validate_study_statistical_method_review(
        manifest=manifest,
        benchmark=benchmark,
        protocols=evidence.protocols,
        registration_record_bytes=evidence.registration_record_bytes,
        registration_review_receipt=evidence.registration_review_receipt,
        review_receipt=evidence.statistical_method_review_receipt,
        independence_audit_artifact_bytes=evidence.independence_audit_artifact_bytes,
        manifest_bytes=evidence.manifest_bytes,
        benchmark_bytes=evidence.benchmark_bytes,
        registered_protocol_bytes=evidence.registered_protocol_bytes,
    )
    require_study_execution_window_open(manifest, boundary="dispatch preflight")
    validated_manifest = RealModelStudyManifest.model_validate(manifest.model_dump(mode="json"))
    capability = _ValidatedStudyDispatchCapability(
        study_manifest_digest=validated_manifest.manifest_digest,
        allowed_arm_bindings=frozenset(
            (
                condition.design_commitment_digest,
                configuration_digest,
            )
            for condition in validated_manifest.conditions
            if condition.execution_origin is StudyExecutionOrigin.real_provider
            for configuration_digest in (
                condition.baseline_configuration_digest,
                condition.counterfactual_configuration_digest,
            )
        ),
        manifest=validated_manifest,
        seal=_VALIDATED_STUDY_DISPATCH_SEAL,
    )
    proof = object.__new__(ValidatedStudyDispatchPreflight)
    object.__setattr__(proof, "_capability", capability)
    return proof


def require_validated_study_dispatch_authorization(
    proof: ValidatedStudyDispatchPreflight,
    *,
    study_manifest_digest: str,
    evidence_sensitivity_design_digest: str,
    configuration_digest: str,
) -> None:
    """Validate an opaque preflight proof against one exact registered arm."""

    capability = _validated_study_dispatch_capability(proof)
    if capability.study_manifest_digest != study_manifest_digest:
        raise ValueError("study dispatch preflight proof does not match the manifest")
    if (
        evidence_sensitivity_design_digest,
        configuration_digest,
    ) not in capability.allowed_arm_bindings:
        raise ValueError(
            "study dispatch preflight proof does not authorize this design and configuration"
        )


def require_validated_study_dispatch_window_open(
    proof: ValidatedStudyDispatchPreflight,
    *,
    boundary: str,
    minimum_remaining_seconds: Decimal = Decimal("0"),
) -> None:
    """Recheck the proof-bound manifest window at a provider-call boundary."""

    capability = _validated_study_dispatch_capability(proof)
    require_study_execution_window_open(
        capability.manifest,
        boundary=boundary,
        minimum_remaining_seconds=minimum_remaining_seconds,
    )


def _validated_study_dispatch_capability(
    proof: ValidatedStudyDispatchPreflight,
) -> _ValidatedStudyDispatchCapability:
    capability = getattr(proof, "_capability", None)
    if (
        type(proof) is not ValidatedStudyDispatchPreflight
        or type(capability) is not _ValidatedStudyDispatchCapability
        or capability.seal is not _VALIDATED_STUDY_DISPATCH_SEAL
        or capability.manifest.manifest_digest != capability.study_manifest_digest
    ):
        raise ValueError("study dispatch preflight proof is invalid")
    return capability


def require_study_execution_window_open(
    manifest: RealModelStudyManifest,
    *,
    boundary: str,
    minimum_remaining_seconds: Decimal = Decimal("0"),
) -> None:
    """Require an open window with the requested conservative time reserve."""

    observed_at = _utc_now()
    if not isinstance(observed_at, datetime):
        raise TypeError("study dispatch clock must return a datetime")
    if observed_at.tzinfo is None or observed_at.utcoffset() is None:
        raise ValueError("study dispatch clock must return a timezone-aware datetime")
    observed_at = observed_at.astimezone(UTC)
    starts_at = parse_rfc3339_timestamp(
        manifest.execution_window.start,
        field_name="study execution window start",
    )
    ends_at = parse_rfc3339_timestamp(
        manifest.execution_window.end,
        field_name="study execution window end",
    )
    if (
        isinstance(minimum_remaining_seconds, bool)
        or not isinstance(minimum_remaining_seconds, Decimal)
        or not minimum_remaining_seconds.is_finite()
        or minimum_remaining_seconds < 0
    ):
        raise ValueError("minimum remaining study-window seconds must be finite and nonnegative")
    if observed_at < starts_at:
        raise ValueError(f"study execution window has not opened at {boundary}")
    if observed_at >= ends_at:
        raise ValueError(f"study execution window is closed at {boundary}")
    required_microseconds = int(
        (minimum_remaining_seconds * Decimal(1_000_000)).to_integral_value(rounding=ROUND_CEILING)
    )
    remaining = ends_at - observed_at
    remaining_microseconds = (
        remaining.days * 86_400 + remaining.seconds
    ) * 1_000_000 + remaining.microseconds
    # The window end is exclusive, so exact equality is not enough reserve.
    if remaining_microseconds <= required_microseconds:
        raise ValueError(
            f"study execution window lacks the required provider-attempt reserve at {boundary}"
        )


def _utc_now() -> datetime:
    return datetime.now(UTC)


__all__ = [
    "StudyDispatchPreflightEvidence",
    "ValidatedStudyDispatchPreflight",
    "require_real_provider_condition_dispatch",
    "require_study_execution_window_open",
    "require_validated_study_dispatch_authorization",
    "require_validated_study_dispatch_window_open",
    "validate_study_dispatch_preflight",
]
