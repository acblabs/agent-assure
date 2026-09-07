"""Bounded verification of operator-reviewed preregistration evidence."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256

from agent_assure.io_limits import MAX_ARTIFACT_JSON_BYTES, load_json_bytes_bounded
from agent_assure.privacy.persistence import assert_persisted_payload_safe
from agent_assure.schema.study import (
    RealModelStudyManifest,
    StudyRegistrationReviewReceipt,
)
from agent_assure.timestamps import parse_rfc3339_timestamp


@dataclass(frozen=True, slots=True)
class ValidatedStudyRegistration:
    """Exact local bytes and an internally consistent human review receipt."""

    record_text: str
    record_sha256: str
    review_receipt: StudyRegistrationReviewReceipt


def validate_study_registration(
    *,
    manifest: RealModelStudyManifest,
    registration_record_bytes: bytes,
    review_receipt: StudyRegistrationReviewReceipt,
) -> ValidatedStudyRegistration:
    """Validate exact record bytes and their operator-attested receipt.

    This proves local byte identity, receipt consistency, and claimed temporal
    ordering. It deliberately does not authenticate a remote VCS/registry
    reference or the human reviewer's identity.
    """

    if not registration_record_bytes:
        raise ValueError("study registration record must not be empty")
    if len(registration_record_bytes) > MAX_ARTIFACT_JSON_BYTES:
        raise ValueError("study registration record exceeds the maximum supported size")
    try:
        record_text = registration_record_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("study registration record must be valid UTF-8 JSON") from exc
    payload = load_json_bytes_bounded(
        registration_record_bytes,
        max_bytes=MAX_ARTIFACT_JSON_BYTES,
        label="study registration record",
    )
    if not isinstance(payload, Mapping):
        raise ValueError("study registration record must be a JSON object")
    assert_persisted_payload_safe(payload, owner="study registration record")

    record_sha256 = sha256(registration_record_bytes).hexdigest()
    if record_sha256 != manifest.registration.evidence_digest:
        raise ValueError(
            "study registration record bytes do not match the manifest evidence digest"
        )

    receipt = StudyRegistrationReviewReceipt.model_validate(
        review_receipt.model_dump(mode="json", warnings="error")
    )
    assert_persisted_payload_safe(
        receipt.model_dump(mode="json", warnings="error"),
        owner="study registration review receipt",
    )
    registration = manifest.registration
    if (
        receipt.study_id,
        receipt.study_manifest_digest,
        receipt.registration_method,
        receipt.registration_reference_id,
        receipt.registration_evidence_sha256,
        receipt.registered_at_utc,
    ) != (
        manifest.study_id,
        manifest.manifest_digest,
        registration.method,
        registration.reference_id,
        registration.evidence_digest,
        registration.registered_at_utc,
    ):
        raise ValueError(
            "study registration review receipt does not exactly bind the manifest and record"
        )
    reviewed_at = parse_rfc3339_timestamp(
        receipt.reviewed_at_utc,
        field_name="study registration reviewed_at_utc",
    )
    execution_start = parse_rfc3339_timestamp(
        manifest.execution_window.start,
        field_name="study execution window start",
    )
    if reviewed_at >= execution_start:
        raise ValueError("study registration review must occur before the planned execution window")
    return ValidatedStudyRegistration(
        record_text=record_text,
        record_sha256=record_sha256,
        review_receipt=receipt,
    )


__all__ = [
    "ValidatedStudyRegistration",
    "validate_study_registration",
]
