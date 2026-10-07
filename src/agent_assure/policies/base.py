from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import date

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import (
    MAX_LABEL_CHARS,
    MAX_SUMMARY_CHARS,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.evaluation import (
    MAX_WAIVER_DISPOSITIONS,
    MAX_WAIVER_VALIDITY_DAYS,
    WaiverDisposition,
    WaiverDispositionStatus,
    validate_independent_waiver_approvers,
    validate_unique_waiver_bindings,
    validate_waiver_id,
    waiver_expiry_horizon,
)


def control_finding_id(
    case_id: str,
    control_id: str,
    reason_code: ReasonCode,
    target: str,
) -> str:
    stable_key = json.dumps(
        [case_id, control_id, reason_code.value, target],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    digest = hashlib.sha256(b"agent-assure/control-finding/v2\x00" + stable_key).hexdigest()
    return f"finding-{digest}"


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    case_id: str
    state: GateState
    reason_code: ReasonCode
    severity: Severity
    message: str
    target: str = ""
    gate_profile: str = "default"
    waived: bool = False

    @property
    def is_blocking_state(self) -> bool:
        return self.state is GateState.fail

    @property
    def finding_id(self) -> str:
        return control_finding_id(
            self.case_id,
            self.control_id,
            self.reason_code,
            self.target,
        )


class GateProfile(StrictModel):
    profile_id: str = Field(default="default", min_length=1)
    fail_severities: tuple[Severity, ...] = (
        Severity.info,
        Severity.warning,
        Severity.error,
        Severity.blocker,
    )
    fail_reason_codes: tuple[ReasonCode, ...] = ()
    fail_on_warn: bool = False
    fail_on_not_evaluated: bool = False

    @field_validator("fail_severities", mode="before")
    @classmethod
    def _coerce_severities(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(Severity, item) for item in value)
        return coerce_tuple(value)

    @field_validator("fail_reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_fail_filters(self) -> GateProfile:
        if not self.fail_severities and not self.fail_reason_codes:
            raise ValueError(
                "gate profiles must include at least one fail severity or fail reason code"
            )
        return self

    def is_blocking(self, result: ControlResult) -> bool:
        if result.state is GateState.not_evaluated:
            return self.fail_on_not_evaluated
        if result.state is GateState.warn:
            return self.fail_on_warn and not result.waived
        if result.state is not GateState.fail:
            return False
        return (
            result.severity in self.fail_severities or result.reason_code in self.fail_reason_codes
        )


class Waiver(StrictModel):
    waiver_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    owner: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    rationale: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    reason_code: ReasonCode
    finding_id: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)
    artifact_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_on: date
    reviewer: str = Field(min_length=1, max_length=MAX_LABEL_CHARS)

    @field_validator("waiver_id")
    @classmethod
    def _validate_waiver_id(cls, value: str) -> str:
        return validate_waiver_id(value)

    @field_validator("owner", "reviewer", "rationale")
    @classmethod
    def _validate_persisted_governance_text(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("waiver governance text must not have surrounding whitespace")
        if contains_sensitive_value(value):
            raise ValueError("waiver governance text contains sensitive-looking content")
        return value

    @field_validator("reason_code", mode="before")
    @classmethod
    def _coerce_reason_code(cls, value: object) -> ReasonCode:
        return coerce_enum(ReasonCode, value)

    @field_validator("expires_on", mode="before")
    @classmethod
    def _coerce_expires_on(cls, value: object) -> date:
        if isinstance(value, date):
            return value
        if isinstance(value, str):
            return date.fromisoformat(value)
        raise ValueError("expires_on must be an ISO date")

    def is_expired(self, today: date) -> bool:
        return self.expires_on < today

    def applies_to(self, result: ControlResult, artifact_digest: str, today: date) -> bool:
        return (
            result.state is GateState.fail
            and not self.is_expired(today)
            and self.reason_code is result.reason_code
            and self.finding_id == result.finding_id
            and self.artifact_digest == artifact_digest
        )


DEFAULT_GATE_PROFILE = GateProfile()


@dataclass(frozen=True)
class WaiverApplication:
    results: tuple[ControlResult, ...]
    dispositions: tuple[WaiverDisposition, ...]


def apply_waivers(
    results: tuple[ControlResult, ...],
    *,
    waivers: tuple[Waiver, ...],
    artifact_digest: str,
    today: date,
) -> tuple[ControlResult, ...]:
    return apply_waivers_with_dispositions(
        results,
        waivers=waivers,
        artifact_digest=artifact_digest,
        today=today,
    ).results


def apply_waivers_with_dispositions(
    results: tuple[ControlResult, ...],
    *,
    waivers: tuple[Waiver, ...],
    artifact_digest: str,
    today: date,
) -> WaiverApplication:
    if len(waivers) > MAX_WAIVER_DISPOSITIONS:
        raise ValueError(f"waiver count exceeds disposition limit {MAX_WAIVER_DISPOSITIONS}")
    validate_unique_waiver_bindings(waivers)
    for supplied_waiver in waivers:
        _validate_waiver_governance(supplied_waiver, today=today)
    adjusted: list[ControlResult] = []
    adjusted.extend(
        ControlResult(
            control_id="waiver.expiration",
            case_id="*",
            state=GateState.fail,
            reason_code=ReasonCode.POLICY_FAILED,
            severity=Severity.blocker,
            target=waiver.waiver_id,
            message=(
                f"waiver {waiver.waiver_id!r} for {waiver.reason_code.value} expired "
                f"on {waiver.expires_on.isoformat()}"
            ),
        )
        for waiver in waivers
        if waiver.artifact_digest == artifact_digest and waiver.is_expired(today)
    )
    for result in results:
        waiver = next(
            (
                candidate
                for candidate in waivers
                if candidate.applies_to(result, artifact_digest, today)
            ),
            None,
        )
        if waiver is None:
            adjusted.append(result)
            continue
        adjusted.append(
            replace(
                result,
                state=GateState.warn,
                severity=Severity.warning,
                waived=True,
                message=(
                    f"waived by {waiver.waiver_id} until {waiver.expires_on.isoformat()}: "
                    f"{result.message}"
                ),
            )
        )
    dispositions = tuple(
        sorted(
            (
                _waiver_disposition(
                    waiver,
                    results=results,
                    artifact_digest=artifact_digest,
                    today=today,
                )
                for waiver in waivers
            ),
            key=_waiver_disposition_sort_key,
        )
    )
    return WaiverApplication(results=tuple(adjusted), dispositions=dispositions)


def _validate_waiver_governance(waiver: Waiver, *, today: date) -> None:
    validate_independent_waiver_approvers(waiver.owner, waiver.reviewer)
    if waiver.expires_on > waiver_expiry_horizon(today):
        raise ValueError(
            f"waiver expires_on must be no more than {MAX_WAIVER_VALIDITY_DAYS} days "
            "after the evaluation date"
        )


def _waiver_disposition(
    waiver: Waiver,
    *,
    results: tuple[ControlResult, ...],
    artifact_digest: str,
    today: date,
) -> WaiverDisposition:
    if waiver.artifact_digest != artifact_digest:
        status = WaiverDispositionStatus.unmatched_artifact
    elif waiver.is_expired(today):
        status = WaiverDispositionStatus.expired
    else:
        finding_matches = tuple(
            result for result in results if result.finding_id == waiver.finding_id
        )
        if not finding_matches:
            status = WaiverDispositionStatus.unmatched_finding
        elif not any(result.reason_code is waiver.reason_code for result in finding_matches):
            status = WaiverDispositionStatus.unmatched_reason
        elif not any(
            result.reason_code is waiver.reason_code and result.state is GateState.fail
            for result in finding_matches
        ):
            status = WaiverDispositionStatus.unmatched_finding
        else:
            status = WaiverDispositionStatus.matched
    return WaiverDisposition(
        waiver_id=waiver.waiver_id,
        owner=waiver.owner,
        reviewer=waiver.reviewer,
        rationale=waiver.rationale,
        status=status,
        reason_code=waiver.reason_code,
        finding_id=waiver.finding_id,
        expires_on=waiver.expires_on,
    )


def _waiver_disposition_sort_key(
    disposition: WaiverDisposition,
) -> tuple[str, str, str, str, str]:
    return (
        disposition.waiver_id,
        disposition.finding_id,
        disposition.reason_code.value,
        disposition.expires_on.isoformat(),
        disposition.status.value,
    )


def rollup_state(results: tuple[ControlResult, ...], profile: GateProfile) -> GateState:
    if any(profile.is_blocking(result) for result in results):
        return GateState.fail
    if any(result.state is GateState.fail for result in results):
        return GateState.warn
    if any(result.state is GateState.warn for result in results):
        return GateState.warn
    if any(result.state is GateState.not_evaluated for result in results):
        return GateState.not_evaluated
    return GateState.pass_
