from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import date
from uuid import uuid5

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import GateState, ReasonCode, Severity, coerce_enum, coerce_tuple


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
        stable_key = (
            f"{self.case_id}:{self.control_id}:{self.reason_code.value}:{self.target}"
        )
        return f"finding-{uuid5(AGENT_ASSURE_NAMESPACE, stable_key)}"


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
            return self.fail_on_warn
        if result.state is not GateState.fail:
            return False
        return (
            result.severity in self.fail_severities
            or result.reason_code in self.fail_reason_codes
        )


class Waiver(StrictModel):
    waiver_id: str = Field(min_length=1)
    owner: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    reason_code: ReasonCode
    finding_id: str = Field(min_length=1)
    artifact_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    expires_on: date
    reviewer: str = Field(min_length=1)

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
            not self.is_expired(today)
            and self.reason_code is result.reason_code
            and self.finding_id == result.finding_id
            and self.artifact_digest == artifact_digest
        )


DEFAULT_GATE_PROFILE = GateProfile()


def apply_waivers(
    results: tuple[ControlResult, ...],
    *,
    waivers: tuple[Waiver, ...],
    artifact_digest: str,
    today: date,
) -> tuple[ControlResult, ...]:
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
    return tuple(adjusted)


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
