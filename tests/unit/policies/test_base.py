from __future__ import annotations

import pytest

from agent_assure.policies.base import ControlResult, GateProfile, rollup_state
from agent_assure.schema.common import GateState, ReasonCode, Severity


def test_gate_profile_blocks_failures_by_default() -> None:
    result = ControlResult(
        control_id="policy.example",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        severity=Severity.info,
        message="example failure",
    )

    assert GateProfile().is_blocking(result) is True
    assert rollup_state((result,), GateProfile()) is GateState.fail


def test_gate_profile_requires_at_least_one_fail_filter() -> None:
    with pytest.raises(ValueError, match="at least one fail severity or fail reason code"):
        GateProfile(fail_severities=(), fail_reason_codes=())


def test_gate_profile_allows_reason_only_filter() -> None:
    result = ControlResult(
        control_id="policy.example",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        severity=Severity.info,
        message="example failure",
    )

    profile = GateProfile(
        fail_severities=(),
        fail_reason_codes=(ReasonCode.POLICY_FAILED,),
    )

    assert profile.is_blocking(result) is True


def test_nonblocking_failures_roll_up_to_warn() -> None:
    result = ControlResult(
        control_id="policy.example",
        case_id="case-1",
        state=GateState.fail,
        reason_code=ReasonCode.POLICY_FAILED,
        severity=Severity.error,
        message="example failure",
    )
    profile = GateProfile(
        fail_severities=(Severity.blocker,),
        fail_reason_codes=(),
    )

    assert profile.is_blocking(result) is False
    assert rollup_state((result,), profile) is GateState.warn


def test_finding_identity_is_unambiguous_when_components_contain_delimiters() -> None:
    common = {
        "state": GateState.fail,
        "reason_code": ReasonCode.POLICY_FAILED,
        "severity": Severity.error,
        "message": "example failure",
        "target": "target",
    }
    first = ControlResult(
        control_id="control",
        case_id="case:segment",
        **common,
    )
    second = ControlResult(
        control_id="segment:control",
        case_id="case",
        **common,
    )
    repeated = ControlResult(
        control_id="control",
        case_id="case:segment",
        **common,
    )

    assert first.finding_id != second.finding_id
    assert first.finding_id == repeated.finding_id
    assert len(first.finding_id) == len("finding-") + 64
