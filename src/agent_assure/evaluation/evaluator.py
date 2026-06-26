from __future__ import annotations

import json
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_runset_controls
from agent_assure.policies.base import (
    DEFAULT_GATE_PROFILE,
    ControlResult,
    GateProfile,
    Waiver,
    apply_waivers,
    rollup_state,
)
from agent_assure.policies.catalog import DEFAULT_NOT_EVALUATED_CAPABILITIES, CapabilityStatus
from agent_assure.schema.base import PersistedArtifact, StrictModel
from agent_assure.schema.common import GateState, ReasonCode, Severity, coerce_enum
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite


class EvaluationMetrics(StrictModel):
    total_cases: int = Field(ge=0)
    evaluated_cases: int = Field(ge=0)
    unevaluated_cases: int = Field(ge=0)
    passed_cases: int = Field(ge=0)
    failed_cases: int = Field(ge=0)
    warning_findings: int = Field(ge=0)
    blocking_findings: int = Field(ge=0)
    global_blocking_findings: int = Field(ge=0)
    findings_by_reason: dict[str, int]
    findings_by_control: dict[str, int]


class CapabilityReport(StrictModel):
    capability_id: str
    state: GateState
    reason: str

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class EvaluationReport(PersistedArtifact):
    artifact_kind: Literal["evaluation-report"] = "evaluation-report"
    candidate_vs_expectations: EvaluationSummary
    runset_id: str
    suite_id: str
    suite_version: str
    gate_profile: str
    metrics: EvaluationMetrics
    failed_controls: tuple[Finding, ...] = ()
    warning_controls: tuple[Finding, ...] = ()
    not_evaluated_capabilities: tuple[CapabilityReport, ...] = ()
    limitations: tuple[str, ...] = (
        "offline fixture evaluation does not certify safety, compliance, clinical validity, "
        "or live model quality",
    )


def load_runset(path: Path) -> RunSet:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return RunSet.model_validate(payload)


def runset_digest(runset: RunSet) -> str:
    return sha256_hexdigest(runset.model_dump(mode="json"))


def evaluate_runset(
    suite: CompiledSuite,
    runset: RunSet,
    *,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    today: date | None = None,
) -> EvaluationReport:
    if runset.suite_id != suite.suite_id:
        raise ValueError(
            f"run set suite_id {runset.suite_id!r} does not match compiled suite {suite.suite_id!r}"
        )
    resolver = ExpectationResolver(suite)
    artifact_digest = runset_digest(runset)
    raw_results = evaluate_runset_controls(
        resolver,
        runset,
        allowed_tools=suite.defaults.allowed_tools,
    )
    adjusted_results = apply_waivers(
        raw_results,
        waivers=waivers,
        artifact_digest=artifact_digest,
        today=today or date.today(),
    )
    capabilities = _capabilities(
        DEFAULT_NOT_EVALUATED_CAPABILITIES,
        suite_has_tool_allowlist=bool(suite.defaults.allowed_tools),
    )
    capability_results = _capability_results(capabilities)
    rollup_results = adjusted_results
    if gate_profile.fail_on_not_evaluated:
        rollup_results = adjusted_results + capability_results
    findings = tuple(_finding_from_result(result) for result in rollup_results)
    state = rollup_state(rollup_results, gate_profile)
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id=runset.runset_id,
        state=state,
        findings=findings,
    )
    failed_controls = tuple(
        finding
        for result, finding in zip(rollup_results, findings, strict=True)
        if gate_profile.is_blocking(result)
    )
    warning_controls = tuple(
        finding
        for result, finding in zip(rollup_results, findings, strict=True)
        if result.state is GateState.warn
    )
    return EvaluationReport(
        candidate_vs_expectations=summary,
        runset_id=runset.runset_id,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
        metrics=_metrics(suite, runset, rollup_results, gate_profile),
        failed_controls=failed_controls,
        warning_controls=warning_controls,
        not_evaluated_capabilities=capabilities,
    )


def _finding_from_result(result: ControlResult) -> Finding:
    return Finding(
        artifact_kind="finding",
        finding_id=result.finding_id,
        case_id=result.case_id,
        control_id=result.control_id,
        target=result.target,
        state=result.state,
        reason_code=result.reason_code,
        message=result.message,
    )


def _metrics(
    suite: CompiledSuite,
    runset: RunSet,
    results: tuple[ControlResult, ...],
    gate_profile: GateProfile,
) -> EvaluationMetrics:
    case_ids = {case.case_id for case in suite.cases}
    run_counts = Counter(run.case_id for run in runset.runs)
    evaluated_cases = {case_id for case_id in case_ids if run_counts[case_id] == 1}
    failed_cases = {
        result.case_id
        for result in results
        if result.case_id in evaluated_cases and gate_profile.is_blocking(result)
    }
    global_blocking_findings = sum(
        1
        for result in results
        if result.case_id not in case_ids and gate_profile.is_blocking(result)
    )
    findings_by_reason = Counter(result.reason_code.value for result in results)
    findings_by_control = Counter(result.control_id for result in results)
    return EvaluationMetrics(
        total_cases=len(case_ids),
        evaluated_cases=len(evaluated_cases),
        unevaluated_cases=len(case_ids - evaluated_cases),
        passed_cases=len(evaluated_cases - failed_cases),
        failed_cases=len(failed_cases),
        warning_findings=sum(1 for result in results if result.state is GateState.warn),
        blocking_findings=sum(1 for result in results if gate_profile.is_blocking(result)),
        global_blocking_findings=global_blocking_findings,
        findings_by_reason=dict(sorted(findings_by_reason.items())),
        findings_by_control=dict(sorted(findings_by_control.items())),
    )


def _capabilities(
    capabilities: tuple[CapabilityStatus, ...],
    *,
    suite_has_tool_allowlist: bool,
) -> tuple[CapabilityReport, ...]:
    reports = [
        CapabilityReport(
            capability_id=capability.capability_id,
            state=capability.state,
            reason=capability.reason,
        )
        for capability in capabilities
    ]
    if not suite_has_tool_allowlist:
        reports.append(
            CapabilityReport(
                capability_id="tool_allowlist",
                state=GateState.not_evaluated,
                reason="suite defaults do not configure allowed_tools",
            )
        )
    return tuple(reports)


def _capability_results(
    capabilities: tuple[CapabilityReport, ...],
) -> tuple[ControlResult, ...]:
    return tuple(
        ControlResult(
            control_id=capability.capability_id,
            case_id="*",
            state=capability.state,
            reason_code=ReasonCode.NOT_EVALUATED,
            severity=Severity.info,
            target=capability.capability_id,
            message=capability.reason,
        )
        for capability in capabilities
        if capability.state is GateState.not_evaluated
    )


def reason_code_counts(summary: EvaluationSummary) -> dict[ReasonCode, int]:
    return dict(Counter(finding.reason_code for finding in summary.findings))
