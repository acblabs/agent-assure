from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_runset_controls
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.io_limits import load_json_bounded
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
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.usage import (
    UsageSummary,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)
from agent_assure.usage.aggregation import usage_summary_for_runset

_EVALUATION_REPORT_USAGE_FIELD_PATHS = (
    ("usage_summary",),
    ("candidate_vs_expectations", "usage_summary"),
)


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
    model_config = ConfigDict(
        json_schema_extra=usage_container_json_schema_extra(
            *_EVALUATION_REPORT_USAGE_FIELD_PATHS
        )
    )

    artifact_kind: Literal["evaluation-report"] = "evaluation-report"
    candidate_vs_expectations: EvaluationSummary
    runset_id: str
    suite_id: str
    suite_version: str
    gate_profile: str
    metrics: EvaluationMetrics
    environment: EnvironmentInfo | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)
    failed_controls: tuple[Finding, ...] = ()
    warning_controls: tuple[Finding, ...] = ()
    not_evaluated_capabilities: tuple[CapabilityReport, ...] = ()
    limitations: tuple[str, ...] = (
        "offline fixture evaluation does not certify safety, compliance, clinical validity, "
        "or live model quality",
    )

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvaluationReport:
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evaluation report",
            root=self,
            field_paths=_EVALUATION_REPORT_USAGE_FIELD_PATHS,
        )
        return self


def load_runset(path: Path) -> RunSet:
    payload = load_json_bounded(path)
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
    if runset.suite_version != suite.suite_version:
        raise ValueError(
            f"run set suite_version {runset.suite_version!r} does not match compiled suite "
            f"{suite.suite_version!r}"
        )
    expected_suite_digest = compiled_suite_digest(suite)
    if runset.suite_digest != expected_suite_digest:
        raise ValueError(
            f"run set suite_digest {runset.suite_digest!r} does not match compiled suite digest "
            f"{expected_suite_digest!r}"
        )
    _verify_run_fixture_binding(runset)
    resolver = ExpectationResolver(suite)
    artifact_digest = runset_digest(runset)
    raw_results = evaluate_runset_controls(
        resolver,
        runset,
        allowed_tools=suite.defaults.allowed_tools,
        required_policy_ids=suite.defaults.required_policy_ids,
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
    usage_summary = usage_summary_for_runset(runset)
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id=runset.runset_id,
        state=state,
        findings=findings,
        usage_summary=usage_summary,
    )
    failed_controls = tuple(
        finding
        for result, finding in zip(rollup_results, findings, strict=True)
        if gate_profile.is_blocking(result)
    )
    warning_controls = tuple(
        finding
        for result, finding in zip(rollup_results, findings, strict=True)
        if _is_warning_control(result, gate_profile)
    )
    return EvaluationReport(
        candidate_vs_expectations=summary,
        runset_id=runset.runset_id,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
        metrics=_metrics(suite, runset, rollup_results, gate_profile),
        usage_summary=usage_summary,
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


def _verify_run_fixture_binding(runset: RunSet) -> None:
    for run in runset.runs:
        run_digest = run.provenance.fixture_manifest_digest
        if run_digest != runset.fixture_manifest_digest:
            raise ValueError(
                f"run {run.run_id!r} fixture_manifest_digest {run_digest!r} does not match "
                f"run set fixture_manifest_digest {runset.fixture_manifest_digest!r}"
            )


def _metrics(
    suite: CompiledSuite,
    runset: RunSet,
    results: tuple[ControlResult, ...],
    gate_profile: GateProfile,
) -> EvaluationMetrics:
    case_ids = {case.case_id for case in suite.cases}
    run_counts = Counter(run.case_id for run in runset.runs)
    included_singleton_cases = {
        run.case_id
        for run in runset.runs
        if run.case_id in case_ids
        and run_counts[run.case_id] == 1
        and run.observation_status != "excluded"
    }
    failed_case_ids = {
        result.case_id
        for result in results
        if result.case_id in case_ids and result.state is GateState.fail
    }
    failed_evaluated_cases = failed_case_ids & included_singleton_cases
    global_blocking_findings = sum(
        1
        for result in results
        if result.case_id not in case_ids and gate_profile.is_blocking(result)
    )
    findings_by_reason = Counter(result.reason_code.value for result in results)
    findings_by_control = Counter(result.control_id for result in results)
    return EvaluationMetrics(
        total_cases=len(case_ids),
        evaluated_cases=len(included_singleton_cases),
        unevaluated_cases=len(case_ids - included_singleton_cases),
        passed_cases=len(included_singleton_cases - failed_evaluated_cases),
        failed_cases=len(failed_evaluated_cases),
        warning_findings=sum(
            1 for result in results if _is_warning_control(result, gate_profile)
        ),
        blocking_findings=sum(1 for result in results if gate_profile.is_blocking(result)),
        global_blocking_findings=global_blocking_findings,
        findings_by_reason=dict(sorted(findings_by_reason.items())),
        findings_by_control=dict(sorted(findings_by_control.items())),
    )


def _is_warning_control(result: ControlResult, gate_profile: GateProfile) -> bool:
    if result.state is GateState.warn:
        return True
    return result.state is GateState.fail and not gate_profile.is_blocking(result)


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
