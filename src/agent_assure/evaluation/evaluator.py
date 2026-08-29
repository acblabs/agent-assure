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
from agent_assure.policies.base import (
    DEFAULT_GATE_PROFILE,
    ControlResult,
    GateProfile,
    Waiver,
    apply_waivers_with_dispositions,
    rollup_state,
)
from agent_assure.policies.catalog import DEFAULT_NOT_EVALUATED_CAPABILITIES, CapabilityStatus
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.base import SCHEMA_VERSION, PersistedArtifact, SchemaVersion, StrictModel
from agent_assure.schema.common import (
    V063_CONTRACT_SCHEMA_VERSIONS,
    DigestHex,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import (
    MAX_WAIVER_DISPOSITIONS,
    EvaluationGateProfileContext,
    EvaluationReplayContext,
    EvaluationSummary,
    EvaluationWaiverContext,
    Finding,
    WaiverDisposition,
)
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
_EVALUATION_REPORT_JSON_SCHEMA_EXTRA = usage_container_json_schema_extra(
    *_EVALUATION_REPORT_USAGE_FIELD_PATHS
)
_RUNSET_DIGEST_SCHEMA_VERSIONS = frozenset({"0.6.0", "0.6.1", "0.6.2", "0.6.3", "0.6.4", "0.6.5"})
_EVALUATION_REPORT_JSON_SCHEMA_EXTRA["allOf"].append(
    {
        "if": {
            "required": ["schema_version"],
            "properties": {
                "schema_version": {
                    "enum": sorted(_RUNSET_DIGEST_SCHEMA_VERSIONS),
                }
            },
        },
        "then": {
            "required": ["runset_digest", "waiver_dispositions"],
            "properties": {"runset_digest": {"type": "string"}},
        },
    }
)
RunSetCompatibilityCode = Literal[
    "privacy_profile_incompatible",
    "suite_binding_mismatch",
    "fixture_binding_mismatch",
]


class RunSetCompatibilityError(ValueError):
    """A safe-to-classify incompatibility between a RunSet and evaluation context."""

    diagnostic_code: RunSetCompatibilityCode

    def __init__(self, diagnostic_code: RunSetCompatibilityCode, message: str) -> None:
        super().__init__(message)
        self.diagnostic_code = diagnostic_code


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
    model_config = ConfigDict(json_schema_extra=_EVALUATION_REPORT_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["evaluation-report"] = "evaluation-report"
    candidate_vs_expectations: EvaluationSummary
    runset_id: str
    runset_digest: DigestHex | None = Field(default=None, exclude_if=lambda value: value is None)
    suite_id: str
    suite_version: str
    gate_profile: str
    metrics: EvaluationMetrics
    environment: EnvironmentInfo | None = None
    usage_summary: UsageSummary | None = Field(default=None, exclude_if=lambda value: value is None)
    failed_controls: tuple[Finding, ...] = ()
    warning_controls: tuple[Finding, ...] = ()
    waiver_dispositions: tuple[WaiverDisposition, ...] = Field(
        default=(),
        max_length=MAX_WAIVER_DISPOSITIONS,
    )
    not_evaluated_capabilities: tuple[CapabilityReport, ...] = ()
    limitations: tuple[str, ...] = (
        "offline fixture evaluation does not certify safety, compliance, clinical validity, "
        "or live model quality",
    )

    @field_validator(
        "failed_controls",
        "warning_controls",
        "waiver_dispositions",
        "not_evaluated_capabilities",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> EvaluationReport:
        if self.schema_version in _RUNSET_DIGEST_SCHEMA_VERSIONS and self.runset_digest is None:
            raise ValueError("v0.6 evaluation report requires runset_digest")
        summary_digest = self.candidate_vs_expectations.runset_digest
        if summary_digest is not None and summary_digest != self.runset_digest:
            raise ValueError(
                "evaluation summary runset_digest must match evaluation report runset_digest"
            )
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="evaluation report",
            root=self,
            field_paths=_EVALUATION_REPORT_USAGE_FIELD_PATHS,
        )
        return self


def load_runset(path: Path) -> RunSet:
    # Imported lazily because schema export registration imports EvaluationReport
    # from this module while validation itself is initializing.
    from agent_assure.schema.validation import (
        load_validated_artifact_payload,
        project_validated_artifact_payload,
    )

    payload = load_validated_artifact_payload(path, "run-set", label="RunSet JSON")
    return project_validated_artifact_payload(payload, RunSet, kind="run-set")


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
    if suite.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not suite.cases:
        raise ValueError("current compiled suites require at least one case for evaluation")
    if runset.schema_version in V063_CONTRACT_SCHEMA_VERSIONS and not runset.runs:
        raise ValueError("current run sets require at least one run record for evaluation")
    validate_runset_compatibility(suite, runset)
    resolver = ExpectationResolver(suite)
    artifact_digest = runset_digest(runset)
    evaluation_date = today or date.today()
    raw_results = evaluate_runset_controls(
        resolver,
        runset,
        allowed_tools=suite.defaults.allowed_tools,
        required_policy_ids=suite.defaults.required_policy_ids,
    )
    waiver_application = apply_waivers_with_dispositions(
        raw_results,
        waivers=waivers,
        artifact_digest=artifact_digest,
        today=evaluation_date,
    )
    adjusted_results = waiver_application.results
    capabilities = _capabilities(
        DEFAULT_NOT_EVALUATED_CAPABILITIES,
        suite_has_tool_policy=_suite_has_tool_policy(suite),
    )
    capability_results = _capability_results(capabilities)
    rollup_results = adjusted_results
    if gate_profile.fail_on_not_evaluated:
        rollup_results = adjusted_results + capability_results
    report_findings = tuple(
        _finding_from_result(result, schema_version=SCHEMA_VERSION) for result in rollup_results
    )
    summary_findings = tuple(
        _finding_from_result(
            result,
            schema_version=SCHEMA_VERSION,
            state=(
                GateState.fail
                if gate_profile.is_blocking(result)
                else GateState.warn
                if result.state is GateState.fail
                else result.state
            ),
        )
        for result in rollup_results
    )
    state = rollup_state(rollup_results, gate_profile)
    usage_summary = usage_summary_for_runset(runset)
    summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        schema_version=SCHEMA_VERSION,
        runset_id=runset.runset_id,
        runset_digest=artifact_digest,
        privacy_profile_id=runset.privacy_profile_id or PRIVACY_PROFILE_ID,
        privacy_profile_digest=runset.privacy_profile_digest or PRIVACY_PROFILE_DIGEST,
        state=state,
        findings=summary_findings,
        usage_summary=usage_summary,
        replay_context=EvaluationReplayContext(
            suite_digest=compiled_suite_digest(suite),
            gate_profile=EvaluationGateProfileContext(
                profile_id=gate_profile.profile_id,
                fail_severities=gate_profile.fail_severities,
                fail_reason_codes=gate_profile.fail_reason_codes,
                fail_on_warn=gate_profile.fail_on_warn,
                fail_on_not_evaluated=gate_profile.fail_on_not_evaluated,
            ),
            waivers=tuple(
                EvaluationWaiverContext(
                    waiver_id=waiver.waiver_id,
                    reason_code=waiver.reason_code,
                    finding_id=waiver.finding_id,
                    artifact_digest=waiver.artifact_digest,
                    expires_on=waiver.expires_on,
                )
                for waiver in waivers
            ),
            evaluation_date=evaluation_date,
        ),
    )
    failed_controls = tuple(
        finding
        for result, finding in zip(rollup_results, report_findings, strict=True)
        if gate_profile.is_blocking(result)
    )
    warning_controls = tuple(
        finding
        for result, finding in zip(rollup_results, report_findings, strict=True)
        if _is_warning_control(result, gate_profile)
    )
    return EvaluationReport(
        schema_version=SCHEMA_VERSION,
        candidate_vs_expectations=summary,
        runset_id=runset.runset_id,
        runset_digest=artifact_digest,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
        metrics=_metrics(suite, runset, rollup_results, gate_profile),
        usage_summary=usage_summary,
        failed_controls=failed_controls,
        warning_controls=warning_controls,
        waiver_dispositions=waiver_application.dispositions,
        not_evaluated_capabilities=capabilities,
    )


def validate_runset_compatibility(suite: CompiledSuite, runset: RunSet) -> None:
    """Validate the bindings every evaluator must honor before scoring a RunSet.

    Mutation evaluators may replace the scoring implementation, but they may not
    bypass the suite, fixture-manifest, or privacy-profile trust bindings.
    """
    if runset.privacy_profile_id is not None and (
        runset.privacy_profile_id,
        runset.privacy_profile_digest,
    ) != (PRIVACY_PROFILE_ID, PRIVACY_PROFILE_DIGEST):
        raise RunSetCompatibilityError(
            "privacy_profile_incompatible",
            "run set privacy detector profile is incompatible with the runtime profile",
        )
    if runset.suite_id != suite.suite_id:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            (
                f"run set suite_id {runset.suite_id!r} does not match "
                f"compiled suite {suite.suite_id!r}"
            ),
        )
    if runset.suite_version != suite.suite_version:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            f"run set suite_version {runset.suite_version!r} does not match compiled suite "
            f"{suite.suite_version!r}",
        )
    expected_suite_digest = compiled_suite_digest(suite)
    if runset.suite_digest != expected_suite_digest:
        raise RunSetCompatibilityError(
            "suite_binding_mismatch",
            f"run set suite_digest {runset.suite_digest!r} does not match compiled suite digest "
            f"{expected_suite_digest!r}",
        )
    _verify_run_fixture_binding(runset)


def _finding_from_result(
    result: ControlResult,
    *,
    schema_version: SchemaVersion,
    state: GateState | None = None,
) -> Finding:
    return Finding(
        artifact_kind="finding",
        schema_version=schema_version,
        finding_id=result.finding_id,
        case_id=result.case_id,
        control_id=result.control_id,
        target=result.target,
        state=result.state if state is None else state,
        reason_code=result.reason_code,
        message=result.message,
    )


def _verify_run_fixture_binding(runset: RunSet) -> None:
    for run in runset.runs:
        run_digest = run.provenance.fixture_manifest_digest
        if run_digest != runset.fixture_manifest_digest:
            raise RunSetCompatibilityError(
                "fixture_binding_mismatch",
                f"run {run.run_id!r} fixture_manifest_digest {run_digest!r} does not match "
                f"run set fixture_manifest_digest {runset.fixture_manifest_digest!r}",
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
        warning_findings=sum(1 for result in results if _is_warning_control(result, gate_profile)),
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
    suite_has_tool_policy: bool,
) -> tuple[CapabilityReport, ...]:
    reports = [
        CapabilityReport(
            capability_id=capability.capability_id,
            state=capability.state,
            reason=capability.reason,
        )
        for capability in capabilities
    ]
    if not suite_has_tool_policy:
        reports.append(
            CapabilityReport(
                capability_id="tool_allowlist",
                state=GateState.not_evaluated,
                reason="suite and case expectations do not configure a tool policy",
            )
        )
    return tuple(reports)


def _suite_has_tool_policy(suite: CompiledSuite) -> bool:
    if suite.defaults.allowed_tools:
        return True
    return any(
        expectation.allowed_tools_override
        or bool(expectation.allowed_tools)
        or bool(expectation.forbidden_tools)
        for expectation in suite.resolved_expectations
    )


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
