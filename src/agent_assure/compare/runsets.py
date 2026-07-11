from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.compare.case_map import case_counts, unique_case_map
from agent_assure.compare.classifications import choose_comparison_classification
from agent_assure.compare.invariant_diff import (
    BehaviorChange,
    ControlChange,
    diff_behavior,
    diff_control_findings,
    summarize_control_change,
)
from agent_assure.compare.provenance_diff import (
    ProvenanceChange,
    diff_provenance,
    summarize_provenance_change,
)
from agent_assure.evaluation.evaluator import (
    CapabilityReport,
    EvaluationMetrics,
    EvaluationReport,
    evaluate_runset,
)
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.policies.base import DEFAULT_GATE_PROFILE, ControlResult, GateProfile, Waiver
from agent_assure.schema.base import PersistedArtifact, StrictModel
from agent_assure.schema.common import (
    ComparisonClassification,
    GateState,
    ReasonCode,
    Severity,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.comparison import ComparisonSummary
from agent_assure.schema.environment import EnvironmentInfo
from agent_assure.schema.evaluation import EvaluationSummary, Finding
from agent_assure.schema.run import RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.usage import (
    UsageSummary,
    UsageSummaryDelta,
    usage_container_json_schema_extra,
    validate_usage_field_paths_schema_version,
)
from agent_assure.usage.aggregation import compare_usage_summaries, usage_summary_for_runset

_COMPARISON_REPORT_USAGE_FIELD_PATHS = (
    ("baseline_usage_summary",),
    ("candidate_usage_summary",),
    ("usage_delta",),
    ("candidate_vs_expectations", "usage_summary"),
    ("baseline_vs_expectations", "usage_summary"),
    ("comparison_summary", "baseline_usage_summary"),
    ("comparison_summary", "candidate_usage_summary"),
    ("comparison_summary", "usage_delta"),
)


class InvalidComparisonError(ValueError):
    def __init__(self, message: str, report: ComparisonReport | None = None) -> None:
        super().__init__(message)
        self.report = report


class FixtureEquivalenceReport(StrictModel):
    state: GateState
    findings: tuple[Finding, ...] = ()
    compared_digests: tuple[str, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("findings", "compared_digests", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)


class ComparisonReport(PersistedArtifact):
    model_config = ConfigDict(
        json_schema_extra=usage_container_json_schema_extra(
            *_COMPARISON_REPORT_USAGE_FIELD_PATHS
        )
    )

    artifact_kind: Literal["comparison-report"] = "comparison-report"
    candidate_vs_expectations: EvaluationSummary
    verdict_explanations: tuple[str, ...]
    fixture_equivalence: FixtureEquivalenceReport
    baseline_vs_expectations: EvaluationSummary
    control_changes: tuple[ControlChange, ...]
    behavioral_changes: tuple[BehaviorChange, ...]
    provenance_changes: tuple[ProvenanceChange, ...]
    not_evaluated_capabilities: tuple[CapabilityReport, ...]
    limitations: tuple[str, ...]
    comparison_summary: ComparisonSummary
    baseline_metrics: EvaluationMetrics
    candidate_metrics: EvaluationMetrics
    baseline_usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    candidate_usage_summary: UsageSummary | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    usage_delta: UsageSummaryDelta | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    environment: EnvironmentInfo | None = None
    suite_id: str
    suite_version: str
    gate_profile: str

    @field_validator(
        "verdict_explanations",
        "control_changes",
        "behavioral_changes",
        "provenance_changes",
        "not_evaluated_capabilities",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_usage_schema_version(self) -> ComparisonReport:
        validate_usage_field_paths_schema_version(
            self.schema_version,
            owner="comparison report",
            root=self,
            field_paths=_COMPARISON_REPORT_USAGE_FIELD_PATHS,
        )
        return self


def compare_runsets(
    suite: CompiledSuite,
    baseline: RunSet,
    candidate: RunSet,
    *,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
    waivers: tuple[Waiver, ...] = (),
    today: date | None = None,
) -> ComparisonReport:
    _verify_suite_identity(suite, baseline, candidate)
    fixture_equivalence = verify_fixture_equivalence(baseline, candidate)
    if fixture_equivalence.state is GateState.fail:
        report = _invalid_comparison_report(
            suite,
            baseline,
            candidate,
            fixture_equivalence,
            gate_profile=gate_profile,
        )
        raise InvalidComparisonError("fixture equivalence failed", report)
    candidate_report = evaluate_runset(
        suite,
        candidate,
        gate_profile=gate_profile,
        waivers=waivers,
        today=today,
    )
    baseline_report = evaluate_runset(
        suite,
        baseline,
        gate_profile=gate_profile,
        waivers=waivers,
        today=today,
    )
    control_changes = diff_control_findings(baseline_report, candidate_report)
    behavioral_changes = diff_behavior(baseline, candidate)
    provenance_changes = diff_provenance(baseline, candidate)
    baseline_usage = usage_summary_for_runset(baseline)
    candidate_usage = usage_summary_for_runset(candidate)
    usage_delta = (
        compare_usage_summaries(baseline_usage, candidate_usage)
        if baseline_usage is not None or candidate_usage is not None
        else None
    )
    classification = choose_comparison_classification(
        control_changes=control_changes,
        behavioral_changes=behavioral_changes,
        provenance_changes=provenance_changes,
        baseline_state=baseline_report.candidate_vs_expectations.state,
        candidate_state=candidate_report.candidate_vs_expectations.state,
    )
    summary = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        classification=classification,
        fixture_equivalence_state=fixture_equivalence.state,
        baseline_state=baseline_report.candidate_vs_expectations.state,
        candidate_state=candidate_report.candidate_vs_expectations.state,
        provenance_changes=tuple(
            summarize_provenance_change(change) for change in provenance_changes
        ),
        verdict_findings=tuple(summarize_control_change(change) for change in control_changes),
        baseline_usage_summary=baseline_usage,
        candidate_usage_summary=candidate_usage,
        usage_delta=usage_delta,
    )
    report = ComparisonReport(
        candidate_vs_expectations=candidate_report.candidate_vs_expectations,
        verdict_explanations=_verdict_explanations(
            candidate_report,
            classification,
        ),
        fixture_equivalence=fixture_equivalence,
        baseline_vs_expectations=baseline_report.candidate_vs_expectations,
        control_changes=control_changes,
        behavioral_changes=behavioral_changes,
        provenance_changes=provenance_changes,
        not_evaluated_capabilities=candidate_report.not_evaluated_capabilities,
        limitations=_limitations(),
        comparison_summary=summary,
        baseline_metrics=baseline_report.metrics,
        candidate_metrics=candidate_report.metrics,
        baseline_usage_summary=baseline_usage,
        candidate_usage_summary=candidate_usage,
        usage_delta=usage_delta,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
    )
    return report


def verify_fixture_equivalence(baseline: RunSet, candidate: RunSet) -> FixtureEquivalenceReport:
    baseline_counts = case_counts(baseline)
    candidate_counts = case_counts(candidate)
    baseline_runs = unique_case_map(baseline)
    candidate_runs = unique_case_map(candidate)
    findings: list[Finding] = []
    digests: set[str] = {baseline.fixture_manifest_digest, candidate.fixture_manifest_digest}
    if baseline.fixture_manifest_digest != candidate.fixture_manifest_digest:
        findings.append(
            _fixture_finding(
                "*",
                "fixture_manifest_digest",
                "baseline and candidate run-set fixture manifest digests differ",
            )
        )
    for case_id in sorted(set(baseline_counts) | set(candidate_counts)):
        if baseline_counts[case_id] != 1 or candidate_counts[case_id] != 1:
            findings.append(
                _fixture_finding(
                    case_id,
                    "case-record-count",
                    (
                        "baseline and candidate must each contain exactly one run "
                        "for every compared case"
                    ),
                )
            )
            continue
        baseline_run = baseline_runs[case_id]
        candidate_run = candidate_runs[case_id]
        baseline_digest = baseline_run.provenance.fixture_manifest_digest
        candidate_digest = candidate_run.provenance.fixture_manifest_digest
        if baseline_digest:
            digests.add(baseline_digest)
        if candidate_digest:
            digests.add(candidate_digest)
        if not baseline_digest or not candidate_digest:
            findings.append(
                _fixture_finding(
                    case_id,
                    "fixture_manifest_digest",
                    "both compared runs must record a fixture manifest digest",
                )
            )
        elif baseline_digest != candidate_digest:
            findings.append(
                _fixture_finding(
                    case_id,
                    "fixture_manifest_digest",
                    "baseline and candidate fixture manifest digests differ",
                )
            )
        if baseline_digest and baseline_digest != baseline.fixture_manifest_digest:
            findings.append(
                _fixture_finding(
                    case_id,
                    "baseline.fixture_manifest_digest",
                    "baseline run fixture digest does not match its run-set digest",
                )
            )
        if candidate_digest and candidate_digest != candidate.fixture_manifest_digest:
            findings.append(
                _fixture_finding(
                    case_id,
                    "candidate.fixture_manifest_digest",
                    "candidate run fixture digest does not match its run-set digest",
                )
            )
    return FixtureEquivalenceReport(
        state=GateState.fail if findings else GateState.pass_,
        findings=tuple(findings),
        compared_digests=tuple(sorted(digests)),
    )


def _verify_suite_identity(suite: CompiledSuite, baseline: RunSet, candidate: RunSet) -> None:
    if baseline.suite_id != candidate.suite_id:
        raise InvalidComparisonError(
            "baseline and candidate run sets reference different suite_id values"
        )
    if baseline.suite_id != suite.suite_id:
        raise InvalidComparisonError(
            f"run sets reference suite_id {baseline.suite_id!r}, "
            f"but compiled suite is {suite.suite_id!r}"
        )
    if baseline.suite_version != candidate.suite_version:
        raise InvalidComparisonError(
            "baseline and candidate run sets reference different suite_version values"
        )
    if baseline.suite_version != suite.suite_version:
        raise InvalidComparisonError(
            f"run sets reference suite_version {baseline.suite_version!r}, "
            f"but compiled suite is {suite.suite_version!r}"
        )
    expected_suite_digest = compiled_suite_digest(suite)
    if baseline.suite_digest != candidate.suite_digest:
        raise InvalidComparisonError(
            "baseline and candidate run sets reference different suite_digest values"
        )
    if baseline.suite_digest != expected_suite_digest:
        raise InvalidComparisonError(
            f"run sets reference suite_digest {baseline.suite_digest!r}, "
            f"but compiled suite digest is {expected_suite_digest!r}"
        )


def _invalid_comparison_report(
    suite: CompiledSuite,
    baseline: RunSet,
    candidate: RunSet,
    fixture_equivalence: FixtureEquivalenceReport,
    *,
    gate_profile: GateProfile,
) -> ComparisonReport:
    baseline_summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id=baseline.runset_id,
        state=GateState.not_evaluated,
    )
    candidate_summary = EvaluationSummary(
        artifact_kind="evaluation-summary",
        runset_id=candidate.runset_id,
        state=GateState.not_evaluated,
    )
    summary = ComparisonSummary(
        artifact_kind="comparison-summary",
        baseline_runset_id=baseline.runset_id,
        candidate_runset_id=candidate.runset_id,
        classification=ComparisonClassification.invalid_comparison,
        fixture_equivalence_state=fixture_equivalence.state,
        baseline_state=baseline_summary.state,
        candidate_state=candidate_summary.state,
    )
    return ComparisonReport(
        artifact_kind="comparison-report",
        candidate_vs_expectations=candidate_summary,
        verdict_explanations=(
            "The comparison is invalid because fixture material is not equivalent.",
        ),
        fixture_equivalence=fixture_equivalence,
        baseline_vs_expectations=baseline_summary,
        control_changes=(),
        behavioral_changes=(),
        provenance_changes=(),
        not_evaluated_capabilities=(),
        limitations=_limitations(),
        comparison_summary=summary,
        baseline_metrics=_not_evaluated_metrics(suite),
        candidate_metrics=_not_evaluated_metrics(suite),
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        gate_profile=gate_profile.profile_id,
    )


def _not_evaluated_metrics(suite: CompiledSuite) -> EvaluationMetrics:
    return EvaluationMetrics(
        total_cases=len(suite.cases),
        evaluated_cases=0,
        unevaluated_cases=len(suite.cases),
        passed_cases=0,
        failed_cases=0,
        warning_findings=0,
        blocking_findings=0,
        global_blocking_findings=0,
        findings_by_reason={},
        findings_by_control={},
    )


def _fixture_finding(case_id: str, target: str, message: str) -> Finding:
    result = ControlResult(
        control_id="fixture_equivalence",
        case_id=case_id,
        state=GateState.fail,
        reason_code=ReasonCode.FIXTURE_EQUIVALENCE_FAILED,
        severity=Severity.blocker,
        target=target,
        message=message,
    )
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


def _verdict_explanations(
    candidate_report: EvaluationReport,
    classification: ComparisonClassification,
) -> tuple[str, ...]:
    lines: list[str] = []
    candidate_summary = candidate_report.candidate_vs_expectations
    if candidate_summary.state is GateState.fail:
        lines.extend(
            f"{finding.case_id} {finding.control_id} {finding.reason_code.value}: "
            f"{finding.message}"
            for finding in candidate_report.failed_controls
        )
    else:
        lines.append(
            "The candidate has no blocking deterministic finding under the selected gate profile."
        )
    if classification is ComparisonClassification.provenance_only_change:
        lines.append(
            "Only provenance fields changed; provenance changes are reported separately."
        )
    return tuple(lines)


def _limitations() -> tuple[str, ...]:
    return (
        "comparison results are deterministic fixture-mode governance checks, not live "
        "model-quality or stochastic-provider measurements",
        "provenance differences are reported for review and do not create regression "
        "verdicts by themselves",
    )
