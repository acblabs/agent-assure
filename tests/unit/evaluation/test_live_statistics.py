from __future__ import annotations

import json
from decimal import ROUND_UP, Decimal, Inexact, Rounded, localcontext
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import ValidationError

import agent_assure.live.comparison as live_comparison
import agent_assure.live.drift as live_drift
import agent_assure.live.trajectory as live_trajectory
import agent_assure.schema.validation as schema_validation
from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.advanced import (
    _bootstrap_icc_interval,
    _endpoint_alpha,
    _icc_from_counts,
    _permutation_p_value,
    _poisson_upper_count_bound,
    _rare_event_bound,
    evaluate_statistical_invariants,
)
from agent_assure.live.comparison import (
    _comparison_exploratory,
    _comparison_limitations,
    _comparison_state,
    _randomization_comparison_state,
    compare_live_reports,
    load_live_evaluation_report,
)
from agent_assure.live.drift import (
    _ar1_summary,
    _metric_value,
    _monitoring_status,
    _slope,
    build_live_drift_report,
    verify_live_drift_report_sources,
)
from agent_assure.live.intervals import (
    LIVE_RESAMPLING_ALGORITHM_ID,
    cluster_t_interval,
    difference_t_interval,
    seeded_sampler,
    stable_seed_int,
    t_critical_95,
    wilson_score_interval,
)
from agent_assure.live.primitives import (
    decimal_string as live_decimal_string,
)
from agent_assure.live.primitives import (
    probability_upper_string,
)
from agent_assure.live.source_projection import (
    project_persisted_observation_source,
    project_run_observation_source,
)
from agent_assure.live.statistics import _rate_from_values, evaluate_live_runset
from agent_assure.live.trajectory import (
    build_live_trajectory_report,
    verify_live_trajectory_report_sources,
)
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.reporting.live import (
    render_live_evaluation_markdown,
    render_live_trajectory_markdown,
)
from agent_assure.schema.common import (
    ExecutionMode,
    GateState,
    ReasonCode,
)
from agent_assure.schema.common import (
    decimal_string as schema_decimal_string,
)
from agent_assure.schema.export import writer_json_schema
from agent_assure.schema.live import (
    CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION,
    DriftMetricPlan,
    DriftMonitoringPlan,
    LiveDistribution,
    LiveDriftReport,
    LiveEvaluationReport,
    LiveProtocolRecord,
    LiveRate,
    LiveTrajectoryReport,
    OperationalEventProcessSummary,
    OperationalEventType,
    StatisticalEndpointPlan,
    TrajectoryAnalysisPlan,
    TrajectoryInvariantPlan,
    TrajectoryOperationalEvent,
    TrajectoryPathSummary,
)
from agent_assure.schema.privacy import PrivacyProfileDigest, PrivacyProfileId
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    ClaimEvidenceLink,
    LiveNetworkAuthorityReceipt,
    StructuredFieldOrigin,
    StructuredFieldOrigins,
)
from agent_assure.schema.run import RunSet as RunSetModel
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.suite import CompiledSuite


class RunSet(RunSetModel):
    """Current-profile RunSet fixture for statistics tests unrelated to privacy."""

    privacy_profile_id: PrivacyProfileId = PRIVACY_PROFILE_ID
    privacy_profile_digest: PrivacyProfileDigest = PRIVACY_PROFILE_DIGEST


SUITE = Path("examples/expense_approval_minimal/suite.yaml")


def test_live_evaluator_rejects_unsafe_runset_before_scoring() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    record = _record(repetition_index=0, linked=False)
    forged_link = ClaimEvidenceLink(
        claim_id="claim-receipt-present",
        evidence_ref_id="ref-receipt-exp-001",
    ).model_copy(update={"artifact_kind": "forged-link"})
    forged_record = record.model_copy(update={"claim_evidence_links": (forged_link,)})
    forged_runset = RunSet(
        runset_id="unsafe-live-evaluator-source",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(record,),
    ).model_copy(update={"runs": (forged_record,)})

    with pytest.raises(ValidationError, match="artifact_kind"):
        evaluate_live_runset(compiled, forged_runset, protocol=protocol)


def test_live_comparison_rejects_unsafe_source_report_before_derivation() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)

    def evaluation(runset_id: str) -> LiveEvaluationReport:
        runset = RunSet(
            runset_id=runset_id,
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=(_record(repetition_index=0, linked=False),),
        )
        return evaluate_live_runset(compiled, runset, protocol=protocol)

    baseline = evaluation("unsafe-comparison-baseline")
    candidate = evaluation("unsafe-comparison-candidate")
    forged_observation = candidate.observations[0].model_copy(
        update={
            "state": GateState.pass_,
            "reason_codes": (),
            "findings": (),
        }
    )
    forged_candidate = candidate.model_copy(update={"observations": (forged_observation,)})

    with pytest.raises(ValidationError):
        compare_live_reports(baseline, forged_candidate, protocol=protocol)


def test_live_decimal_rendering_uses_one_schema_helper() -> None:
    exact_half = Decimal("1.2345665")

    assert schema_decimal_string(exact_half) == "1.234566"
    assert live_decimal_string(exact_half) == schema_decimal_string(exact_half)


def test_current_live_rate_zero_denominator_is_fixed_reference_only() -> None:
    fixed_reference = LiveRate(
        artifact_kind="live-rate",
        label="fixed_reference_expectation_pass",
        numerator=0,
        denominator=0,
        cluster_count=0,
        effective_n="0.000000",
        design_effect="1.000000",
        largest_cluster_size=0,
        largest_cluster_design_effect="1.000000",
        largest_cluster_effective_n="0.000000",
        assumed_intraclass_correlation="0.200000",
        analysis_method="fixed_reference",
        exploratory=False,
        rate="0.000000",
        cluster_mean_rate="0.000000",
        interval_center="pooled_rate",
        interval_center_value="0.000000",
        confidence_level="0.950000",
        ci_lower="0.000000",
        ci_upper="0.000000",
    )
    assert fixed_reference.denominator == 0
    assert fixed_reference.analysis_method == "fixed_reference"

    observed_payload = fixed_reference.model_dump(mode="json")
    observed_payload.update(
        {
            "label": "expectation_pass",
            "analysis_method": "cluster_t_interval",
            "exploratory": True,
            "interval_center": "cluster_mean_rate",
        }
    )
    with pytest.raises(ValidationError, match="fixed_reference point-value"):
        LiveRate.model_validate(observed_payload)

    malformed_reference = {**fixed_reference.model_dump(mode="json"), "ci_upper": "0.100000"}
    with pytest.raises(ValidationError, match="count-free point values"):
        LiveRate.model_validate(malformed_reference)

    legacy_payload = {**observed_payload, "schema_version": "0.6.1"}
    legacy_rate = LiveRate.model_validate(legacy_payload)
    assert legacy_rate.schema_version == "0.6.1"
    assert legacy_rate.denominator == 0


def test_current_live_rate_rejects_impossible_standalone_statistics() -> None:
    rate = LiveRate(
        artifact_kind="live-rate",
        label="expectation_pass",
        numerator=2,
        denominator=3,
        cluster_count=2,
        effective_n="2.727273",
        design_effect="1.100000",
        largest_cluster_size=2,
        largest_cluster_design_effect="1.200000",
        largest_cluster_effective_n="2.500000",
        assumed_intraclass_correlation="0.200000",
        analysis_method="descriptive_cluster_t_interval",
        exploratory=True,
        rate="0.666667",
        cluster_mean_rate="0.750000",
        interval_center="cluster_mean_rate",
        interval_center_value="0.750000",
        confidence_level="0.950000",
        ci_lower="0.000000",
        ci_upper="1.000000",
    )
    payload = rate.model_dump(mode="json")

    invalid_mutations = (
        ({"numerator": 4}, "numerator cannot exceed denominator"),
        ({"cluster_count": 0}, "cluster_count between one and denominator"),
        ({"largest_cluster_size": 1}, "largest_cluster_size is impossible"),
        ({"rate": "1.000000"}, "rate does not match numerator and denominator"),
        (
            {"interval_center_value": "0.500000"},
            "interval_center_value does not match interval_center",
        ),
        (
            {"ci_lower": "0.900000", "ci_upper": "0.800000"},
            "confidence interval endpoints are reversed",
        ),
        (
            {"design_effect": "1.000000"},
            "effective sample sizes and design effects do not match",
        ),
        (
            {"largest_cluster_effective_n": "3.000000"},
            "effective sample sizes and design effects do not match",
        ),
    )
    for mutation, message in invalid_mutations:
        with pytest.raises(ValidationError, match=message):
            LiveRate.model_validate({**payload, **mutation})


def test_live_statistics_aggregate_repeated_observations() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True, latency_ms=100, cost="0.010000"),
            _record(repetition_index=1, linked=False, latency_ms=300, cost="0.030000"),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    with localcontext() as context:
        context.prec = 6
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        context.clear_flags()
        hostile_context_report = evaluate_live_runset(compiled, runset, protocol=protocol)

        assert hostile_context_report == report
        assert context.prec == 6
        assert context.rounding == ROUND_UP
        assert context.traps[Inexact] is True
        assert context.traps[Rounded] is True
        assert context.flags[Inexact] is False
        assert context.flags[Rounded] is False

    assert report.state is GateState.fail
    assert report.suite_digest == compiled_suite_digest(compiled)
    assert report.configuration_digest == "4" * 64
    assert report.exploratory is True
    assert report.overall.observations == 2
    assert report.overall.cluster_count == 1
    assert report.overall.expectation_pass_rate.effective_n == "1.666667"
    assert report.overall.expectation_pass_rate.largest_cluster_size == 2
    assert report.overall.expectation_pass_rate.largest_cluster_design_effect == "1.200000"
    assert report.overall.expectation_pass_rate.largest_cluster_effective_n == "1.666667"
    assert report.overall.expectation_pass_rate.exploratory is True
    assert report.overall.expectation_pass_rate.rate == "0.500000"
    assert report.overall.expectation_pass_rate.cluster_mean_rate == "0.500000"
    assert report.overall.expectation_pass_rate.interval_center == "cluster_mean_rate"
    assert report.overall.expectation_pass_rate.interval_center_value == "0.500000"
    assert report.overall.expectation_pass_rate.analysis_method == (
        "descriptive_cluster_t_interval"
    )
    assert report.overall.estimated_cost_usd.total == "0.040000"
    assert report.overall.latency_ms.p50 == "200.000000"
    assert report.overall.reason_code_rates[0].label == (
        f"reason_code:{ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value}"
    )
    assert report.observations[0].tool_schema_digest == "6" * 64
    assert report.observations[0].policy_bundle_digest == "7" * 64


def test_load_live_evaluation_report_projects_current_model_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-single-projection",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(_record(repetition_index=0, linked=True),),
    )
    report = evaluate_live_runset(compiled, runset, protocol=protocol)
    report_path = tmp_path / "live-evaluation-report.json"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")

    original_projection = schema_validation.project_validated_artifact_payload
    projection_kinds: list[str] = []

    def counting_projection(*args: object, **kwargs: object) -> object:
        kind = kwargs.get("kind")
        assert isinstance(kind, str)
        projection_kinds.append(kind)
        return original_projection(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(
        schema_validation,
        "project_validated_artifact_payload",
        counting_projection,
    )

    loaded = load_live_evaluation_report(report_path)

    assert loaded == report
    assert projection_kinds == ["live-evaluation-report"]


def test_live_statistics_accumulates_exact_cost_before_rounding() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-exact-cost",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                cost="0.000000",
                cost_picousd=500_000,
                cost_budget_committed="0.000001",
            ),
            _record(
                repetition_index=1,
                linked=True,
                cost="0.000000",
                cost_picousd=500_000,
                cost_budget_committed="0.000001",
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.overall.estimated_cost_usd.total == "0.000001"


def test_live_statistics_enforces_required_policy_ids() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-missing-required-policy",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(_record(repetition_index=0, linked=True, policy_results=()),),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.state is GateState.fail
    assert report.observations[0].state is GateState.fail
    observation = report.observations[0]
    findings = tuple(
        finding
        for finding in observation.findings
        if finding.control_id == "required_policy_evaluated"
    )
    assert len(findings) == 1
    (finding,) = findings
    assert finding.target == "provider-selection"
    assert finding.reason_code is ReasonCode.POLICY_FAILED
    finding_ids = tuple(finding.finding_id for finding in observation.findings)
    assert len(finding_ids) == len(set(finding_ids))


@pytest.mark.parametrize(
    ("policy_state", "expected_control_id"),
    (
        ("fail", "required_policy:provider-selection"),
        ("not_evaluated", "required_policy_evaluated"),
    ),
)
def test_live_required_policy_nonpass_is_emitted_once(
    policy_state: Literal["fail", "not_evaluated"],
    expected_control_id: str,
) -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-failed-required-policy",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                policy_results=(
                    {
                        "artifact_kind": "policy-result",
                        "policy_id": "provider-selection",
                        "state": policy_state,
                        "reason_codes": [ReasonCode.POLICY_FAILED.value],
                        "severity": "error",
                        "message": "required provider policy failed",
                    },
                ),
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    observation = report.observations[0]
    matching_findings = tuple(
        finding for finding in observation.findings if finding.control_id == expected_control_id
    )
    finding_ids = tuple(finding.finding_id for finding in observation.findings)

    assert report.state is GateState.fail
    assert len(matching_findings) == 1
    assert matching_findings[0].target == "provider-selection"
    assert matching_findings[0].reason_code is ReasonCode.POLICY_FAILED
    assert not any(
        finding.control_id == "policy_result:provider-selection" for finding in observation.findings
    )
    assert len(finding_ids) == len(set(finding_ids))


def test_live_statistics_rejects_heterogeneous_execution_arm_identity() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    second = _record(repetition_index=1, linked=True).model_copy(
        update={
            "provider": "other-provider",
            "model": "other-model",
            "adapter_id": "external-script",
            "pipeline_id": "candidate-b",
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.instrumented_adapter
            ),
            "provenance": _record(
                repetition_index=1,
                linked=True,
            ).provenance.model_copy(update={"model_identifier": "other-model"}),
        }
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-heterogeneous-provider",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True),
            second,
        ),
    )

    with pytest.raises(ValueError, match="one homogeneous execution arm"):
        evaluate_live_runset(compiled, runset, protocol=protocol)


def test_live_statistics_rejects_provider_version_changes_within_an_arm() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    first = _record(repetition_index=0, linked=True)
    second = _record(repetition_index=1, linked=True).model_copy(
        update={"resolved_model": "static-model-2026-07-01"}
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-heterogeneous-provider-version",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(first, second),
    )

    with pytest.raises(ValueError, match="one homogeneous execution arm"):
        evaluate_live_runset(compiled, runset, protocol=protocol)


def test_live_statistics_rejects_duplicate_case_repetition_observations() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    duplicate = _record(repetition_index=0, linked=False).model_copy(
        update={
            "run_id": "run-live-0b",
            "observation_id": "obs-live-0b",
            "schedule_index": 1,
        }
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-duplicate-schedule",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True),
            duplicate,
        ),
    )

    with pytest.raises(ValueError, match="duplicate case/repetition observation"):
        evaluate_live_runset(compiled, runset, protocol=protocol)


@pytest.mark.parametrize(
    ("schedule_indexes", "message"),
    (
        ((0, 0), "duplicate schedule_index"),
        ((0, 2), "complete planned schedule"),
    ),
)
def test_live_statistics_requires_a_unique_complete_schedule_index(
    schedule_indexes: tuple[int, int],
    message: str,
) -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 2)
    protocol = _protocol(compiled, observations=2, clusters=2, repetitions=1)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-schedule-index",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=tuple(
            _record(
                repetition_index=0,
                linked=True,
                case_id=f"case-{index:03d}",
                schedule_index=schedule_indexes[index],
            )
            for index in range(2)
        ),
    )

    with pytest.raises(ValueError, match=message):
        evaluate_live_runset(compiled, runset, protocol=protocol)


def test_live_evaluation_report_rejects_duplicate_pairing_identity() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    report = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-live-report-identity",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=(_record(repetition_index=0, linked=True),),
        ),
        protocol=protocol,
    )
    payload = report.model_dump(mode="json")
    duplicate = dict(payload["observations"][0])
    duplicate["observation_id"] = "obs-live-duplicate"
    duplicate["run_id"] = "run-live-duplicate"
    payload["observations"].append(duplicate)

    with pytest.raises(
        ValueError,
        match=(
            "duplicate prompt and schedule identity|"
            "observation count does not match protocol planned_observations"
        ),
    ):
        LiveEvaluationReport.model_validate(payload)


@pytest.mark.parametrize(
    ("scope", "field_name", "tampered_value", "message"),
    (
        ("overall", "observations", 3, "overall summary observations count"),
        ("group", "included_observations", 1, "included_observations count"),
        ("group", "excluded_observations", 1, "excluded_observations count"),
    ),
)
def test_live_evaluation_report_rejects_tampered_summary_counts(
    scope: str,
    field_name: str,
    tampered_value: int,
    message: str,
) -> None:
    report = _aggregate_validation_report()
    payload = report.model_dump(mode="json")
    summary = payload["overall"] if scope == "overall" else payload["groups"][0]
    summary[field_name] = tampered_value

    with pytest.raises(
        ValueError,
        match=f"{message}|live rate does not match numerator and denominator",
    ):
        LiveEvaluationReport.model_validate(payload)


@pytest.mark.parametrize(
    ("rate_name", "field_name", "tampered_value", "message"),
    (
        ("exclusion_rate", "numerator", 1, "exclusion rate numerator"),
        ("expectation_pass_rate", "numerator", 1, "expectation_pass rate numerator"),
        ("expectation_pass_rate", "rate", "0.500000", "expectation_pass rate does not"),
        ("reason_code_rates", "numerator", 1, "reason_code:.* rate numerator"),
    ),
)
def test_live_evaluation_report_rejects_tampered_derivable_rates(
    rate_name: str,
    field_name: str,
    tampered_value: int | str,
    message: str,
) -> None:
    report = _aggregate_validation_report()
    payload = report.model_dump(mode="json")
    overall = payload["overall"]
    rate = (
        overall["reason_code_rates"][0] if rate_name == "reason_code_rates" else overall[rate_name]
    )
    rate[field_name] = tampered_value

    with pytest.raises(
        ValueError,
        match=f"{message}|live rate does not match numerator and denominator",
    ):
        LiveEvaluationReport.model_validate(payload)


def test_live_evaluation_report_rejects_tampered_group_membership() -> None:
    report = _aggregate_validation_report()
    payload = report.model_dump(mode="json")
    payload["groups"][0]["group_id"] = "provider=tampered"

    with pytest.raises(ValueError, match="group summaries do not match observation groups"):
        LiveEvaluationReport.model_validate(payload)


def test_v060_live_evaluation_retains_execution_and_summary_invariants() -> None:
    report = _aggregate_validation_report()
    payload = report.model_dump(mode="json")
    payload["schema_version"] = "0.6.0"
    payload["configuration_digest"] = None

    with pytest.raises(ValueError, match="suite and configuration digests"):
        LiveEvaluationReport.model_validate(payload)

    payload["configuration_digest"] = report.configuration_digest
    payload["overall"]["observations"] += 1
    with pytest.raises(ValueError, match="overall summary observations count"):
        LiveEvaluationReport.model_validate(payload)


def test_live_binding_rejects_mismatched_suite_and_configuration_digests() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    record = _record(repetition_index=0, linked=True)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-binding",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(record,),
    )

    with pytest.raises(ValueError, match="RunSet suite_digest"):
        evaluate_live_runset(
            compiled,
            runset.model_copy(update={"suite_digest": "f" * 64}),
            protocol=protocol,
        )

    mismatched_provenance = record.provenance.model_copy(update={"configuration_digest": "f" * 64})
    with pytest.raises(ValueError, match="configuration_digest"):
        evaluate_live_runset(
            compiled,
            runset.model_copy(
                update={"runs": (record.model_copy(update={"provenance": mismatched_provenance}),)}
            ),
            protocol=protocol,
        )

    mismatched_model = record.provenance.model_copy(update={"model_identifier": "other-model"})
    with pytest.raises(ValueError, match="model_identifier"):
        evaluate_live_runset(
            compiled,
            runset.model_copy(
                update={"runs": (record.model_copy(update={"provenance": mismatched_model}),)}
            ),
            protocol=protocol,
        )


def test_live_binding_rejects_unstable_prompt_and_caller_supplied_cluster_ids() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    first = _record(repetition_index=0, linked=True)
    second = _record(repetition_index=1, linked=True)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-prompt-binding",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(first, second),
    )
    changed_prompt = second.provenance.model_copy(update={"prompt_digest": "f" * 64})

    with pytest.raises(ValueError, match="prompt_digest must be stable"):
        evaluate_live_runset(
            compiled,
            runset.model_copy(
                update={
                    "runs": (
                        first,
                        second.model_copy(update={"provenance": changed_prompt}),
                    )
                }
            ),
            protocol=protocol,
        )

    with pytest.raises(ValueError, match="does not match protocol.cluster_by"):
        evaluate_live_runset(
            compiled,
            runset.model_copy(
                update={
                    "runs": (
                        first.model_copy(update={"cluster_id": "invented-cluster"}),
                        second,
                    )
                }
            ),
            protocol=protocol,
        )


def test_source_group_clustering_is_forced_exploratory_without_protocol_mapping() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        cluster_by="source_group_id",
    )
    record = _record(
        repetition_index=0,
        linked=True,
        cluster_id="source-a",
        source_group_id="source-a",
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-source-group",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(record,),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.exploratory is True
    assert _comparison_exploratory(protocol, 30) is True


def test_live_rate_reports_largest_cluster_sensitivity() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=3, clusters=2, repetitions=3)

    rate = _rate_from_values(
        "expectation_pass",
        (("shared-source", True), ("shared-source", False), ("single-case", True)),
        protocol=protocol,
        analysis_method="descriptive_cluster_t_interval",
    )

    assert rate.design_effect == "1.100000"
    assert rate.effective_n == "2.727273"
    assert rate.largest_cluster_size == 2
    assert rate.largest_cluster_design_effect == "1.200000"
    assert rate.largest_cluster_effective_n == "2.500000"


def test_live_rate_labels_cluster_interval_when_pooled_rate_differs() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=5, clusters=2, repetitions=5)

    rate = _rate_from_values(
        "expectation_pass",
        (
            ("large-cluster", True),
            ("large-cluster", True),
            ("large-cluster", True),
            ("large-cluster", False),
            ("small-cluster", False),
        ),
        protocol=protocol,
        analysis_method="descriptive_cluster_t_interval",
    )

    assert rate.rate == "0.600000"
    assert rate.cluster_mean_rate == "0.375000"
    assert rate.interval_center == "cluster_mean_rate"
    assert rate.interval_center_value == rate.cluster_mean_rate


def test_live_rate_confidence_interval_serialization_is_outward() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(compiled, observations=50, clusters=5, repetitions=10)
    report = _cluster_success_report(
        compiled,
        protocol,
        runset_id="outward-rate-interval",
        successes=(1, 2, 3, 4, 5),
    )
    rate = report.overall.expectation_pass_rate
    _, raw_lower, raw_upper = cluster_t_interval(
        tuple(map(Decimal, ("0.1", "0.2", "0.3", "0.4", "0.5"))),
        protocol.confidence_level,
    )

    assert rate.ci_lower == "0.103675"
    assert rate.ci_upper == "0.496325"
    assert Decimal(rate.ci_lower) <= raw_lower
    assert Decimal(rate.ci_upper) >= raw_upper


def test_live_comparison_confidence_interval_serialization_is_outward() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(compiled, observations=50, clusters=5, repetitions=10)
    baseline = _cluster_success_report(
        compiled,
        protocol,
        runset_id="outward-comparison-baseline",
        successes=(5, 5, 5, 5, 5),
    )
    candidate = _cluster_success_report(
        compiled,
        protocol,
        runset_id="outward-comparison-candidate",
        successes=(3, 4, 5, 6, 7),
    )
    comparison = compare_live_reports(baseline, candidate, protocol=protocol)
    _, raw_lower, raw_upper, _ = difference_t_interval(
        tuple(map(Decimal, ("-0.2", "-0.1", "0", "0.1", "0.2"))),
        protocol.confidence_level,
    )

    assert comparison.difference_ci_lower == "-0.196325"
    assert comparison.difference_ci_upper == "0.196325"
    assert Decimal(comparison.difference_ci_lower) <= raw_lower
    assert Decimal(comparison.difference_ci_upper) >= raw_upper


def test_live_icc_confidence_interval_serialization_is_outward() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(
        compiled,
        observations=20,
        clusters=5,
        repetitions=4,
        advanced_analysis_plan=_advanced_plan(
            primary_minimum_clusters=3,
            rare_reason_codes=[ReasonCode.RAW_SENSITIVE_CONTENT.value],
        ),
    )
    report = _cluster_success_report(
        compiled,
        protocol,
        runset_id="outward-icc-interval",
        successes=(3, 1, 3, 3, 3),
    )
    correlation = report.statistical_invariants[0].cluster_correlation
    assert correlation is not None
    raw_interval = _bootstrap_icc_interval(
        ((3, 4), (1, 4), (3, 4), (3, 4), (3, 4)),
        seed=sha256_hexdigest(
            {
                "protocol_id": protocol.protocol_id,
                "analysis_digest": protocol.analysis_digest,
                "endpoint_id": "expectation-pass",
                "purpose": "cluster-correlation-bootstrap",
            }
        ),
        confidence_level=protocol.confidence_level,
        iterations=1000,
    )
    assert raw_interval is not None
    raw_lower, raw_upper = raw_interval

    assert correlation.ci_lower == "-0.333334"
    assert correlation.ci_upper == "0.047620"
    assert Decimal(correlation.ci_lower) <= raw_lower
    assert Decimal(correlation.ci_upper) >= raw_upper


def test_comparison_gate_uses_the_persisted_conservative_lower_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 30)
    protocol = _protocol(
        compiled,
        observations=30,
        clusters=30,
        repetitions=1,
        non_inferiority_margin="0.000000",
    )
    baseline = _case_report(
        compiled,
        protocol,
        runset_id="serialized-boundary-baseline",
        count=30,
    )
    candidate = _case_report(
        compiled,
        protocol,
        runset_id="serialized-boundary-candidate",
        count=30,
    )
    monkeypatch.setattr(
        live_comparison,
        "_paired_cluster_difference_from_values",
        lambda _differences, _protocol: (
            Decimal("0.0000001"),
            Decimal("0.0000001"),
            Decimal("0.1000001"),
            30,
        ),
    )
    monkeypatch.setattr(
        live_comparison,
        "_comparison_exploratory",
        lambda _protocol, _compared_clusters: False,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.difference_ci_lower == "0.000000"
    assert comparison.state is GateState.not_evaluated
    assert any("zero-margin equality boundary" in item for item in comparison.limitations)


def test_degenerate_all_pass_rate_is_labeled_as_an_exploratory_point_mass() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=3, clusters=3, repetitions=1)

    rate = _rate_from_values(
        "expectation_pass",
        (("a", True), ("b", True), ("c", True)),
        protocol=protocol,
        analysis_method="descriptive_cluster_t_interval",
    )

    assert rate.rate == "1.000000"
    assert rate.cluster_mean_rate == "1.000000"
    assert rate.ci_lower == "1.000000"
    assert rate.ci_upper == "1.000000"
    assert rate.analysis_method == "descriptive_degenerate_point_mass"
    assert rate.exploratory is True


def test_degenerate_point_mass_remains_exploratory_with_thirty_clusters() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 30)
    protocol = _protocol(compiled, observations=30, clusters=30, repetitions=1)

    report = _case_report(
        compiled,
        protocol,
        runset_id="degenerate-point-mass-thirty-clusters",
        count=30,
    )

    rate = report.overall.expectation_pass_rate
    assert rate.analysis_method == "descriptive_degenerate_point_mass"
    assert rate.exploratory is True
    assert report.exploratory is True


def test_bootstrap_rate_method_is_used_for_bootstrap_protocols() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=4,
        clusters=4,
        repetitions=1,
        analysis_method="paired_cluster_bootstrap_percentile",
    )

    rate = _rate_from_values(
        "expectation_pass",
        (("a", True), ("b", True), ("c", False), ("d", False)),
        protocol=protocol,
        analysis_method="descriptive_cluster_bootstrap_percentile",
    )

    assert rate.analysis_method == "descriptive_cluster_bootstrap_percentile"
    assert rate.interval_center == "cluster_mean_rate"
    assert rate.exploratory is True


def test_advanced_statistical_invariants_report_rare_event_bounds_and_icc() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 3)
    advanced_plan = _advanced_plan(
        primary_minimum_clusters=3,
        rare_reason_codes=[ReasonCode.RAW_SENSITIVE_CONTENT.value],
    )
    advanced_plan["observed_icc_confirmatory_use"] = "external_review"
    protocol = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=2,
        advanced_analysis_plan=advanced_plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-advanced",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True, case_id="case-000"),
            _record(
                repetition_index=1,
                linked=False,
                case_id="case-000",
                schedule_index=1,
            ),
            _record(
                repetition_index=0,
                linked=True,
                case_id="case-001",
                schedule_index=2,
            ),
            _record(
                repetition_index=1,
                linked=True,
                case_id="case-001",
                schedule_index=3,
            ),
            _record(
                repetition_index=0,
                linked=False,
                case_id="case-002",
                schedule_index=4,
            ),
            _record(
                repetition_index=1,
                linked=False,
                case_id="case-002",
                schedule_index=5,
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert len(report.statistical_invariants) == 2
    primary = report.statistical_invariants[0]
    rare = report.statistical_invariants[1]
    assert primary.endpoint_id == "expectation-pass"
    assert primary.interpretation == "exploratory"
    assert primary.prerequisite_status == "exploratory"
    assert primary.cluster_correlation is not None
    assert primary.cluster_correlation.planned_intraclass_correlation == "0.200000"
    assert primary.cluster_correlation.observed_intraclass_correlation is not None
    assert primary.cluster_correlation.confirmatory_use == "disabled"
    assert primary.cluster_correlation.confirmatory_interval_uses_planned_icc is False
    assert any(
        "confirmatory use is disabled" in limitation
        for limitation in primary.cluster_correlation.limitations
    )
    assert primary.cluster_correlation.bootstrap_iterations == 1000
    assert rare.endpoint_id == "critical-sensitive-content"
    assert rare.rare_event_bound is not None
    assert rare.rare_event_bound.observed_events == 0
    assert rare.rare_event_bound.zero_events is True
    assert rare.rare_event_bound.interval_sidedness == "one_sided_upper"
    assert Decimal(rare.rare_event_bound.upper_rate_bound) > Decimal("0.000000")
    assert any("one-sided upper" in limitation for limitation in rare.rare_event_bound.limitations)
    assert any("not proof" in limitation for limitation in rare.rare_event_bound.limitations)

    markdown = render_live_evaluation_markdown(report)
    assert "observation_event_rate=" in markdown
    assert "observations=" in markdown
    assert "independence_clusters=" in markdown
    assert "cluster_incidence_events=" in markdown
    assert "independence_cluster_exposure=" in markdown
    assert "cluster_incidence_upper_rate=" in markdown

    assert "rare-event limitation:" in markdown
    assert "cluster-correlation limitation:" in markdown
    assert "endpoint limitation:" in markdown

    asterisk_limitation = "display *nested* <limit>"
    angle_limitation = "display > estimate"
    bracket_limitation = "display [scope]"
    scoped_markdown = render_live_evaluation_markdown(
        report.model_copy(
            update={
                "limitations": (
                    asterisk_limitation,
                    angle_limitation,
                    bracket_limitation,
                )
            }
        )
    )
    assert scoped_markdown.count("display \\*nested\\* &lt;limit&gt;") == 1
    assert scoped_markdown.count("display &gt; estimate") == 1
    assert scoped_markdown.count("display \\[scope\\]") == 1


def test_rare_event_bound_uses_one_binary_endpoint_per_independence_cluster() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 3)
    protocol = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=2,
        advanced_analysis_plan=_advanced_plan(
            primary_minimum_clusters=3,
            rare_reason_codes=[ReasonCode.RAW_SENSITIVE_CONTENT.value],
        ),
    )
    runs = tuple(
        _record(
            repetition_index=repetition_index,
            linked=True,
            case_id=f"case-{cluster_index:03d}",
            cluster_id=f"case-{cluster_index:03d}",
            schedule_index=cluster_index * 2 + repetition_index,
        )
        for cluster_index in range(3)
        for repetition_index in range(2)
    )
    report = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-live-cluster-rare-event",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=runs,
        ),
        protocol=protocol,
    )
    observations = tuple(
        observation.model_copy(
            update={"reason_codes": ((ReasonCode.RAW_SENSITIVE_CONTENT,) if index < 2 else ())}
        )
        for index, observation in enumerate(report.observations)
    )

    rare = next(
        invariant
        for invariant in evaluate_statistical_invariants(runs, observations, protocol)
        if invariant.endpoint_id == "critical-sensitive-content"
    )

    assert rare.numerator == 2
    assert rare.denominator == 6
    assert rare.rate == "0.333333"
    assert rare.rare_event_bound is not None
    assert rare.rare_event_bound.observed_events == 1
    assert rare.rare_event_bound.exposure == 3
    assert rare.rare_event_bound.exposure_unit == "independence_cluster"
    assert rare.rare_event_bound.event_rate == "0.333333"
    assert any(
        "one binary event indicator per independence cluster" in limitation
        for limitation in rare.rare_event_bound.limitations
    )


def test_advanced_zero_exposure_estimates_fail_closed() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    )

    with pytest.raises(ValueError, match="rate is undefined for zero exposure"):
        evaluate_statistical_invariants((), (), protocol)

    assert protocol.advanced_analysis_plan is not None
    endpoint = next(
        candidate
        for candidate in protocol.advanced_analysis_plan.endpoints
        if candidate.analysis_method == "clopper_pearson_exact_one_sided"
    )
    with pytest.raises(ValueError, match="bound are undefined for zero exposure"):
        _rare_event_bound(
            endpoint,
            observed_events=0,
            exposure=0,
            confidence_alpha=Decimal("0.050000"),
            bonferroni_adjusted=False,
        )


def test_degenerate_icc_is_not_reported_as_zero_with_a_zero_width_interval() -> None:
    counts = ((0, 2), (0, 2), (0, 2))

    assert _icc_from_counts(counts) is None
    assert (
        _bootstrap_icc_interval(
            counts,
            seed="degenerate-icc",
            confidence_level="0.950000",
            iterations=25,
        )
        is None
    )


def test_empty_paired_randomization_sample_fails_closed() -> None:
    with pytest.raises(ValueError, match="undefined for an empty sample"):
        _permutation_p_value(
            (),
            margin=Decimal("0"),
            method="paired_cluster_permutation_exact",
            seed="empty-sample",
        )


def test_zero_event_poisson_bound_matches_exact_rule_of_three_value() -> None:
    upper = _poisson_upper_count_bound(0, alpha=Decimal("0.050000"))

    assert upper.quantize(Decimal("0.000001")) == Decimal("2.995732")


def test_exact_binomial_upper_bound_is_serialized_outward() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=2,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    )
    assert protocol.advanced_analysis_plan is not None
    endpoint = next(
        candidate
        for candidate in protocol.advanced_analysis_plan.endpoints
        if candidate.analysis_method == "clopper_pearson_exact_one_sided"
    )

    bound = _rare_event_bound(
        endpoint,
        observed_events=0,
        exposure=2,
        confidence_alpha=Decimal("0.050000"),
        bonferroni_adjusted=False,
    )

    assert bound.upper_rate_bound == "0.776394"
    assert bound.upper_count_bound == "1.552787"
    assert Decimal(bound.upper_rate_bound) <= Decimal("1")

    invalid_payload = bound.model_dump(mode="json")
    invalid_payload["upper_rate_bound"] = "1.000001"
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(type(bound).model_json_schema(mode="validation")).validate(
            invalid_payload
        )
    with pytest.raises(ValidationError):
        type(bound).model_validate(invalid_payload)

    historical_payload = invalid_payload | {
        "schema_version": "0.6.5",
        "analysis_method": "poisson_upper_bound",
        "upper_count_bound": "2.995732",
        "upper_rate_bound": "1.497866",
    }
    type(bound).model_validate(historical_payload)
    Draft202012Validator(type(bound).model_json_schema(mode="validation")).validate(
        historical_payload
    )


def test_current_report_rejects_persisted_observation_under_delivery() -> None:
    report = _repeated_validation_report()
    payload = report.model_dump(mode="json")
    payload["observations"].pop()

    with pytest.raises(
        ValidationError,
        match="observation count does not match protocol planned_observations",
    ):
        LiveEvaluationReport.model_validate(payload)


def test_current_report_rejects_forged_observation_protocol_metadata() -> None:
    report = _repeated_validation_report()
    mutations = (
        (1, "schedule_index", 0, "duplicate schedule_index"),
        (1, "randomization_block_id", "repetition:0", "does not match repetition_index"),
        (1, "cluster_id", "forged-cluster", "cluster_id does not match"),
        (1, "prompt_digest", "4" * 64, "prompt_digest must be stable"),
        (1, "source_group_id", "forged-source", "source_group_id must be stable"),
        (1, "provider", "other-provider", "one homogeneous execution arm"),
        (1, "resolved_model", None, "missing provider-version field"),
        (0, "retry_count", 1, "retry_count exceeds"),
        (0, "rate_limit_events", 1, "rate_limit_events exceeds"),
        (0, "tool_schema_digest", "8" * 64, "tool_schema_digest does not match"),
        (0, "policy_bundle_digest", "8" * 64, "policy_bundle_digest does not match"),
        (0, "observation_status", "excluded", "excluded status requires exclusion_reason"),
        (0, "exclusion_reason", "undeclared", "exclusion_reason is not declared"),
    )

    for observation_index, field_name, value, message in mutations:
        payload = report.model_dump(mode="json")
        payload["observations"][observation_index][field_name] = value
        with pytest.raises(ValidationError, match=message):
            LiveEvaluationReport.model_validate(payload)


@pytest.mark.parametrize(
    ("count_field", "protocol_max_field"),
    (
        ("retry_count", "max_retries"),
        ("rate_limit_events", "max_rate_limit_events"),
    ),
)
def test_current_report_rejects_attempt_event_counts_above_attempts(
    count_field: str,
    protocol_max_field: str,
) -> None:
    report = _repeated_validation_report()
    payload = report.model_dump(mode="json")
    payload["protocol"][protocol_max_field] = 2
    bound_protocol = LiveProtocolRecord.model_validate(payload["protocol"])
    payload["protocol_digest"] = sha256_hexdigest(bound_protocol)
    payload["observations"][0].update(
        {
            "attempt_count": 1,
            count_field: 2,
        }
    )

    with pytest.raises(ValidationError, match=f"{count_field} cannot exceed attempt_count"):
        LiveEvaluationReport.model_validate(payload)


def test_current_observation_and_report_reject_forged_exact_costs() -> None:
    report = _repeated_validation_report()
    observation_payload = report.observations[0].model_dump(mode="json")
    observation_payload.update(
        {
            "estimated_cost_usd": "0.000000",
            "estimated_cost_picousd": 1_000_000,
        }
    )
    with pytest.raises(ValidationError, match="half-even six-decimal projection"):
        type(report.observations[0]).model_validate(observation_payload)

    downgraded_nested_cost = report.model_dump(mode="json")
    downgraded_nested_cost["observations"][0].update(
        {
            "schema_version": "0.6.5",
            "estimated_cost_usd": "0.000000",
            "estimated_cost_picousd": 1_000_000,
        }
    )
    with pytest.raises(ValidationError, match="picodollar projection"):
        LiveEvaluationReport.model_validate(downgraded_nested_cost)

    per_observation_overrun = report.model_dump(mode="json")
    per_observation_overrun["observations"][0].update(
        {
            "estimated_cost_usd": "2.000000",
            "estimated_cost_picousd": None,
        }
    )
    with pytest.raises(ValidationError, match="max_cost_per_observation_usd"):
        LiveEvaluationReport.model_validate(per_observation_overrun)

    total_overrun = report.model_dump(mode="json")
    total_overrun["protocol"]["max_total_cost_usd"] = "0.100000"
    bound_protocol = LiveProtocolRecord.model_validate(total_overrun["protocol"])
    total_overrun["protocol_digest"] = sha256_hexdigest(bound_protocol)
    for observation in total_overrun["observations"]:
        observation.update(
            {
                "estimated_cost_usd": "0.060000",
                "estimated_cost_picousd": None,
            }
        )
    with pytest.raises(ValidationError, match="max_total_cost_usd"):
        LiveEvaluationReport.model_validate(total_overrun)


def test_current_persisted_statistics_reject_impossible_math_and_nested_downgrades() -> None:
    report = _advanced_validation_report()
    assert LiveEvaluationReport.model_validate_json(report.model_dump_json()) == report

    report_payload = report.model_dump(mode="json")
    report_schema = Draft202012Validator(LiveEvaluationReport.model_json_schema(mode="validation"))
    report_schema.validate(report_payload)
    for required_field in ("source_runset_digest", "source_completion_status", "protocol"):
        missing_binding = report.model_dump(mode="json")
        missing_binding.pop(required_field)
        with pytest.raises(JsonSchemaValidationError):
            report_schema.validate(missing_binding)
    missing_outcome = report.model_dump(mode="json")
    missing_outcome["observations"][0].pop("outcome")
    with pytest.raises(JsonSchemaValidationError):
        report_schema.validate(missing_outcome)

    downgraded_protocol = report.model_dump(mode="json")
    downgraded_protocol["protocol"]["schema_version"] = "0.6.5"
    with pytest.raises(JsonSchemaValidationError):
        report_schema.validate(downgraded_protocol)
    with pytest.raises(ValidationError, match="current bound protocol record"):
        LiveEvaluationReport.model_validate(downgraded_protocol)

    historical_report = report.model_dump(mode="json")
    historical_report["schema_version"] = "0.6.5"
    for current_only_field in ("source_runset_digest", "source_completion_status", "protocol"):
        historical_report.pop(current_only_field)
    historical_report["observations"][0].pop("outcome")
    report_schema.validate(historical_report)

    false_pass = report.model_dump(mode="json")
    false_pass["state"] = "pass"
    with pytest.raises(ValidationError, match="state does not match observation-derived evidence"):
        LiveEvaluationReport.model_validate(false_pass)

    forged_cluster_statistics = report.model_dump(mode="json")
    forged_cluster_statistics["overall"]["expectation_pass_rate"].update(
        {
            "cluster_mean_rate": "0.999999",
            "interval_center_value": "0.999999",
            "ci_lower": "0.999999",
            "ci_upper": "0.999999",
            "effective_n": "999999999.000000",
            "design_effect": "999999999.000000",
        }
    )
    with pytest.raises(
        ValidationError,
        match=(
            "effective sample sizes and design effects do not match|overall summary does not match"
        ),
    ):
        LiveEvaluationReport.model_validate(forged_cluster_statistics)

    observation_unbound_invariant = report.model_dump(mode="json")
    primary = next(
        invariant
        for invariant in observation_unbound_invariant["statistical_invariants"]
        if invariant["endpoint_kind"] == "expectation_pass_rate"
    )
    primary.update({"numerator": 2, "rate": "1.000000"})
    with pytest.raises(ValidationError, match="statistical invariants do not match"):
        LiveEvaluationReport.model_validate(observation_unbound_invariant)

    rare_index = next(
        index
        for index, invariant in enumerate(report.statistical_invariants)
        if invariant.rare_event_bound is not None
    )
    rare = report.statistical_invariants[rare_index]
    assert rare.rare_event_bound is not None

    impossible_bound = rare.rare_event_bound.model_dump(mode="json")
    impossible_bound.update(
        {
            "observed_events": 5,
            "exposure": 1,
            "event_rate": "0.000000",
            "zero_events": True,
        }
    )
    with pytest.raises(ValidationError, match="observed_events cannot exceed exposure"):
        type(rare.rare_event_bound).model_validate(impossible_bound)

    impossible_invariant = rare.model_dump(mode="json")
    impossible_invariant.update(
        {
            "numerator": 0,
            "denominator": 1,
            "cluster_count": 1,
            "rate": "1.000000",
        }
    )
    with pytest.raises(ValidationError, match="rate does not match numerator/denominator"):
        type(rare).model_validate(impossible_invariant)

    downgraded_payload = report.model_dump(mode="json")
    downgraded_invariant = downgraded_payload["statistical_invariants"][rare_index]
    downgraded_invariant["schema_version"] = "0.6.5"
    downgraded_bound = downgraded_invariant["rare_event_bound"]
    downgraded_bound["schema_version"] = "0.6.5"
    downgraded_bound["zero_events"] = False
    with pytest.raises(
        ValidationError,
        match=("zero_events does not match observed_events|historical rare-event bounds require"),
    ):
        LiveEvaluationReport.model_validate(downgraded_payload)

    inexact_payload = report.model_dump(mode="json")
    inexact_invariant = inexact_payload["statistical_invariants"][rare_index]
    inexact_invariant["schema_version"] = "0.6.5"
    inexact_invariant["rare_event_bound"]["schema_version"] = "0.6.5"
    inexact_invariant["rare_event_bound"]["upper_rate_bound"] = "0.500000"
    with pytest.raises(
        ValidationError,
        match="upper_rate_bound does not match|historical rare-event bounds require",
    ):
        LiveEvaluationReport.model_validate(inexact_payload)

    mismatched_payload = report.model_dump(mode="json")
    mismatched_invariant = mismatched_payload["statistical_invariants"][rare_index]
    mismatched_invariant["schema_version"] = "0.6.5"
    mismatched_invariant["rare_event_bound"]["schema_version"] = "0.6.5"
    mismatched_invariant["rare_event_bound"]["endpoint_id"] = "other-endpoint"
    with pytest.raises(
        ValidationError,
        match="bound identity does not match|historical rare-event bounds require",
    ):
        LiveEvaluationReport.model_validate(mismatched_payload)

    reversed_correlation = report.model_dump(mode="json")
    primary = reversed_correlation["statistical_invariants"][0]
    primary["schema_version"] = "0.6.5"
    primary["cluster_correlation"]["schema_version"] = "0.6.5"
    primary["cluster_correlation"].update(
        {
            "ci_lower": "0.500000",
            "ci_upper": "0.400000",
        }
    )
    with pytest.raises(ValidationError, match="interval endpoints are reversed"):
        LiveEvaluationReport.model_validate(reversed_correlation)


def test_current_report_preflights_aggregate_exact_bound_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report = _advanced_validation_report()
    payload = report.model_dump(mode="json")
    rare_payload = next(
        invariant
        for invariant in payload["statistical_invariants"]
        if invariant["rare_event_bound"] is not None
    )
    expensive_invariants = []
    for index, confidence in enumerate(("0.950000", "0.940000", "0.930000")):
        invariant = {**rare_payload, "schema_version": "0.6.5"}
        bound = {
            **rare_payload["rare_event_bound"],
            "schema_version": "0.6.5",
            "endpoint_id": f"expensive-{index}",
            "observed_events": 500,
            "exposure": 1000,
            "confidence_level": confidence,
        }
        invariant.update(
            {
                "endpoint_id": f"expensive-{index}",
                "rare_event_bound": bound,
            }
        )
        expensive_invariants.append(invariant)
    payload["statistical_invariants"] = expensive_invariants

    monkeypatch.setattr(
        "agent_assure.schema.live.binomial_upper_bound_one_sided",
        lambda *_args, **_kwargs: pytest.fail("exact inversion ran before aggregate preflight"),
    )
    with pytest.raises(ValidationError, match="aggregate Clopper-Pearson exact-tail work"):
        LiveEvaluationReport.model_validate(payload)


def test_large_rare_event_protocol_uses_explicit_bounded_methods() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=4_096,
        clusters=4_096,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    )
    assert protocol.planned_clusters == 4_096
    assert protocol.advanced_analysis_plan is not None
    endpoint = next(
        candidate
        for candidate in protocol.advanced_analysis_plan.endpoints
        if candidate.analysis_method == "clopper_pearson_exact_one_sided"
    )

    zero_event = _rare_event_bound(
        endpoint,
        observed_events=0,
        exposure=4_096,
        confidence_alpha=Decimal("0.050000"),
        bonferroni_adjusted=False,
    )
    assert zero_event.analysis_method == "clopper_pearson_zero_event_closed_form"
    assert zero_event.upper_rate_bound == "0.000732"
    assert zero_event.upper_count_bound == "2.994638"
    assert type(zero_event).model_validate_json(zero_event.model_dump_json()) == zero_event
    Draft202012Validator(type(zero_event).model_json_schema(mode="validation")).validate(
        zero_event.model_dump(mode="json")
    )

    nonzero = _rare_event_bound(
        endpoint,
        observed_events=5,
        exposure=4_096,
        confidence_alpha=Decimal("0.050000"),
        bonferroni_adjusted=False,
    )
    assert nonzero.analysis_method == "bernoulli_kl_chernoff_upper_bound_one_sided"
    assert nonzero.upper_rate_bound == "0.003081"
    assert nonzero.upper_count_bound == "12.616453"
    assert any(
        "conservative one-sided Bernoulli KL-Chernoff" in limitation
        for limitation in nonzero.limitations
    )
    assert type(nonzero).model_validate_json(nonzero.model_dump_json()) == nonzero

    forged_method = zero_event.model_dump(mode="json")
    forged_method["analysis_method"] = "clopper_pearson_exact_one_sided"
    with pytest.raises(ValidationError, match="count/exposure regime"):
        type(zero_event).model_validate(forged_method)

    downgraded_method = zero_event.model_dump(mode="json")
    downgraded_method["schema_version"] = "0.6.5"
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(type(zero_event).model_json_schema(mode="validation")).validate(
            downgraded_method
        )
    with pytest.raises(ValidationError, match="historical rare-event bounds"):
        type(zero_event).model_validate(downgraded_method)


def test_p_value_serialization_cannot_round_a_result_down_across_alpha() -> None:
    raw_p_value = Decimal(52_429) / Decimal(1_048_576)
    serialized = probability_upper_string(raw_p_value)

    assert raw_p_value > Decimal("0.050000")
    assert serialized == "0.050001"

    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    )
    result = SimpleNamespace(
        adjusted_p_value=serialized,
        prerequisite_status="met",
        interpretation="confirmatory",
    )
    assert (
        _randomization_comparison_state(
            Decimal("0.100000"),
            Decimal("0"),
            result,
            protocol,
        )
        is GateState.not_evaluated
    )


def test_exact_permutation_null_behavior_is_not_anti_conservative() -> None:
    p_value, resamples, exhaustive = _permutation_p_value(
        (Decimal("1"), Decimal("-1"), Decimal("1"), Decimal("-1")),
        margin=Decimal("0"),
        method="paired_cluster_permutation_exact",
        seed="unused-for-exact-test",
    )

    assert exhaustive is True
    assert resamples == 16
    assert p_value == Decimal("0.6875")


def test_paired_permutation_rejects_nonzero_non_inferiority_margin() -> None:
    with pytest.raises(ValueError, match="zero non-inferiority margin"):
        _permutation_p_value(
            (Decimal("0.1"), Decimal("-0.1")),
            margin=Decimal("0.05"),
            method="paired_cluster_permutation_exact",
            seed="unused-for-exact-test",
        )

    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    ).model_dump(mode="json")
    payload["analysis_method"] = "paired_cluster_permutation_exact"

    with pytest.raises(ValueError, match="zero non_inferiority_margin"):
        LiveProtocolRecord.model_validate(payload)


def test_stable_seed_int_is_sha256_derived() -> None:
    assert stable_seed_int("agent-assure-seed") == int(
        "39dec969c19734e81fee5e704f5a2aea",
        16,
    )


def test_live_sha256_sampler_has_version_stable_index_and_sign_vectors() -> None:
    assert (
        LIVE_RESAMPLING_ALGORITHM_ID == "agent-assure/live-resampling/sha256-counter-rejection/v1"
    )
    indexes = seeded_sampler("agent-assure-seed")
    assert tuple(indexes.randbelow(7) for _ in range(12)) == (
        1,
        1,
        4,
        0,
        0,
        5,
        6,
        3,
        6,
        2,
        2,
        3,
    )
    signs = seeded_sampler("agent-assure-signs")
    assert tuple(signs.randbelow(2) for _ in range(16)) == (
        1,
        0,
        1,
        1,
        1,
        1,
        1,
        0,
        1,
        0,
        1,
        1,
        1,
        0,
        1,
        1,
    )


def test_bonferroni_alpha_is_conservatively_floored_to_six_places() -> None:
    compiled = compile_suite(SUITE)
    plan_payload = _advanced_plan(
        multiplicity_method="bonferroni",
        familywise_alpha="0.050000",
        primary_minimum_clusters=1,
        secondary_interpretation="confirmatory",
    )
    endpoints = plan_payload["endpoints"]
    assert isinstance(endpoints, list)
    third = dict(endpoints[1])
    third.update(
        {
            "endpoint_id": "critical-sensitive-content-secondary",
            "label": "Secondary critical sensitive-content events",
        }
    )
    endpoints.append(third)
    protocol = _protocol(
        compiled,
        observations=3,
        clusters=3,
        repetitions=1,
        advanced_analysis_plan=plan_payload,
    )

    assert protocol.advanced_analysis_plan is not None
    endpoint = protocol.advanced_analysis_plan.endpoints[0]
    assert _endpoint_alpha(
        endpoint,
        plan=protocol.advanced_analysis_plan,
        confirmatory_count=3,
    ) == Decimal("0.016666")


def test_advanced_plan_rejects_unadjusted_multiple_confirmatory_endpoints() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=6,
    ).model_dump(mode="json")
    payload["advanced_analysis_plan"] = _advanced_plan(
        multiplicity_method="none",
        primary_minimum_clusters=3,
        secondary_interpretation="confirmatory",
    )

    with pytest.raises(ValueError, match="multiple confirmatory endpoints"):
        LiveProtocolRecord.model_validate(payload)


def test_advanced_plan_accepts_bonferroni_multiple_confirmatory_endpoints() -> None:
    compiled = compile_suite(SUITE)

    protocol = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=6,
        advanced_analysis_plan=_advanced_plan(
            multiplicity_method="bonferroni",
            primary_minimum_clusters=3,
            secondary_interpretation="confirmatory",
        ),
    )

    assert protocol.advanced_analysis_plan is not None
    assert protocol.advanced_analysis_plan.multiplicity_method == "bonferroni"


def test_advanced_plan_rejects_zero_familywise_alpha() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    payload["advanced_analysis_plan"] = _advanced_plan(
        familywise_alpha="0.000000",
        primary_minimum_clusters=1,
    )

    with pytest.raises(ValueError, match="familywise_alpha must be greater than zero"):
        LiveProtocolRecord.model_validate(payload)


def test_advanced_plan_rejects_unrepresentable_bonferroni_alpha() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    payload["advanced_analysis_plan"] = _advanced_plan(
        multiplicity_method="bonferroni",
        familywise_alpha="0.000001",
        primary_minimum_clusters=1,
        secondary_interpretation="confirmatory",
    )

    with pytest.raises(ValueError, match="below the persisted six-decimal precision"):
        LiveProtocolRecord.model_validate(payload)


def test_advanced_plan_rejects_reserved_endpoint_hierarchy() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=6,
    ).model_dump(mode="json")
    payload["advanced_analysis_plan"] = _advanced_plan(
        multiplicity_method="bonferroni",
        primary_minimum_clusters=3,
    )
    payload["advanced_analysis_plan"]["endpoints"][0]["hierarchy_rank"] = 1

    with pytest.raises(ValueError, match="hierarchy_rank is reserved"):
        LiveProtocolRecord.model_validate(payload)


def test_advanced_plan_rejects_unimplemented_endpoint_analysis_methods() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=6,
        clusters=3,
        repetitions=6,
    ).model_dump(mode="json")
    plan = _advanced_plan(primary_minimum_clusters=3)
    plan["endpoints"][0]["analysis_method"] = "cluster_t_interval"
    payload["advanced_analysis_plan"] = plan

    with pytest.raises(ValueError, match="not implemented"):
        LiveProtocolRecord.model_validate(payload)


def test_rare_event_plan_requires_independence_cluster_exposure() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    plan = _advanced_plan(primary_minimum_clusters=1)
    endpoints = plan["endpoints"]
    assert isinstance(endpoints, list)
    endpoints[1]["exposure_unit"] = "observation"
    payload["advanced_analysis_plan"] = plan

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveProtocolRecord.model_json_schema(mode="validation")).validate(
            payload
        )
    with pytest.raises(ValueError, match="exposure_unit='independence_cluster'"):
        LiveProtocolRecord.model_validate(payload)


def test_current_rare_event_plan_rejects_legacy_poisson_selector() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    plan = _advanced_plan(primary_minimum_clusters=1)
    endpoints = plan["endpoints"]
    assert isinstance(endpoints, list)
    endpoints[1]["analysis_method"] = "poisson_upper_bound"
    payload["advanced_analysis_plan"] = plan

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveProtocolRecord.model_json_schema(mode="validation")).validate(
            payload
        )
    with pytest.raises(ValueError, match="clopper_pearson_exact_one_sided"):
        LiveProtocolRecord.model_validate(payload)


def test_current_protocol_enforces_bonferroni_floor_for_current_nested_plan() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    plan = _advanced_plan(
        multiplicity_method="bonferroni",
        familywise_alpha="0.000002",
        primary_minimum_clusters=1,
        secondary_interpretation="confirmatory",
    )
    endpoints = plan["endpoints"]
    assert isinstance(endpoints, list)
    third_endpoint = dict(endpoints[1])
    third_endpoint["endpoint_id"] = "critical-runtime-failure"
    endpoints.append(third_endpoint)
    payload["advanced_analysis_plan"] = plan

    with pytest.raises(ValueError, match="below the persisted six-decimal precision"):
        LiveProtocolRecord.model_validate(payload)


def test_rare_event_exact_binomial_bound_uses_protocol_confidence_not_familywise_alpha() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(
            familywise_alpha="0.100000",
            primary_minimum_clusters=1,
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-alpha-bound",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(_record(repetition_index=0, linked=True),),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)
    rare = next(
        invariant
        for invariant in report.statistical_invariants
        if invariant.endpoint_id == "critical-sensitive-content"
    )

    assert rare.adjusted_alpha == "0.100000"
    assert rare.rare_event_bound is not None
    assert rare.rare_event_bound.confidence_level == "0.950000"
    assert rare.analysis_method == "clopper_pearson_exact_one_sided"
    assert rare.rare_event_bound.analysis_method == "clopper_pearson_exact_one_sided"
    assert rare.rare_event_bound.upper_count_bound == "0.950001"
    assert rare.rare_event_bound.upper_rate_bound == "0.950001"


def test_confirmatory_bonferroni_exact_binomial_bound_uses_adjusted_alpha() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 2)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=2,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(
            multiplicity_method="bonferroni",
            familywise_alpha="0.050000",
            primary_minimum_clusters=2,
            secondary_interpretation="confirmatory",
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-bonferroni-poisson",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=tuple(
            _record(
                repetition_index=0,
                linked=True,
                case_id=f"case-{index:03d}",
                schedule_index=index,
            )
            for index in range(2)
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)
    rare = next(
        invariant
        for invariant in report.statistical_invariants
        if invariant.endpoint_id == "critical-sensitive-content"
    )

    assert rare.adjusted_alpha == "0.025000"
    assert rare.rare_event_bound is not None
    assert rare.rare_event_bound.confidence_level == "0.975000"
    assert rare.rare_event_bound.upper_count_bound == "1.683773"
    assert rare.rare_event_bound.upper_rate_bound == "0.841887"
    assert Decimal("1") - Decimal(rare.rare_event_bound.confidence_level) == Decimal(
        rare.adjusted_alpha
    )
    assert any(
        "Bonferroni multiplicity control" in limitation
        for limitation in rare.rare_event_bound.limitations
    )


def test_t_critical_lookup_rounds_down_to_conservative_bucket() -> None:
    assert t_critical_95("0.950000", 31) == Decimal("2.042272")
    assert t_critical_95("0.950000", 35) == Decimal("2.042272")
    assert t_critical_95("0.950000", 59) == Decimal("2.021075")
    assert t_critical_95("0.950000", 61) == Decimal("2.000298")
    assert t_critical_95("0.950000", 121) == Decimal("1.979930")


def test_live_intervals_ignore_and_restore_hostile_ambient_decimal_context() -> None:
    values = (Decimal("0"), Decimal("0.333333"), Decimal("0.666667"), Decimal("1"))
    expected_cluster = cluster_t_interval(values, "0.950000")
    expected_wilson = wilson_score_interval(Decimal("3"), 3, "0.950000")
    expected_poisson = _poisson_upper_count_bound(2, alpha=Decimal("0.050000"))
    expected_icc = _icc_from_counts(((1, 3), (2, 3), (1, 2)))

    with localcontext() as context:
        context.prec = 6
        context.rounding = ROUND_UP
        context.traps[Inexact] = True
        context.traps[Rounded] = True
        context.clear_flags()

        assert cluster_t_interval(values, "0.950000") == expected_cluster
        assert wilson_score_interval(Decimal("3"), 3, "0.950000") == expected_wilson
        assert _poisson_upper_count_bound(2, alpha=Decimal("0.050000")) == expected_poisson
        assert _icc_from_counts(((1, 3), (2, 3), (1, 2))) == expected_icc
        assert context.prec == 6
        assert context.rounding == ROUND_UP
        assert context.traps[Inexact] is True
        assert context.traps[Rounded] is True
        assert context.flags[Inexact] is False
        assert context.flags[Rounded] is False


def test_zero_width_difference_interval_is_labeled_as_degenerate() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=30, clusters=30, repetitions=1)
    center, lower, upper, compared_clusters = difference_t_interval(
        (Decimal("0.100000"),) * 30,
        protocol.confidence_level,
    )

    limitations = _comparison_limitations(
        protocol,
        compared_clusters,
        False,
        center,
        lower,
        upper,
    )

    assert center == Decimal("0.100000")
    assert lower == center
    assert upper == center
    assert any("collapsed to zero width" in limitation for limitation in limitations)


def test_zero_width_difference_interval_cannot_produce_confirmatory_pass() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 30)
    protocol = _protocol(compiled, observations=30, clusters=30, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)

    def report(runset_id: str, *, linked: bool) -> LiveEvaluationReport:
        return evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=runset_id,
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=tuple(
                    _record(
                        repetition_index=0,
                        linked=linked,
                        case_id=f"case-{index:03d}",
                        schedule_index=index,
                    )
                    for index in range(30)
                ),
            ),
            protocol=protocol,
        )

    comparison = compare_live_reports(
        report("baseline-degenerate", linked=False),
        report("candidate-degenerate", linked=True),
        protocol=protocol,
    )

    assert comparison.difference_ci_lower == comparison.difference_ci_upper
    assert comparison.exploratory is True
    assert comparison.state is GateState.not_evaluated


def test_zero_margin_identical_candidate_is_not_a_regression() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 30)
    protocol = _protocol(
        compiled,
        observations=30,
        clusters=30,
        repetitions=1,
        non_inferiority_margin="0.000000",
    )

    comparison = compare_live_reports(
        _case_report(compiled, protocol, runset_id="baseline-identical", count=30),
        _case_report(compiled, protocol, runset_id="candidate-identical", count=30),
        protocol=protocol,
    )

    assert comparison.pass_rate_difference == "0.000000"
    assert comparison.difference_ci_lower == "0.000000"
    assert comparison.state is GateState.not_evaluated
    assert any(
        "zero-margin equality boundary" in limitation for limitation in comparison.limitations
    )
    assert not any("gate fails closed" in limitation for limitation in comparison.limitations)


def test_live_statistics_accounts_for_declared_exclusions() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        allowed_exclusion_reasons=("provider_incident",),
        max_exclusion_rate="0.600000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-exclusions",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True),
            _record(
                repetition_index=1,
                linked=True,
                exclusion_reason="provider_incident",
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.state is GateState.pass_
    assert report.overall.included_observations == 1
    assert report.overall.excluded_observations == 1
    assert report.overall.exclusion_rate.rate == "0.500000"
    assert report.observations[1].state is GateState.not_evaluated


def test_zero_denominator_rate_estimation_fails_closed() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
    )

    with pytest.raises(ValueError, match="undefined for a zero observation denominator"):
        _rate_from_values(
            "expectation_pass",
            (),
            protocol=protocol,
            analysis_method="cluster_t_interval",
        )


def test_drift_zero_denominators_use_missing_metric_semantics() -> None:
    report = _aggregate_validation_report()
    reason_plan = DriftMetricPlan(
        artifact_kind="drift-metric-plan",
        metric="reason_code_rate",
        label="Sensitive-content rate",
        reason_codes=(ReasonCode.RAW_SENSITIVE_CONTENT,),
    )
    excluded_report = report.model_copy(
        update={
            "observations": tuple(
                observation.model_copy(update={"observation_status": "excluded"})
                for observation in report.observations
            )
        }
    )

    computed_rate = _metric_value(excluded_report, reason_plan)

    assert computed_rate.numerator == 0
    assert computed_rate.denominator == 0
    assert computed_rate.value is None

    persisted_rate = report.overall.expectation_pass_rate.model_copy(update={"denominator": 0})
    zero_denominator_report = report.model_copy(
        update={
            "overall": report.overall.model_copy(update={"expectation_pass_rate": persisted_rate})
        }
    )
    persisted_metric = _metric_value(
        zero_denominator_report,
        DriftMetricPlan(
            artifact_kind="drift-metric-plan",
            metric="expectation_pass_rate",
            label="Expectation pass rate",
        ),
    )

    assert persisted_metric.denominator == 0
    assert persisted_metric.value is None


def test_all_excluded_observations_fail_closed_without_fabricating_a_rate() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        allowed_exclusion_reasons=("provider_incident",),
        max_exclusion_rate="0.500000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-all-excluded",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                exclusion_reason="provider_incident",
            ),
            _record(
                repetition_index=1,
                linked=True,
                exclusion_reason="provider_incident",
            ),
        ),
    )

    with pytest.raises(ValueError, match="exceeds max_exclusion_rate"):
        evaluate_live_runset(compiled, runset, protocol=protocol)


def test_live_statistics_marks_budget_stop_as_incomplete() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-budget",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        completion_status="incomplete",
        stop_reasons=("budget_exhausted",),
        runs=(
            _record(repetition_index=0, linked=True),
            _record(
                repetition_index=1,
                linked=True,
                exclusion_reason="budget_exhausted",
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.state is GateState.not_evaluated
    assert report.completion_status == "incomplete"
    assert report.stop_reasons == ("budget_exhausted",)
    assert report.budget_exceeded is True


def test_live_monitoring_replays_effective_qualification_and_nested_budget_stops() -> None:
    compiled = compile_suite(SUITE)
    drift_plan = _drift_plan(minimum_windows=2)
    drift_plan["interpretation"] = "confirmatory"
    drift_plan["drift_hypothesis"] = "Source-qualified pass-rate drift remains estimable."
    metric_plan = drift_plan["metrics"][0]
    assert isinstance(metric_plan, dict)
    metric_plan["interpretation"] = "confirmatory"
    exploratory_trajectory_plan = _trajectory_plan()
    exploratory_trajectory_plan["analysis_methods"] = ["observable_transition_profile"]
    exploratory_trajectory_plan["invariants"] = []
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
        drift_monitoring_plan=drift_plan,
        trajectory_analysis_plan=exploratory_trajectory_plan,
    )
    protocol_digest = sha256_hexdigest(protocol)

    nested_budget_runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-nested-budget-stop",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
            _record(
                repetition_index=1,
                linked=True,
                exclusion_reason="budget_exhausted",
                started_at_utc="2026-06-27T00:00:02Z",
                completed_at_utc="2026-06-27T00:00:03Z",
            ),
        ),
    )
    complete_runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-complete-drift-window",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                started_at_utc="2026-06-27T00:01:00Z",
                completed_at_utc="2026-06-27T00:01:01Z",
            ),
            _record(
                repetition_index=1,
                linked=True,
                started_at_utc="2026-06-27T00:01:02Z",
                completed_at_utc="2026-06-27T00:01:03Z",
            ),
        ),
    )
    incomplete_evaluation = evaluate_live_runset(
        compiled,
        nested_budget_runset,
        protocol=protocol,
    )
    complete_evaluation = evaluate_live_runset(
        compiled,
        complete_runset,
        protocol=protocol,
    )

    assert nested_budget_runset.completion_status == "complete"
    assert nested_budget_runset.stop_reasons == ()
    assert incomplete_evaluation.source_completion_status == "complete"
    assert incomplete_evaluation.completion_status == "incomplete"
    assert incomplete_evaluation.stop_reasons == ("budget_exhausted",)

    erased_evaluation_payload = incomplete_evaluation.model_dump(mode="json")
    erased_evaluation_payload.update(
        {
            "completion_status": "complete",
            "stop_reasons": [],
            "budget_exceeded": False,
        }
    )
    with pytest.raises(ValidationError, match="observation-derived budget stop reasons"):
        LiveEvaluationReport.model_validate(erased_evaluation_payload)
    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(
            erased_evaluation_payload,
            "live-evaluation-report",
        )

    mixed_stop_runset = nested_budget_runset.model_copy(
        update={
            "completion_status": "incomplete",
            "stop_reasons": ("live_adapter_error",),
        }
    )
    mixed_stop_evaluation = evaluate_live_runset(
        compiled,
        mixed_stop_runset,
        protocol=protocol,
    )
    assert mixed_stop_evaluation.stop_reasons == (
        "budget_exhausted",
        "live_adapter_error",
    )
    assert (
        LiveEvaluationReport.model_validate(mixed_stop_evaluation.model_dump(mode="json"))
        == mixed_stop_evaluation
    )
    missing_observation_reason = mixed_stop_evaluation.model_dump(mode="json")
    missing_observation_reason["stop_reasons"] = ["live_adapter_error"]
    missing_observation_reason["budget_exceeded"] = False
    with pytest.raises(ValidationError, match="observation-derived budget stop reasons"):
        LiveEvaluationReport.model_validate(missing_observation_reason)
    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(
            missing_observation_reason,
            "live-evaluation-report",
        )

    trajectory = build_live_trajectory_report(
        nested_budget_runset,
        incomplete_evaluation,
        protocol=protocol,
    )
    verify_live_trajectory_report_sources(
        trajectory,
        nested_budget_runset,
        incomplete_evaluation,
        protocol=protocol,
    )
    assert trajectory.source_runset_completion_status == "complete"
    assert trajectory.source_evaluation_completion_status == "incomplete"
    assert trajectory.source_evaluation_stop_reasons == ("budget_exhausted",)
    assert trajectory.source_evaluation_exploratory is True
    assert trajectory.trajectory_status == "exploratory"
    assert (
        sum(
            event.count
            for event in trajectory.operational_events
            if event.event_type == "budget_stop"
        )
        == 1
    )
    assert any("source evaluation is incomplete" in item for item in trajectory.limitations)

    erased_updates = {
        "completion_status": "complete",
        "stop_reasons": (),
        "budget_exceeded": False,
    }
    copied_erased_evaluation = incomplete_evaluation.model_copy(update=erased_updates)
    constructed_erased_evaluation = type(incomplete_evaluation).model_construct(
        **{**incomplete_evaluation.__dict__, **erased_updates}
    )
    for forged_evaluation in (
        copied_erased_evaluation,
        constructed_erased_evaluation,
    ):
        with pytest.raises(ValidationError, match="observation-derived budget stop reasons"):
            build_live_trajectory_report(
                nested_budget_runset,
                forged_evaluation,
                protocol=protocol,
            )
        with pytest.raises(ValidationError, match="observation-derived budget stop reasons"):
            verify_live_trajectory_report_sources(
                trajectory,
                nested_budget_runset,
                forged_evaluation,
                protocol=protocol,
            )

    assert trajectory.trajectory_plan is not None
    erased_budget_events = tuple(
        event for event in trajectory.operational_events if event.event_type != "budget_stop"
    )
    erased_budget_payload = trajectory.model_dump(mode="json")
    erased_budget_payload["operational_events"] = [
        event.model_dump(mode="json") for event in erased_budget_events
    ]
    erased_budget_payload["event_processes"] = [
        process.model_dump(mode="json")
        for process in (
            live_trajectory._event_processes(
                erased_budget_events,
                exposure=len(trajectory.paths),
                plan=trajectory.trajectory_plan,
            )
            if "event_process_summary" in trajectory.trajectory_plan.analysis_methods
            else ()
        )
    ]
    erased_budget_payload["report_id"] = live_trajectory._trajectory_report_id(
        protocol_digest=trajectory.protocol_digest,
        plan=trajectory.trajectory_plan,
        source_runset_digest=trajectory.source_runset_digest or "",
        source_evaluation_digest=trajectory.source_evaluation_digest or "",
        source_runset_completion_status=trajectory.source_runset_completion_status,
        source_evaluation_completion_status=trajectory.source_evaluation_completion_status,
        source_evaluation_stop_reasons=trajectory.source_evaluation_stop_reasons,
        source_evaluation_exploratory=trajectory.source_evaluation_exploratory,
        paths=trajectory.paths,
        operational_events=erased_budget_events,
    )
    with pytest.raises(ValidationError, match="budget-stop events"):
        LiveTrajectoryReport.model_validate(erased_budget_payload)
    with pytest.raises(ValueError, match="failed model validation"):
        schema_validation.validate_artifact_payload(
            erased_budget_payload,
            "live-trajectory-report",
        )

    drift = build_live_drift_report(
        (incomplete_evaluation, complete_evaluation),
        protocol=protocol,
    )
    verify_live_drift_report_sources(
        drift,
        (incomplete_evaluation, complete_evaluation),
        protocol=protocol,
    )
    assert drift.windows[0].source_runset_completion_status == "complete"
    assert drift.windows[0].source_evaluation_completion_status == "incomplete"
    assert drift.windows[0].source_evaluation_exploratory is True
    assert drift.windows[1].source_evaluation_completion_status == "complete"
    assert drift.monitoring_status == "invalid"
    assert drift.diagnostics[0].prerequisite_status == "invalid"
    assert any("source evaluations are incomplete" in item for item in drift.limitations)

    confirmatory_trajectory_plan = _trajectory_plan()
    confirmatory_trajectory_plan["interpretation"] = "confirmatory"
    confirmatory_invariant = confirmatory_trajectory_plan["invariants"][0]
    assert isinstance(confirmatory_invariant, dict)
    confirmatory_invariant["interpretation"] = "confirmatory"
    confirmatory_protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
        trajectory_analysis_plan=confirmatory_trajectory_plan,
    )
    confirmatory_protocol_digest = sha256_hexdigest(confirmatory_protocol)
    confirmatory_runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-confirmatory-nested-budget-stop",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=confirmatory_protocol.protocol_id,
        protocol_digest=confirmatory_protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                human_review_required=True,
                human_review_performed=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
            _record(
                repetition_index=1,
                linked=True,
                exclusion_reason="budget_exhausted",
                started_at_utc="2026-06-27T00:00:02Z",
                completed_at_utc="2026-06-27T00:00:03Z",
            ),
        ),
    )
    confirmatory_evaluation = evaluate_live_runset(
        compiled,
        confirmatory_runset,
        protocol=confirmatory_protocol,
    )
    confirmatory_trajectory = build_live_trajectory_report(
        confirmatory_runset,
        confirmatory_evaluation,
        protocol=confirmatory_protocol,
    )
    assert confirmatory_trajectory.source_evaluation_completion_status == "incomplete"
    assert confirmatory_trajectory.source_evaluation_exploratory is True
    assert confirmatory_trajectory.trajectory_status == "invalid"

    forged_qualification = trajectory.model_dump(mode="json")
    forged_qualification["source_evaluation_completion_status"] = "complete"
    with pytest.raises(ValidationError, match="status|limitations|report_id"):
        LiveTrajectoryReport.model_validate(forged_qualification)


def test_live_comparison_marks_incomplete_reports_not_evaluated() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
        non_inferiority_margin="0.000000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live-complete",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live-incomplete",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            completion_status="incomplete",
            stop_reasons=("budget_exhausted",),
            runs=(
                _record(repetition_index=0, linked=True),
                _record(
                    repetition_index=1,
                    linked=True,
                    exclusion_reason="budget_exhausted",
                ),
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.state is GateState.not_evaluated
    assert comparison.exploratory is True
    assert comparison.compared_clusters == 0
    assert comparison.randomization_tests == ()
    assert type(comparison).model_validate_json(comparison.model_dump_json()) == comparison
    assert any("candidate live report is incomplete" in item for item in comparison.limitations)
    assert (
        "source-evaluation digests are external linkage; latency and cost absolutes remain "
        "source-declarative until both digests are resolved against trusted evaluation reports"
        in comparison.limitations
    )

    forged_state = comparison.model_dump(mode="json")
    forged_state["state"] = "fail"
    with pytest.raises(ValidationError, match="zero-cluster comparison must be not_evaluated"):
        type(comparison).model_validate(forged_state)


def test_live_statistics_marks_post_response_budget_stop_as_incomplete() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-budget-after-response",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        completion_status="incomplete",
        stop_reasons=("cost_budget_exceeded_after_response",),
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                cost="0.000000",
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.state is GateState.not_evaluated
    assert report.budget_exceeded is True


def test_live_statistics_preserves_included_failures_after_budget_stop() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-budget-after-response-failure",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        completion_status="incomplete",
        stop_reasons=("cost_budget_exceeded_after_response",),
        runs=(
            _record(
                repetition_index=0,
                linked=False,
                cost="0.000000",
            ),
        ),
    )

    report = evaluate_live_runset(compiled, runset, protocol=protocol)

    assert report.state is GateState.fail
    assert report.budget_exceeded is True


def test_live_statistics_rejects_cumulative_total_token_budget_violation() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_total_tokens=10,
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-total-token-overrun",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(repetition_index=0, linked=True, total_tokens=6),
            _record(repetition_index=1, linked=True, total_tokens=6),
        ),
    )

    with pytest.raises(ValueError, match="total_tokens exceeds protocol max_total_tokens"):
        evaluate_live_runset(compiled, runset, protocol=protocol)


def test_live_record_rejects_understated_budget_commitments() -> None:
    with pytest.raises(ValueError, match="commitment cannot be below estimated cost"):
        _record(
            repetition_index=0,
            linked=True,
            cost="1.000000",
            cost_budget_committed="0.500000",
        )

    with pytest.raises(
        ValueError,
        match="generated-token budget commitment cannot be below completion_tokens",
    ):
        _record(
            repetition_index=0,
            linked=True,
            completion_tokens=10,
            total_tokens=10,
            generated_token_budget_committed=5,
            total_token_budget_committed=10,
        )


def test_live_comparison_reports_pass_rate_difference() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=False),
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(
        baseline,
        candidate,
        protocol=protocol,
    )

    assert comparison.state is GateState.fail
    assert comparison.pass_rate_difference == "-0.500000"
    assert comparison.analysis_method == "paired_cluster_t_interval"
    assert comparison.compared_clusters == 1
    assert comparison.exploratory is True
    assert comparison.effective_n == "1.666667"
    assert comparison.baseline_pass_rate.rate == "1.000000"
    assert comparison.candidate_pass_rate.rate == "0.500000"


def test_live_comparison_reports_unclamped_latency_and_cost_differences() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        max_cost_per_observation_usd="5.000000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(
                    repetition_index=0,
                    linked=True,
                    latency_ms=100,
                    cost="0.500000",
                ),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(
                    repetition_index=0,
                    linked=True,
                    latency_ms=1500,
                    cost="3.000000",
                ),
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.latency_p50_difference_ms == "1400.000000"
    assert comparison.cost_total_difference_usd == "2.500000"


def test_live_comparison_honors_paired_bootstrap_protocol_method() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        analysis_method="paired_cluster_bootstrap_percentile",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=False),
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.analysis_method == "paired_cluster_bootstrap_percentile"
    assert comparison.pass_rate_difference == "-0.500000"
    assert comparison.exploratory is True


def test_live_comparison_reports_exact_paired_randomization_test() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(
        compiled,
        observations=5,
        clusters=5,
        repetitions=1,
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=5),
        non_inferiority_margin="0.000000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=tuple(
                _record(
                    repetition_index=0,
                    linked=False,
                    case_id=f"case-{index:03d}",
                    schedule_index=index,
                )
                for index in range(5)
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=tuple(
                _record(
                    repetition_index=0,
                    linked=True,
                    case_id=f"case-{index:03d}",
                    schedule_index=index,
                )
                for index in range(5)
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.state is GateState.not_evaluated
    assert comparison.exploratory is True
    assert comparison.pass_rate_difference == "1.000000"
    assert len(comparison.randomization_tests) == 1
    test = comparison.randomization_tests[0]
    assert test.interpretation == "exploratory"
    assert test.prerequisite_status == "exploratory"
    assert test.p_value == "0.031250"
    assert test.adjusted_p_value == "0.031250"
    assert test.exhaustive is True
    assert test.resamples == 32


def test_current_comparison_round_trip_rejects_impossible_math_tests_and_gate_state() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(
        compiled,
        observations=5,
        clusters=5,
        repetitions=1,
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=5),
        non_inferiority_margin="0.000000",
    )
    comparison = compare_live_reports(
        _case_report(
            compiled,
            protocol,
            runset_id="validation-baseline",
            count=5,
            linked=False,
        ),
        _case_report(
            compiled,
            protocol,
            runset_id="validation-candidate",
            count=5,
            linked=True,
        ),
        protocol=protocol,
    )
    comparison_type = type(comparison)
    assert comparison_type.model_validate_json(comparison.model_dump_json()) == comparison
    source_linkage_limitation = (
        "source-evaluation digests are external linkage; latency and cost absolutes remain "
        "source-declarative until both digests are resolved against trusted evaluation reports"
    )
    assert source_linkage_limitation in comparison.limitations
    assert all(
        (
            item.baseline_numerator,
            item.baseline_denominator,
            item.candidate_numerator,
            item.candidate_denominator,
        )
        == (0, 1, 1, 1)
        for item in comparison.paired_clusters
    )

    comparison_schema = Draft202012Validator(comparison_type.model_json_schema(mode="validation"))
    comparison_schema.validate(comparison.model_dump(mode="json"))
    for required_field in (
        "derivation_contract",
        "baseline_evaluation_digest",
        "candidate_evaluation_digest",
        "baseline_completion_status",
        "candidate_completion_status",
        "protocol",
    ):
        missing_binding = comparison.model_dump(mode="json")
        missing_binding.pop(required_field)
        with pytest.raises(JsonSchemaValidationError):
            comparison_schema.validate(missing_binding)

    downgraded_protocol = comparison.model_dump(mode="json")
    downgraded_protocol["protocol"]["schema_version"] = "0.6.5"
    with pytest.raises(JsonSchemaValidationError):
        comparison_schema.validate(downgraded_protocol)
    with pytest.raises(ValidationError, match="current bound protocol record"):
        comparison_type.model_validate(downgraded_protocol)

    missing_source_linkage_boundary = comparison.model_dump(mode="json")
    missing_source_linkage_boundary["limitations"].remove(source_linkage_limitation)
    with pytest.raises(JsonSchemaValidationError):
        comparison_schema.validate(missing_source_linkage_boundary)
    with pytest.raises(ValidationError, match="limitations does not match source-derived"):
        comparison_type.model_validate(missing_source_linkage_boundary)

    missing_paired_count = comparison.model_dump(mode="json")
    missing_paired_count["paired_clusters"][0].pop("candidate_denominator")
    with pytest.raises(JsonSchemaValidationError):
        comparison_schema.validate(missing_paired_count)
    with pytest.raises(ValidationError, match="require per-arm count evidence"):
        comparison_type.model_validate(missing_paired_count)

    downgraded_nested_rate = comparison.model_dump(mode="json")
    downgraded_nested_rate["candidate_pass_rate"]["schema_version"] = "0.6.5"
    with pytest.raises(JsonSchemaValidationError):
        comparison_schema.validate(downgraded_nested_rate)
    with pytest.raises(ValidationError, match="current nested statistical artifacts"):
        comparison_type.model_validate(downgraded_nested_rate)

    forged_inference = comparison.model_dump(mode="json")
    forged_inference["exploratory"] = False
    forged_inference["randomization_tests"][0].update(
        {
            "p_value": "1.000000",
            "adjusted_p_value": "1.000000",
            "interpretation": "confirmatory",
        }
    )
    with pytest.raises(ValidationError, match="source-derived comparison evidence"):
        comparison_type.model_validate(forged_inference)

    inconsistent_rate = comparison.model_dump(mode="json")
    inconsistent_rate["candidate_pass_rate"].update(
        {
            "numerator": 0,
            "denominator": 1,
            "cluster_count": 1,
            "rate": "1.000000",
        }
    )
    with pytest.raises(
        ValidationError,
        match=r"rate does not match numerator(?: and |/)denominator",
    ):
        comparison_type.model_validate(inconsistent_rate)

    downgraded_rate_derivation = comparison.model_dump(mode="json")
    downgraded_rate_derivation["candidate_pass_rate"].update(
        {
            "effective_n": "999999999.000000",
        }
    )
    with pytest.raises(
        ValidationError,
        match="effective sample sizes and design effects do not match",
    ):
        comparison_type.model_validate(downgraded_rate_derivation)

    mismatched_cluster_denominator = comparison.model_dump(mode="json")
    mismatched_cluster_denominator["paired_clusters"][0]["baseline_denominator"] = 2
    with pytest.raises(
        ValidationError,
        match="concurrent paired cluster arm denominators must be equal",
    ):
        comparison_type.model_validate(mismatched_cluster_denominator)

    mismatched_cluster_rate = comparison.model_dump(mode="json")
    mismatched_cluster_rate["paired_clusters"][0]["candidate_numerator"] = 0
    with pytest.raises(
        ValidationError,
        match="candidate rate does not match numerator and denominator",
    ):
        comparison_type.model_validate(mismatched_cluster_rate)

    forged_arm_summary = comparison.model_dump(mode="json")
    forged_arm_summary["candidate_pass_rate"].update(
        {
            "numerator": 4,
            "rate": "0.800000",
            "cluster_mean_rate": "0.800000",
            "interval_center_value": "0.800000",
            "ci_lower": "0.800000",
        }
    )
    forged_arm_summary["pass_rate_difference"] = "0.800000"
    forged_arm_summary["randomization_tests"][0]["observed_difference"] = "0.800000"
    with pytest.raises(
        ValidationError,
        match="candidate_pass_rate does not match source-derived comparison evidence",
    ):
        comparison_type.model_validate(forged_arm_summary)

    for field_name, forged_value in (
        ("ci_lower", "0.500000"),
        ("analysis_method", "forged_method"),
        ("exploratory", False),
    ):
        forged_derivation = comparison.model_dump(mode="json")
        forged_derivation["candidate_pass_rate"][field_name] = forged_value
        with pytest.raises(
            ValidationError,
            match="candidate_pass_rate does not match source-derived comparison evidence",
        ):
            comparison_type.model_validate(forged_derivation)

    inconsistent_difference = comparison.model_dump(mode="json")
    inconsistent_difference["pass_rate_difference"] = "-1.000000"
    with pytest.raises(ValidationError, match="candidate minus baseline"):
        comparison_type.model_validate(inconsistent_difference)

    inconsistent_test = comparison.model_dump(mode="json")
    inconsistent_test["randomization_tests"][0]["observed_difference"] = "-1.000000"
    with pytest.raises(ValidationError, match="observed_difference does not match"):
        comparison_type.model_validate(inconsistent_test)

    impossible_adjustment = comparison.model_dump(mode="json")
    impossible_adjustment["randomization_tests"][0]["adjusted_p_value"] = "0.000001"
    with pytest.raises(ValidationError, match="adjusted_p_value cannot be below p_value"):
        comparison_type.model_validate(impossible_adjustment)

    zero_p_value = comparison.model_dump(mode="json")
    zero_p_value["randomization_tests"][0].update(
        {"p_value": "0.000000", "adjusted_p_value": "0.000000"}
    )
    with pytest.raises(ValidationError, match="not attainable from its resample count"):
        comparison_type.model_validate(zero_p_value)

    off_lattice_p_value = comparison.model_dump(mode="json")
    off_lattice_p_value["randomization_tests"][0].update(
        {"p_value": "0.050000", "adjusted_p_value": "0.050000"}
    )
    with pytest.raises(ValidationError, match="not attainable from its resample count"):
        comparison_type.model_validate(off_lattice_p_value)

    invalid_prerequisites = comparison.model_dump(mode="json")
    invalid_prerequisites["randomization_tests"][0]["prerequisite_status"] = "invalid"
    with pytest.raises(ValidationError, match="invalid prerequisites cannot carry a p-value"):
        comparison_type.model_validate(invalid_prerequisites)

    impossible_cluster_count = comparison.model_dump(mode="json")
    impossible_cluster_count["compared_clusters"] = 6
    impossible_cluster_count["randomization_tests"][0].update(
        {
            "compared_clusters": 6,
            "resamples": 64,
            "p_value": "0.031250",
            "adjusted_p_value": "0.031250",
        }
    )
    with pytest.raises(ValidationError, match="cannot exceed either arm cluster_count"):
        comparison_type.model_validate(impossible_cluster_count)

    forged_partial_pairing = comparison.model_dump(mode="json")
    forged_partial_pairing["compared_clusters"] = 4
    forged_partial_pairing["randomization_tests"][0].update(
        {
            "compared_clusters": 4,
            "resamples": 16,
            "p_value": "0.062500",
            "adjusted_p_value": "0.062500",
        }
    )
    with pytest.raises(ValidationError, match="source-derived comparison evidence"):
        comparison_type.model_validate(forged_partial_pairing)

    monte_carlo_boundary = comparison.randomization_tests[0].model_dump(mode="json")
    monte_carlo_boundary.update(
        {
            "analysis_method": "paired_cluster_permutation_monte_carlo",
            "exhaustive": False,
            "resamples": 10_001,
            "seed": "123",
            "p_value": "0.000100",
            "adjusted_p_value": "0.000100",
        }
    )
    test_type = type(comparison.randomization_tests[0])
    assert test_type.model_validate(monte_carlo_boundary).p_value == "0.000100"
    monte_carlo_boundary.update({"p_value": "0.000101", "adjusted_p_value": "0.000101"})
    with pytest.raises(ValidationError, match="not attainable from its resample count"):
        test_type.model_validate(monte_carlo_boundary)

    inconsistent_method = comparison.model_dump(mode="json")
    inconsistent_method["analysis_method"] = "made_up_method"
    with pytest.raises(ValidationError, match="inconsistent comparison analysis_method"):
        comparison_type.model_validate(inconsistent_method)

    zero_cluster_with_test = comparison.model_dump(mode="json")
    zero_cluster_with_test.update(
        {
            "compared_clusters": 0,
            "effective_n": "0.000000",
            "state": "not_evaluated",
        }
    )
    with pytest.raises(ValidationError, match="randomization test cardinality"):
        comparison_type.model_validate(zero_cluster_with_test)

    zero_cluster_without_test = comparison.model_dump(mode="json")
    zero_cluster_without_test.update(
        {
            "compared_clusters": 0,
            "effective_n": "0.000000",
            "state": "not_evaluated",
            "randomization_tests": [],
        }
    )
    with pytest.raises(ValidationError, match="source-derived comparison evidence"):
        comparison_type.model_validate(zero_cluster_without_test)

    false_pass = comparison.model_dump(mode="json")
    false_pass["state"] = "pass"
    with pytest.raises(ValidationError, match="cannot claim a passing gate state"):
        comparison_type.model_validate(false_pass)

    false_failure = comparison.model_dump(mode="json")
    false_failure["state"] = "fail"
    with pytest.raises(ValidationError, match="claims an impossible non-inferiority breach"):
        comparison_type.model_validate(false_failure)

    reversed_interval = comparison.model_dump(mode="json")
    reversed_interval.update(
        {
            "difference_ci_lower": "0.500000",
            "difference_ci_upper": "0.400000",
        }
    )
    with pytest.raises(ValidationError, match="interval endpoints are reversed"):
        comparison_type.model_validate(reversed_interval)


def test_zero_margin_identical_candidate_is_not_a_randomization_regression() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(
        compiled,
        observations=5,
        clusters=5,
        repetitions=1,
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=5),
        non_inferiority_margin="0.000000",
    )

    comparison = compare_live_reports(
        _case_report(
            compiled,
            protocol,
            runset_id="baseline-randomization-identical",
            count=5,
        ),
        _case_report(
            compiled,
            protocol,
            runset_id="candidate-randomization-identical",
            count=5,
        ),
        protocol=protocol,
    )

    assert comparison.pass_rate_difference == "0.000000"
    assert comparison.state is GateState.not_evaluated
    assert comparison.randomization_tests[0].p_value == "1.000000"
    assert any(
        "zero-margin equality boundary" in limitation for limitation in comparison.limitations
    )
    assert not any("gate fails closed" in limitation for limitation in comparison.limitations)

    false_failure = comparison.model_dump(mode="json")
    false_failure["state"] = "fail"
    with pytest.raises(ValidationError, match="state does not match source-derived"):
        type(comparison).model_validate(false_failure)

    breached = compare_live_reports(
        _case_report(
            compiled,
            protocol,
            runset_id="baseline-randomization-breach",
            count=5,
        ),
        _case_report(
            compiled,
            protocol,
            runset_id="candidate-randomization-breach",
            count=5,
            linked=False,
        ),
        protocol=protocol,
    )
    assert breached.pass_rate_difference == "-1.000000"
    assert breached.state is GateState.fail
    assert any(
        "does not prove candidate inferiority" in limitation for limitation in breached.limitations
    )


def test_paired_randomization_rejects_non_pass_rate_primary_endpoint() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=5,
        clusters=5,
        repetitions=5,
    ).model_dump(mode="json")
    payload["analysis_method"] = "paired_cluster_permutation_exact"
    payload["non_inferiority_margin"] = "0.000000"
    payload["primary_endpoint"] = "reason_code_rate"
    payload["advanced_analysis_plan"] = {
        "artifact_kind": "advanced-analysis-plan",
        "schema_version": "0.2.0",
        "multiplicity_method": "single_endpoint",
        "familywise_alpha": "0.050000",
        "observed_icc_confirmatory_use": "disabled",
        "endpoints": [
            {
                "artifact_kind": "statistical-endpoint-plan",
                "schema_version": "0.2.0",
                "endpoint_id": "material-evidence-failure",
                "label": "Material evidence failures",
                "endpoint_kind": "reason_code_rate",
                "role": "primary",
                "interpretation": "confirmatory",
                "analysis_method": "descriptive_rate",
                "reason_codes": [ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE.value],
                "minimum_clusters": 5,
                "minimum_observations": 5,
                "exchangeability_assumption": "baseline_candidate_relabeling",
            },
        ],
    }

    with pytest.raises(ValueError, match="supports only an expectation_pass_rate"):
        LiveProtocolRecord.model_validate(payload)


def test_bonferroni_randomization_uses_adjusted_p_against_familywise_alpha() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 5)
    protocol = _protocol(
        compiled,
        observations=5,
        clusters=5,
        repetitions=1,
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(
            multiplicity_method="bonferroni",
            familywise_alpha="0.100000",
            primary_minimum_clusters=5,
            secondary_interpretation="confirmatory",
        ),
        non_inferiority_margin="0.000000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=tuple(
                _record(
                    repetition_index=0,
                    linked=False,
                    case_id=f"case-{index:03d}",
                    schedule_index=index,
                )
                for index in range(5)
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=tuple(
                _record(
                    repetition_index=0,
                    linked=True,
                    case_id=f"case-{index:03d}",
                    schedule_index=index,
                )
                for index in range(5)
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)
    primary = next(
        invariant
        for invariant in baseline.statistical_invariants
        if invariant.endpoint_id == "expectation-pass"
    )
    test = comparison.randomization_tests[0]
    plan = protocol.advanced_analysis_plan
    assert plan is not None

    assert primary.adjusted_alpha == "0.050000"
    assert test.p_value == "0.031250"
    assert test.adjusted_p_value == "0.062500"
    assert Decimal(test.adjusted_p_value) > Decimal(primary.adjusted_alpha)
    assert Decimal(test.adjusted_p_value) <= Decimal(plan.familywise_alpha)
    assert comparison.state is GateState.not_evaluated
    assert comparison.exploratory is True


def test_exact_paired_randomization_rejects_protocol_above_enumeration_limit() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 21)
    with pytest.raises(ValidationError, match="at most 17 planned clusters"):
        _protocol(
            compiled,
            observations=21,
            clusters=21,
            repetitions=1,
            analysis_method="paired_cluster_permutation_exact",
            advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=21),
            non_inferiority_margin="0.000000",
        )


def test_live_comparison_rejects_mismatched_paired_case_repetition_sets() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = candidate.model_copy(
        update={
            "observations": (
                candidate.observations[0],
                candidate.observations[1].model_copy(update={"repetition_index": 2}),
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="identical included prompt, schedule|repetition_index is outside the protocol grid",
    ):
        compare_live_reports(baseline, candidate, protocol=protocol)


def test_live_comparison_uses_fixed_reference_protocol_mode() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        baseline_mode="fixed_reference",
        analysis_method="fixed_reference_cluster_t_interval",
        fixed_reference_pass_rate="0.750000",
    )
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=False),
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.analysis_method == "fixed_reference_cluster_t_interval"
    assert comparison.baseline_pass_rate.rate == "0.750000"
    assert comparison.pass_rate_difference == "-0.250000"
    assert comparison.fixed_reference_pass_rate == "0.750000"
    assert len(comparison.paired_clusters) == 1
    paired_cluster = comparison.paired_clusters[0]
    assert (paired_cluster.baseline_numerator, paired_cluster.baseline_denominator) == (0, 0)
    assert (paired_cluster.candidate_numerator, paired_cluster.candidate_denominator) == (1, 2)

    forged_reference_counts = comparison.model_dump(mode="json")
    forged_reference_counts["paired_clusters"][0].update(
        {
            "baseline_numerator": 1,
            "baseline_denominator": 1,
            "baseline_rate": "1.000000",
            "difference": "-0.500000",
        }
    )
    with pytest.raises(
        ValidationError,
        match="fixed-reference paired cluster baseline counts must be 0/0",
    ):
        type(comparison).model_validate(forged_reference_counts)

    forged_method = comparison.model_dump(mode="json")
    forged_method["analysis_method"] = "paired_cluster_permutation_exact"
    with pytest.raises(ValidationError, match="inconsistent comparison analysis_method"):
        type(comparison).model_validate(forged_method)


def test_live_comparison_difference_uses_exact_count_ratios_before_rounding() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 1)
    protocol = _protocol(
        compiled,
        observations=3,
        clusters=1,
        repetitions=3,
    )
    comparison = compare_live_reports(
        _cluster_success_report(
            compiled,
            protocol,
            runset_id="baseline-third",
            successes=(1,),
        ),
        _cluster_success_report(
            compiled,
            protocol,
            runset_id="candidate-two-thirds",
            successes=(2,),
        ),
        protocol=protocol,
    )

    paired_cluster = comparison.paired_clusters[0]
    assert paired_cluster.baseline_rate == "0.333333"
    assert paired_cluster.candidate_rate == "0.666667"
    assert paired_cluster.difference == "0.333333"
    assert comparison.pass_rate_difference == "0.333333"
    assert type(comparison).model_validate_json(comparison.model_dump_json()) == comparison

    double_rounded = paired_cluster.model_dump(mode="json")
    double_rounded["difference"] = "0.333334"
    with pytest.raises(ValidationError, match="difference must equal candidate minus baseline"):
        type(paired_cluster).model_validate(double_rounded)

    legacy_display_projection = dict(double_rounded)
    legacy_display_projection["schema_version"] = "0.6.5"
    for field_name in (
        "baseline_numerator",
        "baseline_denominator",
        "candidate_numerator",
        "candidate_denominator",
    ):
        legacy_display_projection.pop(field_name)
    assert type(paired_cluster).model_validate(legacy_display_projection).difference == "0.333334"


def test_live_comparison_rejects_unpaired_cluster_sets() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="candidate-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=protocol_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    candidate = candidate.model_copy(
        update={
            "observations": (
                candidate.observations[0],
                candidate.observations[1].model_copy(update={"cluster_id": "candidate-only"}),
            )
        }
    )

    with pytest.raises(
        ValueError,
        match="identical included prompt, schedule|cluster_id does not match protocol.cluster_by",
    ):
        compare_live_reports(baseline, candidate, protocol=protocol)


def test_ar1_summary_suppresses_a_fit_outside_the_stationary_range() -> None:
    summary = _ar1_summary(
        (Decimal("0.100000"), Decimal("0.200000"), Decimal("0.400000"), Decimal("0.800000"))
    )

    assert summary == (None, None, None, True)


def test_drift_slope_uses_observation_weighted_least_squares() -> None:
    slope = _slope(
        (
            (0, Decimal("0"), 1_000),
            (1, Decimal("0"), 1_000),
            (2, Decimal("1"), 1),
        )
    )

    assert slope is not None
    assert abs(slope) < Decimal("0.01")
    assert (
        _slope(
            (
                (0, Decimal("0"), 1_000),
                (1, Decimal("1"), 0),
            )
        )
        is None
    )


def test_drift_analysis_methods_require_an_authoritative_descriptive_basis() -> None:
    metric = _drift_plan()["metrics"][0]
    assert isinstance(metric, dict)

    empty = {**metric, "analysis_methods": []}
    with pytest.raises(ValidationError):
        DriftMetricPlan.model_validate(empty)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(DriftMetricPlan.model_json_schema()).validate(empty)

    undeclared_descriptive = {**metric, "analysis_methods": ["state_space_ewma"]}
    with pytest.raises(ValidationError, match="descriptive_trend"):
        DriftMetricPlan.model_validate(undeclared_descriptive)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(DriftMetricPlan.model_json_schema()).validate(undeclared_descriptive)


def _assert_current_set_like_sequence_contract(
    model: Any,
    payload: dict[str, object],
    *,
    field_name: str,
    canonical_values: tuple[str, ...],
    historical_duplicates_allowed: bool,
) -> None:
    canonical = {**payload, field_name: list(canonical_values)}
    model.model_validate(canonical)
    writer_validator = Draft202012Validator(writer_json_schema(model))
    writer_validator.validate(canonical)

    permuted = {**canonical, field_name: list(reversed(canonical_values))}
    with pytest.raises(ValidationError, match="canonical order"):
        model.model_validate(permuted)
    # Array ordering is a relational runtime contract; JSON Schema still
    # enforces membership and uniqueness for the current writer.
    writer_validator.validate(permuted)

    duplicated = {**canonical, field_name: [canonical_values[0], canonical_values[0]]}
    with pytest.raises(ValidationError, match="unique"):
        model.model_validate(duplicated)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(duplicated)

    legacy_permuted = {**permuted, "schema_version": "0.6.5"}
    model.model_validate(legacy_permuted)
    legacy_duplicated = {**duplicated, "schema_version": "0.6.5"}
    if historical_duplicates_allowed:
        model.model_validate(legacy_duplicated)
    else:
        with pytest.raises(ValidationError, match="unique"):
            model.model_validate(legacy_duplicated)


def test_current_reason_code_sets_require_unique_canonical_order() -> None:
    reason_codes = (
        ReasonCode.EXPECTED_OUTCOME_MISMATCH.value,
        ReasonCode.FORBIDDEN_OUTCOME.value,
    )
    _assert_current_set_like_sequence_contract(
        StatisticalEndpointPlan,
        {
            "artifact_kind": "statistical-endpoint-plan",
            "schema_version": "0.6.6",
            "endpoint_id": "reason-code-endpoint",
            "label": "Reason-code endpoint",
            "endpoint_kind": "reason_code_rate",
            "analysis_method": "descriptive_rate",
        },
        field_name="reason_codes",
        canonical_values=reason_codes,
        historical_duplicates_allowed=True,
    )
    _assert_current_set_like_sequence_contract(
        DriftMetricPlan,
        {
            "artifact_kind": "drift-metric-plan",
            "schema_version": "0.6.6",
            "metric": "reason_code_rate",
            "label": "Reason-code rate",
            "analysis_methods": ["descriptive_trend"],
        },
        field_name="reason_codes",
        canonical_values=reason_codes,
        historical_duplicates_allowed=True,
    )


def test_current_analysis_method_sets_require_declaration_order() -> None:
    _assert_current_set_like_sequence_contract(
        DriftMetricPlan,
        {
            "artifact_kind": "drift-metric-plan",
            "schema_version": "0.6.6",
            "metric": "expectation_pass_rate",
            "label": "Expectation pass rate",
        },
        field_name="analysis_methods",
        canonical_values=("descriptive_trend", "lag1_autocorrelation"),
        historical_duplicates_allowed=False,
    )
    _assert_current_set_like_sequence_contract(
        TrajectoryAnalysisPlan,
        {
            "artifact_kind": "trajectory-analysis-plan",
            "schema_version": "0.6.6",
            "plan_id": "canonical-trajectory-methods",
        },
        field_name="analysis_methods",
        canonical_values=("observable_transition_profile", "sequence_invariant_check"),
        historical_duplicates_allowed=False,
    )


def test_current_forbidden_state_sets_require_trajectory_state_order() -> None:
    _assert_current_set_like_sequence_contract(
        TrajectoryInvariantPlan,
        {
            "artifact_kind": "trajectory-invariant-plan",
            "schema_version": "0.6.6",
            "invariant_id": "forbidden-states",
            "label": "Forbidden states",
            "invariant_type": "forbidden_state",
        },
        field_name="forbidden_states",
        canonical_values=("provider_call", "human_review"),
        historical_duplicates_allowed=True,
    )


def test_current_protocol_set_fields_require_canonical_order() -> None:
    compiled = compile_suite(SUITE)
    protocol_payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    for field_name, canonical_values in (
        (
            "allowed_exclusion_reasons",
            (
                "budget_exhausted",
                "generated_token_budget_exhausted",
                "token_budget_exhausted",
            ),
        ),
        (
            "provider_version_capture",
            ("resolved_model", "provider_api_version", "provider_sdk"),
        ),
    ):
        _assert_current_set_like_sequence_contract(
            LiveProtocolRecord,
            protocol_payload,
            field_name=field_name,
            canonical_values=canonical_values,
            historical_duplicates_allowed=True,
        )


def test_confirmatory_drift_requires_a_confirmatory_metric() -> None:
    payload = _drift_plan()
    payload["interpretation"] = "confirmatory"
    payload["drift_hypothesis"] = "The declared monitoring endpoint remains stable."

    with pytest.raises(ValidationError, match="at least one confirmatory metric"):
        DriftMonitoringPlan.model_validate(payload)

    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(DriftMonitoringPlan.model_json_schema()).validate(payload)

    metric = payload["metrics"][0]
    assert isinstance(metric, dict)
    metric["interpretation"] = "confirmatory"
    DriftMonitoringPlan.model_validate(payload)
    Draft202012Validator(DriftMonitoringPlan.model_json_schema()).validate(payload)


@pytest.mark.parametrize("ordering_variable", ("release_sequence", "provider_version_window"))
def test_current_drift_rejects_ordering_without_an_authenticated_key(
    ordering_variable: str,
) -> None:
    payload = _drift_plan(ordering_variable=ordering_variable)

    with pytest.raises(ValidationError, match="supports only"):
        DriftMonitoringPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(writer_json_schema(DriftMonitoringPlan)).validate(payload)

    historical = {**payload, "schema_version": "0.6.5"}
    legacy_plan = DriftMonitoringPlan.model_validate(historical)
    assert legacy_plan.ordering_variable == ordering_variable
    Draft202012Validator(DriftMonitoringPlan.model_json_schema()).validate(historical)

    compiled = compile_suite(SUITE)
    valid_plan = DriftMonitoringPlan.model_validate(_drift_plan())
    bypassed_plan = valid_plan.model_copy(update={"ordering_variable": ordering_variable})
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        drift_monitoring_plan=None,
    ).model_copy(update={"drift_monitoring_plan": bypassed_plan})
    with pytest.raises(ValidationError, match="supports only"):
        build_live_drift_report((SimpleNamespace(),), protocol=protocol)  # type: ignore[arg-type]


def test_confirmatory_drift_status_uses_only_confirmatory_prerequisites() -> None:
    plan = SimpleNamespace(interpretation="confirmatory")
    comparability = SimpleNamespace(status="pass")
    diagnostics = (
        SimpleNamespace(interpretation="confirmatory", prerequisite_status="met"),
        SimpleNamespace(interpretation="exploratory", prerequisite_status="exploratory"),
    )

    assert _monitoring_status(plan, comparability, diagnostics) == "valid"
    assert (
        _monitoring_status(
            plan,
            comparability,
            (SimpleNamespace(interpretation="exploratory", prerequisite_status="met"),),
        )
        == "invalid"
    )


def test_exploratory_monitoring_does_not_mask_invalid_prerequisites() -> None:
    assert (
        _monitoring_status(
            SimpleNamespace(interpretation="exploratory"),
            SimpleNamespace(status="pass"),
            (SimpleNamespace(interpretation="exploratory", prerequisite_status="invalid"),),
        )
        == "invalid"
    )


@pytest.mark.parametrize(
    "methods,match",
    (
        ([], None),
        (["sequence_invariant_check"], "observable_transition_profile"),
        (
            ["observable_transition_profile", "event_process_summary"],
            "must be declared together",
        ),
        (
            ["observable_transition_profile", "burst_window_count"],
            "must be declared together",
        ),
    ),
)
def test_trajectory_plan_rejects_unsupported_method_subsets(
    methods: list[str],
    match: str | None,
) -> None:
    payload = _trajectory_plan()
    payload["analysis_methods"] = methods
    payload["invariants"] = []

    if match is None:
        with pytest.raises(ValidationError):
            TrajectoryAnalysisPlan.model_validate(payload)
    else:
        with pytest.raises(ValidationError, match=match):
            TrajectoryAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)


def test_confirmatory_trajectory_requires_the_complete_supported_method_set() -> None:
    payload = _trajectory_plan()
    payload["interpretation"] = "confirmatory"
    payload["invariants"][0]["interpretation"] = "confirmatory"
    payload["analysis_methods"] = [
        "observable_transition_profile",
        "sequence_invariant_check",
    ]

    with pytest.raises(ValidationError, match="complete supported analysis method set"):
        TrajectoryAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)

    payload["analysis_methods"] = [
        "observable_transition_profile",
        "sequence_invariant_check",
        "event_process_summary",
        "burst_window_count",
    ]
    TrajectoryAnalysisPlan.model_validate(payload)
    Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)


@pytest.mark.parametrize("invariant_mode", ("empty", "all_exploratory"))
def test_confirmatory_trajectory_requires_a_confirmatory_invariant(
    invariant_mode: str,
) -> None:
    payload = _trajectory_plan()
    payload["interpretation"] = "confirmatory"
    if invariant_mode == "empty":
        payload["invariants"] = []

    with pytest.raises(ValidationError, match="at least one confirmatory invariant"):
        TrajectoryAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)


def test_exploratory_trajectory_rejects_a_confirmatory_invariant() -> None:
    payload = _trajectory_plan()
    payload["invariants"][0]["interpretation"] = "confirmatory"

    with pytest.raises(ValidationError, match="require a confirmatory trajectory plan"):
        TrajectoryAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)


@pytest.mark.parametrize("invariant_mode", ("empty", "all_exploratory"))
def test_trajectory_status_fails_closed_without_a_confirmatory_result(
    invariant_mode: str,
) -> None:
    invariants = (
        ()
        if invariant_mode == "empty"
        else (SimpleNamespace(interpretation="exploratory", prerequisite_status="met"),)
    )

    assert (
        live_trajectory._trajectory_status(
            SimpleNamespace(interpretation="confirmatory", minimum_observations=1),
            (SimpleNamespace(),),
            (SimpleNamespace(prerequisite_status="met"),),
            invariants,
            (SimpleNamespace(prerequisite_status="met"),),
            source_runset_completion_status="complete",
            source_evaluation_completion_status="complete",
            source_evaluation_exploratory=False,
        )
        == "invalid"
    )


@pytest.mark.parametrize(
    ("plan_field", "member_field"),
    (
        ("advanced_analysis_plan", "endpoints"),
        ("drift_monitoring_plan", "metrics"),
        ("trajectory_analysis_plan", "invariants"),
    ),
)
@pytest.mark.parametrize("downgrade_member", (False, True))
def test_current_protocol_rejects_historical_nested_plan_versions(
    plan_field: str,
    member_field: str,
    downgrade_member: bool,
) -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    if plan_field == "advanced_analysis_plan":
        plan = _advanced_plan(primary_minimum_clusters=1)
    elif plan_field == "drift_monitoring_plan":
        plan = _drift_plan()
    else:
        plan = _trajectory_plan()
    if downgrade_member:
        plan[member_field][0]["schema_version"] = "0.6.5"
    else:
        plan["schema_version"] = "0.6.5"
    payload[plan_field] = plan

    with pytest.raises(ValidationError, match="schema_version must match"):
        LiveProtocolRecord.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveProtocolRecord.model_json_schema()).validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(payload, "live-protocol-record")


def test_legacy_protocol_direct_model_parsing_retains_matching_plan_versions() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
    ).model_dump(mode="json")
    payload["schema_version"] = "0.6.5"
    plan = _trajectory_plan()
    plan["schema_version"] = "0.6.5"
    for invariant in plan["invariants"]:
        invariant["schema_version"] = "0.6.5"
    payload["trajectory_analysis_plan"] = plan

    parsed = LiveProtocolRecord.model_validate(payload)
    Draft202012Validator(LiveProtocolRecord.model_json_schema()).validate(payload)

    assert parsed.schema_version == "0.6.5"
    assert parsed.trajectory_analysis_plan is not None
    assert parsed.trajectory_analysis_plan.schema_version == "0.6.5"


@pytest.mark.parametrize("invariant_mode", ("empty", "all_exploratory"))
def test_public_validator_rejects_confirmatory_trajectory_without_a_target(
    invariant_mode: str,
) -> None:
    compiled = compile_suite(SUITE)
    plan = _trajectory_plan()
    if invariant_mode == "empty":
        plan["invariants"] = []
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        trajectory_analysis_plan=plan,
    ).model_dump(mode="json")
    protocol["trajectory_analysis_plan"]["interpretation"] = "confirmatory"

    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(protocol, "live-protocol-record")


def test_trajectory_invariants_require_the_declared_invariant_method() -> None:
    payload = _trajectory_plan()
    payload["analysis_methods"] = ["observable_transition_profile"]

    with pytest.raises(ValidationError, match="sequence_invariant_check"):
        TrajectoryAnalysisPlan.model_validate(payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(TrajectoryAnalysisPlan.model_json_schema()).validate(payload)


def test_live_distribution_rejects_impossible_persisted_statistics() -> None:
    distribution = LiveDistribution(
        artifact_kind="live-distribution",
        metric="latency_ms",
        count=2,
        min="1.000000",
        p50="1.000000",
        p95="2.000000",
        max="2.000000",
        mean="1.500000",
        total="3.000000",
    )

    zero_count = distribution.model_dump(mode="json")
    zero_count["count"] = 0
    with pytest.raises(ValidationError, match="zero-count live distributions"):
        LiveDistribution.model_validate(zero_count)

    unordered = distribution.model_dump(mode="json")
    unordered["p50"] = "2.000000"
    unordered["p95"] = "1.000000"
    with pytest.raises(ValidationError, match="quantiles must be monotonically ordered"):
        LiveDistribution.model_validate(unordered)

    inconsistent_total = distribution.model_dump(mode="json")
    inconsistent_total["total"] = "4.000000"
    with pytest.raises(ValidationError, match="total and mean are inconsistent"):
        LiveDistribution.model_validate(inconsistent_total)


def test_live_drift_monitor_reports_ordered_review_signal() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(minimum_windows=4),
    )
    protocol_digest = sha256_hexdigest(protocol)
    pass_patterns = (
        (True, True),
        (True, True),
        (True, False),
        (True, False),
        (False, False),
        (False, False),
    )
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-window-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=tuple(
                    _record(
                        repetition_index=repetition,
                        linked=linked,
                        started_at_utc=f"2026-06-27T0{index}:0{repetition}:00Z",
                        completed_at_utc=f"2026-06-27T0{index}:0{repetition}:01Z",
                    )
                    for repetition, linked in enumerate(pattern)
                ),
            ),
            protocol=protocol,
        )
        for index, pattern in enumerate(pass_patterns)
    )

    report = build_live_drift_report(reports, protocol=protocol)
    verify_live_drift_report_sources(report, reports, protocol=protocol)
    with pytest.raises(ValueError, match="ordered source evaluation digests"):
        verify_live_drift_report_sources(
            report,
            tuple(reversed(reports)),
            protocol=protocol,
        )
    Draft202012Validator(LiveDriftReport.model_json_schema()).validate(
        report.model_dump(mode="json")
    )
    missing_schema_binding = report.model_dump(mode="json")
    missing_schema_binding.pop("source_evaluation_digests")
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveDriftReport.model_json_schema()).validate(missing_schema_binding)

    assert report.state is GateState.not_evaluated
    assert report.monitoring_status == "exploratory"
    assert report.comparability.status == "pass"
    assert report.observation_window_start_utc == "2026-06-27T00:00:00Z"
    diagnostic = report.diagnostics[0]
    assert diagnostic.metric == "expectation_pass_rate"
    assert diagnostic.prerequisite_status == "exploratory"
    assert any("source evaluations are exploratory" in item for item in diagnostic.limitations)
    assert diagnostic.stationarity_signal == "review"
    assert diagnostic.dependence_signal == "none"
    assert diagnostic.slope_per_window == "-0.228571"
    assert diagnostic.state_estimate is not None
    assert diagnostic.state_estimate.state_name == "governance_health"
    assert any("review signal" in limitation for limitation in report.limitations)

    bad_plan_version = report.model_dump(mode="json")
    bad_plan_version["drift_plan"]["schema_version"] = "0.6.5"
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_plan_version)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveDriftReport.model_json_schema()).validate(bad_plan_version)

    bad_rate = report.model_dump(mode="json")
    bad_rate["windows"][0]["schema_version"] = "0.6.5"
    bad_rate["windows"][0]["metrics"][0]["schema_version"] = "0.6.5"
    bad_rate["windows"][0]["metrics"][0]["numerator"] = 0
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_rate)

    bad_index = report.model_dump(mode="json")
    bad_index["windows"][1]["window_index"] = 99
    with pytest.raises(ValidationError, match="contiguous zero-based indexes"):
        type(report).model_validate(bad_index)

    bad_material_flag = report.model_dump(mode="json")
    bad_material_flag["comparability"]["material_fields_match"] = False
    with pytest.raises(ValidationError, match="material_fields_match"):
        type(report).model_validate(bad_material_flag)

    bad_diagnostic = report.model_dump(mode="json")
    bad_diagnostic["diagnostics"][0]["schema_version"] = "0.6.5"
    bad_diagnostic["diagnostics"][0]["mean_value"] = "0.999999"
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_diagnostic)

    incomplete_state = report.model_dump(mode="json")
    incomplete_state["diagnostics"][0]["state_estimate"]["latest_level"] = None
    with pytest.raises(ValidationError, match="complete estimate triplet"):
        type(report).model_validate(incomplete_state)

    bad_monitoring_status = report.model_dump(mode="json")
    bad_monitoring_status["monitoring_status"] = "valid"
    with pytest.raises(ValidationError, match="monitoring_status"):
        type(report).model_validate(bad_monitoring_status)

    forged_slope = report.model_dump(mode="json")
    forged_slope["diagnostics"][0]["slope_per_window"] = "0.999999"
    with pytest.raises(ValidationError, match="diagnostics do not match replayed"):
        type(report).model_validate(forged_slope)

    suppressed_review = report.model_dump(mode="json")
    suppressed_review["diagnostics"][0]["stationarity_signal"] = "none"
    suppressed_review["diagnostics"][0]["review_reasons"] = []
    with pytest.raises(ValidationError, match="diagnostics do not match replayed"):
        type(report).model_validate(suppressed_review)

    forged_ewma = report.model_dump(mode="json")
    forged_ewma["diagnostics"][0]["state_estimate"]["latest_level"] = "999.000000"
    with pytest.raises(ValidationError, match="diagnostics do not match replayed"):
        type(report).model_validate(forged_ewma)

    erased_projection = report.model_dump(mode="json")
    erased_projection["diagnostics"] = []
    for window in erased_projection["windows"]:
        window["metrics"] = []
    with pytest.raises(ValidationError, match="at least one metric diagnostic"):
        type(report).model_validate(erased_projection)

    forged_source_digest = report.model_dump(mode="json")
    forged_source_digest["source_evaluation_digests"][0] = "f" * 64
    with pytest.raises(ValidationError, match="report_id"):
        type(report).model_validate(forged_source_digest)

    forged_plan = report.model_dump(mode="json")
    forged_plan["drift_plan"]["metrics"][0]["slope_review_threshold"] = "9.000000"
    with pytest.raises(ValidationError, match="effective plan"):
        type(report).model_validate(forged_plan)


def test_confirmatory_drift_fails_closed_on_exploratory_source_qualification() -> None:
    compiled = compile_suite(SUITE)
    plan = _drift_plan(minimum_windows=2)
    plan["interpretation"] = "confirmatory"
    plan["drift_hypothesis"] = "The confirmatory pass-rate trend remains estimable."
    confirmatory_metric = plan["metrics"][0]
    assert isinstance(confirmatory_metric, dict)
    confirmatory_metric["interpretation"] = "confirmatory"
    exploratory_metric = {
        **confirmatory_metric,
        "metric": "retry_rate",
        "label": "Exploratory retry rate",
        "interpretation": "exploratory",
        "analysis_methods": ["descriptive_trend"],
        "minimum_windows": 3,
    }
    plan["metrics"].append(exploratory_metric)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        drift_monitoring_plan=plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-confirmatory-drift-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=True,
                        started_at_utc=f"2026-06-27T00:00:0{index}Z",
                        completed_at_utc=f"2026-06-27T00:00:1{index}Z",
                    ),
                ),
            ),
            protocol=protocol,
        )
        for index in range(2)
    )

    report = build_live_drift_report(reports, protocol=protocol)

    assert report.monitoring_status == "invalid"
    diagnostic_by_metric = {diagnostic.metric: diagnostic for diagnostic in report.diagnostics}
    assert diagnostic_by_metric["expectation_pass_rate"].prerequisite_status == "invalid"
    assert diagnostic_by_metric["retry_rate"].prerequisite_status == "exploratory"
    assert diagnostic_by_metric["retry_rate"].dependence_signal == "not_evaluated"
    LiveDriftReport.model_validate(report.model_dump(mode="json"))

    copied_source = reports[0].model_copy(update={"exploratory": False})
    constructed_source = type(reports[0]).model_construct(
        **{**reports[0].__dict__, "exploratory": False}
    )
    for forged_source in (copied_source, constructed_source):
        forged_sources = (forged_source, reports[1])
        with pytest.raises(ValidationError, match="exploratory flag"):
            build_live_drift_report(forged_sources, protocol=protocol)
        with pytest.raises(ValidationError, match="exploratory flag"):
            verify_live_drift_report_sources(
                report,
                forged_sources,
                protocol=protocol,
            )

    forged_protocol = protocol.model_copy(
        update={"allowed_exclusion_reasons": tuple(reversed(protocol.allowed_exclusion_reasons))}
    )
    with pytest.raises(ValidationError, match="canonical order"):
        build_live_drift_report(reports, protocol=forged_protocol)
    with pytest.raises(ValidationError, match="canonical order"):
        verify_live_drift_report_sources(
            report,
            reports,
            protocol=forged_protocol,
        )

    historical_protocol_payload = protocol.model_dump(mode="json")
    historical_protocol_payload["schema_version"] = "0.6.5"
    historical_drift_plan = historical_protocol_payload["drift_monitoring_plan"]
    assert isinstance(historical_drift_plan, dict)
    historical_drift_plan["schema_version"] = "0.6.5"
    historical_metrics = historical_drift_plan["metrics"]
    assert isinstance(historical_metrics, list)
    for metric in historical_metrics:
        assert isinstance(metric, dict)
        metric["schema_version"] = "0.6.5"
    historical_protocol = LiveProtocolRecord.model_validate(historical_protocol_payload)
    with pytest.raises(ValueError, match="must use current schema_version"):
        build_live_drift_report(reports, protocol=historical_protocol)

    impossible_source_completion = report.model_dump(mode="json")
    impossible_source_completion["windows"][0]["source_runset_completion_status"] = "incomplete"
    with pytest.raises(ValidationError, match="complete source RunSet"):
        LiveDriftReport.model_validate(impossible_source_completion)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveDriftReport.model_json_schema()).validate(
            impossible_source_completion
        )

    undeclared_dependence_conclusion = report.model_dump(mode="json")
    retry_diagnostic = next(
        diagnostic
        for diagnostic in undeclared_dependence_conclusion["diagnostics"]
        if diagnostic["metric"] == "retry_rate"
    )
    retry_diagnostic["dependence_signal"] = "none"
    with pytest.raises(ValidationError, match="dependence signal availability"):
        LiveDriftReport.model_validate(undeclared_dependence_conclusion)

    forged_downgrade = report.model_dump(mode="json")
    forged_downgrade["monitoring_status"] = "valid"
    with pytest.raises(ValidationError, match="monitoring_status"):
        LiveDriftReport.model_validate(forged_downgrade)


def test_live_drift_comparability_is_invalid_for_changed_analysis_digest() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(minimum_windows=2),
    )
    changed_payload = protocol.model_dump(mode="json")
    changed_payload["analysis_digest"] = "9" * 64
    changed_protocol = LiveProtocolRecord.model_validate(changed_payload)
    first_digest = sha256_hexdigest(protocol)
    changed_digest = sha256_hexdigest(changed_protocol)
    first = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-live-window-a",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=first_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=True),
            ),
        ),
        protocol=protocol,
    )
    second = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="runset-live-window-b",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=changed_protocol.protocol_id,
            protocol_digest=changed_digest,
            runs=(
                _record(repetition_index=0, linked=True),
                _record(repetition_index=1, linked=False),
            ),
        ),
        protocol=changed_protocol,
    )

    report = build_live_drift_report((first, second), protocol=protocol)

    assert report.monitoring_status == "invalid"
    assert report.comparability.status == "invalid"
    assert report.comparability.material_fields_match is True
    assert report.diagnostics[0].prerequisite_status == "invalid"
    assert report.diagnostics[0].stationarity_signal == "invalid"
    assert any("reference protocol digest" in failure for failure in report.comparability.failures)


def test_live_drift_marks_dependence_signal_separately_from_stationarity() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 50)
    protocol = _protocol(
        compiled,
        observations=50,
        clusters=50,
        repetitions=1,
        drift_monitoring_plan=_drift_plan(
            minimum_windows=8,
            minimum_dependence_windows=8,
            minimum_state_space_windows=8,
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    success_counts = (20, 21, 22, 23, 24, 25, 26, 27)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-dependence-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=tuple(
                    _record(
                        repetition_index=0,
                        case_id=f"case-{repetition:03d}",
                        schedule_index=repetition,
                        linked=repetition < success_count,
                        started_at_utc=f"2026-06-{20 + index:02d}T00:00:00Z",
                        completed_at_utc=f"2026-06-{20 + index:02d}T00:00:01Z",
                    )
                    for repetition in range(50)
                ),
            ),
            protocol=protocol,
        )
        for index, success_count in enumerate(success_counts)
    )

    report = build_live_drift_report(reports, protocol=protocol)
    diagnostic = report.diagnostics[0]

    assert diagnostic.stationarity_signal == "none"
    assert diagnostic.dependence_signal == "review"
    assert diagnostic.lag1_autocorrelation is not None
    assert any("lag-1" in reason for reason in diagnostic.review_reasons)
    assert diagnostic.ar1_phi is None
    assert diagnostic.ar1_intercept is None
    assert diagnostic.ar1_innovation_variance is None
    assert any("outside the stationary range" in reason for reason in diagnostic.review_reasons)
    assert any("fitted statistics were suppressed" in item for item in diagnostic.limitations)


def test_live_drift_suppresses_low_window_dependence_and_state_estimates() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(
            minimum_windows=2,
            minimum_dependence_windows=8,
            minimum_state_space_windows=6,
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-low-window-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(repetition_index=0, linked=True),
                    _record(repetition_index=1, linked=index == 0),
                ),
            ),
            protocol=protocol,
        )
        for index in range(2)
    )

    report = build_live_drift_report(reports, protocol=protocol)
    diagnostic = report.diagnostics[0]

    assert diagnostic.prerequisite_status == "exploratory"
    assert diagnostic.lag1_autocorrelation is None
    assert diagnostic.ar1_phi is None
    assert diagnostic.state_estimate is None
    assert diagnostic.dependence_signal == "none"
    assert any("requires at least 8" in limitation for limitation in diagnostic.limitations)
    assert any("requires at least 6" in limitation for limitation in diagnostic.limitations)


def test_live_drift_rejects_nonmonotonic_timestamp_ordering() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(minimum_windows=2),
    )
    protocol_digest = sha256_hexdigest(protocol)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-out-of-order-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=True,
                        started_at_utc=start,
                        completed_at_utc=end,
                    ),
                    _record(
                        repetition_index=1,
                        linked=True,
                        started_at_utc=start,
                        completed_at_utc=end,
                    ),
                ),
            ),
            protocol=protocol,
        )
        for index, (start, end) in enumerate(
            (
                ("2026-06-27T02:00:00+02:00", "2026-06-27T02:00:01+02:00"),
                ("2026-06-26T23:00:00Z", "2026-06-26T23:00:01Z"),
            )
        )
    )

    report = build_live_drift_report(reports, protocol=protocol)

    assert report.monitoring_status == "invalid"
    assert report.comparability.status == "invalid"
    assert any("nondecreasing" in failure for failure in report.comparability.failures)


def test_live_drift_reports_multiple_timestamp_ordering_failures() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(
            minimum_windows=2,
            ordering_variable="window_start_utc",
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-ordering-aggregate-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=True,
                        started_at_utc=start,
                        completed_at_utc=start,
                    ),
                    _record(
                        repetition_index=1,
                        linked=True,
                        started_at_utc=start,
                        completed_at_utc=start,
                    ),
                ),
            ),
            protocol=protocol,
        )
        for index, start in enumerate(
            (
                "2026-06-27T02:00:00Z",
                None,
                "2026-06-27T01:00:00Z",
            )
        )
    )

    report = build_live_drift_report(reports, protocol=protocol)

    assert report.monitoring_status == "invalid"
    assert report.comparability.status == "invalid"
    assert any(
        "missing windows: window-0001" in failure for failure in report.comparability.failures
    )
    assert any(
        "between window-0000 and window-0002" in failure
        for failure in report.comparability.failures
    )


def test_live_drift_timestamp_ordering_rejects_ties_in_every_caller_order() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        drift_monitoring_plan=_drift_plan(
            minimum_windows=2,
            ordering_variable="window_start_utc",
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    reports = tuple(
        evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-tied-start-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=linked,
                        started_at_utc="2026-06-27T00:00:00Z",
                        completed_at_utc="2026-06-27T00:00:01Z",
                    ),
                    _record(
                        repetition_index=1,
                        linked=linked,
                        started_at_utc="2026-06-27T00:00:00Z",
                        completed_at_utc="2026-06-27T00:00:01Z",
                    ),
                ),
            ),
            protocol=protocol,
        )
        for index, linked in enumerate((False, True))
    )

    for ordered_reports in (reports, tuple(reversed(reports))):
        report = build_live_drift_report(ordered_reports, protocol=protocol)

        assert report.monitoring_status == "invalid"
        assert report.comparability.status == "invalid"
        assert any(
            "not strictly increasing by start timestamp" in failure
            for failure in report.comparability.failures
        )


def test_confirmatory_drift_fails_closed_on_an_internal_missing_metric_window() -> None:
    compiled = compile_suite(SUITE)
    plan = _drift_plan(
        minimum_windows=8,
        minimum_dependence_windows=8,
        minimum_state_space_windows=8,
    )
    plan["interpretation"] = "confirmatory"
    plan["drift_hypothesis"] = "expectation pass rate remains stable across all windows"
    plan["metrics"][0]["interpretation"] = "confirmatory"
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        drift_monitoring_plan=plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    source_reports: list[LiveEvaluationReport] = []
    for index in range(9):
        source = evaluate_live_runset(
            compiled,
            RunSet(
                artifact_kind="run-set",
                runset_id=f"runset-live-drift-gap-{index}",
                suite_id=compiled.suite_id,
                suite_version=compiled.suite_version,
                suite_digest=compiled_suite_digest(compiled),
                fixture_manifest_digest="4" * 64,
                execution_mode=ExecutionMode.live,
                protocol_id=protocol.protocol_id,
                protocol_digest=protocol_digest,
                runs=(
                    _record(
                        repetition_index=0,
                        linked=True,
                    ),
                ),
            ),
            protocol=protocol,
        )
        source_reports.append(source)
    reports = tuple(source_reports)
    complete_report = build_live_drift_report(reports, protocol=protocol)
    missing_window_payload = complete_report.windows[4].model_dump(mode="json")
    missing_window_payload.update(included_observations=0, excluded_observations=1)
    missing_window_payload["metrics"][0].update(
        value=None,
        numerator=0,
        denominator=0,
    )
    missing_window = type(complete_report.windows[4]).model_validate(missing_window_payload)
    windows = (
        *complete_report.windows[:4],
        missing_window,
        *complete_report.windows[5:],
    )
    assert complete_report.drift_plan is not None
    comparability = live_drift._comparability(
        windows,
        protocol=protocol,
        protocol_digest=protocol_digest,
    )
    diagnostics = tuple(
        live_drift._diagnostic(metric, windows, comparability=comparability)
        for metric in complete_report.drift_plan.metrics
    )
    report_payload = complete_report.model_dump(mode="json")
    report_payload.update(
        windows=[window.model_dump(mode="json") for window in windows],
        comparability=comparability.model_dump(mode="json"),
        diagnostics=[diagnostic.model_dump(mode="json") for diagnostic in diagnostics],
        monitoring_status=live_drift._monitoring_status(
            complete_report.drift_plan,
            comparability,
            diagnostics,
        ),
        limitations=list(
            live_drift._drift_limitations(
                complete_report.drift_plan,
                comparability,
                windows,
            )
        ),
        report_id=live_drift._drift_report_id(
            protocol_digest=protocol_digest,
            plan=complete_report.drift_plan,
            source_evaluation_digests=complete_report.source_evaluation_digests,
            windows=windows,
        ),
    )
    report = LiveDriftReport.model_validate(report_payload)
    diagnostic = report.diagnostics[0]

    assert diagnostic.windows == 8
    assert diagnostic.missing_windows == 1
    assert diagnostic.prerequisite_status == "invalid"
    assert diagnostic.max_step_change is None
    assert diagnostic.lag1_autocorrelation is None
    assert diagnostic.ar1_phi is None
    assert diagnostic.state_estimate is None
    assert diagnostic.stationarity_signal == "invalid"
    assert diagnostic.dependence_signal == "invalid"
    assert report.monitoring_status == "invalid"
    assert any("not evaluated across the gap" in item for item in diagnostic.limitations)
    LiveDriftReport.model_validate(report.model_dump(mode="json"))
    with pytest.raises(ValueError, match="trusted-source rebuild"):
        verify_live_drift_report_sources(report, reports, protocol=protocol)

    forged = report.model_dump(mode="json")
    forged_diagnostic = forged["diagnostics"][0]
    forged_diagnostic.update(
        {
            "prerequisite_status": "met",
            "stationarity_signal": "none",
            "dependence_signal": "none",
        }
    )
    forged["monitoring_status"] = "valid"
    with pytest.raises(ValidationError, match="diagnostics do not match replayed"):
        LiveDriftReport.model_validate(forged)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        schema_validation.validate_artifact_payload(forged, "live-drift-report")


def test_live_trajectory_reports_transition_paths_and_invariants() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
            _record(
                repetition_index=1,
                linked=True,
                started_at_utc="2026-06-27T00:00:10Z",
                completed_at_utc="2026-06-27T00:00:11Z",
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    verify_live_trajectory_report_sources(
        report,
        runset,
        evaluation,
        protocol=protocol,
    )
    with pytest.raises(ValueError, match="source RunSet digest"):
        verify_live_trajectory_report_sources(
            report,
            runset.model_copy(update={"runset_id": "different-trusted-source"}),
            evaluation,
            protocol=protocol,
        )
    Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
        report.model_dump(mode="json")
    )
    missing_schema_binding = report.model_dump(mode="json")
    missing_schema_binding.pop("operational_events")
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            missing_schema_binding
        )
    missing_stop_projection = report.model_dump(mode="json")
    missing_stop_projection.pop("source_evaluation_stop_reasons")
    with pytest.raises(ValidationError, match="stop reasons"):
        LiveTrajectoryReport.model_validate(missing_stop_projection)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            missing_stop_projection
        )
    missing_path_basis = report.model_dump(mode="json")
    missing_path_basis["paths"][0].pop("claim_evidence_complete")
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(missing_path_basis)
    missing_evidence_status = report.model_dump(mode="json")
    missing_evidence_status["paths"][0].pop("claim_evidence_status")
    with pytest.raises(ValidationError, match="claim-evidence status"):
        LiveTrajectoryReport.model_validate(missing_evidence_status)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            missing_evidence_status
        )

    assert report.state is GateState.not_evaluated
    assert report.trajectory_status == "invalid"
    assert report.paths[0].states == (
        "start",
        "request_assembly",
        "provider_call",
        "tool_call",
        "evidence_check",
        "policy_check",
        "verdict",
    )
    assert report.transition_assumption == "canonical_observable_order"
    assert any(
        transition.from_state == "provider_call"
        and transition.to_state == "tool_call"
        and transition.conditional_frequency == "1.000000"
        for transition in report.transitions
    )
    evidence = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert evidence.affected_observations == 0
    assert evidence.unobservable_observations == 0
    assert evidence.state is GateState.not_evaluated
    assert report.trajectory_plan is not None
    invariant_plans = {
        invariant.invariant_type: invariant for invariant in report.trajectory_plan.invariants
    }
    review = _trajectory_invariant(report, "required-review-for-approval")
    retry = _trajectory_invariant(report, "attempt-retry-consistency")
    assert review.evaluated_observations == 0
    assert evidence.evaluated_observations == 2
    assert retry.evaluated_observations == 2

    review_paths = (
        report.paths[0].model_copy(update={"human_review_required": True}),
        report.paths[1],
    )
    review_result = live_trajectory._invariant_result(
        invariant_plans["required_review_for_approval"],
        review_paths,
        plan=report.trajectory_plan,
    )
    claim_result = live_trajectory._invariant_result(
        invariant_plans["claim_evidence_before_approval"],
        (
            report.paths[0],
            report.paths[1].model_copy(update={"approval_outcome": False}),
        ),
        plan=report.trajectory_plan,
    )
    retry_result = live_trajectory._invariant_result(
        invariant_plans["attempt_retry_consistency"],
        (
            report.paths[0],
            report.paths[1].model_copy(update={"attempt_count": None, "retry_count": None}),
        ),
        plan=report.trajectory_plan,
    )
    forbidden_result = live_trajectory._invariant_result(
        TrajectoryInvariantPlan(
            artifact_kind="trajectory-invariant-plan",
            invariant_id="forbid-emergency",
            label="Emergency state is forbidden",
            invariant_type="forbidden_state",
            forbidden_states=("emergency",),
        ),
        report.paths,
        plan=report.trajectory_plan,
    )
    assert review_result.evaluated_observations == 1
    assert claim_result.evaluated_observations == 1
    assert retry_result.evaluated_observations == 1
    assert forbidden_result.evaluated_observations == 2

    bad_plan_version = report.model_dump(mode="json")
    bad_plan_version["trajectory_plan"]["schema_version"] = "0.6.5"
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_plan_version)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(bad_plan_version)

    bad_path = report.model_dump(mode="json")
    bad_path["paths"][0]["schema_version"] = "0.6.5"
    bad_path["paths"][0]["terminal_state"] = "start"
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_path)

    bad_transition = report.model_dump(mode="json")
    bad_transition["transitions"][0]["count"] += 1
    with pytest.raises(ValidationError, match="transition count cannot exceed|frequency"):
        type(report).model_validate(bad_transition)

    missing_transition = report.model_dump(mode="json")
    missing_transition["transitions"].pop()
    with pytest.raises(ValidationError, match="transition set does not match"):
        type(report).model_validate(missing_transition)

    bad_invariant = report.model_dump(mode="json")
    bad_invariant["invariants"][0]["schema_version"] = "0.6.5"
    bad_invariant["invariants"][0]["affected_observations"] = 1
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_invariant)

    bad_event_rate = report.model_dump(mode="json")
    bad_event_rate["event_processes"][0]["schema_version"] = "0.6.5"
    bad_event_rate["event_processes"][0]["event_rate"] = "1.000000"
    with pytest.raises(ValidationError, match="schema_version must match"):
        type(report).model_validate(bad_event_rate)

    missing_event_type = report.model_dump(mode="json")
    missing_event_type["event_processes"].pop()
    with pytest.raises(ValidationError, match="complete operational event set"):
        type(report).model_validate(missing_event_type)

    assert report.trajectory_plan is not None
    ghost_emergency = TrajectoryOperationalEvent(
        artifact_kind="trajectory-operational-event",
        event_type="emergency_process",
        observation_id="not-a-real-observation",
        count=1,
    )
    ghost_events = (*report.operational_events, ghost_emergency)
    ghost_emergency_report = report.model_dump(mode="json")
    ghost_emergency_report["operational_events"] = [
        event.model_dump(mode="json") for event in ghost_events
    ]
    ghost_emergency_report["event_processes"] = [
        process.model_dump(mode="json")
        for process in live_trajectory._event_processes(
            ghost_events,
            exposure=report.included_observations,
            plan=report.trajectory_plan,
        )
    ]
    ghost_emergency_report["report_id"] = live_trajectory._trajectory_report_id(
        protocol_digest=report.protocol_digest,
        plan=report.trajectory_plan,
        source_runset_digest=report.source_runset_digest or "",
        source_evaluation_digest=report.source_evaluation_digest or "",
        source_runset_completion_status=report.source_runset_completion_status,
        source_evaluation_completion_status=report.source_evaluation_completion_status,
        source_evaluation_stop_reasons=report.source_evaluation_stop_reasons or (),
        source_evaluation_exploratory=report.source_evaluation_exploratory,
        paths=report.paths,
        operational_events=ghost_events,
    )
    with pytest.raises(ValidationError, match="emergency event references an unknown"):
        type(report).model_validate(ghost_emergency_report)

    bad_excluded_count = report.model_dump(mode="json")
    bad_excluded_count["excluded_observations"] = 1
    bad_excluded_count["included_observations"] = 1
    with pytest.raises(ValidationError, match="excluded count does not match"):
        type(report).model_validate(bad_excluded_count)

    verdict_state = report.model_dump(mode="json")
    verdict_state["state"] = "pass"
    with pytest.raises(ValidationError, match="non-verdict review artifacts"):
        type(report).model_validate(verdict_state)

    missing_invariants = report.model_dump(mode="json")
    missing_invariants["invariants"] = []
    with pytest.raises(ValidationError, match="invariants do not match replayed"):
        type(report).model_validate(missing_invariants)

    missing_history = report.model_dump(mode="json")
    missing_history["history_dependent_checks"] = []
    with pytest.raises(ValidationError, match="complete history-check set"):
        type(report).model_validate(missing_history)

    forged_source_digest = report.model_dump(mode="json")
    forged_source_digest["source_runset_digest"] = "f" * 64
    with pytest.raises(ValidationError, match="report_id"):
        type(report).model_validate(forged_source_digest)

    wrong_source_binding = evaluation.model_copy(update={"source_runset_digest": "f" * 64})
    with pytest.raises(ValueError, match="source_runset_digest"):
        build_live_trajectory_report(runset, wrong_source_binding, protocol=protocol)


def test_live_trajectory_marks_observable_missing_evidence_reference_incomplete() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["evidence_refs"] = []
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-missing-evidence-reference",
    )

    assert ReasonCode.REQUIRED_SOURCE_MISSING in evaluation.observations[0].reason_codes
    assert ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE in (evaluation.observations[0].reason_codes)
    _assert_trajectory_evidence_incomplete(report)


def test_live_trajectory_marks_observable_evidence_source_mismatch_incomplete() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["evidence_items"][0]["source_id"] = "different-receipt-source"
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-evidence-source-mismatch",
    )

    assert ReasonCode.EVIDENCE_PROVENANCE_MISMATCH in (evaluation.observations[0].reason_codes)
    _assert_trajectory_evidence_incomplete(report)


def test_live_trajectory_marks_observable_missing_evidence_item_incomplete() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["evidence_items"] = []
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-missing-evidence-item",
    )

    evidence_reasons = {
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ReasonCode.REQUIRED_SOURCE_MISSING,
    }.intersection(evaluation.observations[0].reason_codes)
    assert evidence_reasons == {
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
    }
    _assert_trajectory_evidence_incomplete(report)


def test_live_trajectory_marks_observable_missing_claim_evidence_link_incomplete() -> None:
    compiled = compile_suite(SUITE)
    record = _record(repetition_index=0, linked=False)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-missing-claim-evidence-link",
    )

    evidence_reasons = {
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ReasonCode.REQUIRED_SOURCE_MISSING,
    }.intersection(evaluation.observations[0].reason_codes)
    assert evidence_reasons == {ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE}
    _assert_trajectory_evidence_incomplete(report)


def test_live_trajectory_excludes_excluded_approvals_from_control_exposure() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        allowed_exclusion_reasons=("provider_incident",),
        max_exclusion_rate="0.500000",
        trajectory_analysis_plan=_trajectory_plan(minimum_observations=2),
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="trajectory-excluded-approval",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(
            _record(repetition_index=0, linked=True),
            _record(
                repetition_index=1,
                linked=False,
                exclusion_reason="provider_incident",
                human_review_required=True,
                human_review_performed=True,
            ),
        ),
    )

    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)
    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)

    assert evaluation.observations[1].state is GateState.not_evaluated
    included_path, excluded_path = report.paths
    assert included_path.claim_evidence_status == "complete"
    assert included_path.claim_evidence_complete is True
    assert excluded_path.approval_outcome is True
    assert excluded_path.claim_evidence_link_count == 0
    assert excluded_path.claim_evidence_status == "not_evaluated"
    assert excluded_path.claim_evidence_complete is False
    assert excluded_path.states == (
        "start",
        "request_assembly",
        "human_review",
        "excluded",
    )
    assert excluded_path.terminal_state == "excluded"
    assert excluded_path.human_review_performed is True
    transition_by_edge = {
        (transition.from_state, transition.to_state): transition
        for transition in report.transitions
    }
    assert transition_by_edge[("request_assembly", "human_review")].count == 1
    assert transition_by_edge[("human_review", "excluded")].count == 1

    evidence = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert evidence.evaluated_observations == 1
    assert evidence.affected_observations == 0
    assert evidence.unobservable_observations == 0
    assert evidence.prerequisite_status == "exploratory"

    review = _trajectory_invariant(report, "required-review-for-approval")
    assert review.evaluated_observations == 0
    assert review.affected_observations == 0
    assert review.prerequisite_status == "invalid"

    history = {check.check_id: check for check in report.history_dependent_checks}
    assert history["claim-evidence-history"].prerequisite_status == "met"
    assert history["review-required-history"].prerequisite_status == "invalid"
    assert history["review-required-history"].affected_observations == 0

    round_tripped = LiveTrajectoryReport.model_validate(report.model_dump(mode="json"))
    assert round_tripped == report
    Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
        report.model_dump(mode="json")
    )
    verify_live_trajectory_report_sources(
        round_tripped,
        runset,
        evaluation,
        protocol=protocol,
    )

    markdown = render_live_trajectory_markdown(report)
    assert "observation=`excluded`" in markdown
    assert "claim_evidence=`not_evaluated`" in markdown
    assert "approval=`true`" in markdown

    forged_path = report.model_dump(mode="json")
    forged_path["paths"][1]["claim_evidence_status"] = "complete"
    forged_path["paths"][1]["claim_evidence_complete"] = True
    with pytest.raises(ValidationError, match="observation and approval applicability"):
        LiveTrajectoryReport.model_validate(forged_path)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(forged_path)

    forged_denominator = report.model_dump(mode="json")
    forged_evidence = next(
        item
        for item in forged_denominator["invariants"]
        if item["invariant_id"] == "claim-evidence-before-approval"
    )
    forged_evidence["evaluated_observations"] = 2
    forged_evidence["prerequisite_status"] = "met"
    with pytest.raises(ValidationError, match="invariants do not match replayed"):
        LiveTrajectoryReport.model_validate(forged_denominator)


def test_live_trajectory_preserves_review_and_emergency_before_excluded_terminal() -> None:
    compiled = compile_suite(SUITE)
    record = _record(
        repetition_index=0,
        linked=False,
        exclusion_reason="provider_incident",
        human_review_required=True,
        human_review_performed=True,
        started_at_utc="2026-06-27T00:00:00Z",
        completed_at_utc="2026-06-27T00:00:01Z",
    )
    emergency = EmergencyProcessRecord(
        artifact_kind="emergency-process-record",
        emergency_id="trajectory-emergency-reviewed-exclusion",
        failure_kind="timeout",
        command_digest="1" * 64,
        executable_name="external-adapter",
        script_name="adapter.py",
        observation_id=record.observation_id,
        run_id=record.run_id,
        case_id=record.case_id,
        adapter_id=record.adapter_id,
        started_at_utc="2026-06-27T00:00:00Z",
        completed_at_utc="2026-06-27T00:00:01Z",
        duration_ms=1_000,
        timeout_seconds=1,
        stdout_bytes=0,
        stderr_bytes=0,
        safe_error_code="external_script_timeout",
        safe_error_message="external adapter timed out",
        local_debug_reference="trajectory-debug-reviewed-exclusion",
    )

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id="trajectory-reviewed-excluded-emergency",
        emergency_records=(emergency,),
    )

    excluded_path = report.paths[0]
    assert excluded_path.states == (
        "start",
        "request_assembly",
        "human_review",
        "emergency",
        "excluded",
    )
    assert excluded_path.terminal_state == "excluded"
    transition_by_edge = {
        (transition.from_state, transition.to_state): transition
        for transition in report.transitions
    }
    assert transition_by_edge[("request_assembly", "human_review")].count == 1
    assert transition_by_edge[("human_review", "emergency")].count == 1
    assert transition_by_edge[("emergency", "excluded")].count == 1

    emergency_events = tuple(
        event for event in report.operational_events if event.event_type == "emergency_process"
    )
    assert len(emergency_events) == 1
    assert emergency_events[0].observation_id == excluded_path.observation_id
    assert emergency_events[0].count == 1
    assert _event_process(report, "emergency_process").observed_events == 1

    evidence = _trajectory_invariant(report, "claim-evidence-before-approval")
    review = _trajectory_invariant(report, "required-review-for-approval")
    retry = _trajectory_invariant(report, "attempt-retry-consistency")
    assert evidence.evaluated_observations == 1
    assert review.evaluated_observations == 0
    assert retry.evaluated_observations == 1
    assert excluded_path.observation_id not in evidence.affected_observation_ids
    assert excluded_path.observation_id not in review.affected_observation_ids
    assert excluded_path.observation_id not in retry.affected_observation_ids
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)

    writer_validator = Draft202012Validator(writer_json_schema(LiveTrajectoryReport))

    excluded_nonterminal = report.model_dump(mode="json")
    excluded_nonterminal_path = excluded_nonterminal["paths"][0]
    excluded_nonterminal_path.update(
        {
            "states": ["start", "request_assembly", "excluded", "human_review"],
            "terminal_state": "human_review",
            "transition_count": 3,
        }
    )
    with pytest.raises(ValidationError, match="excluded-state membership"):
        LiveTrajectoryReport.model_validate(excluded_nonterminal)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(excluded_nonterminal)

    terminal_excluded_without_state = report.model_dump(mode="json")
    terminal_excluded_path = terminal_excluded_without_state["paths"][0]
    terminal_excluded_path.update(
        {
            "states": ["start", "request_assembly", "human_review", "emergency"],
            "terminal_state": "excluded",
            "transition_count": 3,
        }
    )
    with pytest.raises(ValidationError, match="terminal_state must match"):
        LiveTrajectoryReport.model_validate(terminal_excluded_without_state)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(terminal_excluded_without_state)

    included_nonverdict = report.model_dump(mode="json")
    included_nonverdict_path = included_nonverdict["paths"][1]
    included_nonverdict_path["states"][-1] = "emergency"
    included_nonverdict_path["terminal_state"] = "emergency"
    with pytest.raises(ValidationError, match="included trajectory paths must terminate"):
        LiveTrajectoryReport.model_validate(included_nonverdict)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(included_nonverdict)

    excluded_reordered = report.model_dump(mode="json")
    excluded_reordered_path = excluded_reordered["paths"][0]
    excluded_reordered_path.update(
        {
            "states": [
                "start",
                "request_assembly",
                "emergency",
                "human_review",
                "excluded",
            ],
            "transition_count": 4,
        }
    )
    with pytest.raises(ValidationError, match="canonical observable order"):
        LiveTrajectoryReport.model_validate(excluded_reordered)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(excluded_reordered)

    included_reordered = report.model_dump(mode="json")
    included_reordered_path = included_reordered["paths"][1]
    included_reordered_path.update(
        {
            "states": [
                "start",
                "request_assembly",
                "provider_call",
                "policy_check",
                "tool_call",
                "evidence_check",
                "verdict",
            ],
            "transition_count": 6,
        }
    )
    with pytest.raises(ValidationError, match="canonical observable order"):
        LiveTrajectoryReport.model_validate(included_reordered)
    with pytest.raises(JsonSchemaValidationError):
        writer_validator.validate(included_reordered)

    for invalid_states in (
        ["start", "provider_call", "verdict"],
        ["start", "request_assembly", "verdict"],
    ):
        missing_mandatory_state = report.model_dump(mode="json")
        missing_mandatory_path = missing_mandatory_state["paths"][1]
        missing_mandatory_path.update(
            {
                "states": invalid_states,
                "transition_count": len(invalid_states) - 1,
            }
        )
        with pytest.raises(ValidationError, match="canonical observable order"):
            LiveTrajectoryReport.model_validate(missing_mandatory_state)
        with pytest.raises(JsonSchemaValidationError):
            writer_validator.validate(missing_mandatory_state)

    historical_path_payload = {
        "artifact_kind": "trajectory-path-summary",
        "schema_version": "0.6.5",
        "observation_id": "historical-observation",
        "run_id": "historical-run",
        "case_id": "historical-case",
        "repetition_index": 0,
        "cluster_id": "historical-cluster",
        "states": ["start", "request_assembly", "excluded", "emergency"],
        "terminal_state": "emergency",
        "transition_count": 3,
        "tool_count": 0,
        "claim_count": 0,
        "evidence_ref_count": 0,
        "claim_evidence_link_count": 0,
        "policy_result_count": 0,
    }
    historical_path = TrajectoryPathSummary.model_validate(historical_path_payload)
    assert historical_path.terminal_state == "emergency"
    assert historical_path.states[-2:] == ("excluded", "emergency")
    historical_writer_schema = json.loads(
        Path("schemas/v0.6.5/live-trajectory-report.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(historical_writer_schema["$defs"]["TrajectoryPathSummary"]).validate(
        historical_path_payload
    )
    historical_path_validator = Draft202012Validator(
        historical_writer_schema["$defs"]["TrajectoryPathSummary"]
    )
    for legacy_states in (
        ["start", "request_assembly", "policy_check", "provider_call", "verdict"],
        ["start", "request_assembly", "verdict"],
    ):
        legacy_included_payload = {
            **historical_path_payload,
            "states": legacy_states,
            "terminal_state": "verdict",
            "transition_count": len(legacy_states) - 1,
        }
        legacy_included_path = TrajectoryPathSummary.model_validate(legacy_included_payload)
        assert legacy_included_path.states == tuple(legacy_states)
        historical_path_validator.validate(legacy_included_payload)


def test_current_trajectory_path_writer_schema_matches_pydantic_semantics() -> None:
    writer_validator = Draft202012Validator(writer_json_schema(TrajectoryPathSummary))
    included_nonapproval: dict[str, Any] = {
        "artifact_kind": "trajectory-path-summary",
        "schema_version": "0.6.6",
        "observation_id": "trajectory-schema-parity-observation",
        "run_id": "trajectory-schema-parity-run",
        "case_id": "trajectory-schema-parity-case",
        "repetition_index": 0,
        "cluster_id": "trajectory-schema-parity-cluster",
        "states": ["start", "request_assembly", "provider_call", "verdict"],
        "terminal_state": "verdict",
        "transition_count": 3,
        "tool_count": 0,
        "claim_count": 0,
        "evidence_ref_count": 0,
        "claim_evidence_link_count": 0,
        "policy_result_count": 0,
        "claim_evidence_complete": False,
        "claim_evidence_status": "not_applicable",
    }

    def assert_valid(payload: dict[str, Any]) -> TrajectoryPathSummary:
        validated = TrajectoryPathSummary.model_validate(payload)
        writer_validator.validate(payload)
        return validated

    def assert_invalid(payload: dict[str, Any], *, match: str) -> None:
        with pytest.raises(ValidationError, match=match):
            TrajectoryPathSummary.model_validate(payload)
        with pytest.raises(JsonSchemaValidationError):
            writer_validator.validate(payload)

    # Omitted booleans have the same false defaults in both validators.
    assert assert_valid(included_nonapproval).approval_outcome is False
    assert assert_valid(included_nonapproval).human_review_performed is False

    reviewed_approval = {
        **included_nonapproval,
        "states": [
            "start",
            "request_assembly",
            "provider_call",
            "human_review",
            "verdict",
        ],
        "transition_count": 4,
        "human_review_performed": True,
        "approval_outcome": True,
        "claim_evidence_complete": True,
        "claim_evidence_status": "complete",
    }
    assert assert_valid(reviewed_approval).human_review_performed is True

    unobservable_approval = {
        **included_nonapproval,
        "approval_outcome": True,
        "claim_evidence_status": "unobservable",
        "limitations": [CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION],
    }
    assert assert_valid(unobservable_approval).claim_evidence_status == "unobservable"

    assert_invalid(
        {**included_nonapproval, "transition_count": 2},
        match="transition_count must match",
    )
    assert_invalid(
        {**included_nonapproval, "human_review_performed": True},
        match="human-review fact",
    )
    assert_invalid(
        {**reviewed_approval, "human_review_performed": False},
        match="human-review fact",
    )
    reviewed_with_omitted_fact = dict(reviewed_approval)
    reviewed_with_omitted_fact.pop("human_review_performed")
    assert_invalid(reviewed_with_omitted_fact, match="human-review fact")

    assert_invalid(
        {
            **included_nonapproval,
            "limitations": [CLAIM_EVIDENCE_UNOBSERVABLE_PATH_LIMITATION],
        },
        match="observability limitation",
    )
    assert_invalid(
        {
            **included_nonapproval,
            "claim_evidence_complete": True,
            "claim_evidence_status": "complete",
        },
        match="observation and approval applicability",
    )
    assert_invalid(
        {**included_nonapproval, "approval_outcome": True},
        match="included approval paths require",
    )


@pytest.mark.parametrize(
    ("origin", "adapter_id", "reason_code", "path_field", "event_type"),
    (
        (
            StructuredFieldOrigin.fixture,
            "static-jsonl",
            ReasonCode.RUNTIME_FAILED,
            "runtime_failed",
            "runtime_failure",
        ),
        (
            StructuredFieldOrigin.instrumented_adapter,
            "external-script",
            ReasonCode.STRUCTURED_OUTPUT_INVALID,
            "malformed_output",
            "malformed_output",
        ),
    ),
)
def test_live_trajectory_counts_control_eligible_excluded_policy_failures_once(
    origin: StructuredFieldOrigin,
    adapter_id: str,
    reason_code: ReasonCode,
    path_field: Literal["runtime_failed", "malformed_output"],
    event_type: Literal["runtime_failure", "malformed_output"],
) -> None:
    compiled = compile_suite(SUITE)
    duplicate_failures = tuple(
        {
            "artifact_kind": "policy-result",
            "policy_id": f"runtime.live.{index}",
            "state": "fail",
            "reason_codes": [reason_code.value],
            "severity": "blocker",
            "message": "trusted operational failure",
        }
        for index in range(2)
    )
    payload = _record(
        repetition_index=0,
        linked=False,
        exclusion_reason="provider_incident",
        policy_results=duplicate_failures,
    ).model_dump(mode="json")
    payload["adapter_id"] = adapter_id
    payload["structured_field_origins"] = StructuredFieldOrigins.uniform(origin).model_dump(
        mode="json"
    )
    record = AgentRunRecord.model_validate(payload)

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id=f"trajectory-trusted-excluded-{origin.value}-{reason_code.value.lower()}",
    )

    assert evaluation.observations[0].reason_codes == ()
    path = report.paths[0]
    assert getattr(path, path_field) is True
    other_path_field = "malformed_output" if path_field == "runtime_failed" else "runtime_failed"
    assert getattr(path, other_path_field) is False
    matching_events = tuple(
        event
        for event in report.operational_events
        if event.event_type == event_type and event.observation_id == path.observation_id
    )
    assert len(matching_events) == 1
    assert matching_events[0].count == 1
    process = _event_process(report, event_type)
    assert process.observed_events == 1
    assert process.event_rate == "0.500000"
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)


@pytest.mark.parametrize(
    ("reason_code", "path_field", "event_type"),
    (
        (ReasonCode.RUNTIME_FAILED, "runtime_failed", "runtime_failure"),
        (
            ReasonCode.STRUCTURED_OUTPUT_INVALID,
            "malformed_output",
            "malformed_output",
        ),
    ),
)
def test_live_trajectory_counts_runner_observed_excluded_failures(
    reason_code: ReasonCode,
    path_field: Literal["runtime_failed", "malformed_output"],
    event_type: Literal["runtime_failure", "malformed_output"],
) -> None:
    compiled = compile_suite(SUITE)
    record = _runner_error_record(reason_code)

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id=f"trajectory-runner-excluded-{reason_code.value.lower()}",
    )

    assert evaluation.observations[0].reason_codes == ()
    path = report.paths[0]
    assert getattr(path, path_field) is True
    assert _event_process(report, event_type).observed_events == 1
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)


@pytest.mark.parametrize(
    ("origin", "adapter_id", "state"),
    (
        (StructuredFieldOrigin.model_self_report, "openai-chat-completions", "fail"),
        (StructuredFieldOrigin.legacy_unspecified, "static-jsonl", "fail"),
        (StructuredFieldOrigin.fixture, "static-jsonl", "pass"),
        (StructuredFieldOrigin.fixture, "static-jsonl", "warn"),
        (StructuredFieldOrigin.fixture, "static-jsonl", "not_evaluated"),
    ),
)
def test_live_trajectory_does_not_promote_untrusted_or_nonfailed_excluded_reasons(
    origin: StructuredFieldOrigin,
    adapter_id: str,
    state: Literal["pass", "fail", "warn", "not_evaluated"],
) -> None:
    compiled = compile_suite(SUITE)
    payload = _record(
        repetition_index=0,
        linked=False,
        exclusion_reason="provider_incident",
        policy_results=(
            {
                "artifact_kind": "policy-result",
                "policy_id": "runtime.live",
                "state": state,
                "reason_codes": [
                    ReasonCode.RUNTIME_FAILED.value,
                    ReasonCode.STRUCTURED_OUTPUT_INVALID.value,
                ],
                "severity": "blocker",
                "message": "non-authoritative operational reason",
            },
        ),
    ).model_dump(mode="json")
    payload["adapter_id"] = adapter_id
    payload["structured_field_origins"] = StructuredFieldOrigins.uniform(origin).model_dump(
        mode="json"
    )
    record = AgentRunRecord.model_validate(payload)

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id=f"trajectory-nonauthoritative-excluded-{origin.value}-{state}",
    )

    assert evaluation.observations[0].reason_codes == ()
    path = report.paths[0]
    assert path.runtime_failed is False
    assert path.malformed_output is False
    assert _event_process(report, "runtime_failure").observed_events == 0
    assert _event_process(report, "malformed_output").observed_events == 0
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)


def test_live_trajectory_keeps_evaluator_reasons_authoritative_for_included_records() -> None:
    compiled = compile_suite(SUITE)
    payload = _record(
        repetition_index=0,
        linked=True,
        policy_results=(
            {
                "artifact_kind": "policy-result",
                "policy_id": "runtime.live",
                "state": "fail",
                "reason_codes": [ReasonCode.RUNTIME_FAILED.value],
                "severity": "blocker",
                "message": "evaluator-visible runtime failure",
            },
        ),
    ).model_dump(mode="json")
    payload["adapter_id"] = "openai-chat-completions"
    payload["structured_field_origins"] = StructuredFieldOrigins.uniform(
        StructuredFieldOrigin.model_self_report
    ).model_dump(mode="json")
    record = AgentRunRecord.model_validate(payload)

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id="trajectory-included-evaluator-operational-reason",
    )

    assert ReasonCode.RUNTIME_FAILED in evaluation.observations[0].reason_codes
    assert report.paths[0].runtime_failed is True
    matching_events = tuple(
        event for event in report.operational_events if event.event_type == "runtime_failure"
    )
    assert len(matching_events) == 1
    assert matching_events[0].count == 1
    assert _event_process(report, "runtime_failure").observed_events == 1
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)


def test_live_trajectory_does_not_supplement_included_evaluator_reason_projection() -> None:
    compiled = compile_suite(SUITE)
    record = _record(
        repetition_index=0,
        linked=True,
        policy_results=(
            {
                "artifact_kind": "policy-result",
                "policy_id": "runtime.live",
                "state": "fail",
                "reason_codes": [
                    ReasonCode.POLICY_FAILED.value,
                    ReasonCode.RUNTIME_FAILED.value,
                    ReasonCode.STRUCTURED_OUTPUT_INVALID.value,
                ],
                "severity": "blocker",
                "message": "only the evaluator-projected primary reason is authoritative",
            },
        ),
    )

    protocol, runset, evaluation, report = _trajectory_for_record(
        compiled,
        record,
        runset_id="trajectory-included-no-source-policy-supplement",
    )

    assert ReasonCode.POLICY_FAILED in evaluation.observations[0].reason_codes
    assert ReasonCode.RUNTIME_FAILED not in evaluation.observations[0].reason_codes
    assert ReasonCode.STRUCTURED_OUTPUT_INVALID not in evaluation.observations[0].reason_codes
    assert report.paths[0].runtime_failed is False
    assert report.paths[0].malformed_output is False
    assert _event_process(report, "runtime_failure").observed_events == 0
    assert _event_process(report, "malformed_output").observed_events == 0
    _assert_trajectory_source_round_trip(report, runset, evaluation, protocol)


def test_live_trajectory_marks_included_nonapproval_evidence_not_applicable() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["recommendation"] = "deny"
    record_payload["outcome"] = "deny"
    record = AgentRunRecord.model_validate(record_payload)

    _, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-included-nonapproval",
    )

    path = report.paths[0]
    assert "excluded" not in path.states
    assert path.approval_outcome is False
    assert path.claim_evidence_status == "not_applicable"
    assert path.claim_evidence_complete is False
    evidence = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert evidence.evaluated_observations == 0
    assert evidence.prerequisite_status == "invalid"
    history = next(
        check
        for check in report.history_dependent_checks
        if check.check_id == "claim-evidence-history"
    )
    assert history.prerequisite_status == "invalid"
    assert "claim_evidence=`not_applicable`" in render_live_trajectory_markdown(report)

    forged = report.model_dump(mode="json")
    forged["paths"][0]["claim_evidence_status"] = "complete"
    forged["paths"][0]["claim_evidence_complete"] = True
    with pytest.raises(ValidationError, match="observation and approval applicability"):
        LiveTrajectoryReport.model_validate(forged)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(forged)


def test_live_trajectory_does_not_expand_material_claim_contract() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["claims"].append(
        {
            "artifact_kind": "claim-record",
            "claim_id": "non-material-observation",
        }
    )
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-non-material-claim",
    )

    assert not {
        ReasonCode.REQUIRED_SOURCE_MISSING,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
    }.intersection(evaluation.observations[0].reason_codes)
    assert report.paths[0].claim_evidence_status == "complete"
    assert report.paths[0].claim_evidence_complete is True
    invariant = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert invariant.affected_observations == 0
    assert invariant.unobservable_observations == 0


def test_live_trajectory_keeps_provenance_mismatch_definite_with_unobservable_ref() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["evidence_items"][0]["source_id"] = "different-receipt-source"
    record_payload["structured_field_origins"]["evidence_refs"] = "legacy_unspecified"
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-provenance-mismatch-unobservable-reference",
    )

    assert ReasonCode.EVIDENCE_PROVENANCE_MISMATCH in (evaluation.observations[0].reason_codes)
    _assert_trajectory_evidence_incomplete(report)


def test_live_trajectory_does_not_require_run_claim_observability() -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    record_payload["structured_field_origins"]["claims"] = "legacy_unspecified"
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id="trajectory-unobservable-run-claims",
    )

    assert not {
        ReasonCode.REQUIRED_SOURCE_MISSING,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
    }.intersection(evaluation.observations[0].reason_codes)
    assert report.paths[0].claim_count == 0
    assert report.paths[0].claim_evidence_status == "complete"
    assert report.paths[0].claim_evidence_complete is True
    invariant = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert invariant.affected_observations == 0
    assert invariant.unobservable_observations == 0


@pytest.mark.parametrize(
    ("unobservable_field", "expected_evidence_reasons"),
    [
        (
            "evidence_refs",
            frozenset(
                {
                    ReasonCode.REQUIRED_SOURCE_MISSING,
                    ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
                }
            ),
        ),
        (
            "evidence_items",
            frozenset({ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE}),
        ),
        (
            "claim_evidence_links",
            frozenset({ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE}),
        ),
    ],
    ids=("evidence-refs", "evidence-items", "claim-evidence-links"),
)
def test_live_trajectory_marks_each_unobservable_graph_field_unknown_and_warns_reviewers(
    unobservable_field: Literal["evidence_refs", "evidence_items", "claim_evidence_links"],
    expected_evidence_reasons: frozenset[ReasonCode],
) -> None:
    compiled = compile_suite(SUITE)
    record_payload = _record(repetition_index=0, linked=True).model_dump(mode="json")
    assert record_payload[unobservable_field]
    record_payload["structured_field_origins"][unobservable_field] = "legacy_unspecified"
    record = AgentRunRecord.model_validate(record_payload)

    evaluation, report = _single_record_trajectory(
        compiled,
        record,
        runset_id=f"trajectory-unobservable-{unobservable_field.replace('_', '-')}",
    )

    # The authoritative evaluator fails closed when any graph control field is
    # unobservable, while trajectory reporting preserves the epistemic reason:
    # unknown is neither a success nor a falsely asserted observable defect.
    evidence_reasons = {
        ReasonCode.EVIDENCE_PROVENANCE_MISMATCH,
        ReasonCode.MATERIAL_CLAIM_MISSING_EVIDENCE,
        ReasonCode.REQUIRED_SOURCE_MISSING,
    }.intersection(evaluation.observations[0].reason_codes)
    assert evidence_reasons == expected_evidence_reasons
    path = report.paths[0]
    assert path.claim_evidence_status == "unobservable"
    assert path.claim_evidence_complete is False
    assert any("completeness is unknown" in item for item in path.limitations)

    invariant = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert invariant.affected_observations == 0
    assert invariant.evaluated_observations == 0
    assert invariant.unobservable_observations == 1
    assert invariant.unobservable_observation_ids == (path.observation_id,)
    assert invariant.prerequisite_status == "invalid"
    assert invariant.state is GateState.warn
    assert any("cannot establish completeness" in item for item in invariant.limitations)

    history = next(
        check
        for check in report.history_dependent_checks
        if check.check_id == "claim-evidence-history"
    )
    assert history.affected_observations == 0
    assert history.prerequisite_status == "invalid"
    assert any("unobservable" in item for item in history.limitations)
    assert any("evidence completeness is unknown" in item for item in report.limitations)

    markdown = render_live_trajectory_markdown(report)
    assert "claim_evidence=`unobservable`" in markdown
    assert "unobservable=`1`" in markdown

    forged_path = report.model_dump(mode="json")
    forged_path["paths"][0]["claim_evidence_status"] = "complete"
    with pytest.raises(ValidationError, match="compatibility state"):
        LiveTrajectoryReport.model_validate(forged_path)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(forged_path)

    suppressed_warning = report.model_dump(mode="json")
    evidence_invariant = next(
        item
        for item in suppressed_warning["invariants"]
        if item["invariant_id"] == "claim-evidence-before-approval"
    )
    evidence_invariant["state"] = "not_evaluated"
    with pytest.raises(ValidationError, match="affected or unobservable"):
        LiveTrajectoryReport.model_validate(suppressed_warning)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(suppressed_warning)

    suppressed_limitation = report.model_dump(mode="json")
    suppressed_limitation["limitations"] = [
        item
        for item in suppressed_limitation["limitations"]
        if "evidence completeness is unknown" not in item
    ]
    with pytest.raises(ValidationError, match="observability limitation"):
        LiveTrajectoryReport.model_validate(suppressed_limitation)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            suppressed_limitation
        )


def test_live_trajectory_emits_only_plan_declared_analysis_families() -> None:
    compiled = compile_suite(SUITE)
    plan = _trajectory_plan()
    plan["analysis_methods"] = ["observable_transition_profile"]
    plan["invariants"] = []
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        trajectory_analysis_plan=plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-method-authority",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)

    assert report.transitions
    assert report.invariants == ()
    assert report.history_dependent_checks == ()
    assert report.event_processes == ()
    assert not any("burst-window" in limitation for limitation in report.limitations)
    Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
        report.model_dump(mode="json")
    )

    injected_event_output = report.model_dump(mode="json")
    full_plan = TrajectoryAnalysisPlan.model_validate(_trajectory_plan(minimum_event_count=1))
    injected_event_output["event_processes"] = [
        live_trajectory._event_processes((), exposure=1, plan=full_plan)[0].model_dump(mode="json")
    ]
    with pytest.raises(ValidationError, match="require event_process_summary"):
        LiveTrajectoryReport.model_validate(injected_event_output)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            injected_event_output
        )

    injected_invariant_output = report.model_dump(mode="json")
    injected_invariant_output["history_dependent_checks"] = [
        live_trajectory._history_dependent_checks(report.paths)[0].model_dump(mode="json")
    ]
    with pytest.raises(ValidationError, match="require sequence_invariant_check"):
        LiveTrajectoryReport.model_validate(injected_invariant_output)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            injected_invariant_output
        )


def test_live_trajectory_binds_runset_only_stop_reasons_to_trusted_source() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    complete_runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-trajectory-stop-reason-binding",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(_record(repetition_index=0, linked=True),),
    )
    complete_evaluation = evaluate_live_runset(
        compiled,
        complete_runset,
        protocol=protocol,
    )
    stopped_runset = RunSet.model_validate(
        complete_runset.model_copy(
            update={
                "completion_status": "incomplete",
                "stop_reasons": ("live_adapter_error",),
            }
        ).model_dump(mode="json")
    )
    stopped_evaluation = evaluate_live_runset(
        compiled,
        stopped_runset,
        protocol=protocol,
    )
    stopped_trajectory = build_live_trajectory_report(
        stopped_runset,
        stopped_evaluation,
        protocol=protocol,
    )

    assert stopped_evaluation.stop_reasons == ("live_adapter_error",)
    assert stopped_evaluation.source_completion_status == "incomplete"
    cleared_updates = {
        "stop_reasons": (),
        "budget_exceeded": False,
        "state": complete_evaluation.state,
    }
    copied_cleared = stopped_evaluation.model_copy(update=cleared_updates)
    constructed_cleared = type(stopped_evaluation).model_construct(
        **{**stopped_evaluation.__dict__, **cleared_updates}
    )
    for forged_evaluation in (copied_cleared, constructed_cleared):
        canonical_forgery = LiveEvaluationReport.model_validate(
            forged_evaluation.model_dump(mode="json")
        )
        schema_validation.validate_artifact_payload(
            canonical_forgery.model_dump(mode="json"),
            "live-evaluation-report",
        )
        with pytest.raises(ValueError, match="stop reasons do not match.*RunSet projection"):
            build_live_trajectory_report(
                stopped_runset,
                forged_evaluation,
                protocol=protocol,
            )

        rebound_report = _trajectory_with_source_evaluation_digest(
            stopped_trajectory,
            sha256_hexdigest(canonical_forgery),
        )
        assert (
            LiveTrajectoryReport.model_validate(rebound_report.model_dump(mode="json"))
            == rebound_report
        )
        with pytest.raises(ValueError, match="stop reasons do not match.*RunSet projection"):
            verify_live_trajectory_report_sources(
                rebound_report,
                stopped_runset,
                canonical_forgery,
                protocol=protocol,
            )


def test_live_trajectory_reconciles_complete_runset_observation_source_projection() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    run = _record(
        repetition_index=0,
        linked=True,
        cost="0.000001",
        cost_picousd=1_000_000,
        started_at_utc="2026-06-27T00:00:00Z",
        completed_at_utc="2026-06-27T00:00:01Z",
    )
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-trajectory-observation-source-binding",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(run,),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)
    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    trusted_runset_digest = sha256_hexdigest(runset)
    expected_source_projection = project_run_observation_source(run)
    assert (
        project_persisted_observation_source(evaluation.observations[0])
        == expected_source_projection
    )
    assert set(expected_source_projection.model_values()) == {
        "observation_id",
        "run_id",
        "case_id",
        "repetition_index",
        "schedule_index",
        "randomization_block_id",
        "prompt_digest",
        "provider",
        "model",
        "resolved_model",
        "provider_api_version",
        "provider_sdk",
        "provider_region",
        "adapter_id",
        "pipeline_id",
        "cluster_id",
        "source_group_id",
        "started_at_utc",
        "completed_at_utc",
        "observation_status",
        "exclusion_reason",
        "attempt_count",
        "retry_count",
        "rate_limit_events",
        "tool_schema_digest",
        "policy_bundle_digest",
        "outcome",
        "latency_ms",
        "estimated_cost_usd",
        "estimated_cost_picousd",
    }
    empty_outcome_run = AgentRunRecord.model_validate(
        {**run.model_dump(mode="json"), "outcome": ""}
    )
    empty_outcome_observation = evaluation.observations[0].model_copy(update={"outcome": ""})
    assert project_run_observation_source(empty_outcome_run).outcome == ""
    assert project_persisted_observation_source(empty_outcome_observation).outcome == ""

    mutation_cases = (
        (
            "observation_id",
            {"observation_id": "obs-forged-source-identity"},
        ),
        (
            "started_at_utc",
            {"started_at_utc": "2026-06-27T00:00:00.500000Z"},
        ),
        (
            "estimated_cost_picousd",
            {"estimated_cost_picousd": 999_999},
        ),
    )
    for expected_mismatch, run_updates in mutation_cases:
        tampered_run_payload = run.model_dump(mode="json")
        tampered_run_payload.update(run_updates)
        tampered_run = AgentRunRecord.model_validate(tampered_run_payload)
        tampered_runset_payload = runset.model_dump(mode="json")
        tampered_runset_payload["runs"] = [tampered_run.model_dump(mode="json")]
        tampered_runset = RunSet.model_validate(tampered_runset_payload)
        tampered_evaluation = evaluate_live_runset(
            compiled,
            tampered_runset,
            protocol=protocol,
        )
        source_digest_update = {"source_runset_digest": trusted_runset_digest}
        copied_forgery = tampered_evaluation.model_copy(update=source_digest_update)
        constructed_forgery = type(tampered_evaluation).model_construct(
            **{**tampered_evaluation.__dict__, **source_digest_update}
        )

        for forged_evaluation in (copied_forgery, constructed_forgery):
            canonical_forgery = LiveEvaluationReport.model_validate(
                forged_evaluation.model_dump(mode="json")
            )
            schema_validation.validate_artifact_payload(
                canonical_forgery.model_dump(mode="json"),
                "live-evaluation-report",
            )
            with pytest.raises(
                ValueError,
                match=rf"source projection.*mismatched fields: {expected_mismatch}",
            ):
                build_live_trajectory_report(
                    runset,
                    forged_evaluation,
                    protocol=protocol,
                )

            rebound_report = _trajectory_with_source_evaluation_digest(
                report,
                sha256_hexdigest(canonical_forgery),
            )
            with pytest.raises(
                ValueError,
                match=rf"source projection.*mismatched fields: {expected_mismatch}",
            ):
                verify_live_trajectory_report_sources(
                    rebound_report,
                    runset,
                    canonical_forgery,
                    protocol=protocol,
                )


def test_confirmatory_live_trajectory_has_a_reachable_valid_status() -> None:
    compiled = compile_suite(SUITE)
    plan = _trajectory_plan(minimum_event_count=3)
    plan["interpretation"] = "confirmatory"
    plan["invariants"][0]["interpretation"] = "confirmatory"
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        trajectory_analysis_plan=plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-confirmatory-valid",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                human_review_required=True,
                human_review_performed=True,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)

    assert report.trajectory_status == "invalid"
    assert report.source_evaluation_exploratory is True
    assert any("source evaluation is exploratory" in item for item in report.limitations)
    assert report.transition_assumption_status == "met"
    assert any(invariant.interpretation == "confirmatory" for invariant in report.invariants)
    assert all(process.observed_events == 0 for process in report.event_processes)
    assert all(process.prerequisite_status == "met" for process in report.event_processes)
    assert all(process.burst_signal == "none" for process in report.event_processes)
    Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
        report.model_dump(mode="json")
    )

    copied_evaluation = evaluation.model_copy(update={"exploratory": False})
    constructed_evaluation = type(evaluation).model_construct(
        **{**evaluation.__dict__, "exploratory": False}
    )
    for forged_evaluation in (copied_evaluation, constructed_evaluation):
        with pytest.raises(ValidationError, match="exploratory flag"):
            build_live_trajectory_report(
                runset,
                forged_evaluation,
                protocol=protocol,
            )
        with pytest.raises(ValidationError, match="exploratory flag"):
            verify_live_trajectory_report_sources(
                report,
                runset,
                forged_evaluation,
                protocol=protocol,
            )

    copied_runset = runset.model_copy(
        update={"completion_status": "incomplete", "stop_reasons": ()}
    )
    constructed_runset = type(runset).model_construct(
        **{
            **runset.__dict__,
            "completion_status": "incomplete",
            "stop_reasons": (),
        }
    )
    for forged_runset in (copied_runset, constructed_runset):
        with pytest.raises(ValidationError, match="incomplete live run sets require stop_reasons"):
            build_live_trajectory_report(
                forged_runset,
                evaluation,
                protocol=protocol,
            )
        with pytest.raises(ValidationError, match="incomplete live run sets require stop_reasons"):
            verify_live_trajectory_report_sources(
                report,
                forged_runset,
                evaluation,
                protocol=protocol,
            )

    complete_with_stop_payload = runset.model_dump(mode="json")
    complete_with_stop_payload["stop_reasons"] = ["live_adapter_error"]
    with pytest.raises(ValidationError, match="complete live run sets require empty stop_reasons"):
        RunSetModel.model_validate(complete_with_stop_payload)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(RunSetModel.model_json_schema(mode="validation")).validate(
            complete_with_stop_payload
        )
    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(
            complete_with_stop_payload,
            "run-set",
        )
    current_runset_schema = Draft202012Validator(RunSetModel.model_json_schema(mode="validation"))
    for omitted_completion_fields in (
        ("completion_status", "stop_reasons"),
        ("completion_status",),
        ("stop_reasons",),
    ):
        defaulted_completion_payload = runset.model_dump(mode="json")
        for field_name in omitted_completion_fields:
            defaulted_completion_payload.pop(field_name)
        current_runset_schema.validate(defaulted_completion_payload)
        defaulted_runset = RunSetModel.model_validate(defaulted_completion_payload)
        assert defaulted_runset.completion_status == "complete"
        assert defaulted_runset.stop_reasons == ()

    copied_complete_with_stop = runset.model_copy(update={"stop_reasons": ("live_adapter_error",)})
    constructed_complete_with_stop = type(runset).model_construct(
        **{**runset.__dict__, "stop_reasons": ("live_adapter_error",)}
    )
    for forged_runset in (copied_complete_with_stop, constructed_complete_with_stop):
        with pytest.raises(
            ValidationError,
            match="complete live run sets require empty stop_reasons",
        ):
            build_live_trajectory_report(
                forged_runset,
                evaluation,
                protocol=protocol,
            )
        with pytest.raises(
            ValidationError,
            match="complete live run sets require empty stop_reasons",
        ):
            verify_live_trajectory_report_sources(
                report,
                forged_runset,
                evaluation,
                protocol=protocol,
            )

    forged_protocol = protocol.model_copy(
        update={"allowed_exclusion_reasons": tuple(reversed(protocol.allowed_exclusion_reasons))}
    )
    with pytest.raises(ValidationError, match="canonical order"):
        build_live_trajectory_report(runset, evaluation, protocol=forged_protocol)
    with pytest.raises(ValidationError, match="canonical order"):
        verify_live_trajectory_report_sources(
            report,
            runset,
            evaluation,
            protocol=forged_protocol,
        )

    historical_protocol_payload = protocol.model_dump(mode="json")
    historical_protocol_payload["schema_version"] = "0.6.5"
    historical_trajectory_plan = historical_protocol_payload["trajectory_analysis_plan"]
    assert isinstance(historical_trajectory_plan, dict)
    historical_trajectory_plan["schema_version"] = "0.6.5"
    historical_invariants = historical_trajectory_plan["invariants"]
    assert isinstance(historical_invariants, list)
    for invariant in historical_invariants:
        assert isinstance(invariant, dict)
        invariant["schema_version"] = "0.6.5"
    historical_protocol = LiveProtocolRecord.model_validate(historical_protocol_payload)
    with pytest.raises(ValueError, match="must use current schema_version"):
        build_live_trajectory_report(runset, evaluation, protocol=historical_protocol)

    impossible_source_completion = report.model_dump(mode="json")
    impossible_source_completion["source_runset_completion_status"] = "incomplete"
    with pytest.raises(ValidationError, match="completion status does not match"):
        LiveTrajectoryReport.model_validate(impossible_source_completion)
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(
            impossible_source_completion
        )

    assert report.protocol is not None
    assert report.trajectory_plan is not None
    targetless_plan = report.trajectory_plan.model_copy(update={"invariants": ()})
    targetless_protocol = report.protocol.model_copy(
        update={"trajectory_analysis_plan": targetless_plan}
    )
    forged_targetless_report = report.model_copy(
        update={
            "protocol": targetless_protocol,
            "protocol_digest": sha256_hexdigest(targetless_protocol),
            "trajectory_plan": targetless_plan,
            "invariants": (),
            "trajectory_status": "valid",
        }
    )
    with pytest.raises(ValueError, match="status does not match replayed conclusions"):
        live_trajectory.verify_live_trajectory_report_derivation(forged_targetless_report)
    with pytest.raises(JsonSchemaValidationError):
        schema_validation.validate_artifact_payload(
            forged_targetless_report.model_dump(mode="json"),
            "live-trajectory-report",
        )


def test_required_review_invariant_restricts_declared_state_in_model_and_schema() -> None:
    payload = {
        "artifact_kind": "trajectory-invariant-plan",
        "schema_version": "0.6.6",
        "invariant_id": "review-before-approval",
        "label": "Required review occurs for approval",
        "invariant_type": "required_review_for_approval",
        "interpretation": "confirmatory",
        "required_state": "redaction_check",
    }

    with pytest.raises(ValidationError, match="human_review"):
        TrajectoryInvariantPlan.model_validate(payload)
    validator = Draft202012Validator(TrajectoryInvariantPlan.model_json_schema())
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(payload)

    implicit_current = dict(payload)
    implicit_current.pop("schema_version")
    with pytest.raises(ValidationError, match="human_review"):
        TrajectoryInvariantPlan.model_validate(implicit_current)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(implicit_current)

    omitted = dict(payload)
    omitted.pop("required_state")
    with pytest.raises(ValidationError, match="require required_state"):
        TrajectoryInvariantPlan.model_validate(omitted)
    with pytest.raises(JsonSchemaValidationError):
        validator.validate(omitted)

    legacy = {**payload, "schema_version": "0.6.5"}
    assert TrajectoryInvariantPlan.model_validate(legacy).required_state == "redaction_check"
    validator.validate(legacy)


def test_confirmatory_trajectory_rejects_zero_applicable_invariant_exposure() -> None:
    compiled = compile_suite(SUITE)
    plan = _trajectory_plan(minimum_event_count=3)
    plan["interpretation"] = "confirmatory"
    plan["invariants"][0]["interpretation"] = "confirmatory"
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        trajectory_analysis_plan=plan,
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-zero-applicable",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                human_review_required=False,
                human_review_performed=False,
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    review = _trajectory_invariant(report, "required-review-for-approval")

    assert review.evaluated_observations == 0
    assert review.prerequisite_status == "invalid"
    assert report.trajectory_status == "invalid"
    assert any("no observations were applicable" in item for item in review.limitations)

    forged = report.model_dump(mode="json")
    forged_review = next(
        item
        for item in forged["invariants"]
        if item["invariant_id"] == "required-review-for-approval"
    )
    forged_review.update(
        {
            "evaluated_observations": 1,
            "prerequisite_status": "met",
            "limitations": [],
        }
    )
    forged["trajectory_status"] = "valid"
    with pytest.raises(
        ValidationError,
        match="valid trajectory status|invariants do not match replayed",
    ):
        LiveTrajectoryReport.model_validate(forged)
    with pytest.raises((ValueError, JsonSchemaValidationError)):
        schema_validation.validate_artifact_payload(forged, "live-trajectory-report")


def test_live_trajectory_flags_history_dependent_governance_failures() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-failure",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=False,
                human_review_required=True,
                human_review_performed=False,
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)

    review = _trajectory_invariant(report, "required-review-for-approval")
    evidence = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert review.state is GateState.fail
    assert review.affected_observation_ids == ("obs-live-exp-001-0",)
    assert evidence.state is GateState.fail
    assert evidence.affected_observation_ids == ("obs-live-exp-001-0",)
    assert report.state is GateState.not_evaluated
    assert any(
        check.check_id == "claim-evidence-history" and check.affected_observations == 1
        for check in report.history_dependent_checks
    )

    suppressed_invariant = report.model_dump(mode="json")
    invariant = next(
        item
        for item in suppressed_invariant["invariants"]
        if item["invariant_id"] == "required-review-for-approval"
    )
    invariant["affected_observations"] = 0
    invariant["affected_observation_ids"] = []
    invariant["state"] = "not_evaluated"
    invariant["limitations"] = []
    with pytest.raises(ValidationError, match="invariants do not match replayed"):
        type(report).model_validate(suppressed_invariant)

    suppressed_history = report.model_dump(mode="json")
    check = next(
        item
        for item in suppressed_history["history_dependent_checks"]
        if item["check_id"] == "review-required-history"
    )
    check["affected_observations"] = 0
    check["affected_observation_ids"] = []
    check["limitations"] = []
    with pytest.raises(ValidationError, match="history checks do not match replayed"):
        type(report).model_validate(suppressed_history)


def test_live_trajectory_event_process_detects_retry_burst() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=4,
        clusters=1,
        repetitions=4,
        max_retries=1,
        trajectory_analysis_plan=_trajectory_plan(
            minimum_event_count=3,
            burst_window_seconds=60,
            burst_count_threshold=3,
        ),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-burst",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=tuple(
            _record(
                repetition_index=index,
                linked=True,
                attempt_count=2,
                retry_count=1,
                started_at_utc=f"2026-06-27T00:00:{index:02d}Z",
                completed_at_utc=f"2026-06-27T00:00:{index + 1:02d}Z",
            )
            for index in range(4)
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    retry_process = _event_process(report, "retry")

    assert retry_process.observed_events == 4
    assert retry_process.prerequisite_status == "met"
    assert retry_process.burst_signal == "review"
    assert retry_process.max_events_in_burst_window == 4
    assert retry_process.mean_interarrival_seconds == "1.000000"


def test_live_trajectory_event_process_marks_missing_timestamps_exploratory() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        max_retries=1,
        trajectory_analysis_plan=_trajectory_plan(minimum_event_count=1),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-missing-time",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                attempt_count=2,
                retry_count=1,
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    retry_process = _event_process(report, "retry")

    assert retry_process.prerequisite_status == "exploratory"
    assert retry_process.burst_signal == "invalid"
    assert retry_process.missing_timestamp_events == 1
    assert any("timestamps" in limitation for limitation in retry_process.limitations)


def test_live_trajectory_counted_retry_events_do_not_invent_timestamps() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=1,
        clusters=1,
        repetitions=1,
        max_retries=3,
        trajectory_analysis_plan=_trajectory_plan(minimum_event_count=1),
    )
    protocol_digest = sha256_hexdigest(protocol)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-trajectory-counted-retries",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        runs=(
            _record(
                repetition_index=0,
                linked=True,
                attempt_count=4,
                retry_count=3,
                started_at_utc="2026-06-27T00:00:00Z",
                completed_at_utc="2026-06-27T00:00:01Z",
            ),
        ),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)

    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    retry_process = _event_process(report, "retry")

    assert retry_process.observed_events == 3
    assert retry_process.timestamped_events == 1
    assert retry_process.missing_timestamp_events == 2
    assert retry_process.event_rate == "3.000000"
    assert retry_process.prerequisite_status == "exploratory"
    assert retry_process.burst_signal == "invalid"

    suppressed_retries = report.model_dump(mode="json")
    retry_process_payload = next(
        item for item in suppressed_retries["event_processes"] if item["event_type"] == "retry"
    )
    retry_process_payload.update(
        observed_events=0,
        event_rate="0.000000",
        timestamped_events=0,
        missing_timestamp_events=0,
        max_events_in_burst_window=0,
        burst_signal="none",
    )
    with pytest.raises(ValidationError, match="event processes do not match replayed"):
        type(report).model_validate(suppressed_retries)


def test_event_count_below_timing_threshold_cannot_claim_no_burst() -> None:
    plan = TrajectoryAnalysisPlan.model_validate(_trajectory_plan(minimum_event_count=3))
    event = TrajectoryOperationalEvent(
        artifact_kind="trajectory-operational-event",
        event_type="retry",
        observation_id="observation-1",
        count=1,
        timestamp_utc="2026-06-27T00:00:00Z",
    )

    process = live_trajectory._event_process_summary(
        "retry",
        [event],
        exposure=1,
        plan=plan,
    )

    assert process.prerequisite_status == "exploratory"
    assert process.burst_signal == "invalid"

    false_negative = process.model_dump(mode="json")
    false_negative["burst_signal"] = "none"
    with pytest.raises(ValidationError, match="burst signal"):
        OperationalEventProcessSummary.model_validate(false_negative)


def test_incomplete_event_timing_cannot_claim_no_burst() -> None:
    plan = TrajectoryAnalysisPlan.model_validate(_trajectory_plan(minimum_event_count=1))
    events = [
        TrajectoryOperationalEvent(
            artifact_kind="trajectory-operational-event",
            event_type="retry",
            observation_id=f"observation-{index}",
            count=1,
            timestamp_utc=timestamp,
        )
        for index, timestamp in enumerate(
            ("2026-06-27T00:00:00Z", "2026-06-27T00:00:10Z", None),
            start=1,
        )
    ]

    process = live_trajectory._event_process_summary(
        "retry",
        events,
        exposure=3,
        plan=plan,
    )

    assert process.timestamped_events == 2
    assert process.missing_timestamp_events == 1
    assert process.prerequisite_status == "exploratory"
    assert process.burst_signal == "invalid"

    false_negative = process.model_dump(mode="json")
    false_negative["burst_signal"] = "none"
    with pytest.raises(ValidationError, match="burst signal"):
        OperationalEventProcessSummary.model_validate(false_negative)


def test_trajectory_event_replay_is_linear_in_compact_rows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    parse_calls = 0
    original_parse = live_trajectory.parse_timestamp

    def counted_parse(value: str):
        nonlocal parse_calls
        parse_calls += 1
        return original_parse(value)

    monkeypatch.setattr(live_trajectory, "parse_timestamp", counted_parse)
    event = TrajectoryOperationalEvent(
        artifact_kind="trajectory-operational-event",
        event_type="retry",
        observation_id="observation-1",
        count=4_096,
        timestamp_utc="2026-06-27T00:00:00Z",
    )

    processes = live_trajectory._event_processes(
        (event,),
        exposure=1,
        plan=TrajectoryAnalysisPlan.model_validate(_trajectory_plan(minimum_event_count=1)),
    )
    retry_process = next(process for process in processes if process.event_type == "retry")

    assert parse_calls == 1
    assert retry_process.observed_events == 4_096
    assert retry_process.timestamped_events == 1
    assert retry_process.missing_timestamp_events == 4_095
    assert retry_process.event_rate == "4096.000000"


def test_live_protocol_rejects_inconsistent_design_effect() -> None:
    compiled = compile_suite(SUITE)

    with pytest.raises(ValueError, match="design_effect"):
        _protocol(compiled, observations=2, clusters=1, repetitions=2, design_effect="1.000000")


def test_live_protocol_rejects_unsupported_confidence_level() -> None:
    compiled = compile_suite(SUITE)
    payload = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
    ).model_dump(mode="json")
    payload["confidence_level"] = "0.990000"

    with pytest.raises(ValueError, match="confidence_level"):
        LiveProtocolRecord.model_validate(payload)


def test_non_inferiority_boundary_is_exact() -> None:
    assert _comparison_state(Decimal("-0.050000"), Decimal("0.050000"), 30, False) is GateState.fail
    assert (
        _comparison_state(Decimal("-0.049999"), Decimal("0.050000"), 30, False) is GateState.pass_
    )
    assert _comparison_state(Decimal("-0.050001"), Decimal("0.050000"), 30, False) is GateState.fail
    assert (
        _comparison_state(Decimal("0.000000"), Decimal("0.000000"), 30, False)
        is GateState.not_evaluated
    )
    assert _comparison_state(Decimal("-0.000001"), Decimal("0.000000"), 30, False) is GateState.fail


def _record(
    *,
    repetition_index: int,
    linked: bool,
    case_id: str = "exp-001",
    schedule_index: int | None = None,
    latency_ms: int = 100,
    cost: str = "0.000000",
    cost_picousd: int | None = None,
    cost_budget_committed: str | None = None,
    generated_token_budget_committed: int | None = None,
    total_token_budget_committed: int | None = None,
    exclusion_reason: str | None = None,
    cluster_id: str | None = None,
    source_group_id: str | None = None,
    started_at_utc: str | None = None,
    completed_at_utc: str | None = None,
    attempt_count: int = 1,
    retry_count: int = 0,
    rate_limit_events: int = 0,
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    total_tokens: int | None = None,
    human_review_required: bool = False,
    human_review_performed: bool = False,
    policy_results: tuple[dict[str, object], ...] | None = None,
) -> AgentRunRecord:
    links: list[dict[str, str]] = []
    if linked:
        links.append(
            {
                "artifact_kind": "claim-evidence-link",
                "claim_id": "claim-receipt-present",
                "evidence_ref_id": "ref-receipt-exp-001",
            }
        )
    return AgentRunRecord.model_validate(
        {
            "artifact_kind": "agent-run-record",
            "run_id": f"run-live-{case_id}-{repetition_index}",
            "case_id": case_id,
            "execution_mode": "live",
            "pipeline_id": "candidate",
            "recommendation": "approve",
            "outcome": "approve",
            "input_summary": "expense request",
            "output_summary": "receipt-backed approval",
            "observation_status": "excluded" if exclusion_reason else "included",
            "observation_id": f"obs-live-{case_id}-{repetition_index}",
            "repetition_index": repetition_index,
            "schedule_index": repetition_index if schedule_index is None else schedule_index,
            "randomization_block_id": f"repetition:{repetition_index}",
            "cluster_id": cluster_id or case_id,
            "source_group_id": source_group_id,
            "adapter_id": "static-jsonl",
            "provider": "static-provider",
            "model": "static-model",
            "resolved_model": "static-model-2026-06-27",
            "provider_api_version": "2026-06-27",
            "provider_sdk": "static-sdk/1.0.0",
            "started_at_utc": started_at_utc,
            "completed_at_utc": completed_at_utc,
            "latency_ms": latency_ms,
            "attempt_count": attempt_count,
            "retry_count": retry_count,
            "rate_limit_events": rate_limit_events,
            "exclusion_reason": exclusion_reason,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": cost,
            "estimated_cost_picousd": cost_picousd,
            "estimated_cost_source": "adapter_reported",
            "cost_budget_committed_usd": cost_budget_committed or cost,
            "generated_token_budget_committed": (
                completion_tokens
                if generated_token_budget_committed is None and completion_tokens is not None
                else generated_token_budget_committed or 0
            ),
            "total_token_budget_committed": (
                total_tokens
                if total_token_budget_committed is None and total_tokens is not None
                else total_token_budget_committed
                or generated_token_budget_committed
                or completion_tokens
                or 0
            ),
            "tools": ["expense_policy_check", "receipt_check"],
            "evidence_refs": [
                {
                    "artifact_kind": "evidence-ref",
                    "ref_id": "ref-receipt-exp-001",
                    "source_id": "receipt-exp-001",
                    "claim_ids": ["claim-receipt-present"],
                }
            ],
            "evidence_items": [
                {
                    "artifact_kind": "evidence-item",
                    "ref_id": "ref-receipt-exp-001",
                    "source_id": "receipt-exp-001",
                    "content_digest": "8" * 64,
                }
            ],
            "claims": [
                {
                    "artifact_kind": "claim-record",
                    "claim_id": "claim-receipt-present",
                }
            ],
            "claim_evidence_links": links,
            "policy_results": list(policy_results)
            if policy_results is not None
            else [
                {
                    "artifact_kind": "policy-result",
                    "policy_id": "provider-selection",
                    "state": "pass",
                    "reason_codes": [],
                    "severity": "info",
                    "message": "provider policy evaluated",
                }
            ],
            "human_review_required": human_review_required,
            "human_review_performed": human_review_performed,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.fixture
            ).model_dump(mode="json"),
            "provenance": Provenance(
                artifact_kind="provenance",
                prompt_digest="3" * 64,
                configuration_digest="4" * 64,
                tool_schema_digest="6" * 64,
                policy_bundle_digest="7" * 64,
                model_identifier="static-model",
            ).model_dump(mode="json"),
        }
    )


def _compiled_with_cases(compiled: CompiledSuite, count: int) -> CompiledSuite:
    case_template = compiled.cases[0]
    expectation_template = compiled.resolved_expectations[0]
    cases: list[dict[str, object]] = []
    expectations: list[dict[str, object]] = []
    for index in range(count):
        case_id = f"case-{index:03d}"
        expectation_id = f"expectation-{index:03d}"
        cases.append(
            case_template.model_copy(
                update={
                    "case_id": case_id,
                    "expectation_id": expectation_id,
                    "fixture_id": case_id,
                }
            ).model_dump(mode="json")
        )
        expectations.append(
            expectation_template.model_copy(
                update={
                    "case_id": case_id,
                    "expectation_id": expectation_id,
                }
            ).model_dump(mode="json")
        )
    return CompiledSuite.model_validate(
        {
            **compiled.model_dump(mode="json"),
            "cases": cases,
            "resolved_expectations": expectations,
        }
    )


def _case_report(
    compiled: CompiledSuite,
    protocol: LiveProtocolRecord,
    *,
    runset_id: str,
    count: int,
    linked: bool = True,
) -> LiveEvaluationReport:
    return evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id=runset_id,
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=tuple(
                _record(
                    repetition_index=0,
                    linked=linked,
                    case_id=f"case-{index:03d}",
                    schedule_index=index,
                )
                for index in range(count)
            ),
        ),
        protocol=protocol,
    )


def _cluster_success_report(
    compiled: CompiledSuite,
    protocol: LiveProtocolRecord,
    *,
    runset_id: str,
    successes: tuple[int, ...],
) -> LiveEvaluationReport:
    repetitions = protocol.planned_repetitions
    runs = tuple(
        _record(
            repetition_index=repetition_index,
            linked=repetition_index < success_count,
            case_id=f"case-{case_index:03d}",
            schedule_index=case_index * repetitions + repetition_index,
        )
        for case_index, success_count in enumerate(successes)
        for repetition_index in range(repetitions)
    )
    return evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id=runset_id,
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=runs,
        ),
        protocol=protocol,
    )


def _aggregate_validation_report() -> LiveEvaluationReport:
    compiled = _compiled_with_cases(compile_suite(SUITE), 2)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=2,
        repetitions=1,
    )
    return _case_report(
        compiled,
        protocol,
        runset_id="aggregate-validation",
        count=2,
        linked=False,
    )


def _advanced_validation_report() -> LiveEvaluationReport:
    compiled = _compiled_with_cases(compile_suite(SUITE), 2)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=2,
        repetitions=1,
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=1),
    )
    return _case_report(
        compiled,
        protocol,
        runset_id="advanced-validation",
        count=2,
        linked=False,
    )


def _repeated_validation_report() -> LiveEvaluationReport:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
    )
    return evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="repeated-validation",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="4" * 64,
            execution_mode=ExecutionMode.live,
            protocol_id=protocol.protocol_id,
            protocol_digest=sha256_hexdigest(protocol),
            runs=(
                _record(repetition_index=0, linked=False),
                _record(repetition_index=1, linked=False),
            ),
        ),
        protocol=protocol,
    )


def _protocol(
    compiled,
    *,
    observations: int,
    clusters: int,
    repetitions: int,
    baseline_mode: str = "concurrent_paired",
    analysis_method: str = "paired_cluster_t_interval",
    fixed_reference_pass_rate: str | None = None,
    design_effect: str | None = None,
    allowed_exclusion_reasons: tuple[str, ...] = (
        "budget_exhausted",
        "generated_token_budget_exhausted",
        "token_budget_exhausted",
    ),
    max_exclusion_rate: str = "0.000000",
    max_retries: int = 0,
    max_rate_limit_events: int = 0,
    max_cost_per_observation_usd: str = "1.000000",
    max_total_tokens: int | None = None,
    max_generated_tokens: int | None = None,
    advanced_analysis_plan: dict[str, object] | None = None,
    drift_monitoring_plan: dict[str, object] | None = None,
    trajectory_analysis_plan: dict[str, object] | None = None,
    non_inferiority_margin: str = "0.050000",
    cluster_by: Literal["case_id", "source_group_id"] = "case_id",
) -> LiveProtocolRecord:  # type: ignore[no-untyped-def]
    planned_observations_per_cluster = Decimal(observations) / Decimal(clusters)
    rho = Decimal("0.200000")
    expected_design_effect = Decimal("1") + (planned_observations_per_cluster - Decimal("1")) * rho
    selected_design_effect = design_effect or _decimal_string(expected_design_effect)
    return LiveProtocolRecord(
        artifact_kind="live-protocol-record",
        protocol_id="protocol-live-test",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        baseline_mode=baseline_mode,
        hypothesis_family="governance_control_non_inferiority",
        primary_endpoint="expectation_pass_rate",
        analysis_method=analysis_method,
        baseline_group_id="overall",
        candidate_group_id="overall",
        fixed_reference_pass_rate=fixed_reference_pass_rate,
        confidence_level="0.950000",
        non_inferiority_margin=non_inferiority_margin,
        cluster_by=cluster_by,
        planned_observations=observations,
        planned_clusters=clusters,
        planned_observations_per_cluster=_decimal_string(planned_observations_per_cluster),
        assumed_intraclass_correlation="0.200000",
        design_effect=selected_design_effect,
        planned_effective_n=_decimal_string(
            Decimal(observations) / Decimal(selected_design_effect)
        ),
        sample_size_rationale="unit test protocol fixture",
        planned_repetitions=repetitions,
        randomization_seed=17,
        randomization_blocking="balanced_case_blocks",
        max_requests=observations,
        max_total_cost_usd="10.000000",
        max_cost_per_observation_usd=max_cost_per_observation_usd,
        max_total_tokens=max_total_tokens,
        max_generated_tokens=max_generated_tokens,
        max_retries=max_retries,
        exclusion_policy="only pre-provider local configuration exclusions are allowed",
        allowed_exclusion_reasons=allowed_exclusion_reasons,
        max_exclusion_rate=max_exclusion_rate,
        max_rate_limit_events=max_rate_limit_events,
        provider_version_capture=("resolved_model", "provider_api_version", "provider_sdk"),
        stopping_rules=("stop on sensitive persistence",),
        tool_schema_digest="6" * 64,
        policy_bundle_digest="7" * 64,
        analysis_digest="5" * 64,
        advanced_analysis_plan=advanced_analysis_plan,
        drift_monitoring_plan=drift_monitoring_plan,
        trajectory_analysis_plan=trajectory_analysis_plan,
        approved_data_boundary="synthetic local test prompts",
        safety_limits=("no raw sensitive content",),
    )


def _advanced_plan(
    *,
    multiplicity_method: str = "single_endpoint",
    familywise_alpha: str = "0.050000",
    primary_minimum_clusters: int = 30,
    secondary_interpretation: str = "exploratory",
    rare_reason_codes: list[str] | None = None,
) -> dict[str, object]:
    return {
        "artifact_kind": "advanced-analysis-plan",
        "schema_version": "0.6.6",
        "multiplicity_method": multiplicity_method,
        "familywise_alpha": familywise_alpha,
        "observed_icc_confirmatory_use": "disabled",
        "endpoints": [
            {
                "artifact_kind": "statistical-endpoint-plan",
                "schema_version": "0.6.6",
                "endpoint_id": "expectation-pass",
                "label": "Expectation pass rate",
                "endpoint_kind": "expectation_pass_rate",
                "role": "primary",
                "interpretation": "confirmatory",
                "analysis_method": "hierarchical_binomial_summary",
                "minimum_clusters": primary_minimum_clusters,
                "minimum_observations": primary_minimum_clusters,
                "exchangeability_assumption": "baseline_candidate_relabeling",
            },
            {
                "artifact_kind": "statistical-endpoint-plan",
                "schema_version": "0.6.6",
                "endpoint_id": "critical-sensitive-content",
                "label": "Critical sensitive-content events",
                "endpoint_kind": "critical_event_rate",
                "role": "secondary",
                "interpretation": secondary_interpretation,
                "analysis_method": "clopper_pearson_exact_one_sided",
                "reason_codes": rare_reason_codes or [ReasonCode.RAW_SENSITIVE_CONTENT.value],
                "minimum_clusters": 1,
                "minimum_observations": 1,
                "exposure_unit": "independence_cluster",
            },
        ],
    }


def _drift_plan(
    *,
    minimum_windows: int = 3,
    minimum_dependence_windows: int | None = None,
    minimum_state_space_windows: int | None = None,
    ordering_variable: str = "window_index",
) -> dict[str, object]:
    dependence_windows = minimum_dependence_windows or 8
    state_space_windows = minimum_state_space_windows or 6
    return {
        "artifact_kind": "drift-monitoring-plan",
        "schema_version": "0.6.6",
        "plan_id": "drift-test-plan",
        "interpretation": "exploratory",
        "ordering_variable": ordering_variable,
        "comparability_mode": "strict_protocol_digest",
        "metrics": [
            {
                "artifact_kind": "drift-metric-plan",
                "schema_version": "0.6.6",
                "metric": "expectation_pass_rate",
                "label": "Expectation pass rate",
                "interpretation": "exploratory",
                "analysis_methods": [
                    "descriptive_trend",
                    "lag1_autocorrelation",
                    "ar1_summary",
                    "state_space_ewma",
                ],
                "minimum_windows": minimum_windows,
                "minimum_dependence_windows": dependence_windows,
                "minimum_state_space_windows": state_space_windows,
                "minimum_observations_per_window": 1,
                "slope_review_threshold": "0.050000",
                "step_review_threshold": "0.100000",
                "autocorrelation_review_threshold": "0.500000",
                "ar1_review_threshold": "0.500000",
                "state_space_alpha": "0.300000",
            }
        ],
    }


def _trajectory_plan(
    *,
    minimum_observations: int = 1,
    minimum_event_count: int = 3,
    burst_window_seconds: int = 60,
    burst_count_threshold: int = 3,
) -> dict[str, object]:
    return {
        "artifact_kind": "trajectory-analysis-plan",
        "schema_version": "0.6.6",
        "plan_id": "trajectory-test-plan",
        "interpretation": "exploratory",
        "analysis_methods": [
            "observable_transition_profile",
            "sequence_invariant_check",
            "event_process_summary",
            "burst_window_count",
        ],
        "minimum_observations": minimum_observations,
        "minimum_transition_support": 1,
        "minimum_event_count": minimum_event_count,
        "minimum_event_exposure": 1,
        "burst_window_seconds": burst_window_seconds,
        "burst_count_threshold": burst_count_threshold,
        "invariants": [
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.6.6",
                "invariant_id": "required-review-for-approval",
                "label": "Required review occurs before approval verdicts",
                "invariant_type": "required_review_for_approval",
                "category": "governance_control_failure",
                "interpretation": "exploratory",
                "required_state": "human_review",
            },
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.6.6",
                "invariant_id": "claim-evidence-before-approval",
                "label": "Approval verdicts retain explicit claim evidence links",
                "invariant_type": "claim_evidence_before_approval",
                "category": "governance_control_failure",
                "interpretation": "exploratory",
            },
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.6.6",
                "invariant_id": "attempt-retry-consistency",
                "label": "Attempt counters remain consistent with retry counters",
                "invariant_type": "attempt_retry_consistency",
                "category": "operational_reliability_warning",
                "interpretation": "exploratory",
            },
        ],
    }


def _trajectory_with_source_evaluation_digest(
    report: LiveTrajectoryReport,
    source_evaluation_digest: str,
) -> LiveTrajectoryReport:
    assert report.trajectory_plan is not None
    return report.model_copy(
        update={
            "source_evaluation_digest": source_evaluation_digest,
            "report_id": live_trajectory._trajectory_report_id(
                protocol_digest=report.protocol_digest,
                plan=report.trajectory_plan,
                source_runset_digest=report.source_runset_digest or "",
                source_evaluation_digest=source_evaluation_digest,
                source_runset_completion_status=report.source_runset_completion_status,
                source_evaluation_completion_status=(report.source_evaluation_completion_status),
                source_evaluation_stop_reasons=(report.source_evaluation_stop_reasons or ()),
                source_evaluation_exploratory=report.source_evaluation_exploratory,
                paths=report.paths,
                operational_events=report.operational_events,
            ),
        }
    )


def _single_record_trajectory(
    compiled: CompiledSuite,
    record: AgentRunRecord,
    *,
    runset_id: str,
) -> tuple[LiveEvaluationReport, LiveTrajectoryReport]:
    protocol = _protocol(compiled, observations=1, clusters=1, repetitions=1)
    runset = RunSet(
        artifact_kind="run-set",
        runset_id=runset_id,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        runs=(record,),
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)
    return evaluation, build_live_trajectory_report(
        runset,
        evaluation,
        protocol=protocol,
    )


def _trajectory_for_record(
    compiled: CompiledSuite,
    record: AgentRunRecord,
    *,
    runset_id: str,
    emergency_records: tuple[EmergencyProcessRecord, ...] = (),
) -> tuple[LiveProtocolRecord, RunSet, LiveEvaluationReport, LiveTrajectoryReport]:
    exclusion_reason = record.exclusion_reason
    observations = 2 if exclusion_reason else 1
    protocol = _protocol(
        compiled,
        observations=observations,
        clusters=1,
        repetitions=observations,
        allowed_exclusion_reasons=((exclusion_reason,) if exclusion_reason else ()),
        max_exclusion_rate="0.500000" if exclusion_reason else "0.000000",
        trajectory_analysis_plan=_trajectory_plan(minimum_event_count=1),
    )
    network_authority_receipt = (
        LiveNetworkAuthorityReceipt(
            endpoint_host="api.openai.com",
            api_key_env="OPENAI_API_KEY",
        )
        if record.adapter_id == "openai-chat-completions"
        else None
    )
    runs = (record,)
    if exclusion_reason:
        companion_payload = _record(repetition_index=1, linked=True).model_dump(mode="json")
        companion_payload["adapter_id"] = record.adapter_id
        if (
            record.structured_field_origins is not None
            and StructuredFieldOrigin.runner_observed
            not in set(record.structured_field_origins.model_dump(mode="python").values())
        ):
            companion_payload["structured_field_origins"] = (
                record.structured_field_origins.model_dump(mode="json")
            )
        runs = (record, AgentRunRecord.model_validate(companion_payload))
    runset = RunSet(
        artifact_kind="run-set",
        runset_id=runset_id,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="4" * 64,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        network_authority_receipt=network_authority_receipt,
        emergency_records=emergency_records,
        runs=runs,
    )
    evaluation = evaluate_live_runset(compiled, runset, protocol=protocol)
    report = build_live_trajectory_report(runset, evaluation, protocol=protocol)
    return protocol, runset, evaluation, report


def _runner_error_record(reason_code: ReasonCode) -> AgentRunRecord:
    payload = _record(
        repetition_index=0,
        linked=False,
        exclusion_reason=(
            "structured-output-invalid"
            if reason_code is ReasonCode.STRUCTURED_OUTPUT_INVALID
            else "runtime-failed"
        ),
    ).model_dump(mode="json")
    payload.update(
        {
            "recommendation": "error",
            "outcome": "excluded",
            "output_summary": "runner observed an operational failure",
            "tools": [],
            "evidence_refs": [],
            "evidence_items": [],
            "claims": [],
            "claim_evidence_links": [],
            "policy_results": [
                {
                    "artifact_kind": "policy-result",
                    "policy_id": "runtime.live",
                    "state": "fail",
                    "reason_codes": [reason_code.value],
                    "severity": "blocker",
                    "message": "runner-observed operational failure",
                }
            ],
            "human_review_required": False,
            "human_review_performed": False,
            "structured_field_origins": StructuredFieldOrigins.uniform(
                StructuredFieldOrigin.runner_observed
            ).model_dump(mode="json"),
        }
    )
    return AgentRunRecord.model_validate(payload)


def _assert_trajectory_source_round_trip(
    report: LiveTrajectoryReport,
    runset: RunSet,
    evaluation: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> None:
    payload = report.model_dump(mode="json")
    round_tripped = LiveTrajectoryReport.model_validate(payload)
    assert round_tripped == report
    Draft202012Validator(LiveTrajectoryReport.model_json_schema()).validate(payload)
    verify_live_trajectory_report_sources(
        round_tripped,
        runset,
        evaluation,
        protocol=protocol,
    )


def _assert_trajectory_evidence_incomplete(report: LiveTrajectoryReport) -> None:
    path = report.paths[0]
    assert path.claim_evidence_status == "incomplete"
    assert path.claim_evidence_complete is False
    assert not any("completeness is unknown" in item for item in path.limitations)

    invariant = _trajectory_invariant(report, "claim-evidence-before-approval")
    assert invariant.affected_observations == 1
    assert invariant.affected_observation_ids == (path.observation_id,)
    assert invariant.evaluated_observations == 1
    assert invariant.unobservable_observations == 0
    assert invariant.unobservable_observation_ids == ()
    assert invariant.prerequisite_status == "met"
    assert invariant.state is GateState.fail

    history = next(
        check
        for check in report.history_dependent_checks
        if check.check_id == "claim-evidence-history"
    )
    assert history.affected_observations == 1
    assert history.affected_observation_ids == (path.observation_id,)
    assert history.prerequisite_status == "met"


def _trajectory_invariant(report: LiveTrajectoryReport, invariant_id: str):
    for invariant in report.invariants:
        if invariant.invariant_id == invariant_id:
            return invariant
    raise AssertionError(f"missing trajectory invariant {invariant_id!r}")


def _event_process(report: LiveTrajectoryReport, event_type: OperationalEventType):
    for process in report.event_processes:
        if process.event_type == event_type:
            return process
    raise AssertionError(f"missing event process {event_type!r}")


def _decimal_string(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.000001')):f}"
