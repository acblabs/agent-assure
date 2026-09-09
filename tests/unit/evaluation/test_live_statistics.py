from __future__ import annotations

from decimal import Decimal
from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.advanced import (
    _bootstrap_icc_interval,
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
    compare_live_reports,
)
from agent_assure.live.drift import _metric_value, build_live_drift_report
from agent_assure.live.intervals import difference_t_interval, stable_seed_int, t_critical_95
from agent_assure.live.primitives import decimal_string as live_decimal_string
from agent_assure.live.statistics import _rate_from_values, evaluate_live_runset
from agent_assure.live.trajectory import build_live_trajectory_report
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.schema.common import (
    ExecutionMode,
    GateState,
    ReasonCode,
)
from agent_assure.schema.common import (
    decimal_string as schema_decimal_string,
)
from agent_assure.schema.live import (
    DriftMetricPlan,
    LiveEvaluationReport,
    LiveProtocolRecord,
    LiveRate,
    LiveTrajectoryReport,
    OperationalEventType,
)
from agent_assure.schema.privacy import PrivacyProfileDigest, PrivacyProfileId
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import (
    AgentRunRecord,
    StructuredFieldOrigin,
    StructuredFieldOrigins,
)
from agent_assure.schema.run import RunSet as RunSetModel
from agent_assure.schema.suite import CompiledSuite


class RunSet(RunSetModel):
    """Current-profile RunSet fixture for statistics tests unrelated to privacy."""

    privacy_profile_id: PrivacyProfileId = PRIVACY_PROFILE_ID
    privacy_profile_digest: PrivacyProfileDigest = PRIVACY_PROFILE_DIGEST


SUITE = Path("examples/expense_approval_minimal/suite.yaml")


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
            "adapter_id": "other-adapter",
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

    with pytest.raises(ValueError, match="duplicate prompt and schedule identity"):
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

    with pytest.raises(ValueError, match=message):
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

    with pytest.raises(ValueError, match=message):
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


def test_degenerate_all_pass_rate_interval_is_not_spuriously_exact() -> None:
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
    assert Decimal(rate.ci_lower) < Decimal("1.000000")
    assert rate.ci_upper == "1.000000"
    assert rate.analysis_method == "descriptive_degenerate_boundary_interval"
    assert rate.exploratory is True


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
        if candidate.analysis_method == "poisson_upper_bound"
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


def test_rare_event_poisson_bound_uses_protocol_confidence_not_familywise_alpha() -> None:
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
    assert rare.rare_event_bound.upper_count_bound == "2.995732"


def test_confirmatory_bonferroni_poisson_bound_uses_adjusted_alpha() -> None:
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
    assert rare.rare_event_bound.upper_count_bound == "3.688879"
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


def test_live_comparison_marks_incomplete_reports_not_evaluated() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
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
    assert any("candidate live report is incomplete" in item for item in comparison.limitations)


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


def test_exact_paired_randomization_fails_closed_above_enumeration_limit() -> None:
    compiled = _compiled_with_cases(compile_suite(SUITE), 21)
    protocol = _protocol(
        compiled,
        observations=21,
        clusters=21,
        repetitions=1,
        analysis_method="paired_cluster_permutation_exact",
        advanced_analysis_plan=_advanced_plan(primary_minimum_clusters=21),
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
                for index in range(21)
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
                for index in range(21)
            ),
        ),
        protocol=protocol,
    )

    comparison = compare_live_reports(baseline, candidate, protocol=protocol)

    assert comparison.state is GateState.not_evaluated
    assert comparison.exploratory is True
    assert comparison.randomization_tests[0].prerequisite_status == "invalid"
    assert comparison.randomization_tests[0].p_value is None


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

    with pytest.raises(ValueError, match="identical included prompt, schedule"):
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

    with pytest.raises(ValueError, match="identical included prompt, schedule"):
        compare_live_reports(baseline, candidate, protocol=protocol)


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

    assert report.state is GateState.not_evaluated
    assert report.monitoring_status == "exploratory"
    assert report.comparability.status == "pass"
    assert report.observation_window_start_utc == "2026-06-27T00:00:00Z"
    diagnostic = report.diagnostics[0]
    assert diagnostic.metric == "expectation_pass_rate"
    assert diagnostic.prerequisite_status == "met"
    assert diagnostic.stationarity_signal == "review"
    assert diagnostic.dependence_signal == "none"
    assert diagnostic.slope_per_window == "-0.228571"
    assert diagnostic.state_estimate is not None
    assert diagnostic.state_estimate.state_name == "governance_health"
    assert any("review signal" in limitation for limitation in report.limitations)


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

    assert diagnostic.prerequisite_status == "met"
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

    assert report.state is GateState.not_evaluated
    assert report.trajectory_status == "exploratory"
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
    assert evidence.state is GateState.not_evaluated


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
    assert retry_process.prerequisite_status == "exploratory"
    assert retry_process.burst_signal == "invalid"


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
            "provider_sdk": "static-sdk@1.0.0",
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
        "token_budget_exhausted",
        "generated_token_budget_exhausted",
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
        "schema_version": "0.2.0",
        "multiplicity_method": multiplicity_method,
        "familywise_alpha": familywise_alpha,
        "observed_icc_confirmatory_use": "disabled",
        "endpoints": [
            {
                "artifact_kind": "statistical-endpoint-plan",
                "schema_version": "0.2.0",
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
                "schema_version": "0.2.0",
                "endpoint_id": "critical-sensitive-content",
                "label": "Critical sensitive-content events",
                "endpoint_kind": "critical_event_rate",
                "role": "secondary",
                "interpretation": secondary_interpretation,
                "analysis_method": "poisson_upper_bound",
                "reason_codes": rare_reason_codes or [ReasonCode.RAW_SENSITIVE_CONTENT.value],
                "minimum_clusters": 1,
                "minimum_observations": 1,
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
        "schema_version": "0.2.0",
        "plan_id": "drift-test-plan",
        "interpretation": "exploratory",
        "ordering_variable": ordering_variable,
        "comparability_mode": "strict_protocol_digest",
        "metrics": [
            {
                "artifact_kind": "drift-metric-plan",
                "schema_version": "0.2.0",
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
    minimum_event_count: int = 3,
    burst_window_seconds: int = 60,
    burst_count_threshold: int = 3,
) -> dict[str, object]:
    return {
        "artifact_kind": "trajectory-analysis-plan",
        "schema_version": "0.2.0",
        "plan_id": "trajectory-test-plan",
        "interpretation": "exploratory",
        "analysis_methods": [
            "observable_transition_profile",
            "sequence_invariant_check",
            "event_process_summary",
            "burst_window_count",
        ],
        "minimum_observations": 1,
        "minimum_transition_support": 1,
        "minimum_event_count": minimum_event_count,
        "minimum_event_exposure": 1,
        "burst_window_seconds": burst_window_seconds,
        "burst_count_threshold": burst_count_threshold,
        "invariants": [
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.2.0",
                "invariant_id": "required-review-for-approval",
                "label": "Required review occurs before approval verdicts",
                "invariant_type": "required_review_for_approval",
                "category": "governance_control_failure",
                "interpretation": "exploratory",
                "required_state": "human_review",
            },
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.2.0",
                "invariant_id": "claim-evidence-before-approval",
                "label": "Approval verdicts retain explicit claim evidence links",
                "invariant_type": "claim_evidence_before_approval",
                "category": "governance_control_failure",
                "interpretation": "exploratory",
            },
            {
                "artifact_kind": "trajectory-invariant-plan",
                "schema_version": "0.2.0",
                "invariant_id": "attempt-retry-consistency",
                "label": "Attempt counters remain consistent with retry counters",
                "invariant_type": "attempt_retry_consistency",
                "category": "operational_reliability_warning",
                "interpretation": "exploratory",
            },
        ],
    }


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
