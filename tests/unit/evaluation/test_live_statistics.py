from __future__ import annotations

from decimal import Decimal
from pathlib import Path

import pytest

from agent_assure.authoring.compiler import compile_suite
from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.fixtures.loader import compiled_suite_digest
from agent_assure.live.comparison import _comparison_state, compare_live_reports
from agent_assure.live.statistics import _rate_from_values, evaluate_live_runset
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, RunSet

SUITE = Path("examples/expense_approval_minimal/suite.yaml")


def test_live_statistics_aggregate_repeated_observations() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="1" * 64,
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
    assert report.overall.observations == 2
    assert report.overall.cluster_count == 1
    assert report.overall.expectation_pass_rate.effective_n == "1.666667"
    assert report.overall.expectation_pass_rate.largest_cluster_size == 2
    assert report.overall.expectation_pass_rate.largest_cluster_design_effect == "1.200000"
    assert report.overall.expectation_pass_rate.largest_cluster_effective_n == "1.666667"
    assert report.overall.expectation_pass_rate.exploratory is True
    assert report.overall.expectation_pass_rate.rate == "0.500000"
    assert report.overall.expectation_pass_rate.cluster_mean_rate == "0.500000"
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
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-exclusions",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="1" * 64,
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


def test_live_statistics_marks_budget_stop_as_incomplete() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        max_exclusion_rate="0.600000",
    )
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    runset = RunSet(
        artifact_kind="run-set",
        runset_id="runset-live-budget",
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=compiled_suite_digest(compiled),
        fixture_manifest_digest="1" * 64,
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


def test_live_comparison_reports_pass_rate_difference() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(compiled, observations=2, clusters=1, repetitions=2)
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="1" * 64,
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
            fixture_manifest_digest="2" * 64,
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


def test_live_comparison_honors_paired_bootstrap_protocol_method() -> None:
    compiled = compile_suite(SUITE)
    protocol = _protocol(
        compiled,
        observations=2,
        clusters=1,
        repetitions=2,
        analysis_method="paired_cluster_bootstrap_percentile",
    )
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="1" * 64,
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
            fixture_manifest_digest="2" * 64,
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
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
    baseline = evaluate_live_runset(
        compiled,
        RunSet(
            artifact_kind="run-set",
            runset_id="baseline-live",
            suite_id=compiled.suite_id,
            suite_version=compiled.suite_version,
            suite_digest=compiled_suite_digest(compiled),
            fixture_manifest_digest="1" * 64,
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
            fixture_manifest_digest="2" * 64,
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
    assert (
        _comparison_state(Decimal("-0.050000"), Decimal("0.050000"), 30, False)
        is GateState.pass_
    )
    assert (
        _comparison_state(Decimal("-0.050001"), Decimal("0.050000"), 30, False)
        is GateState.fail
    )


def _record(
    *,
    repetition_index: int,
    linked: bool,
    latency_ms: int = 100,
    cost: str = "0.000000",
    exclusion_reason: str | None = None,
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
            "run_id": f"run-live-{repetition_index}",
            "case_id": "exp-001",
            "execution_mode": "live",
            "pipeline_id": "candidate",
            "recommendation": "approve",
            "outcome": "approve",
            "input_summary": "expense request",
            "output_summary": "receipt-backed approval",
            "observation_status": "excluded" if exclusion_reason else "included",
            "observation_id": f"obs-live-{repetition_index}",
            "repetition_index": repetition_index,
            "schedule_index": repetition_index,
            "randomization_block_id": f"repetition:{repetition_index}",
            "cluster_id": "exp-001",
            "adapter_id": "static-jsonl",
            "provider": "static-provider",
            "model": "static-model",
            "resolved_model": "static-model-2026-06-27",
            "provider_api_version": "2026-06-27",
            "provider_sdk": "static-sdk@1.0.0",
            "latency_ms": latency_ms,
            "attempt_count": 1,
            "retry_count": 0,
            "rate_limit_events": 0,
            "exclusion_reason": exclusion_reason,
            "estimated_cost_usd": cost,
            "tools": ["expense_policy_check", "receipt_check"],
            "evidence_refs": [
                {
                    "artifact_kind": "evidence-ref",
                    "ref_id": "ref-receipt-exp-001",
                    "source_id": "receipt-exp-001",
                    "claim_ids": ["claim-receipt-present"],
                }
            ],
            "claims": [
                {
                    "artifact_kind": "claim-record",
                    "claim_id": "claim-receipt-present",
                }
            ],
            "claim_evidence_links": links,
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
) -> LiveProtocolRecord:  # type: ignore[no-untyped-def]
    planned_observations_per_cluster = Decimal(observations) / Decimal(clusters)
    rho = Decimal("0.200000")
    expected_design_effect = Decimal("1") + (
        planned_observations_per_cluster - Decimal("1")
    ) * rho
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
        non_inferiority_margin="0.000000",
        cluster_by="case_id",
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
        max_cost_per_observation_usd="1.000000",
        max_retries=0,
        exclusion_policy="only pre-provider local configuration exclusions are allowed",
        allowed_exclusion_reasons=allowed_exclusion_reasons,
        max_exclusion_rate=max_exclusion_rate,
        provider_version_capture=("resolved_model", "provider_api_version", "provider_sdk"),
        stopping_rules=("stop on sensitive persistence",),
        tool_schema_digest="6" * 64,
        policy_bundle_digest="7" * 64,
        analysis_digest="5" * 64,
        approved_data_boundary="synthetic local test prompts",
        safety_limits=("no raw sensitive content",),
    )


def _decimal_string(value: Decimal) -> str:
    return f"{value.quantize(Decimal('0.000001')):f}"
