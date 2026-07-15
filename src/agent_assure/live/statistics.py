from __future__ import annotations

from collections import Counter, defaultdict
from decimal import Decimal
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import (
    evaluate_case,
    evaluate_required_policy_results_for_run,
)
from agent_assure.live.advanced import evaluate_statistical_invariants
from agent_assure.live.intervals import (
    bootstrap_mean_interval,
    cluster_t_interval,
    nearest_rank_percentile,
)
from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    probability_string,
)
from agent_assure.policies.base import (
    DEFAULT_GATE_PROFILE,
    ControlResult,
    GateProfile,
    rollup_state,
)
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.evaluation import Finding
from agent_assure.schema.live import (
    LiveDistribution,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveRate,
)
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.suite import CompiledSuite

BUDGET_STOP_REASONS = {
    "budget_exhausted",
    "cost_budget_exceeded_after_response",
    "generated_token_budget_exceeded_after_response",
    "token_budget_exceeded_after_response",
    "token_budget_exhausted",
    "generated_token_budget_exhausted",
}


def evaluate_live_runset(
    suite: CompiledSuite,
    runset: RunSet,
    *,
    protocol: LiveProtocolRecord,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
) -> LiveEvaluationReport:
    _verify_live_binding(suite, runset, protocol)
    resolver = ExpectationResolver(suite)
    observations = tuple(
        _evaluate_observation(
            resolver,
            run,
            gate_profile=gate_profile,
            allowed_tools=suite.defaults.allowed_tools,
            required_policy_ids=suite.defaults.required_policy_ids,
        )
        for run in runset.runs
    )
    groups = tuple(
        _summarize_group(
            group_id,
            group_runs,
            group_observations,
            protocol=protocol,
        )
        for group_id, group_runs, group_observations in _groups(runset.runs, observations)
    )
    overall = _summarize_group(
        "overall",
        tuple(runset.runs),
        observations,
        protocol=protocol,
    )
    stop_reasons = _stop_reasons(runset)
    completion_status: Literal["complete", "incomplete"]
    if stop_reasons or runset.completion_status == "incomplete":
        completion_status = "incomplete"
    else:
        completion_status = "complete"
    return LiveEvaluationReport(
        artifact_kind="live-evaluation-report",
        runset_id=runset.runset_id,
        suite_id=suite.suite_id,
        suite_version=suite.suite_version,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        cluster_by=protocol.cluster_by,
        planned_repetitions=protocol.planned_repetitions,
        planned_observations=protocol.planned_observations,
        planned_clusters=protocol.planned_clusters,
        completion_status=completion_status,
        stop_reasons=stop_reasons,
        budget_exceeded=bool(BUDGET_STOP_REASONS & set(stop_reasons)),
        state=_report_state(observations, overall, protocol, stop_reasons),
        confidence_level=protocol.confidence_level,
        observations=observations,
        overall=overall,
        groups=groups,
        statistical_invariants=evaluate_statistical_invariants(
            tuple(runset.runs),
            observations,
            protocol,
        ),
    )


def _verify_live_binding(
    suite: CompiledSuite,
    runset: RunSet,
    protocol: LiveProtocolRecord,
) -> None:
    if runset.suite_id != suite.suite_id:
        raise ValueError(
            f"run set suite_id {runset.suite_id!r} does not match compiled suite {suite.suite_id!r}"
        )
    if runset.suite_version != suite.suite_version:
        raise ValueError(
            f"run set suite_version {runset.suite_version!r} does not match compiled suite "
            f"{suite.suite_version!r}"
        )
    if runset.execution_mode.value != "live":
        raise ValueError("live evaluation requires a RunSet with execution_mode='live'")
    protocol_digest = sha256_hexdigest(protocol)
    if runset.protocol_id != protocol.protocol_id or runset.protocol_digest != protocol_digest:
        raise ValueError("live RunSet protocol binding does not match protocol")
    _verify_protocol_obligations(runset, protocol)


def _verify_protocol_obligations(runset: RunSet, protocol: LiveProtocolRecord) -> None:
    if len(runset.runs) != protocol.planned_observations:
        raise ValueError("live RunSet observation count does not match protocol")
    repetitions = {run.repetition_index for run in runset.runs if run.repetition_index is not None}
    if len(repetitions) != protocol.planned_repetitions:
        raise ValueError("live RunSet repetitions do not match protocol")
    clusters = {run.cluster_id for run in runset.runs if run.cluster_id is not None}
    if len(clusters) != protocol.planned_clusters:
        raise ValueError("live RunSet cluster count does not match protocol")
    allowed_exclusions = set(protocol.allowed_exclusion_reasons)
    seen_run_ids: set[str] = set()
    seen_observation_ids: set[str] = set()
    seen_schedule_cells: set[tuple[str, int]] = set()
    for run in runset.runs:
        if run.run_id in seen_run_ids:
            raise ValueError(f"live RunSet duplicate run_id {run.run_id!r}")
        seen_run_ids.add(run.run_id)
        # Live protocol identity defects are structural, so they raise before
        # rate evaluation rather than becoming report-shaped observations.
        if run.observation_id is None or run.repetition_index is None or run.cluster_id is None:
            raise ValueError("live RunSet run missing observation metadata")
        if run.observation_id in seen_observation_ids:
            raise ValueError(f"live RunSet duplicate observation_id {run.observation_id!r}")
        seen_observation_ids.add(run.observation_id)
        schedule_cell = (run.case_id, run.repetition_index)
        if schedule_cell in seen_schedule_cells:
            raise ValueError(
                "live RunSet duplicate case/repetition observation "
                f"case_id={run.case_id!r}, repetition_index={run.repetition_index}"
            )
        seen_schedule_cells.add(schedule_cell)
        if run.exclusion_reason and run.exclusion_reason not in allowed_exclusions:
            raise ValueError(f"live exclusion reason {run.exclusion_reason!r} is not declared")
        if run.retry_count is not None and run.retry_count > protocol.max_retries:
            raise ValueError("live run retry_count exceeds protocol")
        if (
            run.rate_limit_events is not None
            and run.rate_limit_events > protocol.max_rate_limit_events
        ):
            raise ValueError("live run rate_limit_events exceeds protocol")
        if Decimal(run.estimated_cost_usd or "0.000000") > Decimal(
            protocol.max_cost_per_observation_usd
        ):
            raise ValueError("live run cost exceeds protocol max_cost_per_observation_usd")
        if (
            protocol.max_total_tokens is not None
            and (run.total_tokens or 0) > protocol.max_total_tokens
        ):
            raise ValueError("live run total_tokens exceeds protocol max_total_tokens")
        if (
            protocol.max_generated_tokens is not None
            and (run.completion_tokens or 0) > protocol.max_generated_tokens
        ):
            raise ValueError("live run completion_tokens exceeds protocol max_generated_tokens")
        for field_name in protocol.provider_version_capture:
            if getattr(run, field_name, None) is None:
                raise ValueError(f"live run missing provider-version field {field_name!r}")
        if run.provenance.tool_schema_digest != protocol.tool_schema_digest:
            raise ValueError("live run provenance tool_schema_digest does not match protocol")
        if run.provenance.policy_bundle_digest != protocol.policy_bundle_digest:
            raise ValueError("live run provenance policy_bundle_digest does not match protocol")
    total_cost = sum(Decimal(run.estimated_cost_usd or "0.000000") for run in runset.runs)
    if total_cost > Decimal(protocol.max_total_cost_usd):
        raise ValueError("live RunSet cost exceeds protocol max_total_cost_usd")
    if protocol.max_total_tokens is not None:
        total_tokens = sum(run.total_tokens or 0 for run in runset.runs)
        if total_tokens > protocol.max_total_tokens:
            raise ValueError("live RunSet total_tokens exceeds protocol max_total_tokens")
    if protocol.max_generated_tokens is not None:
        generated_tokens = sum(run.completion_tokens or 0 for run in runset.runs)
        if generated_tokens > protocol.max_generated_tokens:
            raise ValueError(
                "live RunSet completion_tokens exceeds protocol max_generated_tokens"
            )


def _evaluate_observation(
    resolver: ExpectationResolver,
    run: AgentRunRecord,
    *,
    gate_profile: GateProfile,
    allowed_tools: tuple[str, ...],
    required_policy_ids: tuple[str, ...],
) -> LiveObservationResult:
    if run.observation_status == "excluded":
        return _observation_result(run, GateState.not_evaluated, ())
    try:
        case_expectation = resolver.for_case(run.case_id)
    except KeyError:
        findings = (
            _finding_from_result(
                ControlResult(
                    control_id="valid_record_required",
                    case_id=run.case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target="unknown-case",
                    message=f"run set contains case {run.case_id!r} not present in the suite",
                )
            ),
        )
        return _observation_result(run, GateState.fail, findings)
    results = (
        *evaluate_required_policy_results_for_run(run, required_policy_ids),
        *evaluate_case(
            case_expectation,
            run,
            allowed_tools=allowed_tools,
            required_policy_ids=required_policy_ids,
        ),
    )
    evaluated_findings = tuple(_finding_from_result(result) for result in results)
    state = rollup_state(results, gate_profile)
    return _observation_result(run, state, evaluated_findings)


def _observation_result(
    run: AgentRunRecord,
    state: GateState,
    findings: tuple[Finding, ...],
) -> LiveObservationResult:
    reason_codes = tuple(sorted({finding.reason_code for finding in findings}, key=str))
    tool_schema_digest = _required_digest(
        run.provenance.tool_schema_digest,
        "tool_schema_digest",
    )
    policy_bundle_digest = _required_digest(
        run.provenance.policy_bundle_digest,
        "policy_bundle_digest",
    )
    return LiveObservationResult(
        artifact_kind="live-observation-result",
        observation_id=run.observation_id or f"missing-observation:{run.run_id}",
        run_id=run.run_id,
        case_id=run.case_id,
        repetition_index=run.repetition_index or 0,
        provider=run.provider,
        model=run.model,
        resolved_model=run.resolved_model,
        provider_api_version=run.provider_api_version,
        provider_sdk=run.provider_sdk,
        provider_region=run.provider_region,
        adapter_id=run.adapter_id,
        pipeline_id=run.pipeline_id,
        cluster_id=run.cluster_id or run.case_id,
        source_group_id=run.source_group_id,
        started_at_utc=run.started_at_utc,
        completed_at_utc=run.completed_at_utc,
        observation_status=run.observation_status,
        exclusion_reason=run.exclusion_reason,
        attempt_count=run.attempt_count,
        retry_count=run.retry_count,
        rate_limit_events=run.rate_limit_events,
        tool_schema_digest=tool_schema_digest,
        policy_bundle_digest=policy_bundle_digest,
        state=state,
        reason_codes=reason_codes,
        findings=findings,
    )


def _summarize_group(
    group_id: str,
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    *,
    protocol: LiveProtocolRecord,
) -> LiveGroupSummary:
    identity = _group_identity(group_id, runs)
    included = tuple(
        (run, observation)
        for run, observation in zip(runs, observations, strict=True)
        if observation.observation_status == "included"
    )
    included_runs = tuple(run for run, _ in included)
    included_observations = tuple(observation for _, observation in included)
    excluded_count = len(observations) - len(included_observations)
    outcome_counts = Counter(run.outcome for run in included_runs)
    reason_observation_counts: Counter[str] = Counter()
    for observation in included_observations:
        for reason_code in observation.reason_codes:
            reason_observation_counts[reason_code.value] += 1
    rate_method = _rate_analysis_method(protocol)
    exclusion_values = tuple(
        (observation.cluster_id, observation.observation_status == "excluded")
        for observation in observations
    )
    pass_values = tuple(
        (observation.cluster_id, observation.state is GateState.pass_)
        for observation in included_observations
    )
    expectation_rate = _rate_from_values(
        "expectation_pass",
        pass_values,
        protocol=protocol,
        analysis_method=rate_method,
    )
    return LiveGroupSummary(
        artifact_kind="live-group-summary",
        group_id=group_id,
        provider=identity["provider"],
        model=identity["model"],
        adapter_id=identity["adapter_id"],
        pipeline_id=identity["pipeline_id"] or group_id,
        observations=len(observations),
        included_observations=len(included_observations),
        excluded_observations=excluded_count,
        cluster_count=expectation_rate.cluster_count,
        effective_n=expectation_rate.effective_n,
        design_effect=expectation_rate.design_effect,
        exclusion_rate=_rate_from_values(
            "exclusion",
            exclusion_values,
            protocol=protocol,
            analysis_method=rate_method,
        ),
        expectation_pass_rate=expectation_rate,
        outcome_rates=tuple(
            _rate_from_values(
                f"outcome:{outcome}",
                tuple(
                    (observation.cluster_id, run.outcome == outcome)
                    for run, observation in included
                ),
                protocol=protocol,
                analysis_method=rate_method,
            )
            for outcome in sorted(outcome_counts)
        ),
        reason_code_rates=tuple(
            _rate_from_values(
                f"reason_code:{reason}",
                tuple(
                    (observation.cluster_id, ReasonCode(reason) in observation.reason_codes)
                    for observation in included_observations
                ),
                protocol=protocol,
                analysis_method=rate_method,
            )
            for reason in sorted(reason_observation_counts)
        ),
        latency_ms=_distribution(
            "latency_ms",
            tuple(
                Decimal(run.latency_ms)
                for run in included_runs
                if run.latency_ms is not None
            ),
        ),
        estimated_cost_usd=_distribution(
            "estimated_cost_usd",
            tuple(
                Decimal(run.estimated_cost_usd)
                for run in included_runs
                if run.estimated_cost_usd is not None
            ),
        ),
    )


def _group_identity(
    group_id: str,
    runs: tuple[AgentRunRecord, ...],
) -> dict[str, str | None]:
    if not runs:
        return {
            "provider": None,
            "model": None,
            "adapter_id": None,
            "pipeline_id": group_id,
        }
    fields = ("provider", "model", "adapter_id", "pipeline_id")
    if group_id == "overall":
        return {field: _homogeneous_value(runs, field) for field in fields}
    first = runs[0]
    return {field: getattr(first, field) for field in fields}


def _homogeneous_value(
    runs: tuple[AgentRunRecord, ...],
    field_name: str,
) -> str | None:
    values = {getattr(run, field_name) for run in runs}
    if len(values) != 1:
        return None
    value = next(iter(values))
    return value if isinstance(value, str) else None


def _groups(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
) -> tuple[tuple[str, tuple[AgentRunRecord, ...], tuple[LiveObservationResult, ...]], ...]:
    run_groups: dict[str, list[AgentRunRecord]] = defaultdict(list)
    observation_groups: dict[str, list[LiveObservationResult]] = defaultdict(list)
    for run, observation in zip(runs, observations, strict=True):
        group_id = live_record_group_id(run)
        run_groups[group_id].append(run)
        observation_groups[group_id].append(observation)
    return tuple(
        (group_id, tuple(run_groups[group_id]), tuple(observation_groups[group_id]))
        for group_id in sorted(run_groups)
    )


def _rate_from_values(
    label: str,
    values: tuple[tuple[str, bool], ...],
    *,
    protocol: LiveProtocolRecord,
    analysis_method: str,
) -> LiveRate:
    denominator = len(values)
    numerator = sum(1 for _, passed in values if passed)
    if denominator == 0:
        return LiveRate(
            artifact_kind="live-rate",
            label=label,
            numerator=0,
            denominator=0,
            cluster_count=0,
            effective_n="0.000000",
            design_effect="1.000000",
            largest_cluster_size=0,
            largest_cluster_design_effect="1.000000",
            largest_cluster_effective_n="0.000000",
            assumed_intraclass_correlation=protocol.assumed_intraclass_correlation,
            analysis_method=analysis_method,
            exploratory=True,
            rate="0.000000",
            cluster_mean_rate="0.000000",
            interval_center="cluster_mean_rate",
            interval_center_value="0.000000",
            confidence_level=protocol.confidence_level,
            ci_lower="0.000000",
            ci_upper="0.000000",
        )
    clustered = _cluster_values(values)
    cluster_rates = tuple(
        Decimal(cluster_numerator) / Decimal(cluster_denominator)
        for cluster_numerator, cluster_denominator in clustered.values()
    )
    cluster_count = len(cluster_rates)
    design_effect = _design_effect(denominator, cluster_count, protocol)
    effective_n = Decimal(denominator) / design_effect
    largest_cluster_size = max(cluster_denominator for _, cluster_denominator in clustered.values())
    largest_cluster_design_effect = _design_effect_for_size(largest_cluster_size, protocol)
    largest_cluster_effective_n = Decimal(denominator) / largest_cluster_design_effect
    cluster_mean, lower, upper = _rate_interval(
        label,
        cluster_rates,
        protocol=protocol,
        analysis_method=analysis_method,
    )
    reported_analysis_method = _reported_rate_analysis_method(analysis_method, cluster_rates)
    return LiveRate(
        artifact_kind="live-rate",
        label=label,
        numerator=numerator,
        denominator=denominator,
        cluster_count=cluster_count,
        effective_n=decimal_string(effective_n),
        design_effect=decimal_string(design_effect),
        largest_cluster_size=largest_cluster_size,
        largest_cluster_design_effect=decimal_string(largest_cluster_design_effect),
        largest_cluster_effective_n=decimal_string(largest_cluster_effective_n),
        assumed_intraclass_correlation=protocol.assumed_intraclass_correlation,
        analysis_method=reported_analysis_method,
        exploratory=_rate_exploratory(cluster_count, analysis_method),
        rate=probability_string(Decimal(numerator) / Decimal(denominator)),
        cluster_mean_rate=probability_string(cluster_mean),
        interval_center="cluster_mean_rate",
        interval_center_value=probability_string(cluster_mean),
        confidence_level=protocol.confidence_level,
        ci_lower=probability_string(lower),
        ci_upper=probability_string(upper),
    )


def _cluster_values(values: tuple[tuple[str, bool], ...]) -> dict[str, tuple[int, int]]:
    clustered: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for cluster_id, passed in values:
        clustered[cluster_id][0] += int(passed)
        clustered[cluster_id][1] += 1
    return {cluster_id: (counts[0], counts[1]) for cluster_id, counts in clustered.items()}


def _design_effect(
    denominator: int,
    cluster_count: int,
    protocol: LiveProtocolRecord,
) -> Decimal:
    if denominator == 0 or cluster_count == 0:
        return Decimal("1")
    mean_cluster_size = Decimal(denominator) / Decimal(cluster_count)
    return _design_effect_for_size(mean_cluster_size, protocol)


def _design_effect_for_size(
    cluster_size: Decimal | int,
    protocol: LiveProtocolRecord,
) -> Decimal:
    rho = Decimal(protocol.assumed_intraclass_correlation)
    return Decimal("1") + (Decimal(cluster_size) - Decimal("1")) * rho


def _rate_interval(
    label: str,
    cluster_rates: tuple[Decimal, ...],
    *,
    protocol: LiveProtocolRecord,
    analysis_method: str,
) -> tuple[Decimal, Decimal, Decimal]:
    if analysis_method == "descriptive_cluster_bootstrap_percentile":
        return bootstrap_mean_interval(
            cluster_rates,
            confidence_level=protocol.confidence_level,
            seed=f"{protocol.protocol_id}:{protocol.analysis_digest}:{label}:rate-bootstrap",
        )
    return cluster_t_interval(cluster_rates, protocol.confidence_level)


def _distribution(
    metric: Literal["latency_ms", "estimated_cost_usd"],
    values: tuple[Decimal, ...],
) -> LiveDistribution:
    if not values:
        return LiveDistribution(artifact_kind="live-distribution", metric=metric, count=0)
    ordered = tuple(sorted(values))
    total = sum(ordered, Decimal(0))
    return LiveDistribution(
        artifact_kind="live-distribution",
        metric=metric,
        count=len(ordered),
        min=decimal_string(ordered[0]),
        p50=decimal_string(_median(ordered)),
        p95=decimal_string(nearest_rank_percentile(ordered, Decimal("0.95"))),
        max=decimal_string(ordered[-1]),
        mean=decimal_string(total / Decimal(len(ordered))),
        total=decimal_string(total),
    )


def _median(values: tuple[Decimal, ...]) -> Decimal:
    midpoint = len(values) // 2
    if len(values) % 2:
        return values[midpoint]
    return (values[midpoint - 1] + values[midpoint]) / Decimal("2")


def _report_state(
    observations: tuple[LiveObservationResult, ...],
    overall: LiveGroupSummary,
    protocol: LiveProtocolRecord,
    stop_reasons: tuple[str, ...],
) -> GateState:
    included = tuple(
        observation for observation in observations if observation.observation_status == "included"
    )
    if not included:
        return GateState.not_evaluated
    if any(observation.state is GateState.fail for observation in included):
        return GateState.fail
    if Decimal(overall.exclusion_rate.rate) > Decimal(protocol.max_exclusion_rate):
        return GateState.fail
    if stop_reasons:
        return GateState.not_evaluated
    if any(observation.state is GateState.warn for observation in included):
        return GateState.warn
    if any(observation.state is GateState.not_evaluated for observation in included):
        return GateState.not_evaluated
    return GateState.pass_


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


def _required_digest(value: str | None, field_name: str) -> str:
    if value is None:
        raise ValueError(f"live observation missing provenance {field_name}")
    return value


def _rate_analysis_method(protocol: LiveProtocolRecord) -> str:
    if protocol.analysis_method == "paired_cluster_bootstrap_percentile":
        return "descriptive_cluster_bootstrap_percentile"
    if protocol.analysis_method in {
        "paired_cluster_permutation_exact",
        "paired_cluster_permutation_monte_carlo",
    }:
        return "descriptive_cluster_t_interval"
    if protocol.analysis_method == "exploratory":
        return "exploratory_cluster_t_interval"
    return "descriptive_cluster_t_interval"


def _reported_rate_analysis_method(
    analysis_method: str,
    cluster_rates: tuple[Decimal, ...],
) -> str:
    if len(cluster_rates) > 1 and len(set(cluster_rates)) == 1:
        if analysis_method == "exploratory_cluster_t_interval":
            return "exploratory_degenerate_boundary_interval"
        if analysis_method == "descriptive_cluster_t_interval":
            return "descriptive_degenerate_boundary_interval"
    return analysis_method


def _rate_exploratory(cluster_count: int, analysis_method: str) -> bool:
    if cluster_count < 30:
        return True
    return analysis_method == "descriptive_cluster_bootstrap_percentile" and cluster_count < 50


def _stop_reasons(runset: RunSet) -> tuple[str, ...]:
    reasons = set(runset.stop_reasons)
    reasons.update(
        run.exclusion_reason
        for run in runset.runs
        if run.exclusion_reason in BUDGET_STOP_REASONS
    )
    return tuple(sorted(reasons))
