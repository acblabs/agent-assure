from __future__ import annotations

from collections import Counter, defaultdict
from decimal import ROUND_CEILING, Decimal
from statistics import mean
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_case
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
        protocol_digest=sha256_hexdigest(protocol.model_dump(mode="json")),
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        cluster_by=protocol.cluster_by,
        planned_repetitions=protocol.planned_repetitions,
        planned_observations=protocol.planned_observations,
        planned_clusters=protocol.planned_clusters,
        completion_status=completion_status,
        stop_reasons=stop_reasons,
        budget_exceeded=bool(BUDGET_STOP_REASONS & set(stop_reasons)),
        state=_report_state(observations, overall, gate_profile, protocol, stop_reasons),
        confidence_level=protocol.confidence_level,
        observations=observations,
        overall=overall,
        groups=groups,
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
    protocol_digest = sha256_hexdigest(protocol.model_dump(mode="json"))
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
    for run in runset.runs:
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


def _evaluate_observation(
    resolver: ExpectationResolver,
    run: AgentRunRecord,
    *,
    gate_profile: GateProfile,
    allowed_tools: tuple[str, ...],
) -> LiveObservationResult:
    if run.observation_id is None or run.repetition_index is None or run.cluster_id is None:
        findings = (
            _finding_from_result(
                ControlResult(
                    control_id="valid_live_observation",
                    case_id=run.case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target=run.run_id,
                    message="live run record is missing observation metadata",
                )
            ),
        )
        return _observation_result(run, GateState.fail, findings)
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
    results = evaluate_case(case_expectation, run, allowed_tools=allowed_tools)
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
        adapter_id=run.adapter_id,
        pipeline_id=run.pipeline_id,
        cluster_id=run.cluster_id or run.case_id,
        source_group_id=run.source_group_id,
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
    first = runs[0] if runs else None
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
        provider=first.provider if first else None,
        model=first.model if first else None,
        adapter_id=first.adapter_id if first else None,
        pipeline_id=first.pipeline_id if first else "overall",
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


def _groups(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
) -> tuple[tuple[str, tuple[AgentRunRecord, ...], tuple[LiveObservationResult, ...]], ...]:
    run_groups: dict[str, list[AgentRunRecord]] = defaultdict(list)
    observation_groups: dict[str, list[LiveObservationResult]] = defaultdict(list)
    for run, observation in zip(runs, observations, strict=True):
        group_id = _group_id(run)
        run_groups[group_id].append(run)
        observation_groups[group_id].append(observation)
    return tuple(
        (group_id, tuple(run_groups[group_id]), tuple(observation_groups[group_id]))
        for group_id in sorted(run_groups)
    )


def _group_id(run: AgentRunRecord) -> str:
    return "|".join(
        (
            f"provider={run.provider or 'unknown'}",
            f"model={run.model or 'unknown'}",
            f"adapter={run.adapter_id or 'unknown'}",
            f"pipeline={run.pipeline_id}",
        )
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
    cluster_mean = Decimal(str(mean(cluster_rates)))
    lower, upper = _cluster_interval(cluster_rates, protocol.confidence_level)
    return LiveRate(
        artifact_kind="live-rate",
        label=label,
        numerator=numerator,
        denominator=denominator,
        cluster_count=cluster_count,
        effective_n=_decimal(effective_n),
        design_effect=_decimal(design_effect),
        largest_cluster_size=largest_cluster_size,
        largest_cluster_design_effect=_decimal(largest_cluster_design_effect),
        largest_cluster_effective_n=_decimal(largest_cluster_effective_n),
        assumed_intraclass_correlation=protocol.assumed_intraclass_correlation,
        analysis_method=analysis_method,
        exploratory=cluster_count < 30,
        rate=_probability(Decimal(numerator) / Decimal(denominator)),
        cluster_mean_rate=_probability(cluster_mean),
        confidence_level=protocol.confidence_level,
        ci_lower=_probability(lower),
        ci_upper=_probability(upper),
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


def _cluster_interval(
    cluster_rates: tuple[Decimal, ...],
    confidence_level: str,
) -> tuple[Decimal, Decimal]:
    if not cluster_rates:
        return Decimal("0"), Decimal("0")
    if len(cluster_rates) == 1:
        return Decimal("0"), Decimal("1")
    center = Decimal(str(mean(cluster_rates)))
    variance = sum((value - center) ** 2 for value in cluster_rates) / Decimal(
        len(cluster_rates) - 1
    )
    standard_error = (variance / Decimal(len(cluster_rates))).sqrt()
    half_width = _critical_value(confidence_level, len(cluster_rates) - 1) * standard_error
    return max(Decimal("0"), center - half_width), min(Decimal("1"), center + half_width)


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
        min=_decimal(ordered[0]),
        p50=_decimal(_median(ordered)),
        p95=_decimal(_nearest_rank(ordered, Decimal("0.95"))),
        max=_decimal(ordered[-1]),
        mean=_decimal(total / Decimal(len(ordered))),
        total=_decimal(total),
    )


def _nearest_rank(values: tuple[Decimal, ...], percentile: Decimal) -> Decimal:
    raw_rank = int((percentile * Decimal(len(values))).to_integral_value(rounding=ROUND_CEILING))
    index = max(0, min(len(values) - 1, raw_rank - 1))
    return values[index]


def _median(values: tuple[Decimal, ...]) -> Decimal:
    midpoint = len(values) // 2
    if len(values) % 2:
        return values[midpoint]
    return (values[midpoint - 1] + values[midpoint]) / Decimal("2")


def _report_state(
    observations: tuple[LiveObservationResult, ...],
    overall: LiveGroupSummary,
    gate_profile: GateProfile,
    protocol: LiveProtocolRecord,
    stop_reasons: tuple[str, ...],
) -> GateState:
    del gate_profile
    included = tuple(
        observation for observation in observations if observation.observation_status == "included"
    )
    if not included:
        return GateState.not_evaluated
    if stop_reasons:
        return GateState.not_evaluated
    if Decimal(overall.exclusion_rate.rate) > Decimal(protocol.max_exclusion_rate):
        return GateState.fail
    if any(observation.state is GateState.fail for observation in included):
        return GateState.fail
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


def _probability(value: Decimal) -> str:
    return _decimal(min(Decimal("1"), max(Decimal("0"), value)))


def _decimal(value: Decimal | str | int) -> str:
    projected = Decimal(str(value))
    if projected == Decimal("-0"):
        projected = Decimal("0")
    text = f"{projected.quantize(Decimal('0.000001')):f}"
    if text == "-0.000000":
        return "0.000000"
    return text


def _critical_value(confidence_level: str, degrees_of_freedom: int) -> Decimal:
    if confidence_level != "0.950000":
        raise ValueError(f"unsupported live confidence_level: {confidence_level}")
    table = {
        1: "12.706205",
        2: "4.302653",
        3: "3.182446",
        4: "2.776445",
        5: "2.570582",
        6: "2.446912",
        7: "2.364624",
        8: "2.306004",
        9: "2.262157",
        10: "2.228139",
        15: "2.131450",
        20: "2.085963",
        30: "2.042272",
        40: "2.021075",
        60: "2.000298",
    }
    if degrees_of_freedom in table:
        return Decimal(table[degrees_of_freedom])
    if degrees_of_freedom < 15:
        return Decimal(table[10])
    if degrees_of_freedom < 20:
        return Decimal(table[15])
    if degrees_of_freedom < 30:
        return Decimal(table[20])
    if degrees_of_freedom < 40:
        return Decimal(table[30])
    if degrees_of_freedom < 60:
        return Decimal(table[40])
    return Decimal("1.959964")


def _rate_analysis_method(protocol: LiveProtocolRecord) -> str:
    if protocol.analysis_method == "exploratory":
        return "exploratory_cluster_t_interval"
    return "descriptive_cluster_t_interval"


def _stop_reasons(runset: RunSet) -> tuple[str, ...]:
    reasons = set(runset.stop_reasons)
    reasons.update(
        run.exclusion_reason
        for run in runset.runs
        if run.exclusion_reason in BUDGET_STOP_REASONS
    )
    return tuple(sorted(reasons))
