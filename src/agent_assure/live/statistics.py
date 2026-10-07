from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass
from decimal import Decimal
from typing import Literal, cast

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.evaluation.expectations import ExpectationResolver
from agent_assure.evaluation.invariants import evaluate_case
from agent_assure.fixed_point import PICODOLLARS_PER_DOLLAR, usd_six_from_picousd
from agent_assure.live.advanced import (
    _statistical_invariant_work_plan,
    evaluate_statistical_invariants,
)
from agent_assure.live.intervals import (
    bootstrap_mean_interval,
    cluster_t_interval,
    nearest_rank_percentile,
)
from agent_assure.live.primitives import (
    decimal_string,
    live_record_group_id,
    probability_lower_string,
    probability_string,
    probability_upper_string,
    with_live_decimal_context,
)
from agent_assure.live.source_projection import (
    BUDGET_STOP_REASONS,
    project_live_stop_reasons,
    project_run_observation_source,
)
from agent_assure.live.work_limits import (
    LIVE_RATE_BOOTSTRAP_ITERATIONS,
    MAX_LIVE_OUTCOME_CATEGORIES,
    LiveAnalysisWorkPlan,
    combine_live_analysis_work_plans,
    validate_live_analysis_work_plan,
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
    LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION,
    LiveDistribution,
    LiveEvaluationReport,
    LiveGroupSummary,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveRate,
    StatisticalInvariantResult,
)
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.suite import CompiledSuite
from agent_assure.schema.validation import validate_loaded_artifact_payload

_PERSISTED_ARM_IDENTITY_FIELDS = (
    "provider",
    "model",
    "resolved_model",
    "provider_api_version",
    "provider_sdk",
    "provider_region",
    "adapter_id",
    "pipeline_id",
)
_PERSISTED_PROVIDER_CAPTURE_FIELDS = frozenset(_PERSISTED_ARM_IDENTITY_FIELDS)


@with_live_decimal_context
def evaluate_live_runset(
    suite: CompiledSuite,
    runset: RunSet,
    *,
    protocol: LiveProtocolRecord,
    gate_profile: GateProfile = DEFAULT_GATE_PROFILE,
) -> LiveEvaluationReport:
    suite_payload = suite.model_dump(mode="json", warnings="error")
    suite = CompiledSuite.model_validate(suite_payload)
    validate_loaded_artifact_payload(suite_payload, "compiled-suite")
    runset_payload = runset.model_dump(mode="json", warnings="error")
    runset = RunSet.model_validate(runset_payload)
    validate_loaded_artifact_payload(runset_payload, "run-set")
    protocol_payload = protocol.model_dump(mode="json", warnings="error")
    protocol = LiveProtocolRecord.model_validate(protocol_payload)
    validate_loaded_artifact_payload(protocol_payload, "live-protocol-record")
    gate_profile = GateProfile.model_validate(
        gate_profile.model_dump(mode="json", warnings="error")
    )
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
    if (
        observations
        and all(observation.observation_status == "excluded" for observation in observations)
        and Decimal("1") > Decimal(protocol.max_exclusion_rate)
    ):
        raise ValueError(
            "live exclusion rate exceeds max_exclusion_rate before observed rate estimation"
        )
    _validate_live_evaluation_work_budget(
        tuple(runset.runs),
        observations,
        protocol=protocol,
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
    statistical_invariants = evaluate_statistical_invariants(
        tuple(runset.runs),
        observations,
        protocol,
    )
    stop_reasons = project_live_stop_reasons(
        runset.stop_reasons,
        (run.exclusion_reason for run in runset.runs),
    )
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
        suite_digest=runset.suite_digest,
        configuration_digest=runset.fixture_manifest_digest,
        source_runset_digest=sha256_hexdigest(runset),
        source_completion_status=runset.completion_status,
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        protocol=protocol,
        baseline_mode=protocol.baseline_mode,
        analysis_method=protocol.analysis_method,
        exploratory=_report_exploratory(
            protocol,
            overall,
            statistical_invariants,
        ),
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
        statistical_invariants=statistical_invariants,
    )


def _verify_live_binding(
    suite: CompiledSuite,
    runset: RunSet,
    protocol: LiveProtocolRecord,
) -> None:
    suite_digest = sha256_hexdigest(suite)
    if protocol.suite_id != suite.suite_id:
        raise ValueError(
            f"live protocol suite_id {protocol.suite_id!r} does not match compiled suite "
            f"{suite.suite_id!r}"
        )
    if protocol.suite_version != suite.suite_version:
        raise ValueError(
            f"live protocol suite_version {protocol.suite_version!r} does not match "
            f"compiled suite {suite.suite_version!r}"
        )
    if protocol.suite_digest != suite_digest:
        raise ValueError("live protocol suite_digest does not match compiled suite")
    if runset.suite_id != suite.suite_id:
        raise ValueError(
            f"run set suite_id {runset.suite_id!r} does not match compiled suite {suite.suite_id!r}"
        )
    if runset.suite_version != suite.suite_version:
        raise ValueError(
            f"run set suite_version {runset.suite_version!r} does not match compiled suite "
            f"{suite.suite_version!r}"
        )
    if runset.suite_digest != suite_digest:
        raise ValueError("live RunSet suite_digest does not match compiled suite")
    if runset.suite_digest != protocol.suite_digest:
        raise ValueError("live RunSet suite_digest does not match protocol")
    if runset.execution_mode.value != "live":
        raise ValueError("live evaluation requires a RunSet with execution_mode='live'")
    protocol_digest = sha256_hexdigest(protocol)
    if runset.protocol_id != protocol.protocol_id or runset.protocol_digest != protocol_digest:
        raise ValueError("live RunSet protocol binding does not match protocol")
    _verify_protocol_obligations(suite, runset, protocol)


def _verify_protocol_obligations(
    suite: CompiledSuite,
    runset: RunSet,
    protocol: LiveProtocolRecord,
) -> None:
    if len(runset.runs) != protocol.planned_observations:
        raise ValueError("live RunSet observation count does not match protocol")
    repetitions = {run.repetition_index for run in runset.runs if run.repetition_index is not None}
    expected_repetitions = set(range(protocol.planned_repetitions))
    if repetitions != expected_repetitions:
        raise ValueError("live RunSet repetitions do not match protocol")
    known_case_ids = {case.case_id for case in suite.cases}
    allowed_exclusions = set(protocol.allowed_exclusion_reasons)
    seen_run_ids: set[str] = set()
    seen_observation_ids: set[str] = set()
    seen_schedule_indexes: set[int] = set()
    seen_schedule_cells: set[tuple[str, int]] = set()
    case_prompt_digests: dict[str, set[str]] = defaultdict(set)
    case_source_groups: dict[str, set[str | None]] = defaultdict(set)
    arm_identities: set[
        tuple[
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str | None,
            str,
        ]
    ] = set()
    for run in runset.runs:
        if run.run_id in seen_run_ids:
            raise ValueError(f"live RunSet duplicate run_id {run.run_id!r}")
        seen_run_ids.add(run.run_id)
        # Live protocol identity defects are structural, so they raise before
        # rate evaluation rather than becoming report-shaped observations.
        if (
            run.observation_id is None
            or run.repetition_index is None
            or run.schedule_index is None
            or run.randomization_block_id is None
            or run.cluster_id is None
        ):
            raise ValueError("live RunSet run missing observation metadata")
        if run.observation_id in seen_observation_ids:
            raise ValueError(f"live RunSet duplicate observation_id {run.observation_id!r}")
        seen_observation_ids.add(run.observation_id)
        if run.schedule_index in seen_schedule_indexes:
            raise ValueError(f"live RunSet duplicate schedule_index {run.schedule_index}")
        seen_schedule_indexes.add(run.schedule_index)
        if run.case_id not in known_case_ids:
            raise ValueError(f"live RunSet case_id {run.case_id!r} is not in the compiled suite")
        schedule_cell = (run.case_id, run.repetition_index)
        if schedule_cell in seen_schedule_cells:
            raise ValueError(
                "live RunSet duplicate case/repetition observation "
                f"case_id={run.case_id!r}, repetition_index={run.repetition_index}"
            )
        seen_schedule_cells.add(schedule_cell)
        expected_block_id = f"repetition:{run.repetition_index}"
        if run.randomization_block_id != expected_block_id:
            raise ValueError("live run randomization_block_id does not match repetition_index")
        if run.provenance.configuration_digest != runset.fixture_manifest_digest:
            raise ValueError(
                "live run provenance configuration_digest does not match "
                "RunSet fixture_manifest_digest"
            )
        if run.provenance.prompt_digest is None:
            raise ValueError("live run provenance prompt_digest is required")
        if run.provenance.model_identifier != run.model:
            raise ValueError(
                "live run provenance model_identifier does not match run model identity"
            )
        case_prompt_digests[run.case_id].add(run.provenance.prompt_digest)
        case_source_groups[run.case_id].add(run.source_group_id)
        expected_cluster_id = (
            run.source_group_id if protocol.cluster_by == "source_group_id" else run.case_id
        )
        if expected_cluster_id is None:
            raise ValueError(
                "source_group_id clustering requires source_group_id on every live run"
            )
        if run.cluster_id != expected_cluster_id:
            raise ValueError(
                f"live run cluster_id {run.cluster_id!r} does not match "
                f"protocol.cluster_by={protocol.cluster_by!r}"
            )
        arm_identities.add(
            (
                run.provider,
                run.model,
                run.resolved_model,
                run.provider_api_version,
                run.provider_sdk,
                run.provider_region,
                run.adapter_id,
                run.pipeline_id,
            )
        )
        if run.exclusion_reason and run.exclusion_reason not in allowed_exclusions:
            raise ValueError(f"live exclusion reason {run.exclusion_reason!r} is not declared")
        if run.retry_count is not None and run.retry_count > protocol.max_retries:
            raise ValueError("live run retry_count exceeds protocol")
        if (
            run.rate_limit_events is not None
            and run.rate_limit_events > protocol.max_rate_limit_events
        ):
            raise ValueError("live run rate_limit_events exceeds protocol")
        if _run_estimated_cost_decimal(run) > Decimal(protocol.max_cost_per_observation_usd):
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
    if any(len(digests) != 1 for digests in case_prompt_digests.values()):
        raise ValueError("live RunSet prompt_digest must be stable within each case")
    if any(len(source_groups) != 1 for source_groups in case_source_groups.values()):
        raise ValueError("live RunSet source_group_id must be stable within each case")
    if len(arm_identities) != 1:
        raise ValueError("live RunSet must contain one homogeneous execution arm")
    if seen_schedule_indexes != set(range(protocol.planned_observations)):
        raise ValueError(
            "live RunSet schedule_index values must cover the complete planned schedule"
        )
    case_ids = set(case_prompt_digests)
    expected_schedule_cells = {
        (case_id, repetition_index)
        for case_id in case_ids
        for repetition_index in expected_repetitions
    }
    if seen_schedule_cells != expected_schedule_cells:
        raise ValueError(
            "live RunSet observations must form the complete frozen case/repetition schedule"
        )
    planned_clusters = {
        case_id if protocol.cluster_by == "case_id" else next(iter(case_source_groups[case_id]))
        for case_id in case_ids
    }
    if None in planned_clusters or len(planned_clusters) != protocol.planned_clusters:
        raise ValueError(
            "live RunSet cluster count derived from frozen cases does not match protocol"
        )
    total_cost = sum((_run_estimated_cost_decimal(run) for run in runset.runs), Decimal(0))
    if total_cost > Decimal(protocol.max_total_cost_usd):
        raise ValueError("live RunSet cost exceeds protocol max_total_cost_usd")
    committed_cost = sum(
        Decimal(run.cost_budget_committed_usd or run.estimated_cost_usd or "0.000000")
        for run in runset.runs
    )
    if committed_cost > Decimal(protocol.max_total_cost_usd):
        raise ValueError("live RunSet committed cost exceeds protocol max_total_cost_usd")
    if protocol.max_total_tokens is not None:
        total_tokens = sum(run.total_tokens or 0 for run in runset.runs)
        if total_tokens > protocol.max_total_tokens:
            raise ValueError("live RunSet total_tokens exceeds protocol max_total_tokens")
        committed_total_tokens = sum(
            run.total_token_budget_committed
            if run.total_token_budget_committed is not None
            else run.total_tokens or 0
            for run in runset.runs
        )
        if committed_total_tokens > protocol.max_total_tokens:
            raise ValueError("live RunSet committed total tokens exceed protocol max_total_tokens")
    if protocol.max_generated_tokens is not None:
        generated_tokens = sum(run.completion_tokens or 0 for run in runset.runs)
        if generated_tokens > protocol.max_generated_tokens:
            raise ValueError("live RunSet completion_tokens exceeds protocol max_generated_tokens")
        committed_generated_tokens = sum(
            run.generated_token_budget_committed
            if run.generated_token_budget_committed is not None
            else run.completion_tokens or 0
            for run in runset.runs
        )
        if committed_generated_tokens > protocol.max_generated_tokens:
            raise ValueError(
                "live RunSet committed generated tokens exceed protocol max_generated_tokens"
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
    results = evaluate_case(
        case_expectation,
        run,
        allowed_tools=allowed_tools,
        required_policy_ids=required_policy_ids,
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
    source_projection = project_run_observation_source(run)
    return LiveObservationResult(
        artifact_kind="live-observation-result",
        **source_projection.model_values(),
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
            tuple(Decimal(run.latency_ms) for run in included_runs if run.latency_ms is not None),
        ),
        estimated_cost_usd=_distribution(
            "estimated_cost_usd",
            tuple(
                _run_estimated_cost_decimal(run)
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


@with_live_decimal_context
def _run_estimated_cost_decimal(run: AgentRunRecord) -> Decimal:
    if run.estimated_cost_picousd is not None:
        return Decimal(run.estimated_cost_picousd) / Decimal(PICODOLLARS_PER_DOLLAR)
    return Decimal(run.estimated_cost_usd or "0.000000")


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


def _rate_requires_resampling(values: tuple[tuple[str, bool], ...]) -> int:
    clustered = tuple(_cluster_values(values).values())
    if len(clustered) <= 1:
        return 0
    first_numerator, first_denominator = clustered[0]
    if all(
        numerator * first_denominator == first_numerator * denominator
        for numerator, denominator in clustered[1:]
    ):
        return 0
    return len(clustered)


def _validate_live_evaluation_work_budget(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    *,
    protocol: LiveProtocolRecord,
) -> int:
    rate_plan = _live_evaluation_rate_work_plan(
        runs,
        observations,
        protocol=protocol,
    )
    advanced_plan = getattr(protocol, "advanced_analysis_plan", None)
    invariant_plan = LiveAnalysisWorkPlan()
    if advanced_plan is not None:
        confirmatory_count = sum(
            1 for endpoint in advanced_plan.endpoints if endpoint.interpretation == "confirmatory"
        )
        invariant_plan = _statistical_invariant_work_plan(
            runs,
            observations,
            protocol=protocol,
            plan=advanced_plan,
            confirmatory_count=confirmatory_count,
        )
    combined = combine_live_analysis_work_plans(rate_plan, invariant_plan)
    resampling_work, _ = validate_live_analysis_work_plan(combined)
    return resampling_work


def _live_evaluation_rate_work_plan(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    *,
    protocol: LiveProtocolRecord,
) -> LiveAnalysisWorkPlan:
    """Plan every overall and group rate bootstrap without running one."""

    if len(runs) != len(observations):
        raise ValueError("live resampling preflight requires one run per observation")
    partitions = _groups(runs, observations)
    summaries = (
        ("overall", runs, observations),
        *partitions,
    )
    work_items: list[tuple[str, int]] = []
    for group_id, group_runs, group_observations in summaries:
        included = tuple(
            (run, observation)
            for run, observation in zip(group_runs, group_observations, strict=True)
            if observation.observation_status == "included"
        )
        outcomes = {run.outcome for run, _ in included}
        if len(outcomes) > MAX_LIVE_OUTCOME_CATEGORIES:
            raise ValueError(
                "live evaluation outcome categories exceed the maximum supported cardinality"
            )
        if protocol.analysis_method != "paired_cluster_bootstrap_percentile":
            continue

        rate_series: list[tuple[str, tuple[tuple[str, bool], ...]]] = [
            (
                "exclusion",
                tuple(
                    (observation.cluster_id, observation.observation_status == "excluded")
                    for observation in group_observations
                ),
            ),
            (
                "expectation_pass",
                tuple(
                    (observation.cluster_id, observation.state is GateState.pass_)
                    for _, observation in included
                ),
            ),
        ]
        for outcome in sorted(outcomes):
            rate_series.append(
                (
                    f"outcome:{outcome}",
                    tuple(
                        (observation.cluster_id, run.outcome == outcome)
                        for run, observation in included
                    ),
                )
            )
        reason_codes = sorted(
            {
                reason_code
                for _, observation in included
                for reason_code in observation.reason_codes
            },
            key=str,
        )
        for reason_code in reason_codes:
            rate_series.append(
                (
                    f"reason_code:{reason_code.value}",
                    tuple(
                        (observation.cluster_id, reason_code in observation.reason_codes)
                        for _, observation in included
                    ),
                )
            )
        for label, values in rate_series:
            sampled_clusters = _rate_requires_resampling(values)
            work_items.append(
                (
                    f"{group_id}:{label}",
                    LIVE_RATE_BOOTSTRAP_ITERATIONS * sampled_clusters,
                )
            )
    return LiveAnalysisWorkPlan(resampling_items=tuple(work_items))


@with_live_decimal_context
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
        raise ValueError("live rate is undefined for a zero observation denominator")
    clustered = _cluster_values(values)
    cluster_rates = tuple(
        Decimal(clustered[cluster_id][0]) / Decimal(clustered[cluster_id][1])
        for cluster_id in sorted(clustered)
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
    if lower == upper:
        ci_lower = ci_upper = probability_string(lower)
    else:
        ci_lower = probability_lower_string(lower)
        ci_upper = probability_upper_string(upper)
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
        exploratory=_rate_exploratory(cluster_count, reported_analysis_method),
        rate=probability_string(Decimal(numerator) / Decimal(denominator)),
        cluster_mean_rate=probability_string(cluster_mean),
        interval_center="cluster_mean_rate",
        interval_center_value=probability_string(cluster_mean),
        confidence_level=protocol.confidence_level,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
    )


def _cluster_values(values: tuple[tuple[str, bool], ...]) -> dict[str, tuple[int, int]]:
    clustered: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for cluster_id, passed in values:
        clustered[cluster_id][0] += int(passed)
        clustered[cluster_id][1] += 1
    return {cluster_id: (counts[0], counts[1]) for cluster_id, counts in clustered.items()}


@with_live_decimal_context
def _design_effect(
    denominator: int,
    cluster_count: int,
    protocol: LiveProtocolRecord,
) -> Decimal:
    if denominator == 0 or cluster_count == 0:
        return Decimal("1")
    mean_cluster_size = Decimal(denominator) / Decimal(cluster_count)
    return _design_effect_for_size(mean_cluster_size, protocol)


@with_live_decimal_context
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
        if cluster_rates and all(rate == cluster_rates[0] for rate in cluster_rates[1:]):
            return cluster_rates[0], cluster_rates[0], cluster_rates[0]
        return bootstrap_mean_interval(
            cluster_rates,
            confidence_level=protocol.confidence_level,
            seed=f"{protocol.protocol_id}:{protocol.analysis_digest}:{label}:rate-bootstrap",
            iterations=LIVE_RATE_BOOTSTRAP_ITERATIONS,
        )
    return cluster_t_interval(cluster_rates, protocol.confidence_level)


@with_live_decimal_context
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


@with_live_decimal_context
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
    if Decimal(overall.exclusion_rate.rate) > Decimal(protocol.max_exclusion_rate):
        return GateState.fail
    if not included:
        return GateState.not_evaluated
    if any(observation.state is GateState.fail for observation in included):
        return GateState.fail
    if stop_reasons:
        return GateState.not_evaluated
    if any(observation.state is GateState.warn for observation in included):
        return GateState.warn
    if any(observation.state is GateState.not_evaluated for observation in included):
        return GateState.not_evaluated
    return GateState.pass_


def _report_exploratory(
    protocol: LiveProtocolRecord,
    overall: LiveGroupSummary,
    statistical_invariants: tuple[StatisticalInvariantResult, ...],
) -> bool:
    if not LIVE_PROTOCOL_BINDS_EXECUTION_CONFIGURATION:
        return True
    if protocol.cluster_by == "source_group_id":
        return True
    if protocol.analysis_method == "exploratory":
        return True
    if not statistical_invariants:
        return overall.expectation_pass_rate.exploratory
    primary = tuple(
        invariant for invariant in statistical_invariants if invariant.role == "primary"
    )
    if len(primary) != 1:
        return True
    primary_result = primary[0]
    return (
        overall.expectation_pass_rate.exploratory
        or primary_result.interpretation != "confirmatory"
        or primary_result.prerequisite_status != "met"
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
            return "exploratory_degenerate_point_mass"
        if analysis_method == "descriptive_cluster_t_interval":
            return "descriptive_degenerate_point_mass"
    return analysis_method


def _rate_exploratory(cluster_count: int, analysis_method: str) -> bool:
    if analysis_method.endswith("_degenerate_point_mass"):
        return True
    if analysis_method.startswith("exploratory_"):
        return True
    if cluster_count < 30:
        return True
    return analysis_method == "descriptive_cluster_bootstrap_percentile" and cluster_count < 50


@dataclass(frozen=True)
class _PersistedObservationRunProjection:
    """Non-sensitive RunSet fields sufficient to rederive persisted summaries."""

    provider: str | None
    model: str | None
    adapter_id: str | None
    pipeline_id: str
    outcome: str
    latency_ms: int | None
    estimated_cost_usd: str | None
    estimated_cost_picousd: int | None


def _persisted_run_projections(
    observations: tuple[LiveObservationResult, ...],
) -> tuple[_PersistedObservationRunProjection, ...]:
    projections: list[_PersistedObservationRunProjection] = []
    for observation in observations:
        if observation.outcome is None:
            raise ValueError("current live observation is missing outcome sufficient statistics")
        projections.append(
            _PersistedObservationRunProjection(
                provider=observation.provider,
                model=observation.model,
                adapter_id=observation.adapter_id,
                pipeline_id=observation.pipeline_id,
                outcome=observation.outcome,
                latency_ms=observation.latency_ms,
                estimated_cost_usd=observation.estimated_cost_usd,
                estimated_cost_picousd=observation.estimated_cost_picousd,
            )
        )
    return tuple(projections)


def _require_equal_derived_field(*, owner: str, actual: object, expected: object) -> None:
    if actual != expected:
        verb = "do" if owner.endswith("s") else "does"
        raise ValueError(f"{owner} {verb} not match observation-derived evidence")


def _persisted_observation_cost(
    observation: LiveObservationResult,
    *,
    owner: str,
) -> Decimal:
    picousd = observation.estimated_cost_picousd
    usd = observation.estimated_cost_usd
    if picousd is not None:
        if usd is None:
            raise ValueError(f"{owner} estimated_cost_picousd requires estimated_cost_usd")
        if usd_six_from_picousd(picousd) != usd:
            raise ValueError(
                f"{owner} estimated_cost_usd does not match the exact picodollar projection"
            )
        return Decimal(picousd) / Decimal(PICODOLLARS_PER_DOLLAR)
    return Decimal(usd or "0.000000")


@with_live_decimal_context
def verify_persisted_observation_protocol_coherence(
    report: LiveEvaluationReport,
) -> None:
    """Validate protocol obligations rederivable from current embedded observations.

    The compact report intentionally omits token counts, committed cost/token
    budgets, per-run configuration digests, provenance model identifiers, and
    the complete compiled-suite case/prompt manifest. Those source-RunSet
    obligations cannot be reconstructed here; callers must separately anchor
    ``source_runset_digest`` to trusted source bytes when they matter.
    """

    protocol = report.protocol
    if protocol is None:
        raise ValueError("current live evaluation report is missing its bound protocol")
    observations = report.observations
    if len(observations) != protocol.planned_observations:
        raise ValueError(
            "persisted live observation count does not match protocol planned_observations"
        )
    if protocol.planned_observations > protocol.max_requests:
        raise ValueError("protocol planned_observations exceeds its request budget")

    expected_repetitions = set(range(protocol.planned_repetitions))
    seen_repetitions: set[int] = set()
    seen_schedule_indexes: set[int] = set()
    seen_schedule_cells: set[tuple[str, int]] = set()
    case_prompt_digests: dict[str, set[str]] = defaultdict(set)
    case_source_groups: dict[str, set[str | None]] = defaultdict(set)
    derived_cluster_ids: set[str] = set()
    arm_identities: set[tuple[str | None, ...]] = set()
    allowed_exclusions = set(protocol.allowed_exclusion_reasons)
    total_cost = Decimal("0")

    for index, observation in enumerate(observations):
        owner = f"persisted live observation[{index}]"
        repetition_index = observation.repetition_index
        schedule_index = observation.schedule_index
        if repetition_index not in expected_repetitions:
            raise ValueError(f"{owner} repetition_index is outside the protocol grid")
        seen_repetitions.add(repetition_index)
        if schedule_index is None:
            raise ValueError(f"{owner} is missing schedule_index")
        if schedule_index in seen_schedule_indexes:
            raise ValueError("persisted live observations contain duplicate schedule_index")
        seen_schedule_indexes.add(schedule_index)
        schedule_cell = (observation.case_id, repetition_index)
        if schedule_cell in seen_schedule_cells:
            raise ValueError("persisted live observations contain a duplicate case/repetition cell")
        seen_schedule_cells.add(schedule_cell)
        expected_block_id = f"repetition:{repetition_index}"
        if observation.randomization_block_id != expected_block_id:
            raise ValueError(f"{owner} randomization_block_id does not match repetition_index")
        if observation.prompt_digest is None:
            raise ValueError(f"{owner} is missing prompt_digest")
        case_prompt_digests[observation.case_id].add(observation.prompt_digest)
        case_source_groups[observation.case_id].add(observation.source_group_id)

        expected_cluster_id = (
            observation.source_group_id
            if protocol.cluster_by == "source_group_id"
            else observation.case_id
        )
        if expected_cluster_id is None:
            raise ValueError(
                "source_group_id clustering requires source_group_id on every observation"
            )
        if observation.cluster_id != expected_cluster_id:
            raise ValueError(f"{owner} cluster_id does not match protocol.cluster_by")
        derived_cluster_ids.add(expected_cluster_id)

        arm_identities.add(
            tuple(getattr(observation, field_name) for field_name in _PERSISTED_ARM_IDENTITY_FIELDS)
        )
        for field_name in protocol.provider_version_capture:
            if field_name not in _PERSISTED_PROVIDER_CAPTURE_FIELDS:
                raise ValueError(
                    "current live evaluation cannot verify provider_version_capture field "
                    f"{field_name!r} because it is not persisted in observations"
                )
            if getattr(observation, field_name) is None:
                raise ValueError(f"{owner} is missing provider-version field {field_name!r}")

        if observation.observation_status == "excluded" and not observation.exclusion_reason:
            raise ValueError(f"{owner} excluded status requires exclusion_reason")
        if observation.exclusion_reason and observation.exclusion_reason not in allowed_exclusions:
            raise ValueError(f"{owner} exclusion_reason is not declared by the protocol")
        if observation.attempt_count is not None:
            if (
                observation.retry_count is not None
                and observation.retry_count > observation.attempt_count
            ):
                raise ValueError(f"{owner} retry_count cannot exceed attempt_count")
            if (
                observation.rate_limit_events is not None
                and observation.rate_limit_events > observation.attempt_count
            ):
                raise ValueError(f"{owner} rate_limit_events cannot exceed attempt_count")
        if observation.retry_count is not None and observation.retry_count > protocol.max_retries:
            raise ValueError(f"{owner} retry_count exceeds the protocol maximum")
        if (
            observation.rate_limit_events is not None
            and observation.rate_limit_events > protocol.max_rate_limit_events
        ):
            raise ValueError(f"{owner} rate_limit_events exceeds the protocol maximum")
        if observation.tool_schema_digest != protocol.tool_schema_digest:
            raise ValueError(f"{owner} tool_schema_digest does not match the protocol")
        if observation.policy_bundle_digest != protocol.policy_bundle_digest:
            raise ValueError(f"{owner} policy_bundle_digest does not match the protocol")

        observation_cost = _persisted_observation_cost(observation, owner=owner)
        if observation_cost > Decimal(protocol.max_cost_per_observation_usd):
            raise ValueError(f"{owner} cost exceeds max_cost_per_observation_usd")
        total_cost += observation_cost

    if seen_repetitions != expected_repetitions:
        raise ValueError("persisted live observation repetitions do not match the protocol")
    if seen_schedule_indexes != set(range(protocol.planned_observations)):
        raise ValueError(
            "persisted live schedule_index values must cover the complete planned schedule"
        )
    if any(len(digests) != 1 for digests in case_prompt_digests.values()):
        raise ValueError("persisted live prompt_digest must be stable within each case")
    if any(len(groups) != 1 for groups in case_source_groups.values()):
        raise ValueError("persisted live source_group_id must be stable within each case")
    if len(arm_identities) != 1:
        raise ValueError("persisted live observations must contain one homogeneous execution arm")

    expected_schedule_cells = {
        (case_id, repetition_index)
        for case_id in case_prompt_digests
        for repetition_index in expected_repetitions
    }
    if seen_schedule_cells != expected_schedule_cells:
        raise ValueError(
            "persisted live observations must form the complete case/repetition schedule"
        )
    if len(derived_cluster_ids) != protocol.planned_clusters:
        raise ValueError("persisted live cluster count does not match protocol planned_clusters")
    if total_cost > Decimal(protocol.max_total_cost_usd):
        raise ValueError("persisted live observation cost exceeds protocol max_total_cost_usd")


@with_live_decimal_context
def verify_live_evaluation_report_derivation(report: LiveEvaluationReport) -> None:
    """Recompute every decision-bearing report projection from persisted evidence.

    This verifier intentionally uses the same derivation functions as report
    generation. The report remains producer-attested; source_runset_digest
    binds it to external evidence that a signed manifest or verifier-controlled
    workflow must anchor independently.
    """

    protocol = report.protocol
    if protocol is None:
        raise ValueError("current live evaluation report is missing its bound protocol")
    protocol_digest = sha256_hexdigest(protocol)
    protocol_bindings = {
        "protocol_id": (report.protocol_id, protocol.protocol_id),
        "protocol_digest": (report.protocol_digest, protocol_digest),
        "suite_id": (report.suite_id, protocol.suite_id),
        "suite_version": (report.suite_version, protocol.suite_version),
        "suite_digest": (report.suite_digest, protocol.suite_digest),
        "baseline_mode": (report.baseline_mode, protocol.baseline_mode),
        "analysis_method": (report.analysis_method, protocol.analysis_method),
        "cluster_by": (report.cluster_by, protocol.cluster_by),
        "planned_repetitions": (report.planned_repetitions, protocol.planned_repetitions),
        "planned_observations": (report.planned_observations, protocol.planned_observations),
        "planned_clusters": (report.planned_clusters, protocol.planned_clusters),
        "confidence_level": (report.confidence_level, protocol.confidence_level),
    }
    for field_name, (actual, expected) in protocol_bindings.items():
        if actual != expected:
            raise ValueError(f"live evaluation {field_name} does not match bound protocol")

    # Structural/protocol checks precede every resampling or interval kernel.
    verify_persisted_observation_protocol_coherence(report)

    if report.stop_reasons != tuple(sorted(set(report.stop_reasons))):
        raise ValueError("live evaluation stop_reasons must be unique and sorted")
    expected_observation_budget_reasons = project_live_stop_reasons(
        (),
        (observation.exclusion_reason for observation in report.observations),
    )
    observation_budget_reason_set = set(expected_observation_budget_reasons)
    persisted_observation_budget_reasons = tuple(
        reason for reason in report.stop_reasons if reason in observation_budget_reason_set
    )
    if persisted_observation_budget_reasons != expected_observation_budget_reasons:
        raise ValueError(
            "live evaluation observation-derived budget stop reasons do not match "
            "persisted stop_reasons"
        )
    expected_completion = (
        "incomplete"
        if report.stop_reasons or report.source_completion_status == "incomplete"
        else "complete"
    )
    _require_equal_derived_field(
        owner="live evaluation completion_status",
        actual=report.completion_status,
        expected=expected_completion,
    )
    _require_equal_derived_field(
        owner="live evaluation budget_exceeded",
        actual=report.budget_exceeded,
        expected=bool(BUDGET_STOP_REASONS & set(report.stop_reasons)),
    )

    # The immutable projection intentionally carries every field consumed by
    # summary and invariant derivation; the cast keeps those shared kernels on
    # their established AgentRunRecord-facing API without reconstructing or
    # trusting fields absent from persisted observations.
    projected_runs = cast(
        tuple[AgentRunRecord, ...],
        _persisted_run_projections(report.observations),
    )
    _validate_live_evaluation_work_budget(
        projected_runs,
        report.observations,
        protocol=protocol,
    )
    expected_groups = tuple(
        _summarize_group(
            group_id,
            group_runs,
            group_observations,
            protocol=protocol,
        )
        for group_id, group_runs, group_observations in _groups(
            projected_runs,
            report.observations,
        )
    )
    expected_overall = _summarize_group(
        "overall",
        projected_runs,
        report.observations,
        protocol=protocol,
    )
    expected_invariants = evaluate_statistical_invariants(
        projected_runs,
        report.observations,
        protocol,
    )
    _require_equal_derived_field(
        owner="live evaluation overall summary",
        actual=report.overall,
        expected=expected_overall,
    )
    _require_equal_derived_field(
        owner="live evaluation group summaries",
        actual=report.groups,
        expected=expected_groups,
    )
    _require_equal_derived_field(
        owner="live evaluation statistical invariants",
        actual=report.statistical_invariants,
        expected=expected_invariants,
    )

    expected_state = _report_state(
        report.observations,
        expected_overall,
        protocol,
        report.stop_reasons,
    )
    _require_equal_derived_field(
        owner="live evaluation state",
        actual=report.state,
        expected=expected_state,
    )
    expected_exploratory = _report_exploratory(
        protocol,
        expected_overall,
        expected_invariants,
    )
    _require_equal_derived_field(
        owner="live evaluation exploratory flag",
        actual=report.exploratory,
        expected=expected_exploratory,
    )
