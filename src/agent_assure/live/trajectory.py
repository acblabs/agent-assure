from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime
from decimal import Decimal
from itertools import pairwise
from typing import Literal

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.primitives import (
    decimal_string,
    mean_decimal,
    parse_timestamp,
    rate_string,
)
from agent_assure.live.statistics import BUDGET_STOP_REASONS
from agent_assure.schema.common import GateState, ReasonCode
from agent_assure.schema.live import (
    HistoryDependentTrajectoryCheck,
    LiveEvaluationReport,
    LiveObservationResult,
    LiveProtocolRecord,
    LiveTrajectoryReport,
    OperationalBurstSignal,
    OperationalEventProcessSummary,
    OperationalEventType,
    TrajectoryAnalysisPlan,
    TrajectoryInvariantPlan,
    TrajectoryInvariantResult,
    TrajectoryPathSummary,
    TrajectoryPrerequisiteStatus,
    TrajectoryState,
    TrajectoryTransitionSummary,
)
from agent_assure.schema.run import AgentRunRecord, RunSet
from agent_assure.schema.runtime import EmergencyProcessRecord

_TrajectoryStatus = Literal["valid", "exploratory", "invalid"]
_APPROVAL_OUTCOMES = {"approve", "approved", "approval"}
_BASE_LIMITATIONS = (
    "trajectory analysis is derived from privacy-filtered structured artifacts",
    "trajectory and event-process outputs are review signals and are not "
    "release-verdict gates",
    "path coverage over observed records is not proof that unsafe paths are impossible",
    "burst-window screens are exploratory reliability diagnostics until event-volume "
    "prerequisites and external review support stronger use",
)


def build_live_trajectory_report(
    runset: RunSet,
    evaluation_report: LiveEvaluationReport,
    *,
    protocol: LiveProtocolRecord,
) -> LiveTrajectoryReport:
    _verify_binding(runset, evaluation_report, protocol)
    plan = protocol.trajectory_analysis_plan or _default_trajectory_plan()
    emergency_by_observation, emergency_by_run = _emergency_indexes(runset.emergency_records)
    paths = tuple(
        _path_summary(
            run,
            observation,
            linked_emergencies=(
                *emergency_by_observation.get(observation.observation_id, ()),
                *emergency_by_run.get(run.run_id, ()),
            ),
        )
        for run, observation in zip(runset.runs, evaluation_report.observations, strict=True)
    )
    transitions = _transition_summaries(paths, plan=plan)
    invariants = _invariant_results(plan, runset.runs, evaluation_report.observations, paths)
    history_dependent_checks = _history_dependent_checks(
        runset.runs,
        evaluation_report.observations,
        paths,
    )
    event_processes = _event_processes(
        runset,
        evaluation_report,
        plan=plan,
    )
    status = _trajectory_status(plan, paths, transitions, invariants, event_processes)
    report_id = "live-trajectory-" + sha256_hexdigest(
        {
            "protocol_digest": sha256_hexdigest(protocol),
            "trajectory_plan": plan,
            "runset_id": runset.runset_id,
            "evaluation_runset_id": evaluation_report.runset_id,
        }
    )[:16]
    transition_status = _transition_assumption_status(plan, paths)
    limitations = list(_BASE_LIMITATIONS)
    if transition_status != "met":
        limitations.append(
            "observable transition profiles are exploratory because path support or "
            "observation prerequisites were not fully met"
        )
    if any(not path.has_ordered_timestamps for path in paths):
        limitations.append(
            "one or more trajectory paths lack complete ordered timestamps; event-process "
            "timing diagnostics are limited"
        )
    return LiveTrajectoryReport(
        artifact_kind="live-trajectory-report",
        report_id=report_id,
        runset_id=runset.runset_id,
        evaluation_report_id=f"{evaluation_report.runset_id}:live-evaluation-report",
        protocol_id=protocol.protocol_id,
        protocol_digest=sha256_hexdigest(protocol),
        trajectory_plan_id=plan.plan_id,
        suite_id=evaluation_report.suite_id,
        suite_version=evaluation_report.suite_version,
        interpretation=plan.interpretation,
        state=GateState.not_evaluated,
        trajectory_status=status,
        transition_assumption="canonical_observable_order",
        transition_assumption_status=transition_status,
        observations=len(paths),
        included_observations=evaluation_report.overall.included_observations,
        excluded_observations=evaluation_report.overall.excluded_observations,
        paths=paths,
        transitions=transitions,
        invariants=invariants,
        history_dependent_checks=history_dependent_checks,
        event_processes=event_processes,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _default_trajectory_plan() -> TrajectoryAnalysisPlan:
    return TrajectoryAnalysisPlan(
        artifact_kind="trajectory-analysis-plan",
        plan_id="default-exploratory-live-trajectory",
        interpretation="exploratory",
        minimum_observations=1,
        minimum_transition_support=1,
        minimum_event_count=3,
        minimum_event_exposure=1,
        burst_window_seconds=60,
        burst_count_threshold=3,
        invariants=(
            TrajectoryInvariantPlan(
                artifact_kind="trajectory-invariant-plan",
                invariant_id="no-emergency-state",
                label="Emergency states are operational warnings",
                invariant_type="forbidden_state",
                category="operational_reliability_warning",
                forbidden_states=("emergency",),
            ),
            TrajectoryInvariantPlan(
                artifact_kind="trajectory-invariant-plan",
                invariant_id="required-review-for-approval",
                label="Approval verdicts retain required review state when review is required",
                invariant_type="required_review_for_approval",
                category="governance_control_failure",
                required_state="human_review",
            ),
            TrajectoryInvariantPlan(
                artifact_kind="trajectory-invariant-plan",
                invariant_id="claim-evidence-before-approval",
                label="Approval verdicts retain explicit claim evidence links",
                invariant_type="claim_evidence_before_approval",
                category="governance_control_failure",
            ),
            TrajectoryInvariantPlan(
                artifact_kind="trajectory-invariant-plan",
                invariant_id="attempt-retry-consistency",
                label="Attempt counters remain consistent with retry counters",
                invariant_type="attempt_retry_consistency",
                category="operational_reliability_warning",
            ),
        ),
    )


def _verify_binding(
    runset: RunSet,
    report: LiveEvaluationReport,
    protocol: LiveProtocolRecord,
) -> None:
    protocol_digest = sha256_hexdigest(protocol)
    if runset.runset_id != report.runset_id:
        raise ValueError("trajectory report requires the RunSet used by the evaluation report")
    if runset.suite_id != report.suite_id or runset.suite_version != report.suite_version:
        raise ValueError("trajectory RunSet and live evaluation report reference different suites")
    if runset.protocol_id != protocol.protocol_id or runset.protocol_digest != protocol_digest:
        raise ValueError("trajectory RunSet protocol binding does not match protocol")
    if report.protocol_id != protocol.protocol_id or report.protocol_digest != protocol_digest:
        raise ValueError("trajectory evaluation report protocol binding does not match protocol")
    run_ids = tuple(run.run_id for run in runset.runs)
    observation_run_ids = tuple(observation.run_id for observation in report.observations)
    if run_ids != observation_run_ids:
        raise ValueError("trajectory RunSet and live evaluation report observations differ")


def _path_summary(
    run: AgentRunRecord,
    observation: LiveObservationResult,
    *,
    linked_emergencies: tuple[EmergencyProcessRecord, ...],
) -> TrajectoryPathSummary:
    states: list[TrajectoryState] = ["start", "request_assembly"]
    limitations: list[str] = []
    if observation.observation_status == "excluded":
        states.append("excluded")
    else:
        states.append("provider_call")
        if run.tools:
            states.append("tool_call")
        if run.evidence_refs or run.evidence_items or run.claims or run.claim_evidence_links:
            states.append("evidence_check")
        if run.policy_results or observation.findings:
            states.append("policy_check")
        if {
            ReasonCode.REDACTION_FAILED,
            ReasonCode.RAW_SENSITIVE_CONTENT,
        }.intersection(observation.reason_codes):
            states.append("redaction_check")
        if run.human_review_required or run.human_review_performed:
            if run.human_review_performed:
                states.append("human_review")
            else:
                limitations.append("human review was required but no review state was observed")
        if linked_emergencies:
            states.append("emergency")
        states.append("verdict")
    if linked_emergencies and "emergency" not in states:
        states.append("emergency")
    has_ordered_timestamps = _has_ordered_timestamps(run.started_at_utc, run.completed_at_utc)
    if not has_ordered_timestamps:
        limitations.append("run timestamps are missing or not ordered")
    terminal = states[-1]
    return TrajectoryPathSummary(
        artifact_kind="trajectory-path-summary",
        observation_id=observation.observation_id,
        run_id=run.run_id,
        case_id=run.case_id,
        repetition_index=observation.repetition_index,
        cluster_id=observation.cluster_id,
        terminal_state=terminal,
        states=tuple(states),
        transition_count=max(0, len(states) - 1),
        tool_count=len(run.tools),
        claim_count=len(run.claims),
        evidence_ref_count=len(run.evidence_refs),
        claim_evidence_link_count=len(run.claim_evidence_links),
        policy_result_count=len(run.policy_results),
        human_review_required=run.human_review_required,
        human_review_performed=run.human_review_performed,
        has_ordered_timestamps=has_ordered_timestamps,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _transition_summaries(
    paths: tuple[TrajectoryPathSummary, ...],
    *,
    plan: TrajectoryAnalysisPlan,
) -> tuple[TrajectoryTransitionSummary, ...]:
    from_counts: Counter[TrajectoryState] = Counter()
    transition_counts: Counter[tuple[TrajectoryState, TrajectoryState]] = Counter()
    for path in paths:
        for left, right in pairwise(path.states):
            from_counts[left] += 1
            transition_counts[(left, right)] += 1
    summaries: list[TrajectoryTransitionSummary] = []
    for (left, right), count in sorted(
        transition_counts.items(),
        key=lambda item: (item[0][0], item[0][1]),
    ):
        support = from_counts[left]
        status: TrajectoryPrerequisiteStatus = (
            "met" if support >= plan.minimum_transition_support else "exploratory"
        )
        limitations: tuple[str, ...] = ()
        if status == "exploratory":
            limitations = ("transition support is below the declared threshold",)
        summaries.append(
            TrajectoryTransitionSummary(
                artifact_kind="trajectory-transition-summary",
                from_state=left,
                to_state=right,
                count=count,
                from_state_count=support,
                conditional_frequency=rate_string(count, support),
                prerequisite_status=status,
                limitations=limitations,
            )
        )
    return tuple(summaries)


def _invariant_results(
    plan: TrajectoryAnalysisPlan,
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    paths: tuple[TrajectoryPathSummary, ...],
) -> tuple[TrajectoryInvariantResult, ...]:
    return tuple(
        _invariant_result(invariant, runs, observations, paths, plan=plan)
        for invariant in plan.invariants
    )


def _invariant_result(
    invariant: TrajectoryInvariantPlan,
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    paths: tuple[TrajectoryPathSummary, ...],
    *,
    plan: TrajectoryAnalysisPlan,
) -> TrajectoryInvariantResult:
    affected: tuple[str, ...]
    if invariant.invariant_type == "forbidden_state":
        forbidden = set(invariant.forbidden_states)
        affected = tuple(
            path.observation_id for path in paths if forbidden.intersection(path.states)
        )
    elif invariant.invariant_type == "required_review_for_approval":
        affected = _required_review_for_approval_violations(runs, observations, paths)
    elif invariant.invariant_type == "claim_evidence_before_approval":
        affected = _claim_evidence_violations(runs, observations)
    elif invariant.invariant_type == "attempt_retry_consistency":
        affected = tuple(
            observation.observation_id
            for run, observation in zip(runs, observations, strict=True)
            if run.retry_count is not None
            and run.attempt_count is not None
            and run.attempt_count != run.retry_count + 1
        )
    else:
        raise ValueError(f"unsupported trajectory invariant: {invariant.invariant_type}")
    evaluated = len(paths)
    status = _observation_prerequisite(
        evaluated,
        minimum=max(plan.minimum_observations, invariant.minimum_observations),
    )
    limitations: list[str] = []
    if status == "exploratory":
        limitations.append("observation count is below the declared trajectory threshold")
    if affected and invariant.interpretation == "exploratory":
        limitations.append("invariant finding is exploratory review evidence")
    state = GateState.not_evaluated
    if affected and status != "invalid":
        state = (
            GateState.fail
            if invariant.category == "governance_control_failure"
            else GateState.warn
        )
    return TrajectoryInvariantResult(
        artifact_kind="trajectory-invariant-result",
        invariant_id=invariant.invariant_id,
        label=invariant.label,
        invariant_type=invariant.invariant_type,
        category=invariant.category,
        interpretation=invariant.interpretation,
        prerequisite_status=status,
        affected_observations=len(affected),
        evaluated_observations=evaluated,
        affected_observation_ids=affected,
        state=state,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _required_review_for_approval_violations(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    paths: tuple[TrajectoryPathSummary, ...],
) -> tuple[str, ...]:
    affected: list[str] = []
    for run, observation, path in zip(runs, observations, paths, strict=True):
        if not run.human_review_required or not _is_approval(run):
            continue
        if "human_review" not in path.states:
            affected.append(observation.observation_id)
    return tuple(affected)


def _claim_evidence_violations(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
) -> tuple[str, ...]:
    affected: list[str] = []
    for run, observation in zip(runs, observations, strict=True):
        if observation.observation_status != "included" or not _is_approval(run):
            continue
        if not run.claims:
            continue
        linked_claims = {link.claim_id for link in run.claim_evidence_links}
        claim_ids = {claim.claim_id for claim in run.claims}
        evidence_item_ids = {item.ref_id for item in run.evidence_items}
        if claim_ids - linked_claims:
            affected.append(observation.observation_id)
            continue
        if any(link.evidence_ref_id not in evidence_item_ids for link in run.claim_evidence_links):
            affected.append(observation.observation_id)
    return tuple(affected)


def _history_dependent_checks(
    runs: tuple[AgentRunRecord, ...],
    observations: tuple[LiveObservationResult, ...],
    paths: tuple[TrajectoryPathSummary, ...],
) -> tuple[HistoryDependentTrajectoryCheck, ...]:
    review_affected = _required_review_for_approval_violations(runs, observations, paths)
    evidence_affected = _claim_evidence_violations(runs, observations)
    path_lookup = _paths_by_id(paths)
    retry_affected = tuple(
        observation.observation_id
        for run, observation in zip(runs, observations, strict=True)
        if (run.retry_count or 0) > 0
        and "provider_call" not in path_lookup[observation.observation_id].states
    )
    return (
        _history_dependent_check(
            check_id="review-required-history",
            dependency="expected review state depends on the run-level human_review_required flag",
            affected=review_affected,
            evaluated=len(paths),
        ),
        _history_dependent_check(
            check_id="claim-evidence-history",
            dependency="approval eligibility depends on complete claim-to-evidence link history",
            affected=evidence_affected,
            evaluated=len(paths),
        ),
        _history_dependent_check(
            check_id="retry-provider-history",
            dependency=(
                "retry events depend on prior provider-call attempts, not only current "
                "state"
            ),
            affected=retry_affected,
            evaluated=len(paths),
        ),
    )


def _paths_by_id(paths: tuple[TrajectoryPathSummary, ...]) -> dict[str, TrajectoryPathSummary]:
    return {path.observation_id: path for path in paths}


def _history_dependent_check(
    *,
    check_id: str,
    dependency: str,
    affected: tuple[str, ...],
    evaluated: int,
) -> HistoryDependentTrajectoryCheck:
    status: TrajectoryPrerequisiteStatus = "invalid" if evaluated == 0 else "met"
    limitations: tuple[str, ...] = ()
    if affected:
        limitations = ("history-dependent trajectory condition requires review",)
    return HistoryDependentTrajectoryCheck(
        artifact_kind="history-dependent-trajectory-check",
        check_id=check_id,
        dependency=dependency,
        prerequisite_status=status,
        affected_observations=len(affected),
        affected_observation_ids=affected,
        limitations=limitations,
    )


def _event_processes(
    runset: RunSet,
    report: LiveEvaluationReport,
    *,
    plan: TrajectoryAnalysisPlan,
) -> tuple[OperationalEventProcessSummary, ...]:
    observations = report.observations
    rows: dict[OperationalEventType, list[str | None]] = {
        "retry": [],
        "rate_limit": [],
        "exclusion": [],
        "runtime_failure": [],
        "malformed_output": [],
        "emergency_process": [],
        "budget_stop": [],
    }
    for observation in observations:
        _append_counted_events(
            rows["retry"],
            count=observation.retry_count or 0,
            timestamp=observation.started_at_utc,
        )
        _append_counted_events(
            rows["rate_limit"],
            count=observation.rate_limit_events or 0,
            timestamp=observation.started_at_utc,
        )
        if observation.observation_status == "excluded":
            rows["exclusion"].append(observation.started_at_utc)
        if ReasonCode.RUNTIME_FAILED in observation.reason_codes:
            rows["runtime_failure"].append(observation.started_at_utc)
        if ReasonCode.STRUCTURED_OUTPUT_INVALID in observation.reason_codes:
            rows["malformed_output"].append(observation.started_at_utc)
    for emergency in runset.emergency_records:
        rows["emergency_process"].append(emergency.started_at_utc or emergency.completed_at_utc)
    rows["budget_stop"].extend(
        None for reason in runset.stop_reasons if reason in BUDGET_STOP_REASONS
    )
    exposure = len(observations)
    return tuple(
        _event_process_summary(
            event_type,
            timestamps,
            exposure=exposure,
            plan=plan,
        )
        for event_type, timestamps in rows.items()
    )


def _event_process_summary(
    event_type: OperationalEventType,
    timestamps: list[str | None],
    *,
    exposure: int,
    plan: TrajectoryAnalysisPlan,
) -> OperationalEventProcessSummary:
    observed = len(timestamps)
    parsed = tuple(
        parsed
        for value in timestamps
        if value is not None and (parsed := parse_timestamp(value)) is not None
    )
    missing = observed - len(parsed)
    status = _event_prerequisite_status(
        observed,
        exposure=exposure,
        missing_timestamps=missing,
        plan=plan,
    )
    ordered = tuple(sorted(parsed))
    mean_gap = _mean_gap_seconds(ordered)
    window_seconds = _window_seconds(ordered)
    max_burst = _max_events_in_window(ordered, window_seconds=plan.burst_window_seconds)
    burst_signal = _burst_signal(
        status,
        observed=observed,
        timestamped=len(parsed),
        missing=missing,
        max_burst=max_burst,
        threshold=plan.burst_count_threshold,
    )
    limitations = list(
        _event_limitations(
            observed,
            exposure=exposure,
            missing_timestamps=missing,
            plan=plan,
            status=status,
        )
    )
    if burst_signal == "review":
        limitations.append(
            "multiple events occurred inside the declared burst window; this is a "
            "reliability review signal, not a governance verdict"
        )
    return OperationalEventProcessSummary(
        artifact_kind="operational-event-process-summary",
        event_type=event_type,
        observed_events=observed,
        exposure=exposure,
        exposure_unit="observation",
        event_rate=rate_string(observed, exposure),
        analysis_method=(
            "burst_window_count"
            if "burst_window_count" in plan.analysis_methods
            else "poisson_rate"
        ),
        prerequisite_status=status,
        timestamped_events=len(parsed),
        missing_timestamp_events=missing,
        observation_window_seconds=(
            decimal_string(window_seconds) if window_seconds is not None else None
        ),
        mean_interarrival_seconds=(
            decimal_string(mean_gap) if mean_gap is not None else None
        ),
        max_events_in_burst_window=max_burst,
        burst_window_seconds=plan.burst_window_seconds,
        burst_signal=burst_signal,
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _event_prerequisite_status(
    observed: int,
    *,
    exposure: int,
    missing_timestamps: int,
    plan: TrajectoryAnalysisPlan,
) -> TrajectoryPrerequisiteStatus:
    if exposure < plan.minimum_event_exposure:
        return "invalid"
    if observed == 0:
        return "exploratory"
    if missing_timestamps:
        return "exploratory"
    if observed < plan.minimum_event_count:
        return "exploratory"
    return "met"


def _append_counted_events(
    target: list[str | None],
    *,
    count: int,
    timestamp: str | None,
) -> None:
    if count <= 0:
        return
    target.append(timestamp)
    target.extend(None for _ in range(count - 1))


def _event_limitations(
    observed: int,
    *,
    exposure: int,
    missing_timestamps: int,
    plan: TrajectoryAnalysisPlan,
    status: TrajectoryPrerequisiteStatus,
) -> tuple[str, ...]:
    limitations: list[str] = []
    if exposure < plan.minimum_event_exposure:
        limitations.append("event exposure is below the declared threshold")
    if observed < plan.minimum_event_count:
        limitations.append("event count is below the declared event-process threshold")
    if missing_timestamps:
        limitations.append("one or more events lack parseable timestamps")
    if status == "exploratory":
        limitations.append("event-process inference is exploratory under declared prerequisites")
    return tuple(limitations)


def _trajectory_status(
    plan: TrajectoryAnalysisPlan,
    paths: tuple[TrajectoryPathSummary, ...],
    transitions: tuple[TrajectoryTransitionSummary, ...],
    invariants: tuple[TrajectoryInvariantResult, ...],
    event_processes: tuple[OperationalEventProcessSummary, ...],
) -> _TrajectoryStatus:
    if not paths:
        return "invalid"
    if len(paths) < plan.minimum_observations:
        return "invalid"
    if plan.interpretation == "exploratory":
        return "exploratory"
    if any(transition.prerequisite_status != "met" for transition in transitions):
        return "exploratory"
    if any(invariant.prerequisite_status != "met" for invariant in invariants):
        return "exploratory"
    if any(process.prerequisite_status != "met" for process in event_processes):
        return "exploratory"
    return "valid"


def _transition_assumption_status(
    plan: TrajectoryAnalysisPlan,
    paths: tuple[TrajectoryPathSummary, ...],
) -> TrajectoryPrerequisiteStatus:
    if not paths or len(paths) < plan.minimum_observations:
        return "invalid"
    transition_counts: Counter[TrajectoryState] = Counter()
    for path in paths:
        for left, _ in pairwise(path.states):
            transition_counts[left] += 1
    if any(count < plan.minimum_transition_support for count in transition_counts.values()):
        return "exploratory"
    return "met"


def _observation_prerequisite(
    observed: int,
    *,
    minimum: int,
) -> TrajectoryPrerequisiteStatus:
    if observed == 0:
        return "invalid"
    if observed < minimum:
        return "exploratory"
    return "met"


def _emergency_indexes(
    emergencies: tuple[EmergencyProcessRecord, ...],
) -> tuple[
    dict[str, tuple[EmergencyProcessRecord, ...]],
    dict[str, tuple[EmergencyProcessRecord, ...]],
]:
    by_observation: dict[str, list[EmergencyProcessRecord]] = defaultdict(list)
    by_run: dict[str, list[EmergencyProcessRecord]] = defaultdict(list)
    for emergency in emergencies:
        if emergency.observation_id is not None:
            by_observation[emergency.observation_id].append(emergency)
        if emergency.run_id is not None:
            by_run[emergency.run_id].append(emergency)
    return (
        {key: tuple(value) for key, value in by_observation.items()},
        {key: tuple(value) for key, value in by_run.items()},
    )


def _is_approval(run: AgentRunRecord) -> bool:
    return (
        run.outcome.lower() in _APPROVAL_OUTCOMES
        or run.recommendation.lower() in _APPROVAL_OUTCOMES
    )


def _has_ordered_timestamps(started: str | None, completed: str | None) -> bool:
    if started is None or completed is None:
        return False
    start = parse_timestamp(started)
    end = parse_timestamp(completed)
    if start is None or end is None:
        return False
    return end >= start


def _mean_gap_seconds(values: tuple[datetime, ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    gaps = tuple(
        Decimal(str((right - left).total_seconds()))
        for left, right in pairwise(values)
    )
    if not gaps:
        return None
    return mean_decimal(gaps)


def _window_seconds(values: tuple[datetime, ...]) -> Decimal | None:
    if len(values) < 2:
        return None
    return Decimal(str((values[-1] - values[0]).total_seconds()))


def _max_events_in_window(values: tuple[datetime, ...], *, window_seconds: int) -> int:
    if not values:
        return 0
    left = 0
    best = 1
    for right, value in enumerate(values):
        while (value - values[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def _burst_signal(
    status: TrajectoryPrerequisiteStatus,
    *,
    observed: int,
    timestamped: int,
    missing: int,
    max_burst: int,
    threshold: int,
) -> OperationalBurstSignal:
    if observed > 0 and timestamped == 0:
        return "invalid"
    if status == "invalid":
        return "invalid"
    if missing and timestamped < 2:
        return "invalid"
    if max_burst >= threshold:
        return "review"
    return "none"
