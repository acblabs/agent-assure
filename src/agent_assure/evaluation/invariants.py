from __future__ import annotations

from collections import Counter

from agent_assure.evaluation.expectations import CaseExpectation, ExpectationResolver
from agent_assure.policies import (
    evidence,
    human_review,
    injection,
    output_schema,
    privacy,
    providers,
    runtime,
    tools,
)
from agent_assure.policies.base import ControlResult
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet


def evaluate_runset_controls(
    resolver: ExpectationResolver,
    runset: RunSet,
    *,
    allowed_tools: tuple[str, ...] | None = None,
    required_policy_ids: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    runs_by_case, coverage_results = _runs_by_case(runset, resolver.case_ids)
    results = list(_runset_status_results(runset))
    results.extend(coverage_results)
    results.extend(
        _evaluate_required_policy_results(
            runs_by_case,
            resolver.case_ids,
            required_policy_ids,
        )
    )
    for case_expectation in resolver.cases():
        run = runs_by_case.get(case_expectation.case.case_id)
        if run is None:
            continue
        if run.observation_status == "excluded":
            results.append(
                ControlResult(
                    control_id="valid_record_required",
                    case_id=run.case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target="observation_status",
                    message="ordinary evaluation cannot treat an excluded observation as evaluated",
                )
            )
            continue
        results.extend(
            evaluate_case(
                case_expectation,
                run,
                allowed_tools=allowed_tools,
                required_policy_ids=required_policy_ids,
            )
        )
    return tuple(results)


def evaluate_case(
    case_expectation: CaseExpectation,
    run: AgentRunRecord,
    *,
    allowed_tools: tuple[str, ...] | None = None,
    required_policy_ids: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    expectation = case_expectation.expectation
    results: list[ControlResult] = []
    if expectation.allowed_tools_override:
        effective_allowed_tools: tuple[str, ...] | None = expectation.allowed_tools
    elif expectation.allowed_tools:
        effective_allowed_tools = expectation.allowed_tools
    else:
        effective_allowed_tools = allowed_tools if allowed_tools else None
    results.extend(_evaluate_expected_recommendation(run, expectation.expected_recommendation))
    results.extend(_evaluate_allowed_outcomes(run, expectation.allowed_outcomes))
    results.extend(_evaluate_forbidden_outcomes(run, expectation.forbidden_outcomes))
    results.extend(runtime.evaluate_runtime_success(run))
    results.extend(
        _evaluate_persisted_policy_results(
            run,
            required_policy_ids=required_policy_ids,
        )
    )
    results.extend(output_schema.evaluate_structured_output(run))
    results.extend(evidence.evaluate_required_evidence(run, expectation))
    results.extend(evidence.evaluate_material_claim_evidence(run, expectation))
    results.extend(
        tools.evaluate_tool_allowlist(
            run,
            allowed_tools=effective_allowed_tools,
            forbidden_tools=expectation.forbidden_tools,
        )
    )
    results.extend(human_review.evaluate_human_review_requirement(run, expectation))
    results.extend(providers.evaluate_provider_boundary(run, case_expectation.case, expectation))
    results.extend(injection.evaluate_prompt_boundary(run, case_expectation.case, expectation))
    results.extend(privacy.evaluate_redaction(run))
    return tuple(results)


def _evaluate_persisted_policy_results(
    run: AgentRunRecord,
    *,
    required_policy_ids: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    results: list[ControlResult] = []
    required = set(required_policy_ids)
    for policy_result in run.policy_results:
        if policy_result.policy_id in required:
            continue
        if policy_result.state is GateState.pass_:
            continue
        if _is_fixture_remediation_signal(run, policy_result):
            continue
        if run.execution_mode is not ExecutionMode.live and policy_result.state is GateState.warn:
            continue
        results.append(
            ControlResult(
                control_id=f"policy_result:{policy_result.policy_id}",
                case_id=run.case_id,
                state=policy_result.state,
                reason_code=_policy_reason_code(policy_result),
                severity=_policy_severity(policy_result),
                target=policy_result.policy_id,
                message=policy_result.message
                or (
                    f"persisted policy result {policy_result.policy_id!r} "
                    f"was {policy_result.state.value}"
                ),
            )
        )
    return tuple(results)


def evaluate_required_policy_results_for_run(
    run: AgentRunRecord,
    required_policy_ids: tuple[str, ...],
) -> tuple[ControlResult, ...]:
    results: list[ControlResult] = []
    if not required_policy_ids:
        return ()

    for policy_id in required_policy_ids:
        observed = tuple(
            policy_result
            for policy_result in run.policy_results
            if policy_result.policy_id == policy_id
        )
        if not observed:
            results.append(
                ControlResult(
                    control_id="required_policy_evaluated",
                    case_id=run.case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.POLICY_FAILED,
                    severity=Severity.error,
                    target=policy_id,
                    message=(
                        f"required policy {policy_id!r} was not evaluated "
                        f"for case {run.case_id!r}"
                    ),
                )
            )
            continue
        for policy_result in observed:
            if policy_result.state is GateState.pass_:
                continue
            if _is_fixture_remediation_signal(run, policy_result):
                continue
            results.append(
                ControlResult(
                    control_id=f"required_policy:{policy_id}",
                    case_id=run.case_id,
                    state=policy_result.state,
                    reason_code=_policy_reason_code(policy_result),
                    severity=_policy_severity(policy_result),
                    target=policy_id,
                    message=policy_result.message
                    or f"required policy {policy_id!r} was {policy_result.state.value}",
                )
            )
    return tuple(results)


def _evaluate_required_policy_results(
    runs_by_case: dict[str, AgentRunRecord],
    expected_case_ids: tuple[str, ...],
    required_policy_ids: tuple[str, ...],
) -> tuple[ControlResult, ...]:
    results: list[ControlResult] = []
    if not required_policy_ids:
        return ()

    for case_id in expected_case_ids:
        run = runs_by_case.get(case_id)
        if run is None or run.observation_status == "excluded":
            continue
        results.extend(evaluate_required_policy_results_for_run(run, required_policy_ids))
    return tuple(results)


def _is_fixture_remediation_signal(
    run: AgentRunRecord,
    policy_result: PolicyResult,
) -> bool:
    return (
        run.execution_mode is not ExecutionMode.live
        and ReasonCode.FORBIDDEN_PROVIDER in policy_result.reason_codes
    )


def _runset_status_results(runset: RunSet) -> tuple[ControlResult, ...]:
    if runset.completion_status == "complete":
        return ()
    stop_reasons = ", ".join(runset.stop_reasons) or "unknown"
    return (
        ControlResult(
            control_id="runset_completion_required",
            case_id="*",
            state=GateState.fail,
            reason_code=ReasonCode.RUNTIME_FAILED,
            severity=Severity.blocker,
            target="completion_status",
            message=(
                "ordinary evaluation requires a complete run set; "
                f"stop reasons: {stop_reasons}"
            ),
        ),
    )


def _policy_reason_code(policy_result: PolicyResult) -> ReasonCode:
    reason_codes = policy_result.reason_codes
    if reason_codes:
        return reason_codes[0]
    if policy_result.state is GateState.not_evaluated:
        return ReasonCode.NOT_EVALUATED
    return ReasonCode.POLICY_FAILED


def _policy_severity(policy_result: PolicyResult) -> Severity:
    severity = policy_result.severity
    if policy_result.state is GateState.fail and severity not in {Severity.error, Severity.blocker}:
        return Severity.error
    if policy_result.state is GateState.warn and severity is Severity.info:
        return Severity.warning
    return severity


def _runs_by_case(
    runset: RunSet,
    expected_case_ids: tuple[str, ...],
) -> tuple[dict[str, AgentRunRecord], tuple[ControlResult, ...]]:
    expected = set(expected_case_ids)
    counts = Counter(run.case_id for run in runset.runs)
    runs_by_case: dict[str, AgentRunRecord] = {}
    results: list[ControlResult] = []
    for run in runset.runs:
        if run.case_id in expected and run.case_id not in runs_by_case:
            runs_by_case[run.case_id] = run
    for case_id in expected_case_ids:
        if counts[case_id] == 0:
            results.append(
                ControlResult(
                    control_id="valid_record_required",
                    case_id=case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target="missing",
                    message="compiled suite case has no run record",
                )
            )
        elif counts[case_id] > 1:
            results.append(
                ControlResult(
                    control_id="valid_record_required",
                    case_id=case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target="duplicate-suite-case",
                    message="compiled suite case has multiple run records",
                )
            )
    for case_id in sorted(counts):
        if case_id not in expected:
            results.append(
                ControlResult(
                    control_id="valid_record_required",
                    case_id=case_id,
                    state=GateState.fail,
                    reason_code=ReasonCode.VALID_RECORD_MISSING,
                    severity=Severity.blocker,
                    target="unknown-case",
                    message=f"run set contains case {case_id!r} not present in the suite",
                )
            )
    return runs_by_case, tuple(results)


def _evaluate_expected_recommendation(
    run: AgentRunRecord,
    expected_recommendation: str | None,
) -> tuple[ControlResult, ...]:
    if expected_recommendation is None or run.recommendation == expected_recommendation:
        return ()
    return (
        ControlResult(
            control_id="expected_recommendation",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.EXPECTED_OUTCOME_MISMATCH,
            severity=Severity.error,
            target="recommendation",
            message=(
                f"expected recommendation {expected_recommendation!r}, "
                f"observed {run.recommendation!r}"
            ),
        ),
    )


def _evaluate_allowed_outcomes(
    run: AgentRunRecord,
    allowed_outcomes: tuple[str, ...],
) -> tuple[ControlResult, ...]:
    if not allowed_outcomes or run.outcome in allowed_outcomes:
        return ()
    return (
        ControlResult(
            control_id="allowed_outcomes",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.EXPECTED_OUTCOME_MISMATCH,
            severity=Severity.error,
            target=f"outcome:{run.outcome}",
            message=f"outcome {run.outcome!r} is outside allowed outcomes {allowed_outcomes!r}",
        ),
    )


def _evaluate_forbidden_outcomes(
    run: AgentRunRecord,
    forbidden_outcomes: tuple[str, ...],
) -> tuple[ControlResult, ...]:
    if run.outcome not in forbidden_outcomes:
        return ()
    return (
        ControlResult(
            control_id="forbidden_outcomes",
            case_id=run.case_id,
            state=GateState.fail,
            reason_code=ReasonCode.FORBIDDEN_OUTCOME,
            severity=Severity.error,
            target=f"outcome:{run.outcome}",
            message=f"outcome {run.outcome!r} is explicitly forbidden for this case",
        ),
    )
