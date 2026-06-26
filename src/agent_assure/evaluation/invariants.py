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
from agent_assure.schema.common import GateState, ReasonCode, Severity
from agent_assure.schema.run import AgentRunRecord, RunSet


def evaluate_runset_controls(
    resolver: ExpectationResolver,
    runset: RunSet,
    *,
    allowed_tools: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    runs_by_case, coverage_results = _runs_by_case(runset, resolver.case_ids)
    results = list(coverage_results)
    for case_expectation in resolver.cases():
        run = runs_by_case.get(case_expectation.case.case_id)
        if run is None:
            continue
        results.extend(evaluate_case(case_expectation, run, allowed_tools=allowed_tools))
    return tuple(results)


def evaluate_case(
    case_expectation: CaseExpectation,
    run: AgentRunRecord,
    *,
    allowed_tools: tuple[str, ...] = (),
) -> tuple[ControlResult, ...]:
    expectation = case_expectation.expectation
    results: list[ControlResult] = []
    results.extend(_evaluate_expected_recommendation(run, expectation.expected_recommendation))
    results.extend(_evaluate_allowed_outcomes(run, expectation.allowed_outcomes))
    results.extend(_evaluate_forbidden_outcomes(run, expectation.forbidden_outcomes))
    results.extend(runtime.evaluate_runtime_success(run))
    results.extend(output_schema.evaluate_structured_output(run))
    results.extend(evidence.evaluate_required_evidence(run, expectation))
    results.extend(evidence.evaluate_material_claim_evidence(run, expectation))
    results.extend(tools.evaluate_tool_allowlist(run, allowed_tools=allowed_tools))
    results.extend(human_review.evaluate_human_review_requirement(run, expectation))
    results.extend(providers.evaluate_provider_boundary(run, case_expectation.case, expectation))
    results.extend(injection.evaluate_prompt_boundary(run, case_expectation.case, expectation))
    results.extend(privacy.evaluate_redaction(run))
    return tuple(results)


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
