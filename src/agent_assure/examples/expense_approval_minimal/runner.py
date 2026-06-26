from __future__ import annotations

from agent_assure.canonical.hmac_tokens import hmac_sha256_token
from agent_assure.runner.evidence import evidence_from_tool_output
from agent_assure.runner.fixture_runner import LoadedFixtures, RunnerContext, VariantConfig
from agent_assure.runner.fixture_values import optional_string, required_string, string_sequence
from agent_assure.runner.governance_controls import apply_provider_policy
from agent_assure.runner.records import build_fixture_run_record
from agent_assure.schema.run import AgentRunRecord
from agent_assure.schema.suite import SuiteCase


def run_expense_case(
    case: SuiteCase,
    fixtures: LoadedFixtures,
    variant: VariantConfig,
    context: RunnerContext,
) -> AgentRunRecord:
    if variant.behavior.runtime_error_case == case.case_id:
        raise RuntimeError("fixture-declared runtime failure")

    provider = optional_string(fixtures.model_output.get("provider"))
    model = optional_string(fixtures.model_output.get("model"))
    recommendation = required_string(fixtures.model_output, "recommendation")
    outcome = required_string(fixtures.model_output, "outcome")
    human_review_required = bool(fixtures.model_output.get("human_review_required", False))
    human_review_performed = bool(fixtures.model_output.get("human_review_performed", False))

    provider_application = apply_provider_policy(
        provider,
        recommendation=recommendation,
        outcome=outcome,
        human_review_required=human_review_required,
        forbidden_providers=variant.provider_policy.forbidden_providers,
        runtime_allowed_providers=variant.provider_policy.runtime_allowed_providers,
        precedence=variant.behavior.provider_policy_precedence,
        fail_recommendation="manual_review",
        fail_outcome="manual_review",
    )
    recommendation = provider_application.recommendation
    outcome = provider_application.outcome
    human_review_required = provider_application.human_review_required

    return build_fixture_run_record(
        case=case,
        variant=variant,
        context=context,
        recommendation=recommendation,
        outcome=outcome,
        input_summary=_input_summary(case, fixtures, context),
        provider=provider,
        model=model,
        tools=tuple(sorted(string_sequence(fixtures.tool_output.get("tools", ())))),
        evidence=evidence_from_tool_output(fixtures.tool_output),
        policy_events=provider_application.events,
        human_review_required=human_review_required,
        human_review_performed=human_review_performed,
    )


def _input_summary(case: SuiteCase, fixtures: LoadedFixtures, context: RunnerContext) -> str:
    employee_id = fixtures.request.get("employee_id")
    employee_token = hmac_sha256_token(str(employee_id or case.case_id), key=context.hmac_key)[:16]
    return f"case={case.case_id}; employee_token={employee_token}; fixture={fixtures.fixture_id}"
