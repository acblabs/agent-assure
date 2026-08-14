from __future__ import annotations

import random
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from pathlib import Path
from uuid import uuid5

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.io_limits import MAX_PROMPT_BYTES, read_text_bounded_at
from agent_assure.live.adapters import (
    LiveProviderAdapter,
    LiveProviderRequest,
    LiveProviderResponse,
    TrustedLiveExecution,
    build_adapter,
    monotonic_ms,
)
from agent_assure.live.config import (
    MAX_LIVE_REQUESTS,
    MAX_LIVE_RETRY_BACKOFF_SECONDS,
    LivePromptCase,
    LiveRunConfig,
)
from agent_assure.live.output_contract import (
    LiveOutputContractError,
    parse_live_structured_content,
)
from agent_assure.live.paths import resolve_live_config_path
from agent_assure.privacy.detectors import PRIVACY_PROFILE_DIGEST, PRIVACY_PROFILE_ID
from agent_assure.privacy.redaction import redact_text
from agent_assure.privacy.safe_errors import safe_error
from agent_assure.runner.ids import AGENT_ASSURE_NAMESPACE
from agent_assure.runner.subprocess_harness import emergency_from_exception
from agent_assure.schema.common import ExecutionMode, GateState, ReasonCode, Severity
from agent_assure.schema.live import LiveProtocolRecord
from agent_assure.schema.provenance import Provenance
from agent_assure.schema.run import AgentRunRecord, PolicyResult, RunSet
from agent_assure.schema.runtime import EmergencyProcessRecord
from agent_assure.schema.suite import CompiledSuite
from agent_assure.telemetry.context import RuntimeTraceContext, trace_context_for_seed


class LiveBudgetExceededError(ValueError):
    def __init__(self, stop_reason: str, message: str) -> None:
        super().__init__(message)
        self.stop_reason = stop_reason


@dataclass
class _LiveRequestBudget:
    maximum: int
    used: int = 0

    @property
    def exhausted(self) -> bool:
        return self.used >= self.maximum

    def consume(self) -> None:
        if self.exhausted:
            raise LiveBudgetExceededError(
                "request_budget_exhausted",
                "configured max_requests was exhausted before another adapter attempt",
            )
        self.used += 1


@dataclass
class _LiveRateLimitBudget:
    maximum: int
    observed: int = 0

    def record(self) -> None:
        self.observed += 1
        if self.observed > self.maximum:
            raise LiveBudgetExceededError(
                "rate_limit_budget_exhausted",
                "provider rate-limit events exceeded the configured run-wide maximum",
            )


@dataclass
class _LiveAttemptState:
    attempt_count: int = 0
    retry_count: int = 0
    rate_limit_events: int = 0


def run_live_suite(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    protocol: LiveProtocolRecord,
    config_dir: Path,
    trust: TrustedLiveExecution | None = None,
) -> RunSet:
    # Pydantic's model_copy(update=...) intentionally skips validation. Treat
    # this library API as the final execution boundary and reconstruct both
    # caller-provided contracts before using any budget or adapter fields.
    config = LiveRunConfig.model_validate(config.model_dump(mode="json"))
    protocol = LiveProtocolRecord.model_validate(protocol.model_dump(mode="json"))
    _validate_cases(compiled, config)
    _validate_protocol_config(compiled, config, protocol)
    planned_observations = _planned_observation_count(config)
    if planned_observations > MAX_LIVE_REQUESTS:
        raise ValueError(
            f"planned live observations ({planned_observations}) exceed the hard limit "
            f"({MAX_LIVE_REQUESTS})"
        )
    if config.max_requests is None:
        raise ValueError("live execution requires an explicit max_requests attempt budget")
    if planned_observations > config.max_requests:
        raise ValueError(
            f"planned live observations ({planned_observations}) exceed max_requests "
            f"({config.max_requests})"
        )
    prompts = {
        prompt_case.case_id: _read_prompt(config_dir, prompt_case.prompt_path)
        for prompt_case in config.cases
    }
    prompt_digests = {
        case_id: sha256_hexdigest({"prompt": prompt}) for case_id, prompt in prompts.items()
    }
    schedule = _schedule(config)
    request_budget = _LiveRequestBudget(config.max_requests)
    rate_limit_budget = _LiveRateLimitBudget(config.max_rate_limit_events)
    adapter = build_adapter(
        config.adapter,
        base_dir=config_dir,
        trust=trust,
    )
    configuration_digest = _configuration_digest(compiled, config, prompt_digests)
    protocol_digest = sha256_hexdigest(protocol)
    committed_cost = Decimal("0")
    committed_total_tokens = 0
    committed_generated_tokens = 0
    cost_budget = Decimal(config.max_total_cost_usd) if config.max_total_cost_usd else None
    max_observation_cost = Decimal(config.max_cost_per_observation_usd)
    attempt_cost_reservation = (
        max_observation_cost if config.adapter.allow_network else Decimal("0")
    )
    last_request_started: float | None = None
    token_window_started: float | None = None
    tokens_window_reserved = 0
    stop_reasons: set[str] = set()
    terminal_stop_reason: str | None = None
    runs: list[AgentRunRecord] = []
    emergency_records: list[EmergencyProcessRecord] = []
    for schedule_index, prompt_case, repetition_index in schedule:
        prompt = prompts[prompt_case.case_id]
        prompt_digest = prompt_digests[prompt_case.case_id]
        run_id = _run_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
        observation_id = _observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
        trace_context = trace_context_for_seed(observation_id)
        if terminal_stop_reason is not None:
            accounting_unavailable = terminal_stop_reason in {
                "cost_accounting_unavailable",
                "token_accounting_unavailable",
            }
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_budget_accounting_unavailable"
                    if accounting_unavailable
                    else "live_execution_stopped",
                    "budget accounting became unavailable after an earlier response"
                    if accounting_unavailable
                    else "live execution stopped after an earlier terminal policy event",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason=(
                        "budget_accounting_unavailable"
                        if accounting_unavailable
                        else "terminal_policy_stop"
                    ),
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if request_budget.exhausted:
            stop_reasons.add("request_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_request_budget_exhausted",
                    "configured max_requests attempt budget was exhausted",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                    reason_code=ReasonCode.POLICY_FAILED,
                )
            )
            continue
        if cost_budget is not None and committed_cost + max_observation_cost > cost_budget:
            stop_reasons.add("budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_budget_exhausted",
                    "configured live cost budget would be exceeded before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                )
            )
            continue
        if (
            config.max_total_tokens is not None
            and committed_total_tokens >= config.max_total_tokens
        ):
            stop_reasons.add("token_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_token_budget_exhausted",
                    "configured live token budget was exhausted before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="token_budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                )
            )
            continue
        if (
            config.max_generated_tokens is not None
            and config.adapter.max_output_tokens is not None
            and committed_generated_tokens + config.adapter.max_output_tokens
            > config.max_generated_tokens
        ):
            stop_reasons.add("generated_token_budget_exhausted")
            runs.append(
                _error_record(
                    compiled,
                    config,
                    prompt_case,
                    repetition_index,
                    schedule_index,
                    configuration_digest,
                    "live_generated_token_budget_exhausted",
                    "configured generated-token budget would be exceeded before this observation",
                    cluster_by=protocol.cluster_by,
                    exclusion_reason="generated_token_budget_exhausted",
                    prompt_digest=prompt_digest,
                    trace_context=trace_context,
                )
            )
            continue
        request = LiveProviderRequest(
            run_id=run_id,
            observation_id=observation_id,
            case_id=prompt_case.case_id,
            repetition_index=repetition_index,
            prompt=prompt,
            provider=config.adapter.provider,
            model=config.adapter.model,
            traceparent=trace_context.traceparent,
            tracestate=trace_context.tracestate,
        )
        token_reservation = _token_reservation(prompt, config)
        generated_token_reservation = (
            (config.adapter.max_output_tokens or 0) if config.adapter.allow_network else 0
        )
        total_token_reservation = (
            _prompt_token_upper_bound(prompt) + generated_token_reservation
            if config.adapter.allow_network
            else 0
        )
        observation_committed_cost = Decimal("0")
        observation_committed_generated_tokens = 0
        observation_committed_total_tokens = 0

        def pace_attempt(
            reserved_tokens: int = token_reservation,
            generated_reservation: int = generated_token_reservation,
            total_reservation: int = total_token_reservation,
        ) -> None:
            nonlocal committed_cost, committed_generated_tokens, committed_total_tokens
            nonlocal last_request_started, observation_committed_cost
            nonlocal observation_committed_generated_tokens
            nonlocal observation_committed_total_tokens
            nonlocal token_window_started, tokens_window_reserved
            if cost_budget is not None and committed_cost + attempt_cost_reservation > cost_budget:
                raise LiveBudgetExceededError(
                    "cost_budget_exhausted_before_attempt",
                    "configured live cost budget cannot reserve another adapter attempt",
                )
            if (
                config.max_generated_tokens is not None
                and committed_generated_tokens + generated_reservation > config.max_generated_tokens
            ):
                raise LiveBudgetExceededError(
                    "generated_token_budget_exhausted_before_attempt",
                    "configured generated-token budget cannot reserve another adapter attempt",
                )
            if (
                config.max_total_tokens is not None
                and committed_total_tokens + total_reservation > config.max_total_tokens
            ):
                raise LiveBudgetExceededError(
                    "token_budget_exhausted_before_attempt",
                    "configured total-token budget cannot reserve another adapter attempt",
                )
            token_window_started, tokens_window_reserved = _pace_request(
                config,
                last_request_started,
                token_window_started,
                tokens_window_reserved,
                reserved_tokens,
            )
            # A failed or timed-out network request may still be billable. Reserve
            # the declared per-observation ceiling for every dispatched attempt;
            # ambiguous failed-attempt reservations are never released.
            committed_cost += attempt_cost_reservation
            observation_committed_cost += attempt_cost_reservation
            committed_generated_tokens += generated_reservation
            observation_committed_generated_tokens += generated_reservation
            committed_total_tokens += total_reservation
            observation_committed_total_tokens += total_reservation
            last_request_started = time.perf_counter()

        started = _utc_now()
        start = time.perf_counter()
        response: LiveProviderResponse | None = None
        attempt_state = _LiveAttemptState()
        try:
            response = _complete_with_retries(
                adapter,
                request,
                config,
                request_budget=request_budget,
                rate_limit_budget=rate_limit_budget,
                attempt_state=attempt_state,
                before_attempt=pace_attempt,
            )
            latency_ms = monotonic_ms(start)
            completed = _utc_now()
            response_total_tokens = _response_total_tokens(response)
            response_cost = Decimal(response.estimated_cost_usd)
            if not (
                config.adapter.allow_network and response.estimated_cost_source == "not_reported"
            ):
                committed_cost += response_cost - attempt_cost_reservation
                observation_committed_cost += response_cost - attempt_cost_reservation
            if response.completion_tokens is not None:
                committed_generated_tokens += (
                    response.completion_tokens - generated_token_reservation
                )
                observation_committed_generated_tokens += (
                    response.completion_tokens - generated_token_reservation
                )
            if response_total_tokens is not None:
                committed_total_tokens += response_total_tokens - total_token_reservation
                observation_committed_total_tokens += (
                    response_total_tokens - total_token_reservation
                )
            if observation_committed_total_tokens < observation_committed_generated_tokens:
                commitment_gap = (
                    observation_committed_generated_tokens - observation_committed_total_tokens
                )
                committed_total_tokens += commitment_gap
                observation_committed_total_tokens += commitment_gap
            if response_total_tokens is not None and response_total_tokens > token_reservation:
                tokens_window_reserved += response_total_tokens - token_reservation
            _verify_response_budgets(response, config)
            if cost_budget is not None and committed_cost > cost_budget:
                raise LiveBudgetExceededError(
                    "cost_budget_exceeded_after_response",
                    "configured total live cost budget was exceeded after response",
                )
            if (
                config.max_generated_tokens is not None
                and committed_generated_tokens > config.max_generated_tokens
            ):
                raise LiveBudgetExceededError(
                    "generated_token_budget_exceeded_after_response",
                    "configured generated-token budget was exceeded after response",
                )
            if (
                config.max_total_tokens is not None
                and committed_total_tokens > config.max_total_tokens
            ):
                raise LiveBudgetExceededError(
                    "token_budget_exceeded_after_response",
                    "configured total-token budget was exceeded after response",
                )
            record = _record_from_response(
                compiled,
                config,
                prompt_case,
                repetition_index,
                schedule_index,
                configuration_digest,
                response,
                prompt_digest=prompt_digest,
                cost_budget_committed_usd=observation_committed_cost,
                generated_token_budget_committed=(observation_committed_generated_tokens),
                total_token_budget_committed=observation_committed_total_tokens,
                cluster_by=protocol.cluster_by,
                attempt_count=attempt_state.attempt_count,
                retry_count=attempt_state.retry_count,
                rate_limit_events=attempt_state.rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
            )
        except Exception as exc:
            emergency = emergency_from_exception(exc)
            if emergency is not None:
                emergency_records.append(emergency)
            if isinstance(exc, LiveBudgetExceededError):
                stop_reasons.add(exc.stop_reason)
                if exc.stop_reason in {
                    "cost_accounting_unavailable",
                    "token_accounting_unavailable",
                    "cost_budget_exhausted_before_attempt",
                    "cost_budget_exceeded_after_response",
                    "generated_token_budget_exhausted_before_attempt",
                    "generated_token_budget_exceeded_after_response",
                    "rate_limit_budget_exhausted",
                    "token_budget_exhausted_before_attempt",
                    "token_budget_exceeded_after_response",
                }:
                    terminal_stop_reason = exc.stop_reason
            reason_code = (
                ReasonCode.STRUCTURED_OUTPUT_INVALID
                if isinstance(exc, LiveOutputContractError)
                else ReasonCode.POLICY_FAILED
                if isinstance(exc, LiveBudgetExceededError)
                else ReasonCode.RUNTIME_FAILED
            )
            category = (
                "live_structured_output_invalid"
                if isinstance(exc, LiveOutputContractError)
                else "live_budget_accounting_unavailable"
                if isinstance(exc, LiveBudgetExceededError)
                and exc.stop_reason
                in {"cost_accounting_unavailable", "token_accounting_unavailable"}
                else "live_budget_exceeded_after_response"
                if isinstance(exc, LiveBudgetExceededError)
                else "live_adapter_error"
            )
            latency_ms = monotonic_ms(start)
            completed = _utc_now()
            record = _error_record(
                compiled,
                config,
                prompt_case,
                repetition_index,
                schedule_index,
                configuration_digest,
                category,
                str(exc),
                cluster_by=protocol.cluster_by,
                prompt_digest=prompt_digest,
                attempt_count=attempt_state.attempt_count or None,
                retry_count=attempt_state.retry_count,
                rate_limit_events=attempt_state.rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
                response=response,
                cost_budget_committed_usd=observation_committed_cost,
                generated_token_budget_committed=(observation_committed_generated_tokens),
                total_token_budget_committed=observation_committed_total_tokens,
                reason_code=reason_code,
                exc=exc,
            )
        runs.append(record)
    return RunSet(
        artifact_kind="run-set",
        runset_id=_runset_id(compiled.suite_id, config.variant_id, configuration_digest),
        privacy_profile_id=PRIVACY_PROFILE_ID,
        privacy_profile_digest=PRIVACY_PROFILE_DIGEST,
        suite_id=compiled.suite_id,
        suite_version=compiled.suite_version,
        suite_digest=sha256_hexdigest(compiled.model_dump(mode="json")),
        fixture_manifest_digest=configuration_digest,
        execution_mode=ExecutionMode.live,
        protocol_id=protocol.protocol_id,
        protocol_digest=protocol_digest,
        completion_status="incomplete" if stop_reasons else "complete",
        stop_reasons=tuple(sorted(stop_reasons)),
        emergency_records=tuple(emergency_records),
        runs=tuple(runs),
    )


def _record_from_response(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    prompt_case: LivePromptCase,
    repetition_index: int,
    schedule_index: int,
    configuration_digest: str,
    response: LiveProviderResponse,
    prompt_digest: str,
    *,
    cost_budget_committed_usd: Decimal,
    generated_token_budget_committed: int,
    total_token_budget_committed: int,
    cluster_by: str,
    attempt_count: int,
    retry_count: int,
    rate_limit_events: int,
    started_at_utc: str,
    completed_at_utc: str,
    latency_ms: int,
    trace_context: RuntimeTraceContext,
) -> AgentRunRecord:
    payload = parse_live_structured_content(response.content)
    total_tokens = _response_total_tokens(response)
    observation_id = _observation_id(
        compiled.suite_id,
        config.variant_id,
        prompt_case.case_id,
        repetition_index,
    )
    return AgentRunRecord.model_validate(
        {
            "artifact_kind": "agent-run-record",
            "run_id": _run_id(
                compiled.suite_id,
                config.variant_id,
                prompt_case.case_id,
                repetition_index,
            ),
            "case_id": prompt_case.case_id,
            "execution_mode": ExecutionMode.live.value,
            "pipeline_id": config.pipeline_id,
            "recommendation": payload.recommendation,
            "outcome": payload.outcome,
            "input_summary": redact_text(prompt_case.input_summary),
            "output_summary": redact_text(payload.output_summary),
            "observation_status": response.observation_status,
            "observation_id": observation_id,
            "repetition_index": repetition_index,
            "schedule_index": schedule_index,
            "randomization_block_id": f"repetition:{repetition_index}",
            "cluster_id": _cluster_id(prompt_case, cluster_by),
            "source_group_id": prompt_case.source_group_id,
            "adapter_id": config.adapter.adapter_id,
            "provider": response.provider,
            "model": response.model,
            "resolved_model": response.resolved_model,
            "provider_api_version": response.provider_api_version,
            "provider_sdk": response.provider_sdk,
            "provider_region": response.provider_region,
            "provider_response_id": response.provider_response_id,
            "traceparent": trace_context.traceparent,
            "tracestate": trace_context.tracestate,
            "started_at_utc": started_at_utc,
            "completed_at_utc": completed_at_utc,
            "latency_ms": latency_ms,
            "attempt_count": attempt_count,
            "retry_count": retry_count,
            "rate_limit_events": rate_limit_events,
            "exclusion_reason": response.exclusion_reason,
            "prompt_tokens": response.prompt_tokens,
            "completion_tokens": response.completion_tokens,
            "total_tokens": total_tokens,
            "estimated_cost_usd": response.estimated_cost_usd,
            "estimated_cost_source": response.estimated_cost_source,
            "cost_budget_committed_usd": _cost_string(cost_budget_committed_usd),
            "generated_token_budget_committed": generated_token_budget_committed,
            "total_token_budget_committed": total_token_budget_committed,
            "tools": payload.tools,
            "evidence_refs": payload.evidence_refs,
            "evidence_items": payload.evidence_items,
            "claims": payload.claims,
            "claim_evidence_links": payload.claim_evidence_links,
            "policy_results": payload.policy_results,
            "human_review_required": payload.human_review_required,
            "human_review_performed": payload.human_review_performed,
            "provenance": _provenance(
                config,
                configuration_digest,
                prompt_digest=prompt_digest,
                model_identifier=response.model,
            ).model_dump(mode="json"),
        }
    )


def _error_record(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    prompt_case: LivePromptCase,
    repetition_index: int,
    schedule_index: int,
    configuration_digest: str,
    category: str,
    message: str,
    *,
    cluster_by: str,
    exclusion_reason: str | None = None,
    prompt_digest: str | None = None,
    attempt_count: int | None = None,
    retry_count: int | None = None,
    rate_limit_events: int | None = None,
    started_at_utc: str | None = None,
    completed_at_utc: str | None = None,
    latency_ms: int | None = None,
    trace_context: RuntimeTraceContext | None = None,
    response: LiveProviderResponse | None = None,
    cost_budget_committed_usd: Decimal = Decimal("0"),
    generated_token_budget_committed: int = 0,
    total_token_budget_committed: int = 0,
    reason_code: ReasonCode = ReasonCode.RUNTIME_FAILED,
    exc: Exception | None = None,
) -> AgentRunRecord:
    safe = safe_error(category, message, exc)
    trace_context = trace_context or trace_context_for_seed(
        _observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        )
    )
    return AgentRunRecord(
        artifact_kind="agent-run-record",
        run_id=_run_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        ),
        case_id=prompt_case.case_id,
        execution_mode=ExecutionMode.live,
        pipeline_id=config.pipeline_id,
        recommendation="error",
        outcome="excluded" if exclusion_reason else "runtime_error",
        input_summary=redact_text(prompt_case.input_summary),
        output_summary=(
            f"live observation failed; code={safe.code}; debug_ref={safe.local_debug_reference}"
        ),
        observation_status="excluded" if exclusion_reason else "included",
        observation_id=_observation_id(
            compiled.suite_id,
            config.variant_id,
            prompt_case.case_id,
            repetition_index,
        ),
        repetition_index=repetition_index,
        schedule_index=schedule_index,
        randomization_block_id=f"repetition:{repetition_index}",
        cluster_id=_cluster_id(prompt_case, cluster_by),
        source_group_id=prompt_case.source_group_id,
        adapter_id=config.adapter.adapter_id,
        provider=response.provider if response else config.adapter.provider,
        model=response.model if response else config.adapter.model,
        resolved_model=(
            response.resolved_model
            if response and response.resolved_model
            else config.adapter.model
        ),
        provider_api_version=(
            response.provider_api_version if response else config.adapter.api_version
        ),
        provider_sdk=response.provider_sdk if response else _sdk_label(config),
        provider_region=response.provider_region if response else config.adapter.region,
        provider_response_id=response.provider_response_id if response else None,
        traceparent=trace_context.traceparent,
        tracestate=trace_context.tracestate,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
        latency_ms=latency_ms,
        attempt_count=attempt_count,
        retry_count=retry_count,
        rate_limit_events=rate_limit_events,
        exclusion_reason=exclusion_reason,
        prompt_tokens=response.prompt_tokens if response else None,
        completion_tokens=response.completion_tokens if response else None,
        total_tokens=_response_total_tokens(response) if response else None,
        estimated_cost_usd=response.estimated_cost_usd if response else "0.000000",
        estimated_cost_source=response.estimated_cost_source if response else "not_reported",
        cost_budget_committed_usd=_cost_string(cost_budget_committed_usd),
        generated_token_budget_committed=generated_token_budget_committed,
        total_token_budget_committed=total_token_budget_committed,
        policy_results=(
            PolicyResult(
                artifact_kind="policy-result",
                policy_id="runtime.live",
                state=GateState.fail,
                reason_codes=(reason_code,),
                severity=Severity.blocker,
                message=(
                    "live response failed the structured output contract"
                    if reason_code is ReasonCode.STRUCTURED_OUTPUT_INVALID
                    else "live response exceeded the configured budget policy"
                    if reason_code is ReasonCode.POLICY_FAILED
                    else "live adapter failed before a valid structured record was accepted"
                ),
            ),
        ),
        provenance=_provenance(
            config,
            configuration_digest,
            prompt_digest=prompt_digest or sha256_hexdigest(_prompt_digest_input(prompt_case)),
            model_identifier=response.model if response else config.adapter.model,
        ),
    )


def _response_total_tokens(response: LiveProviderResponse) -> int | None:
    if response.total_tokens is not None:
        return response.total_tokens
    if response.prompt_tokens is None or response.completion_tokens is None:
        return None
    return response.prompt_tokens + response.completion_tokens


def _cost_string(value: Decimal) -> str:
    return f"{value:.6f}"


def _validate_cases(compiled: CompiledSuite, config: LiveRunConfig) -> None:
    suite_case_ids = {case.case_id for case in compiled.cases}
    config_case_ids = [case.case_id for case in config.cases]
    unknown = sorted(set(config_case_ids) - suite_case_ids)
    if unknown:
        raise ValueError("live config references cases not in suite: " + ", ".join(unknown))
    duplicates = sorted(
        {case_id for case_id in config_case_ids if config_case_ids.count(case_id) > 1}
    )
    if duplicates:
        raise ValueError("live config contains duplicate case_id values: " + ", ".join(duplicates))


def _validate_protocol_config(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    protocol: LiveProtocolRecord,
) -> None:
    suite_digest = sha256_hexdigest(compiled.model_dump(mode="json"))
    protocol_digest = sha256_hexdigest(protocol)
    if protocol.suite_id != compiled.suite_id:
        raise ValueError("live protocol suite_id does not match compiled suite")
    if protocol.suite_version != compiled.suite_version:
        raise ValueError("live protocol suite_version does not match compiled suite")
    if protocol.suite_digest != suite_digest:
        raise ValueError("live protocol suite_digest does not match compiled suite")
    if config.protocol_id != protocol.protocol_id:
        raise ValueError("live run config protocol_id does not match protocol")
    if config.protocol_digest != protocol_digest:
        raise ValueError("live run config protocol_digest does not match protocol")
    if config.tool_schema_digest != protocol.tool_schema_digest:
        raise ValueError("live run config tool_schema_digest does not match protocol")
    if config.policy_bundle_digest != protocol.policy_bundle_digest:
        raise ValueError("live run config policy_bundle_digest does not match protocol")
    planned_requests = len(config.cases) * config.repetitions
    if config.repetitions != protocol.planned_repetitions:
        raise ValueError("live run config repetitions do not match protocol")
    if planned_requests != protocol.planned_observations:
        raise ValueError("live run config planned observations do not match protocol")
    if config.max_requests != protocol.max_requests:
        raise ValueError("live run config max_requests does not match protocol")
    if config.randomization_seed != protocol.randomization_seed:
        raise ValueError("live run config randomization_seed does not match protocol")
    if protocol.cluster_by == "source_group_id" and any(
        prompt_case.source_group_id is None for prompt_case in config.cases
    ):
        raise ValueError("source_group_id clustering requires source_group_id on every case")
    planned_clusters = {
        _cluster_id(prompt_case, protocol.cluster_by) for prompt_case in config.cases
    }
    if len(planned_clusters) != protocol.planned_clusters:
        raise ValueError("live run config cluster count does not match protocol")
    if config.max_total_cost_usd != protocol.max_total_cost_usd:
        raise ValueError("live run config max_total_cost_usd does not match protocol")
    if config.max_cost_per_observation_usd != protocol.max_cost_per_observation_usd:
        raise ValueError("live run config max_cost_per_observation_usd does not match protocol")
    if config.max_generated_tokens != protocol.max_generated_tokens:
        raise ValueError("live run config max_generated_tokens does not match protocol")
    if config.max_total_tokens != protocol.max_total_tokens:
        raise ValueError("live run config max_total_tokens does not match protocol")
    if config.max_retries != protocol.max_retries:
        raise ValueError("live run config max_retries does not match protocol")
    if config.retry_initial_backoff_seconds != protocol.retry_initial_backoff_seconds:
        raise ValueError("live run config retry_initial_backoff_seconds does not match protocol")
    if config.retry_max_backoff_seconds != protocol.retry_max_backoff_seconds:
        raise ValueError("live run config retry_max_backoff_seconds does not match protocol")
    if config.requests_per_minute != protocol.requests_per_minute:
        raise ValueError("live run config requests_per_minute does not match protocol")
    if config.tokens_per_minute != protocol.tokens_per_minute:
        raise ValueError("live run config tokens_per_minute does not match protocol")
    if config.max_rate_limit_events != protocol.max_rate_limit_events:
        raise ValueError("live run config max_rate_limit_events does not match protocol")
    if protocol.tokens_per_minute is not None and config.adapter.max_output_tokens is None:
        raise ValueError("tokens_per_minute requires adapter max_output_tokens")
    if protocol.max_generated_tokens is not None and config.adapter.max_output_tokens is None:
        raise ValueError("max_generated_tokens requires adapter max_output_tokens")
    if config.adapter.adapter_id == "openai-chat-completions" and (
        config.adapter.cost_per_1k_prompt_tokens_usd is None
        or config.adapter.cost_per_1k_completion_tokens_usd is None
    ):
        raise ValueError(
            "openai-chat-completions requires prompt and completion pricing rates "
            "to enforce the declared cost ceilings"
        )
    if config.adapter.allow_network and config.adapter.max_output_tokens is None:
        raise ValueError(
            "network live execution requires adapter max_output_tokens so the "
            "per-attempt cost ceiling is bounded"
        )
    if config.adapter.allow_network and Decimal(config.max_cost_per_observation_usd) <= Decimal(
        "0"
    ):
        raise ValueError("network live execution requires a positive max_cost_per_observation_usd")
    if (
        protocol.max_generated_tokens is not None
        and config.adapter.max_output_tokens is not None
        and config.adapter.max_output_tokens > protocol.max_generated_tokens
    ):
        raise ValueError("adapter max_output_tokens exceeds protocol max_generated_tokens")


def _planned_observation_count(config: LiveRunConfig) -> int:
    return len(config.cases) * config.repetitions


def _schedule(config: LiveRunConfig) -> Iterator[tuple[int, LivePromptCase, int]]:
    rng = random.Random(config.randomization_seed)
    schedule_index = 0
    for repetition_index in range(config.repetitions):
        block = list(config.cases)
        rng.shuffle(block)
        for prompt_case in block:
            yield schedule_index, prompt_case, repetition_index
            schedule_index += 1


def _complete_with_retries(
    adapter: LiveProviderAdapter,
    request: LiveProviderRequest,
    config: LiveRunConfig,
    *,
    request_budget: _LiveRequestBudget,
    rate_limit_budget: _LiveRateLimitBudget,
    attempt_state: _LiveAttemptState,
    before_attempt: Callable[[], None],
) -> LiveProviderResponse:
    max_attempts = config.max_retries + 1
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        before_attempt()
        request_budget.consume()
        attempt_state.attempt_count += 1
        try:
            response = adapter.complete(request)
            if not isinstance(response, LiveProviderResponse):
                raise TypeError("live adapter returned an invalid response object")
            return LiveProviderResponse.model_validate(response.model_dump(mode="python"))
        except Exception as exc:
            last_exc = exc
            if _is_rate_limit_error(exc):
                attempt_state.rate_limit_events += 1
                rate_limit_budget.record()
            if not _is_retryable_error(exc):
                raise
            if attempt >= max_attempts:
                break
            if request_budget.exhausted:
                raise LiveBudgetExceededError(
                    "request_budget_exhausted",
                    "configured max_requests was exhausted before a retry",
                ) from exc
            attempt_state.retry_count += 1
            _sleep_before_retry(
                config,
                attempt_state.retry_count,
                _retry_after_seconds(exc),
            )
    if last_exc is None:
        raise RuntimeError("live adapter failed without an exception")
    raise last_exc


def _sleep_before_retry(
    config: LiveRunConfig,
    retry_count: int,
    retry_after_seconds: Decimal | None,
) -> None:
    initial = Decimal(config.retry_initial_backoff_seconds)
    maximum = Decimal(config.retry_max_backoff_seconds)
    if maximum > MAX_LIVE_RETRY_BACKOFF_SECONDS:
        raise RuntimeError("configured retry backoff exceeds the hard safety limit")
    if retry_after_seconds is not None:
        if retry_after_seconds < 0:
            raise RuntimeError("provider Retry-After must not be negative")
        if retry_after_seconds > maximum:
            raise RuntimeError("provider Retry-After exceeds configured retry_max_backoff_seconds")
        seconds = retry_after_seconds
    else:
        seconds = min(maximum, initial * (Decimal(2) ** max(retry_count - 1, 0)))
    if seconds > 0:
        time.sleep(float(seconds))


def _retry_after_seconds(exc: Exception) -> Decimal | None:
    value = getattr(exc, "retry_after_seconds", None)
    if value is None:
        headers = getattr(exc, "headers", None)
        if headers is None:
            return None
        raw = headers.get("Retry-After")
        if raw is None:
            return None
        value = raw
    text = str(value)
    if len(text) > 32:
        raise RuntimeError("provider Retry-After value exceeds the supported length")
    try:
        return Decimal(text)
    except (InvalidOperation, ValueError) as parse_error:
        raise RuntimeError("provider Retry-After value is not a decimal delay") from parse_error


def _pace_request(
    config: LiveRunConfig,
    last_request_started: float | None,
    token_window_started: float | None,
    tokens_window_reserved: int,
    reserved_tokens: int,
) -> tuple[float | None, int]:
    if config.requests_per_minute is not None and last_request_started is not None:
        min_interval = 60.0 / config.requests_per_minute
        elapsed = time.perf_counter() - last_request_started
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
    if config.tokens_per_minute is None:
        return token_window_started, tokens_window_reserved
    if reserved_tokens > config.tokens_per_minute:
        raise ValueError("single live request token reservation exceeds tokens_per_minute")
    now = time.perf_counter()
    if token_window_started is None or now - token_window_started >= 60.0:
        token_window_started = now
        tokens_window_reserved = 0
    if tokens_window_reserved + reserved_tokens > config.tokens_per_minute:
        time.sleep(max(0.0, 60.0 - (now - token_window_started)))
        token_window_started = time.perf_counter()
        tokens_window_reserved = 0
    return token_window_started, tokens_window_reserved + reserved_tokens


def _token_reservation(prompt: str, config: LiveRunConfig) -> int:
    if config.tokens_per_minute is None:
        return 0
    output_tokens = config.adapter.max_output_tokens
    if output_tokens is None:
        raise ValueError("tokens_per_minute requires adapter max_output_tokens")
    return _prompt_token_upper_bound(prompt) + output_tokens


def _prompt_token_upper_bound(prompt: str) -> int:
    # Byte-fallback tokenizers cannot emit more ordinary-text tokens than the
    # UTF-8 byte length. Bytes are conservative where Unicode character count is not.
    return len(prompt.encode("utf-8"))


def _verify_response_budgets(response: LiveProviderResponse, config: LiveRunConfig) -> None:
    if config.adapter.allow_network and response.estimated_cost_source == "not_reported":
        raise LiveBudgetExceededError(
            "cost_accounting_unavailable",
            "provider response omitted usage required to enforce cost ceilings",
        )
    response_total_tokens = _response_total_tokens(response)
    if config.max_total_tokens is not None and response_total_tokens is None:
        raise LiveBudgetExceededError(
            "token_accounting_unavailable",
            "provider response omitted usage required to enforce max_total_tokens",
        )
    if config.max_generated_tokens is not None and response.completion_tokens is None:
        raise LiveBudgetExceededError(
            "token_accounting_unavailable",
            "provider response omitted usage required to enforce max_generated_tokens",
        )
    if Decimal(response.estimated_cost_usd) > Decimal(config.max_cost_per_observation_usd):
        raise LiveBudgetExceededError(
            "cost_budget_exceeded_after_response",
            "provider response exceeded max_cost_per_observation_usd",
        )
    if (
        config.max_total_tokens is not None
        and response_total_tokens is not None
        and response_total_tokens > config.max_total_tokens
    ):
        raise LiveBudgetExceededError(
            "token_budget_exceeded_after_response",
            "provider response exceeded max_total_tokens",
        )
    if (
        config.max_generated_tokens is not None
        and response.completion_tokens is not None
        and response.completion_tokens > config.max_generated_tokens
    ):
        raise LiveBudgetExceededError(
            "generated_token_budget_exceeded_after_response",
            "provider response exceeded max_generated_tokens",
        )


def _is_rate_limit_error(exc: Exception) -> bool:
    if getattr(exc, "status_code", None) == 429:
        return True
    if getattr(exc, "retry_after_seconds", None) is not None:
        return True
    text = str(exc).lower()
    return "429" in text or "retry-after" in text


def _is_retryable_error(exc: Exception) -> bool:
    status_code = getattr(exc, "status_code", None)
    if type(status_code) is int:
        return status_code in {408, 429} or 500 <= status_code <= 599
    if getattr(exc, "retryable", False) is True:
        return True
    if getattr(exc, "retry_after_seconds", None) is not None:
        return True
    return isinstance(exc, (TimeoutError, ConnectionError))


def _read_prompt(config_dir: Path, prompt_path: str) -> str:
    resolve_live_config_path(config_dir, prompt_path, field_name="prompt_path")
    text = read_text_bounded_at(
        config_dir,
        prompt_path,
        max_bytes=MAX_PROMPT_BYTES,
        label="live prompt",
    )
    if not text.strip():
        raise ValueError(f"prompt file is empty: {prompt_path}")
    return text


def _provenance(
    config: LiveRunConfig,
    configuration_digest: str,
    *,
    prompt_digest: str,
    model_identifier: str | None,
) -> Provenance:
    return Provenance(
        artifact_kind="provenance",
        prompt_digest=prompt_digest,
        configuration_digest=configuration_digest,
        policy_bundle_digest=config.policy_bundle_digest,
        tool_schema_digest=config.tool_schema_digest,
        model_identifier=model_identifier,
    )


def _configuration_digest(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    prompt_digests: dict[str, str],
) -> str:
    return sha256_hexdigest(
        {
            "suite_digest": sha256_hexdigest(compiled.model_dump(mode="json")),
            "live_run_config": config.model_dump(mode="json"),
            "prompt_digests": prompt_digests,
        }
    )


def _prompt_digest_input(prompt_case: LivePromptCase) -> dict[str, str]:
    return {
        "case_id": prompt_case.case_id,
        "prompt_path": prompt_case.prompt_path,
        "input_summary": redact_text(prompt_case.input_summary),
    }


def _cluster_id(prompt_case: LivePromptCase, cluster_by: str) -> str:
    if cluster_by == "source_group_id":
        if prompt_case.source_group_id is None:
            raise ValueError("source_group_id clustering requires source_group_id")
        return prompt_case.source_group_id
    return prompt_case.case_id


def _runset_id(suite_id: str, variant_id: str, configuration_digest: str) -> str:
    key = f"live:{suite_id}:{variant_id}:{configuration_digest}"
    return f"runset-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _run_id(suite_id: str, variant_id: str, case_id: str, repetition_index: int) -> str:
    key = f"live:{suite_id}:{variant_id}:{case_id}:{repetition_index}"
    return f"run-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _observation_id(suite_id: str, variant_id: str, case_id: str, repetition_index: int) -> str:
    key = f"live-observation:{suite_id}:{variant_id}:{case_id}:{repetition_index}"
    return f"obs-{uuid5(AGENT_ASSURE_NAMESPACE, key)}"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _sdk_label(config: LiveRunConfig) -> str | None:
    if config.adapter.sdk_name is None and config.adapter.sdk_version is None:
        return None
    if config.adapter.sdk_name is None:
        return config.adapter.sdk_version
    if config.adapter.sdk_version is None:
        return config.adapter.sdk_name
    return f"{config.adapter.sdk_name}@{config.adapter.sdk_version}"
