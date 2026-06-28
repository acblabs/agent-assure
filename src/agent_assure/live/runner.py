from __future__ import annotations

import random
import time
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from uuid import uuid5

from agent_assure.canonical.digests import sha256_hexdigest
from agent_assure.live.adapters import (
    LiveProviderAdapter,
    LiveProviderRequest,
    LiveProviderResponse,
    build_adapter,
    monotonic_ms,
)
from agent_assure.live.config import LivePromptCase, LiveRunConfig
from agent_assure.live.output_contract import (
    LiveOutputContractError,
    parse_live_structured_content,
)
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


def run_live_suite(
    compiled: CompiledSuite,
    config: LiveRunConfig,
    *,
    protocol: LiveProtocolRecord,
    config_dir: Path,
) -> RunSet:
    _validate_cases(compiled, config)
    _validate_protocol_config(compiled, config, protocol)
    schedule = _schedule(config)
    if config.max_requests is not None and len(schedule) > config.max_requests:
        raise ValueError(
            f"planned live requests ({len(schedule)}) exceed max_requests ({config.max_requests})"
        )
    adapter = build_adapter(config.adapter, base_dir=config_dir)
    configuration_digest = _configuration_digest(compiled, config)
    protocol_digest = sha256_hexdigest(protocol)
    spent = Decimal("0")
    total_tokens_spent = 0
    generated_tokens_spent = 0
    cost_budget = Decimal(config.max_total_cost_usd) if config.max_total_cost_usd else None
    max_observation_cost = Decimal(config.max_cost_per_observation_usd)
    last_request_started: float | None = None
    token_window_started: float | None = None
    tokens_window_reserved = 0
    stop_reasons: set[str] = set()
    runs: list[AgentRunRecord] = []
    emergency_records: list[EmergencyProcessRecord] = []
    for schedule_index, prompt_case, repetition_index in schedule:
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
        if cost_budget is not None and spent + max_observation_cost > cost_budget:
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
                    trace_context=trace_context,
                )
            )
            continue
        if config.max_total_tokens is not None and total_tokens_spent >= config.max_total_tokens:
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
                    trace_context=trace_context,
                )
            )
            continue
        if (
            config.max_generated_tokens is not None
            and config.adapter.max_output_tokens is not None
            and generated_tokens_spent + config.adapter.max_output_tokens
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
                    trace_context=trace_context,
                )
            )
            continue
        prompt = _read_prompt(config_dir, prompt_case.prompt_path)
        prompt_digest = sha256_hexdigest({"prompt": prompt})
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
        token_window_started, tokens_window_reserved = _pace_request(
            config,
            last_request_started,
            token_window_started,
            tokens_window_reserved,
            token_reservation,
        )
        last_request_started = time.perf_counter()
        started = _utc_now()
        start = time.perf_counter()
        response: LiveProviderResponse | None = None
        attempt_count = 0
        retry_count = 0
        rate_limit_events = 0
        try:
            response, attempt_count, retry_count, rate_limit_events = _complete_with_retries(
                adapter,
                request,
                config,
            )
            latency_ms = monotonic_ms(start)
            completed = _utc_now()
            _verify_response_budgets(response, config)
            record = _record_from_response(
                compiled,
                config,
                prompt_case,
                repetition_index,
                schedule_index,
                configuration_digest,
                response,
                prompt_digest=prompt_digest,
                cluster_by=protocol.cluster_by,
                attempt_count=attempt_count,
                retry_count=retry_count,
                rate_limit_events=rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
            )
            spent += Decimal(record.estimated_cost_usd or "0.000000")
            total_tokens_spent += record.total_tokens or 0
            generated_tokens_spent += record.completion_tokens or 0
            if record.total_tokens is not None and record.total_tokens > token_reservation:
                tokens_window_reserved += record.total_tokens - token_reservation
            if (
                config.max_generated_tokens is not None
                and generated_tokens_spent > config.max_generated_tokens
            ):
                raise ValueError("configured generated-token budget was exceeded")
        except Exception as exc:
            emergency = emergency_from_exception(exc)
            if emergency is not None:
                emergency_records.append(emergency)
            if isinstance(exc, LiveBudgetExceededError):
                stop_reasons.add(exc.stop_reason)
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
                attempt_count=max(attempt_count, 1),
                retry_count=retry_count,
                rate_limit_events=rate_limit_events,
                started_at_utc=started,
                completed_at_utc=completed,
                latency_ms=latency_ms,
                trace_context=trace_context,
                reason_code=reason_code,
                exc=exc,
            )
        runs.append(record)
    return RunSet(
        artifact_kind="run-set",
        runset_id=_runset_id(compiled.suite_id, config.variant_id, configuration_digest),
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
    total_tokens = response.total_tokens
    if total_tokens is None and (
        response.prompt_tokens is not None or response.completion_tokens is not None
    ):
        total_tokens = (response.prompt_tokens or 0) + (response.completion_tokens or 0)
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
            f"live observation failed; code={safe.code}; "
            f"debug_ref={safe.local_debug_reference}"
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
        provider=config.adapter.provider,
        model=config.adapter.model,
        resolved_model=config.adapter.model,
        provider_api_version=config.adapter.api_version,
        provider_sdk=_sdk_label(config),
        provider_region=config.adapter.region,
        traceparent=trace_context.traceparent,
        tracestate=trace_context.tracestate,
        started_at_utc=started_at_utc,
        completed_at_utc=completed_at_utc,
        latency_ms=latency_ms,
        attempt_count=attempt_count,
        retry_count=retry_count,
        rate_limit_events=rate_limit_events,
        exclusion_reason=exclusion_reason,
        estimated_cost_usd="0.000000",
        estimated_cost_source="not_reported",
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
            model_identifier=config.adapter.model,
        ),
    )


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
    if (
        protocol.max_generated_tokens is not None
        and config.adapter.max_output_tokens is not None
        and config.adapter.max_output_tokens > protocol.max_generated_tokens
    ):
        raise ValueError("adapter max_output_tokens exceeds protocol max_generated_tokens")


def _schedule(config: LiveRunConfig) -> list[tuple[int, LivePromptCase, int]]:
    rng = random.Random(config.randomization_seed)
    schedule: list[tuple[int, LivePromptCase, int]] = []
    schedule_index = 0
    for repetition_index in range(config.repetitions):
        block = list(config.cases)
        rng.shuffle(block)
        for prompt_case in block:
            schedule.append((schedule_index, prompt_case, repetition_index))
            schedule_index += 1
    return schedule


def _complete_with_retries(
    adapter: LiveProviderAdapter,
    request: LiveProviderRequest,
    config: LiveRunConfig,
) -> tuple[LiveProviderResponse, int, int, int]:
    retry_count = 0
    rate_limit_events = 0
    max_attempts = config.max_retries + 1
    last_exc: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            response = adapter.complete(request)
            if not isinstance(response, LiveProviderResponse):
                raise TypeError("live adapter returned an invalid response object")
            return response, attempt, retry_count, rate_limit_events
        except Exception as exc:
            last_exc = exc
            if _is_rate_limit_error(exc):
                rate_limit_events += 1
                if rate_limit_events > config.max_rate_limit_events:
                    break
            if attempt >= max_attempts:
                break
            retry_count += 1
            _sleep_before_retry(config, retry_count, _retry_after_seconds(exc))
    assert last_exc is not None
    raise last_exc


def _sleep_before_retry(
    config: LiveRunConfig,
    retry_count: int,
    retry_after_seconds: Decimal | None,
) -> None:
    initial = Decimal(config.retry_initial_backoff_seconds)
    maximum = Decimal(config.retry_max_backoff_seconds)
    if retry_after_seconds is not None:
        if retry_after_seconds > maximum:
            raise RuntimeError("provider Retry-After exceeds configured retry_max_backoff_seconds")
        seconds = retry_after_seconds
    else:
        seconds = min(maximum, initial * (Decimal(2) ** max(retry_count - 1, 0)))
    if seconds > 0:
        time.sleep(float(seconds))


def _retry_after_seconds(exc: Exception) -> Decimal | None:
    value = getattr(exc, "retry_after_seconds", None)
    if value is not None:
        return Decimal(str(value))
    headers = getattr(exc, "headers", None)
    if headers is not None:
        raw = headers.get("Retry-After")
        if raw is not None:
            try:
                return Decimal(str(raw))
            except Exception:
                return None
    return None


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
    # Prompt characters deliberately overestimate prompt tokens for conservative TPM pacing.
    return len(prompt) + output_tokens


def _verify_response_budgets(response: LiveProviderResponse, config: LiveRunConfig) -> None:
    if Decimal(response.estimated_cost_usd) > Decimal(config.max_cost_per_observation_usd):
        raise LiveBudgetExceededError(
            "cost_budget_exceeded_after_response",
            "provider response exceeded max_cost_per_observation_usd",
        )
    if (
        config.max_total_tokens is not None
        and response.total_tokens is not None
        and response.total_tokens > config.max_total_tokens
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


def _read_prompt(config_dir: Path, prompt_path: str) -> str:
    path = Path(prompt_path)
    if not path.is_absolute():
        path = config_dir / path
    text = path.read_text(encoding="utf-8")
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


def _configuration_digest(compiled: CompiledSuite, config: LiveRunConfig) -> str:
    return sha256_hexdigest(
        {
            "suite_digest": sha256_hexdigest(compiled.model_dump(mode="json")),
            "live_run_config": config.model_dump(mode="json"),
        }
    )


def _prompt_digest_input(prompt_case: LivePromptCase) -> dict[str, str]:
    return {
        "case_id": prompt_case.case_id,
        "prompt_path": prompt_case.prompt_path,
        "input_summary": prompt_case.input_summary,
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
