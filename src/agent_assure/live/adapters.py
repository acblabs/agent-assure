from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Protocol, cast

from pydantic import Field

from agent_assure.canonical.normalize import normalize_decimal
from agent_assure.live.config import LiveAdapterConfig
from agent_assure.live.output_contract import validate_live_structured_content
from agent_assure.live.paths import resolve_live_config_path
from agent_assure.runner.subprocess_harness import (
    ExternalScriptError,
    ExternalScriptInvocation,
    invalid_output_emergency,
    run_external_script,
)
from agent_assure.schema.base import SCHEMA_VERSION, StrictModel

EstimatedCostSource = Literal[
    "adapter_reported",
    "local_estimate",
    "not_reported",
    "provider_reported",
]

DEFAULT_OPENAI_ENDPOINT_HOSTS = ("api.openai.com",)


class LiveProviderRequest(StrictModel):
    run_id: str = Field(min_length=1)
    observation_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    prompt: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    traceparent: str | None = None
    tracestate: str | None = None


class LiveProviderResponse(StrictModel):
    content: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    resolved_model: str | None = None
    provider_api_version: str | None = None
    provider_sdk: str | None = None
    provider_region: str | None = None
    provider_response_id: str | None = None
    observation_status: str = Field(default="included", pattern=r"^(included|excluded)$")
    exclusion_reason: str | None = None
    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    estimated_cost_usd: str = Field(default="0.000000", pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    estimated_cost_source: EstimatedCostSource = "adapter_reported"


class LiveProviderAdapter(Protocol):
    adapter_id: str

    def complete(self, request: LiveProviderRequest) -> LiveProviderResponse:
        """Return a provider response without persisting raw prompt or output."""


class LiveProviderRequestError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        retry_after_seconds: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.retry_after_seconds = retry_after_seconds


class StaticJsonlAdapter:
    adapter_id = "static-jsonl"

    def __init__(self, config: LiveAdapterConfig, *, base_dir: Path) -> None:
        if config.response_jsonl_path is None:
            raise ValueError("static-jsonl adapter requires response_jsonl_path")
        self._config = config
        path = resolve_live_config_path(
            base_dir,
            config.response_jsonl_path,
            field_name="response_jsonl_path",
        )
        self._responses = _load_jsonl_responses(path)

    def complete(self, request: LiveProviderRequest) -> LiveProviderResponse:
        payload = self._responses.get((request.case_id, request.repetition_index))
        if payload is None:
            payload = self._responses.get((request.case_id, None))
        if payload is None:
            raise KeyError(
                f"no static live response for case_id={request.case_id!r}, "
                f"repetition_index={request.repetition_index}"
            )
        content = payload.get("content")
        if content is None and isinstance(payload.get("record"), dict):
            content = json.dumps(payload["record"], sort_keys=True)
        if content is None and payload.get("observation_status") == "excluded":
            content = json.dumps(
                {
                    "recommendation": "excluded",
                    "outcome": "excluded",
                    "output_summary": "observation excluded before provider interpretation",
                },
                sort_keys=True,
            )
        if not isinstance(content, str):
            raise ValueError("static live response must contain content or record")
        return LiveProviderResponse(
            content=content,
            provider=_string(payload.get("provider"), self._config.provider),
            model=_string(payload.get("model"), self._config.model),
            resolved_model=_optional_string(payload.get("resolved_model")),
            provider_api_version=_optional_string(
                payload.get("provider_api_version"),
                self._config.api_version,
            ),
            provider_sdk=_optional_string(
                payload.get("provider_sdk"),
                _sdk_label(self._config),
            ),
            provider_region=_optional_string(payload.get("provider_region"), self._config.region),
            provider_response_id=_optional_string(payload.get("provider_response_id")),
            observation_status=_string(payload.get("observation_status"), "included"),
            exclusion_reason=_optional_string(payload.get("exclusion_reason")),
            prompt_tokens=_optional_int(payload.get("prompt_tokens")),
            completion_tokens=_optional_int(payload.get("completion_tokens")),
            total_tokens=_optional_int(payload.get("total_tokens")),
            estimated_cost_usd=_normal_cost(payload.get("estimated_cost_usd", "0.000000")),
            estimated_cost_source=_cost_source(payload.get("estimated_cost_source")),
        )


class OpenAIChatCompletionsAdapter:
    adapter_id = "openai-chat-completions"

    def __init__(self, config: LiveAdapterConfig, *, base_dir: Path) -> None:
        del base_dir
        if not config.allow_network:
            raise ValueError("openai-chat-completions requires allow_network: true")
        if not config.endpoint_url:
            raise ValueError("openai-chat-completions requires endpoint_url")
        if not config.api_key_env:
            raise ValueError("openai-chat-completions requires api_key_env")
        _validate_openai_endpoint(config)
        api_key = os.environ.get(config.api_key_env)
        if not api_key:
            raise ValueError(f"environment variable {config.api_key_env!r} is not set")
        self._config = config
        self._api_key = api_key

    def complete(self, request: LiveProviderRequest) -> LiveProviderResponse:
        body: dict[str, Any] = {
            "model": self._config.model,
            "messages": [{"role": "user", "content": request.prompt}],
            "temperature": float(Decimal(self._config.temperature)),
        }
        if self._config.max_output_tokens is not None:
            body["max_tokens"] = self._config.max_output_tokens
        headers = {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }
        if request.traceparent is not None:
            headers["traceparent"] = request.traceparent
        if request.tracestate:
            headers["tracestate"] = request.tracestate
        http_request = urllib.request.Request(
            self._config.endpoint_url or "",
            data=json.dumps(body).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - explicit live adapter opt-in.
                http_request,
                timeout=self._config.timeout_seconds,
            ) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            retry_after = exc.headers.get("Retry-After") if exc.headers is not None else None
            raise LiveProviderRequestError(
                f"provider request failed: HTTP {exc.code}",
                status_code=exc.code,
                retry_after_seconds=retry_after,
            ) from exc
        except urllib.error.URLError as exc:
            raise LiveProviderRequestError(
                f"provider request failed: {exc.__class__.__name__}"
            ) from exc
        return _openai_response(payload, self._config)


class ExternalScriptAdapter:
    adapter_id = "external-script"

    def __init__(self, config: LiveAdapterConfig, *, base_dir: Path) -> None:
        if config.script_path is None:
            raise ValueError("external-script adapter requires script_path")
        self._config = config
        self._script = resolve_live_config_path(
            base_dir,
            config.script_path,
            field_name="script_path",
        )
        if not self._script.exists():
            raise ValueError(f"external script does not exist: {config.script_path}")
        self._cwd = (
            resolve_live_config_path(
                base_dir,
                config.script_cwd,
                field_name="script_cwd",
            )
            if config.script_cwd is not None
            else self._script.parent
        )
        if not self._cwd.exists() or not self._cwd.is_dir():
            raise ValueError(f"external script cwd is not a directory: {self._cwd}")
        self._argv = _script_argv(config, self._script)
        self._environment = tuple((item.name, item.value) for item in config.script_env)
        self._environment_allowlist = tuple(config.script_env_allowlist)

    def complete(self, request: LiveProviderRequest) -> LiveProviderResponse:
        payload: dict[str, object] = {
            "artifact_kind": "external-script-request",
            "schema_version": SCHEMA_VERSION,
            "run_id": request.run_id,
            "observation_id": request.observation_id,
            "case_id": request.case_id,
            "repetition_index": request.repetition_index,
            "prompt": request.prompt,
            "provider": request.provider,
            "model": request.model,
            "trace_context": {
                "traceparent": request.traceparent,
                "tracestate": request.tracestate,
            },
        }
        invocation = ExternalScriptInvocation(
            argv=self._argv,
            cwd=self._cwd,
            timeout_seconds=self._config.timeout_seconds,
            request_payload=payload,
            observation_id=request.observation_id,
            run_id=request.run_id,
            case_id=request.case_id,
            adapter_id=self.adapter_id,
            environment=self._environment,
            environment_allowlist=self._environment_allowlist,
            traceparent=request.traceparent,
            tracestate=request.tracestate,
        )
        completed = run_external_script(invocation)
        try:
            loaded = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            emergency = invalid_output_emergency(
                invocation,
                completed,
                "external script stdout was not valid JSON",
                exc,
            )
            raise ExternalScriptError(
                "external script stdout was not valid JSON",
                emergency,
            ) from exc
        if not isinstance(loaded, dict):
            emergency = invalid_output_emergency(
                invocation,
                completed,
                "external script stdout JSON root was not an object",
            )
            raise ExternalScriptError("external script stdout JSON root was invalid", emergency)
        try:
            return _script_response(loaded, self._config)
        except (TypeError, ValueError) as exc:
            emergency = invalid_output_emergency(
                invocation,
                completed,
                "external script stdout did not match the live provider response contract",
                exc,
            )
            raise ExternalScriptError(
                "external script stdout did not match the live provider response contract",
                emergency,
            ) from exc


def build_adapter(config: LiveAdapterConfig, *, base_dir: Path) -> LiveProviderAdapter:
    if config.adapter_id == StaticJsonlAdapter.adapter_id:
        return StaticJsonlAdapter(config, base_dir=base_dir)
    if config.adapter_id == OpenAIChatCompletionsAdapter.adapter_id:
        return OpenAIChatCompletionsAdapter(config, base_dir=base_dir)
    if config.adapter_id == ExternalScriptAdapter.adapter_id:
        return ExternalScriptAdapter(config, base_dir=base_dir)
    known = ", ".join(adapter_ids())
    raise KeyError(f"unknown live adapter {config.adapter_id!r}; expected one of: {known}")


def adapter_ids() -> tuple[str, ...]:
    return (
        StaticJsonlAdapter.adapter_id,
        OpenAIChatCompletionsAdapter.adapter_id,
        ExternalScriptAdapter.adapter_id,
    )


def _openai_response(payload: dict[str, Any], config: LiveAdapterConfig) -> LiveProviderResponse:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("provider response did not contain choices")
    first = choices[0]
    if not isinstance(first, dict):
        raise ValueError("provider choice was not an object")
    message = first.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise ValueError("provider choice did not contain message.content")
    usage = payload.get("usage")
    prompt_tokens = _optional_int(usage.get("prompt_tokens")) if isinstance(usage, dict) else None
    completion_tokens = (
        _optional_int(usage.get("completion_tokens")) if isinstance(usage, dict) else None
    )
    total_tokens = _optional_int(usage.get("total_tokens")) if isinstance(usage, dict) else None
    return LiveProviderResponse(
        content=message["content"],
        provider=config.provider,
        model=_string(payload.get("model"), config.model),
        resolved_model=_optional_string(payload.get("model"), config.model),
        provider_api_version=config.api_version,
        provider_sdk=_sdk_label(config),
        provider_region=config.region,
        provider_response_id=_optional_string(payload.get("id")),
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        total_tokens=total_tokens,
        estimated_cost_usd=_estimate_cost(config, prompt_tokens, completion_tokens),
        estimated_cost_source=_openai_cost_source(config),
    )


def _estimate_cost(
    config: LiveAdapterConfig,
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> str:
    prompt_rate = _optional_decimal(config.cost_per_1k_prompt_tokens_usd)
    completion_rate = _optional_decimal(config.cost_per_1k_completion_tokens_usd)
    if prompt_rate is None and completion_rate is None:
        return "0.000000"
    prompt_cost = Decimal(prompt_tokens or 0) * (prompt_rate or Decimal("0")) / Decimal("1000")
    completion_cost = (
        Decimal(completion_tokens or 0) * (completion_rate or Decimal("0")) / Decimal("1000")
    )
    return normalize_decimal(prompt_cost + completion_cost)


def _load_jsonl_responses(path: Path) -> dict[tuple[str, int | None], dict[str, Any]]:
    responses: dict[tuple[str, int | None], dict[str, Any]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError(f"{path}:{line_number}: static response must be an object")
        case_id = payload.get("case_id")
        if not isinstance(case_id, str):
            raise ValueError(f"{path}:{line_number}: case_id must be a string")
        repetition = payload.get("repetition_index")
        if repetition is not None and not isinstance(repetition, int):
            raise ValueError(f"{path}:{line_number}: repetition_index must be an integer")
        responses[(case_id, repetition)] = payload
    return responses


def _script_response(payload: dict[str, Any], config: LiveAdapterConfig) -> LiveProviderResponse:
    content = payload.get("content")
    if content is None and isinstance(payload.get("record"), dict):
        content = json.dumps(payload["record"], sort_keys=True)
    if not isinstance(content, str):
        raise ValueError("external script response must contain content or record")
    validate_live_structured_content(content)
    return LiveProviderResponse(
        content=content,
        provider=_string(payload.get("provider"), config.provider),
        model=_string(payload.get("model"), config.model),
        resolved_model=_optional_string(payload.get("resolved_model"), config.model),
        provider_api_version=_optional_string(
            payload.get("provider_api_version"),
            config.api_version,
        ),
        provider_sdk=_optional_string(payload.get("provider_sdk"), _sdk_label(config)),
        provider_region=_optional_string(payload.get("provider_region"), config.region),
        provider_response_id=_optional_string(payload.get("provider_response_id")),
        observation_status=_string(payload.get("observation_status"), "included"),
        exclusion_reason=_optional_string(payload.get("exclusion_reason")),
        prompt_tokens=_optional_int(payload.get("prompt_tokens")),
        completion_tokens=_optional_int(payload.get("completion_tokens")),
        total_tokens=_optional_int(payload.get("total_tokens")),
        estimated_cost_usd=_normal_cost(payload.get("estimated_cost_usd", "0.000000")),
        estimated_cost_source=_cost_source(payload.get("estimated_cost_source")),
    )


def _script_argv(config: LiveAdapterConfig, script: Path) -> tuple[str, ...]:
    args = tuple(config.script_args)
    if config.script_executable is not None:
        return (config.script_executable, str(script), *args)
    if script.suffix.lower() == ".py":
        return (sys.executable, str(script), *args)
    return (str(script), *args)


def _validate_openai_endpoint(config: LiveAdapterConfig) -> None:
    endpoint = config.endpoint_url or ""
    parsed = urllib.parse.urlparse(endpoint)
    if parsed.scheme.lower() != "https":
        raise ValueError("openai-chat-completions endpoint_url must use https")
    if not parsed.hostname:
        raise ValueError("openai-chat-completions endpoint_url must include a host")
    host = parsed.hostname.lower()
    allowed_hosts = {
        host_name.lower()
        for host_name in (*DEFAULT_OPENAI_ENDPOINT_HOSTS, *config.allowed_endpoint_hosts)
    }
    if host not in allowed_hosts:
        raise ValueError(
            "openai-chat-completions endpoint host must be in allowed_endpoint_hosts"
        )


def _string(value: object, default: str) -> str:
    return value if isinstance(value, str) else default


def _optional_string(value: object, default: str | None = None) -> str | None:
    return value if isinstance(value, str) else default


def _optional_int(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _optional_decimal(value: str | None) -> Decimal | None:
    if value is None:
        return None
    return Decimal(value)


def _normal_cost(value: object) -> str:
    if isinstance(value, int | str):
        return normalize_decimal(Decimal(str(value)))
    return "0.000000"


def _cost_source(value: object) -> EstimatedCostSource:
    if value in {"adapter_reported", "local_estimate", "not_reported", "provider_reported"}:
        return cast(EstimatedCostSource, value)
    return "adapter_reported"


def _openai_cost_source(config: LiveAdapterConfig) -> EstimatedCostSource:
    if (
        config.cost_per_1k_prompt_tokens_usd is None
        and config.cost_per_1k_completion_tokens_usd is None
    ):
        return "not_reported"
    return "local_estimate"


def monotonic_ms(start: float) -> int:
    return max(0, int(round((time.perf_counter() - start) * 1000)))


def _sdk_label(config: LiveAdapterConfig) -> str | None:
    if config.sdk_name is None and config.sdk_version is None:
        return None
    if config.sdk_name is None:
        return config.sdk_version
    if config.sdk_version is None:
        return config.sdk_name
    return f"{config.sdk_name}@{config.sdk_version}"
