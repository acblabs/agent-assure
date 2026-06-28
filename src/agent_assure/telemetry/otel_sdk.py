from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure import __version__
from agent_assure.schema.base import StrictModel
from agent_assure.schema.telemetry import SpanPlan
from agent_assure.telemetry.context import trace_context_carrier


class OpenTelemetryUnavailable(RuntimeError):
    pass


class OTelHeader(StrictModel):
    name: str = Field(min_length=1)
    value: str = Field(min_length=1)


class OTelExportConfig(StrictModel):
    protocol: Literal["otlp-http", "console"] = "otlp-http"
    endpoint: str | None = None
    service_name: str = Field(default="agent-assure", min_length=1)
    timeout_seconds: int = Field(default=10, ge=1)
    headers: tuple[OTelHeader, ...] = ()

    @field_validator("headers", mode="before")
    @classmethod
    def _coerce_headers(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value


@dataclass(frozen=True)
class OTelExportResult:
    span_count: int
    protocol: str
    endpoint: str | None


@dataclass(frozen=True)
class _OtelSdk:
    propagate: Any
    tracer_provider: Any
    span_processor: Any
    console_exporter: Any
    otlp_exporter: Any | None
    resource: Any


def emit_span_plans(
    plans: tuple[SpanPlan, ...],
    config: OTelExportConfig,
) -> OTelExportResult:
    sdk = _load_otel_sdk(require_otlp=config.protocol == "otlp-http")
    resource = sdk.resource.create({"service.name": config.service_name})
    provider = sdk.tracer_provider(resource=resource)
    exporter = _build_exporter(sdk, config)
    provider.add_span_processor(sdk.span_processor(exporter))
    tracer = provider.get_tracer("agent_assure", __version__)
    for plan in plans:
        carrier = trace_context_carrier(plan.traceparent, plan.tracestate)
        parent_context = sdk.propagate.extract(carrier) if carrier else None
        with tracer.start_as_current_span(
            plan.span_name,
            context=parent_context,
            attributes=_attributes(plan),
        ) as span:
            for event in plan.events:
                span.add_event(event.name, attributes=_event_attributes(event))
    provider.force_flush()
    provider.shutdown()
    return OTelExportResult(
        span_count=len(plans),
        protocol=config.protocol,
        endpoint=config.endpoint,
    )


def _build_exporter(sdk: _OtelSdk, config: OTelExportConfig) -> Any:
    if config.protocol == "console":
        return sdk.console_exporter()
    if sdk.otlp_exporter is None:
        raise OpenTelemetryUnavailable(
            "OTLP export requires opentelemetry-exporter-otlp-proto-http"
        )
    kwargs: dict[str, Any] = {
        "timeout": config.timeout_seconds,
    }
    if config.endpoint is not None:
        kwargs["endpoint"] = config.endpoint
    if config.headers:
        kwargs["headers"] = {header.name: header.value for header in config.headers}
    return sdk.otlp_exporter(**kwargs)


def _attributes(plan: SpanPlan) -> dict[str, str | int | bool]:
    return {attribute.key: attribute.value for attribute in plan.attributes}


def _event_attributes(event: Any) -> dict[str, str | int | bool]:
    return {attribute.key: attribute.value for attribute in event.attributes}


def _load_otel_sdk(*, require_otlp: bool) -> _OtelSdk:
    try:
        from opentelemetry import propagate
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SimpleSpanProcessor
    except ImportError as exc:
        raise OpenTelemetryUnavailable(
            "OpenTelemetry SDK support requires installing agent-assure[otel]"
        ) from exc
    otlp_exporter: Any | None = None
    if require_otlp:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError as exc:
            raise OpenTelemetryUnavailable(
                "OTLP export requires installing agent-assure[otel]"
            ) from exc
        otlp_exporter = OTLPSpanExporter
    return _OtelSdk(
        propagate=propagate,
        tracer_provider=TracerProvider,
        span_processor=SimpleSpanProcessor,
        console_exporter=ConsoleSpanExporter,
        otlp_exporter=otlp_exporter,
        resource=Resource,
    )
