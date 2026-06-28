from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from agent_assure.schema.telemetry import SpanAttribute, SpanEvent, SpanPlan
from agent_assure.telemetry import otel_sdk
from agent_assure.telemetry.otel_sdk import OTelExportConfig, emit_span_plans


def test_emit_span_plans_uses_sdk_span_with_extracted_context(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    observed: dict[str, Any] = {}

    class FakeSpan:
        def __enter__(self) -> FakeSpan:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def add_event(self, name: str, *, attributes: dict[str, object]) -> None:
            observed["event"] = (name, attributes)

    class FakeTracer:
        def start_as_current_span(
            self,
            name: str,
            *,
            context: object,
            attributes: dict[str, object],
        ) -> FakeSpan:
            observed["span"] = (name, context, attributes)
            return FakeSpan()

    class FakeProvider:
        def __init__(self, *, resource: object) -> None:
            observed["resource"] = resource

        def add_span_processor(self, processor: object) -> None:
            observed["processor"] = processor

        def get_tracer(self, name: str, version: str) -> FakeTracer:
            observed["tracer"] = (name, version)
            return FakeTracer()

        def force_flush(self) -> None:
            observed["flushed"] = True

        def shutdown(self) -> None:
            observed["shutdown"] = True

    class FakeProcessor:
        def __init__(self, exporter: object) -> None:
            self.exporter = exporter

    class FakeConsoleExporter:
        pass

    class FakePropagate:
        @staticmethod
        def extract(carrier: dict[str, str]) -> str:
            observed["carrier"] = carrier
            return "parent-context"

    class FakeResource:
        @staticmethod
        def create(attributes: dict[str, str]) -> dict[str, str]:
            return attributes

    monkeypatch.setattr(
        otel_sdk,
        "_load_otel_sdk",
        lambda *, require_otlp: SimpleNamespace(
            propagate=FakePropagate,
            tracer_provider=FakeProvider,
            span_processor=FakeProcessor,
            console_exporter=FakeConsoleExporter,
            otlp_exporter=None,
            resource=FakeResource,
        ),
    )
    plan = SpanPlan(
        artifact_kind="span-plan",
        span_name="agent_assure.run",
        traceparent="00-11111111111111111111111111111111-2222222222222222-01",
        attributes=(
            SpanAttribute(
                artifact_kind="span-attribute",
                key="agent_assure.run_id",
                value="run-001",
            ),
        ),
        events=(
            SpanEvent(
                artifact_kind="span-event",
                name="agent_assure.tool_call",
                attributes=(
                    SpanAttribute(
                        artifact_kind="span-attribute",
                        key="gen_ai.tool.name",
                        value="tool",
                    ),
                ),
            ),
        ),
        semconv_commit="commit",
        semconv_checksum="0" * 64,
    )

    result = emit_span_plans((plan,), OTelExportConfig(protocol="console"))

    assert result.span_count == 1
    assert observed["carrier"]["traceparent"] == plan.traceparent
    assert observed["span"][1] == "parent-context"
    assert observed["span"][2]["agent_assure.run_id"] == "run-001"
    assert observed["event"][0] == "agent_assure.tool_call"
    assert observed["flushed"] is True
    assert observed["shutdown"] is True
