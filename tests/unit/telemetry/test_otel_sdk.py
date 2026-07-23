from __future__ import annotations

import socket
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest

from agent_assure.schema.telemetry import SpanAttribute, SpanEvent, SpanPlan
from agent_assure.telemetry import otel_sdk
from agent_assure.telemetry.otel_sdk import OTelExportConfig, OTelHeader, emit_span_plans


def _span_plan() -> SpanPlan:
    return SpanPlan(
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


def test_emit_span_plans_uses_sdk_span_with_extracted_context(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    observed: dict[str, Any] = {}
    sampler = object()

    class FakeSpan:
        def __init__(self, processor: object) -> None:
            self._processor = processor

        def __enter__(self) -> FakeSpan:
            return self

        def __exit__(self, *args: object) -> None:
            self._processor.on_end(self)
            return None

        def add_event(self, name: str, *, attributes: dict[str, object]) -> None:
            observed["event"] = (name, attributes)

    class FakeTracer:
        def __init__(self, provider: FakeProvider) -> None:
            self._provider = provider

        def start_as_current_span(
            self,
            name: str,
            *,
            context: object,
            attributes: dict[str, object],
        ) -> FakeSpan:
            observed["span"] = (name, context, attributes)
            assert self._provider.processor is not None
            return FakeSpan(self._provider.processor)

    class FakeProvider:
        def __init__(
            self,
            *,
            resource: object,
            sampler: object,
            shutdown_on_exit: bool,
            span_limits: object,
        ) -> None:
            observed["resource"] = resource
            observed["shutdown_on_exit"] = shutdown_on_exit
            self._disabled = False
            self.sampler = sampler
            self._span_limits = span_limits
            self.processor: Any | None = None

        def add_span_processor(self, processor: object) -> None:
            observed["processor"] = processor
            self.processor = processor

        def get_tracer(self, name: str, version: str) -> FakeTracer:
            observed["tracer"] = (name, version)
            return FakeTracer(self)

        def force_flush(self, *, timeout_millis: int) -> bool:
            observed["flushed"] = True
            observed["flush_timeout"] = timeout_millis
            assert self.processor is not None
            return self.processor.force_flush(timeout_millis)

        def shutdown(self) -> None:
            observed["shutdown"] = True
            assert self.processor is not None
            self.processor.shutdown()

    class FakeConsoleExporter:
        def export(self, spans: tuple[object, ...]) -> str:
            observed["exported"] = spans
            return "success"

        def force_flush(self, timeout_millis: int) -> bool:
            observed["exporter_flush_timeout"] = timeout_millis
            return True

        def shutdown(self) -> None:
            observed["exporter_shutdown"] = True

    class FakePropagate:
        @staticmethod
        def extract(carrier: dict[str, str], *, context: object) -> str:
            observed["carrier"] = carrier
            observed["root_context"] = context
            return "parent-context"

    def fake_resource(attributes: dict[str, str]) -> dict[str, str]:
        observed["resource_attributes"] = attributes
        return attributes

    def fake_span_limits(**kwargs: object) -> object:
        observed["span_limits"] = kwargs
        return object()

    monkeypatch.setattr(
        otel_sdk,
        "_load_otel_sdk",
        lambda *, require_otlp: SimpleNamespace(
            always_on_sampler=sampler,
            compression=None,
            context=lambda: "root-context",
            propagate=FakePropagate,
            tracer_provider=FakeProvider,
            span_export_result=SimpleNamespace(SUCCESS="success"),
            span_limits=fake_span_limits,
            suppress_instrumentation=nullcontext,
            console_exporter=FakeConsoleExporter,
            otlp_exporter=None,
            resource=fake_resource,
        ),
    )
    plan = _span_plan()

    result = emit_span_plans((plan,), OTelExportConfig(protocol="console"))

    assert result.span_count == 1
    assert observed["carrier"]["traceparent"] == plan.traceparent
    assert observed["root_context"] == "root-context"
    assert observed["span"][1] == "parent-context"
    assert observed["span"][2]["agent_assure.run_id"] == "run-001"
    assert observed["event"][0] == "agent_assure.tool_call"
    assert observed["resource_attributes"] == {"service.name": "agent-assure"}
    assert len(observed["exported"]) == 1
    assert observed["flushed"] is True
    assert observed["flush_timeout"] == 10_000
    assert observed["shutdown"] is True
    assert observed["exporter_shutdown"] is True


def test_emit_span_plans_uses_real_console_sdk(capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("opentelemetry.sdk")
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")

    result = emit_span_plans((_span_plan(),), OTelExportConfig(protocol="console"))

    assert result.span_count == 1
    assert result.protocol == "console"
    assert '"name": "agent_assure.run"' in capsys.readouterr().out


def test_real_otlp_exporter_accepts_hardened_private_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("opentelemetry.sdk")
    pytest.importorskip("opentelemetry.exporter.otlp.proto.http.trace_exporter")

    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", fake_getaddrinfo)
    config = OTelExportConfig(
        endpoint="https://collector.example.com/v1/traces",
        allowed_endpoint_hosts=("collector.example.com",),
    )
    sdk = otel_sdk._load_otel_sdk(require_otlp=True)
    exporter = otel_sdk._build_exporter(sdk, config)
    try:
        assert exporter._endpoint == config.endpoint
        assert exporter._session.trust_env is False
        assert exporter._client_cert is None
        assert exporter._client_key_file is None
        assert exporter._client_certificate_file is None
    finally:
        exporter.shutdown()


def test_otel_export_config_rejects_untrusted_http_endpoints() -> None:
    with pytest.raises(ValueError, match="https"):
        OTelExportConfig(endpoint="http://collector.example.com/v1/traces")
    with pytest.raises(ValueError, match="localhost, private"):
        OTelExportConfig(endpoint="https://127.0.0.1:4318/v1/traces")
    with pytest.raises(ValueError, match="userinfo"):
        OTelExportConfig(endpoint="https://user:pass@collector.example.com/v1/traces")


def test_otel_export_config_requires_explicit_allowed_endpoint_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="explicit --endpoint"):
        OTelExportConfig()
    with pytest.raises(ValueError, match="allowed_endpoint_hosts"):
        OTelExportConfig(endpoint="https://collector.example.com/v1/traces")

    config = OTelExportConfig(
        endpoint="https://collector.example.com/v1/traces",
        allowed_endpoint_hosts=("collector.example.com",),
    )

    assert config.endpoint == "https://collector.example.com/v1/traces"
    assert config.allowed_endpoint_hosts == ("collector.example.com",)


def test_otel_export_config_rejects_allowed_host_resolving_to_private_address(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fake_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        return [
            (
                socket.AF_INET,
                socket.SOCK_STREAM,
                6,
                "",
                ("10.0.0.5", 443),
            )
        ]

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", fake_getaddrinfo)

    with pytest.raises(ValueError, match="resolves to localhost, private"):
        OTelExportConfig(
            endpoint="https://collector.example.com/v1/traces",
            allowed_endpoint_hosts=("collector.example.com",),
        )


def test_otel_export_config_rejects_unresolved_allowed_host_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unresolved_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        raise OSError("resolver unavailable")

    monkeypatch.setattr("agent_assure.live.config.socket.getaddrinfo", unresolved_getaddrinfo)

    with pytest.raises(ValueError, match="could not be resolved"):
        OTelExportConfig(
            endpoint="https://collector.example.com/v1/traces",
            allowed_endpoint_hosts=("collector.example.com",),
        )


def test_otel_headers_reject_invalid_names_and_newlines() -> None:
    with pytest.raises(ValueError, match="field names"):
        OTelHeader(name="bad header", value="token")
    with pytest.raises(ValueError, match="newlines"):
        OTelHeader(name="Authorization", value="Bearer token\r\nX-Bad: 1")
