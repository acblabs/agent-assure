from __future__ import annotations

import socket
import time
from contextlib import nullcontext
from types import SimpleNamespace
from typing import Any

import pytest
import requests

from agent_assure.schema.telemetry import SpanAttribute, SpanEvent, SpanPlan
from agent_assure.telemetry import otel_sdk
from agent_assure.telemetry.otel_sdk import OTelExportConfig, OTelHeader, emit_span_plans


def _prepared_otlp_request() -> requests.PreparedRequest:
    return requests.Request(
        "POST",
        "https://collector.example.com/v1/traces",
    ).prepare()


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


def test_emit_span_plans_rejects_public_invalid_plan_before_sdk_initialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid = _span_plan().model_copy(update={"schema_version": "0.6.5"})

    def sdk_tripwire(*, require_otlp: bool) -> object:
        del require_otlp
        raise AssertionError("OpenTelemetry SDK must not be initialized")

    monkeypatch.setattr(otel_sdk, "_load_otel_sdk", sdk_tripwire)

    with pytest.raises(ValueError):
        emit_span_plans((invalid,), OTelExportConfig(protocol="console"))


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

    monkeypatch.setattr("agent_assure.live.config._bounded_getaddrinfo", fake_getaddrinfo)
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
        adapter = exporter._session.get_adapter(config.endpoint)
        assert adapter._agent_assure_expected_host == "collector.example.com"
        assert adapter._agent_assure_expected_port == 443
        assert adapter._agent_assure_pinned_addresses == ("93.184.216.34",)
    finally:
        exporter.shutdown()


def test_otlp_hardened_session_dials_screened_ip_without_dns(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connected: list[tuple[object, ...]] = []

    class FakeSocket:
        def setsockopt(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: object) -> None:
            return None

        def bind(self, _source: object) -> None:
            return None

        def connect(self, destination: tuple[object, ...]) -> None:
            connected.append(destination)

        def dup(self) -> FakeSocket:
            return FakeSocket()

        def shutdown(self, _how: int) -> None:
            return None

        def close(self) -> None:
            return None

    def fake_socket(_family: int, _kind: int) -> FakeSocket:
        return FakeSocket()

    def unexpected_resolution(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("pinned OTLP connection must not resolve DNS")

    monkeypatch.setattr(otel_sdk.socket, "socket", fake_socket)
    monkeypatch.setattr(otel_sdk.socket, "getaddrinfo", unexpected_resolution)
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("93.184.216.34",),
        timeout_seconds=10,
    )
    try:
        adapter = session.get_adapter("https://collector.example.com/v1/traces")
        pool = adapter.poolmanager.connection_from_url("https://collector.example.com/v1/traces")
        connection = pool._new_conn()
        deadline = otel_sdk._OTLPTransportDeadline(10)
        with deadline:
            token = otel_sdk._ACTIVE_OTLP_DEADLINE.set(deadline)
            try:
                assert connection._new_conn().__class__ is FakeSocket
            finally:
                otel_sdk._ACTIVE_OTLP_DEADLINE.reset(token)
        assert connected == [("93.184.216.34", 443)]
    finally:
        session.close()


def test_otlp_connection_registers_post_tls_socket_and_closes_without_reuse(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sockets: list[FakeSocket] = []

    class FakeSocket:
        def __init__(self, label: str) -> None:
            self.label = label
            self.closed = False
            self.shutdown_how: int | None = None

        def setsockopt(self, *_args: object) -> None:
            return None

        def settimeout(self, _timeout: object) -> None:
            return None

        def connect(self, _destination: tuple[object, ...]) -> None:
            return None

        def dup(self) -> FakeSocket:
            duplicate = FakeSocket("watch")
            sockets.append(duplicate)
            return duplicate

        def shutdown(self, how: int) -> None:
            self.shutdown_how = how

        def close(self) -> None:
            self.closed = True

    def fake_socket(_family: int, _kind: int) -> FakeSocket:
        transport_socket = FakeSocket("raw")
        sockets.append(transport_socket)
        return transport_socket

    tls_socket = FakeSocket("tls")

    def fake_parent_connect(connection: object) -> None:
        connection._new_conn()  # type: ignore[attr-defined]
        connection.sock = tls_socket  # type: ignore[attr-defined]

    monkeypatch.setattr(otel_sdk.socket, "socket", fake_socket)
    monkeypatch.setattr("urllib3.connection.HTTPSConnection.connect", fake_parent_connect)
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("2606:4700:4700::1111",),
        timeout_seconds=10,
    )
    try:
        adapter = session.get_adapter("https://collector.example.com/v1/traces")
        pool = adapter.poolmanager.connection_from_url("https://collector.example.com/v1/traces")
        connection = pool._new_conn()
        deadline = otel_sdk._OTLPTransportDeadline(10)
        with deadline:
            token = otel_sdk._ACTIVE_OTLP_DEADLINE.set(deadline)
            try:
                connection.connect()
                assert tls_socket in deadline._sockets
                assert [item.closed for item in sockets] == [True, True]
                pool._put_conn(connection)
                assert tls_socket.closed is True
                assert not deadline._sockets
            finally:
                otel_sdk._ACTIVE_OTLP_DEADLINE.reset(token)
    finally:
        session.close()


def test_otlp_streamed_response_is_bounded_cached_and_transport_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeRawResponse:
        def __init__(self, chunks: tuple[bytes, ...]) -> None:
            self._chunks = iter(chunks)
            self.closed = False
            self.released = False

        def read(self, size: int, *, decode_content: bool) -> bytes:
            assert 0 < size <= otel_sdk._OTLP_RESPONSE_READ_CHUNK_BYTES
            assert decode_content is True
            return next(self._chunks)

        def close(self) -> None:
            self.closed = True

        def release_conn(self) -> None:
            self.released = True

    raw_response = FakeRawResponse((b"partial-", b"success", b""))
    response = requests.Response()
    response.status_code = 200
    response.raw = raw_response  # type: ignore[assignment]

    def fake_parent_send(
        _session: requests.Session,
        _request: object,
        **kwargs: object,
    ) -> requests.Response:
        assert kwargs["stream"] is True
        assert _request.headers["Accept-Encoding"] == "identity"  # type: ignore[attr-defined]
        assert _request.headers["Connection"] == "close"  # type: ignore[attr-defined]
        return response

    monkeypatch.setattr(requests.Session, "send", fake_parent_send)
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("93.184.216.34",),
        timeout_seconds=10,
    )
    try:
        returned = session.send(_prepared_otlp_request(), timeout=20)
    finally:
        session.close()

    assert returned is response
    assert returned.content == b"partial-success"
    assert response._content_consumed is True
    assert raw_response.released is True


def test_otlp_streamed_response_rejects_decoded_body_over_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OversizedRawResponse:
        closed = False
        released = False

        def read(self, size: int, *, decode_content: bool) -> bytes:
            assert decode_content is True
            return b"x" * size

        def close(self) -> None:
            self.closed = True

        def release_conn(self) -> None:
            self.released = True

    raw_response = OversizedRawResponse()
    response = requests.Response()
    response.status_code = 200
    response.raw = raw_response  # type: ignore[assignment]

    monkeypatch.setattr(
        requests.Session,
        "send",
        lambda *_args, **_kwargs: response,
    )
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("93.184.216.34",),
        timeout_seconds=10,
    )
    try:
        with pytest.raises(otel_sdk.OpenTelemetryExportError, match="65536-byte"):
            session.send(_prepared_otlp_request(), timeout=10)
    finally:
        session.close()

    assert raw_response.closed is True
    assert raw_response.released is True


def test_otlp_total_deadline_stops_a_peer_that_keeps_making_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SlowProgressRawResponse:
        closed = False
        released = False

        def read(self, _size: int, *, decode_content: bool) -> bytes:
            assert decode_content is True
            time.sleep(0.02)
            return b"x"

        def close(self) -> None:
            self.closed = True

        def release_conn(self) -> None:
            self.released = True

    raw_response = SlowProgressRawResponse()
    response = requests.Response()
    response.status_code = 200
    response.raw = raw_response  # type: ignore[assignment]
    monkeypatch.setattr(
        requests.Session,
        "send",
        lambda *_args, **_kwargs: response,
    )
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("93.184.216.34",),
        timeout_seconds=0.05,  # type: ignore[arg-type]
    )
    started = time.monotonic()
    try:
        with pytest.raises(TimeoutError, match="total transport deadline"):
            session.send(_prepared_otlp_request(), timeout=10)
    finally:
        session.close()

    assert time.monotonic() - started < 0.5
    assert raw_response.closed is True
    assert raw_response.released is True


def test_otlp_deadline_shutdowns_socket_and_reaps_watchdog_thread() -> None:
    class BlockingSocket:
        shutdown_how: int | None = None
        closed = False

        def shutdown(self, how: int) -> None:
            self.shutdown_how = how

        def close(self) -> None:
            self.closed = True

    transport_socket = BlockingSocket()
    deadline = otel_sdk._OTLPTransportDeadline(0.02)
    with pytest.raises(TimeoutError, match="total transport deadline"):
        with deadline:
            deadline.register(transport_socket)
            time.sleep(0.04)
            deadline.remaining_seconds()

    assert transport_socket.shutdown_how == socket.SHUT_RDWR
    assert transport_socket.closed is True
    assert deadline._timer is not None
    assert not deadline._timer.is_alive()


@pytest.mark.parametrize(
    ("header_name", "header_value"),
    (
        ("Content-Encoding", "gzip"),
        ("Accept-Encoding", "gzip"),
        ("Connection", "keep-alive"),
        ("Proxy-Authorization", "Basic opaque"),
    ),
)
def test_otlp_headers_reject_transport_owned_names(
    header_name: str,
    header_value: str,
) -> None:
    with pytest.raises(ValueError, match="transport-controlled"):
        OTelHeader(name=header_name, value=header_value)


def test_otlp_streamed_response_rejects_encoded_body_before_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class EncodedRawResponse:
        closed = False
        released = False

        def read(self, _size: int, *, decode_content: bool) -> bytes:
            del decode_content
            raise AssertionError("encoded OTLP body must be rejected before decoding")

        def close(self) -> None:
            self.closed = True

        def release_conn(self) -> None:
            self.released = True

    raw_response = EncodedRawResponse()
    response = requests.Response()
    response.status_code = 200
    response.headers["Content-Encoding"] = "gzip"
    response.raw = raw_response  # type: ignore[assignment]
    monkeypatch.setattr(requests.Session, "send", lambda *_args, **_kwargs: response)
    session = otel_sdk._new_hardened_requests_session(
        expected_host="collector.example.com",
        expected_port=443,
        pinned_addresses=("93.184.216.34",),
        timeout_seconds=10,
    )
    try:
        with pytest.raises(otel_sdk.OpenTelemetryExportError, match="non-identity"):
            session.send(_prepared_otlp_request(), timeout=10)
    finally:
        session.close()

    assert raw_response.closed is True
    assert raw_response.released is True


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

    monkeypatch.setattr("agent_assure.live.config._bounded_getaddrinfo", fake_getaddrinfo)

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

    monkeypatch.setattr("agent_assure.live.config._bounded_getaddrinfo", fake_getaddrinfo)

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

    monkeypatch.setattr("agent_assure.live.config._bounded_getaddrinfo", unresolved_getaddrinfo)

    with pytest.raises(ValueError, match="could not be resolved"):
        OTelExportConfig(
            endpoint="https://collector.example.com/v1/traces",
            allowed_endpoint_hosts=("collector.example.com",),
        )


def test_otel_export_config_reports_bounded_resolution_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def timed_out_getaddrinfo(*args: object, **kwargs: object) -> list[tuple[object, ...]]:
        del args, kwargs
        raise TimeoutError("resolver deadline")

    monkeypatch.setattr(
        "agent_assure.live.config._bounded_getaddrinfo",
        timed_out_getaddrinfo,
    )

    with pytest.raises(ValueError, match="resolution exceeded the configured timeout"):
        OTelExportConfig(
            endpoint="https://collector.example.com/v1/traces",
            allowed_endpoint_hosts=("collector.example.com",),
            timeout_seconds=3,
        )


def test_otel_headers_reject_invalid_names_and_newlines() -> None:
    with pytest.raises(ValueError, match="field names"):
        OTelHeader(name="bad header", value="token")
    with pytest.raises(ValueError, match="newlines"):
        OTelHeader(name="Authorization", value="Bearer token\r\nX-Bad: 1")
