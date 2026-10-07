from __future__ import annotations

import importlib.metadata
import ipaddress
import math
import re
import socket
import threading
import time
import urllib.parse
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Literal, Self

from pydantic import Field
from pydantic.functional_validators import field_validator, model_validator

from agent_assure import __version__
from agent_assure.live.config import assert_endpoint_resolution_allowed
from agent_assure.network_authority import (
    is_disallowed_endpoint_host,
    normalize_endpoint_host,
)
from agent_assure.privacy.detectors import contains_sensitive_value
from agent_assure.schema.base import StrictModel
from agent_assure.schema.telemetry import (
    MAX_OTEL_ATTRIBUTE_VALUE_CHARS,
    MAX_OTEL_ATTRIBUTES,
    MAX_OTEL_EVENT_ATTRIBUTES,
    MAX_OTEL_EVENTS,
    MAX_OTEL_SPANS_PER_EXPORT,
    SpanPlan,
)
from agent_assure.schema.validation import validate_loaded_artifact_payload
from agent_assure.telemetry.context import trace_context_carrier
from agent_assure.telemetry.privacy_filter import assert_span_plan_safe_for_export

_HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_FORBIDDEN_TRANSPORT_HEADERS = frozenset(
    {
        "accept-encoding",
        "connection",
        "content-encoding",
        "content-length",
        "host",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)
MAX_OTEL_HEADERS = 32
MAX_OTEL_HEADER_VALUE_CHARS = 8_192
MAX_OTLP_HTTP_RESPONSE_BYTES = 64 * 1_024
_OTLP_RESPONSE_READ_CHUNK_BYTES = 8 * 1_024
_OTEL_COMPATIBILITY_VERSION = "1.44.0"
_OTEL_COMPATIBILITY_DISTRIBUTIONS = (
    "opentelemetry-api",
    "opentelemetry-sdk",
    "opentelemetry-exporter-otlp-proto-http",
)


class _OTLPTransportDeadline:
    """Own one monotonic OTLP HTTP request deadline and its active sockets."""

    def __init__(
        self,
        timeout_seconds: float,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            raise TimeoutError("OTLP HTTP request exceeded its total transport deadline")
        self._clock = clock
        self._deadline_monotonic = clock() + timeout_seconds
        self._lock = threading.Lock()
        self._sockets: set[Any] = set()
        self._expired = False
        self._timer: threading.Timer | None = None

    def __enter__(self) -> _OTLPTransportDeadline:
        delay = max(0.0, self._deadline_monotonic - self._clock())
        timer = threading.Timer(delay, self._expire)
        timer.daemon = True
        self._timer = timer
        timer.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        _exc: BaseException | None,
        _traceback: object,
    ) -> None:
        if exc_type is not None:
            self._expire()
        timer = self._timer
        if timer is not None:
            timer.cancel()
            if timer is not threading.current_thread():
                timer.join()
        with self._lock:
            sockets = tuple(self._sockets)
            self._sockets.clear()
        for transport_socket in sockets:
            _close_otlp_socket(transport_socket, shutdown=False)

    def remaining_seconds(self) -> float:
        remaining = self._deadline_monotonic - self._clock()
        if remaining <= 0:
            self._expire()
            raise TimeoutError("OTLP HTTP request exceeded its total transport deadline")
        with self._lock:
            expired = self._expired
        if expired:
            raise TimeoutError("OTLP HTTP request exceeded its total transport deadline")
        return remaining

    def register(self, transport_socket: Any) -> None:
        with self._lock:
            if self._expired:
                expired = True
            else:
                self._sockets.add(transport_socket)
                expired = False
        if expired:
            _close_otlp_socket(transport_socket, shutdown=True)
            raise TimeoutError("OTLP HTTP request exceeded its total transport deadline")

    def unregister(self, transport_socket: Any) -> None:
        with self._lock:
            self._sockets.discard(transport_socket)

    def abort(self) -> None:
        self._expire()

    def _expire(self) -> None:
        with self._lock:
            self._expired = True
            sockets = tuple(self._sockets)
            self._sockets.clear()
        for transport_socket in sockets:
            _close_otlp_socket(transport_socket, shutdown=True)


def _close_otlp_socket(transport_socket: Any, *, shutdown: bool) -> None:
    if shutdown:
        try:
            transport_socket.shutdown(socket.SHUT_RDWR)
        except (AttributeError, OSError):
            pass
    try:
        transport_socket.close()
    except (AttributeError, OSError):
        pass


_ACTIVE_OTLP_DEADLINE: ContextVar[_OTLPTransportDeadline | None] = ContextVar(
    "agent_assure_active_otlp_deadline",
    default=None,
)


def _screen_otlp_endpoint(host: str, *, timeout_seconds: int) -> tuple[str, ...]:
    try:
        return assert_endpoint_resolution_allowed(
            host,
            label="OTLP HTTP",
            timeout_seconds=float(timeout_seconds),
        )
    except TimeoutError as exc:
        raise ValueError(
            "OTLP HTTP endpoint host resolution exceeded the configured timeout"
        ) from exc


class OpenTelemetryUnavailable(RuntimeError):
    pass


class OpenTelemetryExportError(RuntimeError):
    pass


class OTelHeader(StrictModel):
    name: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=MAX_OTEL_HEADER_VALUE_CHARS)

    @field_validator("name")
    @classmethod
    def _validate_header_name(cls, value: str) -> str:
        if _HEADER_NAME_PATTERN.fullmatch(value) is None:
            raise ValueError("OTLP header names must be valid HTTP field names")
        if value.lower() in _FORBIDDEN_TRANSPORT_HEADERS:
            raise ValueError("OTLP transport-controlled header names are not allowed")
        return value

    @field_validator("value")
    @classmethod
    def _validate_header_value(cls, value: str) -> str:
        if "\r" in value or "\n" in value:
            raise ValueError("OTLP header values must not contain newlines")
        return value


class OTelExportConfig(StrictModel):
    protocol: Literal["otlp-http", "console"] = "otlp-http"
    endpoint: str | None = None
    allowed_endpoint_hosts: tuple[str, ...] = ()
    service_name: str = Field(
        default="agent-assure",
        min_length=1,
        max_length=255,
        pattern=r"^[A-Za-z][A-Za-z0-9_.-]*$",
    )
    timeout_seconds: int = Field(default=10, ge=1, le=120)
    headers: tuple[OTelHeader, ...] = Field(default=(), max_length=MAX_OTEL_HEADERS)

    @field_validator("allowed_endpoint_hosts", "headers", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        return value

    @field_validator("allowed_endpoint_hosts")
    @classmethod
    def _validate_allowed_endpoint_hosts(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for host in value:
            cleaned = host.strip().lower()
            if not cleaned:
                raise ValueError("allowed_endpoint_hosts entries must not be empty")
            if any(marker in cleaned for marker in (":", "/", "*")):
                raise ValueError("allowed_endpoint_hosts entries must be bare hostnames")
            if is_disallowed_endpoint_host(cleaned):
                raise ValueError(
                    "allowed_endpoint_hosts entries must not target localhost, private, "
                    "link-local, reserved, or multicast hosts"
                )
            normalized.append(cleaned)
        return tuple(normalized)

    @field_validator("endpoint")
    @classmethod
    def _validate_endpoint(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urllib.parse.urlparse(value)
        if parsed.scheme.lower() != "https":
            raise ValueError("OTLP HTTP endpoint must use https")
        if not parsed.hostname:
            raise ValueError("OTLP HTTP endpoint must include a host")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("OTLP HTTP endpoint must not include userinfo")
        if parsed.query or parsed.fragment:
            raise ValueError("OTLP HTTP endpoint must not include query or fragment data")
        if contains_sensitive_value(value):
            raise ValueError("OTLP HTTP endpoint contains sensitive-looking content")
        host = normalize_endpoint_host(parsed.hostname)
        if is_disallowed_endpoint_host(host):
            raise ValueError(
                "OTLP HTTP endpoint must not target localhost, private, link-local, "
                "reserved, or multicast hosts"
            )
        return value

    @field_validator("service_name")
    @classmethod
    def _validate_service_name_privacy(cls, value: str) -> str:
        if contains_sensitive_value(value):
            raise ValueError("OpenTelemetry service_name contains sensitive-looking content")
        return value

    @model_validator(mode="after")
    def _validate_otlp_endpoint_policy(self) -> Self:
        normalized_header_names = [header.name.lower() for header in self.headers]
        if len(normalized_header_names) != len(set(normalized_header_names)):
            raise ValueError("OTLP header names must be unique, ignoring case")
        if self.protocol == "console":
            return self
        if self.endpoint is None:
            raise ValueError("OTLP HTTP export requires an explicit --endpoint")
        parsed = urllib.parse.urlparse(self.endpoint)
        host = normalize_endpoint_host(parsed.hostname or "")
        if host not in set(self.allowed_endpoint_hosts):
            raise ValueError("OTLP HTTP endpoint host must be listed in allowed_endpoint_hosts")
        _screen_otlp_endpoint(host, timeout_seconds=self.timeout_seconds)
        return self


@dataclass(frozen=True)
class OTelExportResult:
    span_count: int
    protocol: str
    endpoint: str | None


@dataclass(frozen=True)
class _OtelSdk:
    always_on_sampler: Any
    compression: Any | None
    context: Any
    propagate: Any
    tracer_provider: Any
    span_export_result: Any
    span_limits: Any
    suppress_instrumentation: Any
    console_exporter: Any
    otlp_exporter: Any | None
    resource: Any


class _FailClosedSpanProcessor:
    """Synchronously export spans while preserving failures hidden by the SDK."""

    def __init__(
        self,
        exporter: Any,
        *,
        success_result: Any,
        expected_span_count: int,
        suppress_instrumentation: Any,
    ) -> None:
        self._exporter = exporter
        self._success_result = success_result
        self._expected_span_count = expected_span_count
        self._successful_exports = 0
        self._failures: list[str] = []
        self._suppress_instrumentation = suppress_instrumentation

    def on_start(self, span: Any, parent_context: Any | None = None) -> None:
        del span, parent_context

    def _on_ending(self, span: Any) -> None:
        del span

    def on_end(self, span: Any) -> None:
        if self._failures:
            return
        try:
            with self._suppress_instrumentation():
                result = self._exporter.export((span,))
        except Exception:
            self._record_failure("span exporter raised an exception")
            return
        if result != self._success_result:
            self._record_failure("span exporter returned failure")
            return
        self._successful_exports += 1

    def force_flush(self, timeout_millis: int = 30_000) -> bool:
        try:
            with self._suppress_instrumentation():
                flushed = self._exporter.force_flush(timeout_millis)
        except Exception:
            self._record_failure("span exporter force_flush raised an exception")
            return False
        if flushed is not True:
            self._record_failure("span exporter force_flush did not succeed")
            return False
        return True

    def shutdown(self) -> None:
        try:
            with self._suppress_instrumentation():
                result = self._exporter.shutdown()
        except Exception:
            self._record_failure("span exporter shutdown raised an exception")
            return
        if result is False:
            self._record_failure("span exporter shutdown returned failure")

    def record_provider_failure(self, operation: str) -> None:
        self._record_failure(f"tracer provider {operation} did not succeed")

    def assert_succeeded(self) -> None:
        if not self._failures and self._successful_exports != self._expected_span_count:
            self._record_failure("not every requested span reached the exporter")
        if self._failures:
            raise OpenTelemetryExportError(
                "OpenTelemetry export failed: " + "; ".join(self._failures)
            )

    def _record_failure(self, reason: str) -> None:
        if reason not in self._failures:
            self._failures.append(reason)


def emit_span_plans(
    plans: tuple[SpanPlan, ...],
    config: OTelExportConfig,
) -> OTelExportResult:
    if len(plans) > MAX_OTEL_SPANS_PER_EXPORT:
        raise ValueError(f"OpenTelemetry export exceeds span limit of {MAX_OTEL_SPANS_PER_EXPORT}")
    validated_plans: list[SpanPlan] = []
    for plan in plans:
        payload = plan.model_dump(mode="json", warnings="error")
        validated = SpanPlan.model_validate(payload)
        validate_loaded_artifact_payload(payload, "span-plan")
        validated_plans.append(validated)
    for plan in validated_plans:
        assert_span_plan_safe_for_export(plan)
    validated_config = OTelExportConfig.model_validate(
        config.model_dump(mode="json", warnings="error")
    )
    sdk = _load_otel_sdk(require_otlp=validated_config.protocol == "otlp-http")
    # Resource.create(), the global propagator, and default provider arguments
    # all consult OTEL_* process configuration. Build each SDK component from
    # explicit project-owned inputs instead.
    resource = sdk.resource({"service.name": validated_config.service_name})
    provider = _build_tracer_provider(sdk, resource)
    exporter = _build_exporter(sdk, validated_config)
    processor = _FailClosedSpanProcessor(
        exporter,
        success_result=sdk.span_export_result.SUCCESS,
        expected_span_count=len(validated_plans),
        suppress_instrumentation=sdk.suppress_instrumentation,
    )
    provider.add_span_processor(processor)
    tracer = provider.get_tracer("agent_assure", __version__)
    emission_error: Exception | None = None
    try:
        for plan in validated_plans:
            carrier = trace_context_carrier(plan.traceparent, plan.tracestate)
            root_context = sdk.context()
            parent_context = sdk.propagate.extract(carrier, context=root_context)
            with tracer.start_as_current_span(
                plan.span_name,
                context=parent_context,
                attributes=_attributes(plan),
            ) as span:
                for event in plan.events:
                    span.add_event(event.name, attributes=_event_attributes(event))
    except Exception as exc:
        emission_error = exc
    try:
        flushed = provider.force_flush(timeout_millis=validated_config.timeout_seconds * 1_000)
        if flushed is not True:
            processor.record_provider_failure("force_flush")
    except Exception:
        processor.record_provider_failure("force_flush")
    try:
        shutdown_result = provider.shutdown()
        if shutdown_result is False:
            processor.record_provider_failure("shutdown")
    except Exception:
        processor.record_provider_failure("shutdown")
    if emission_error is not None:
        raise OpenTelemetryExportError(
            "OpenTelemetry SDK failed while emitting a span"
        ) from emission_error
    processor.assert_succeeded()
    return OTelExportResult(
        span_count=len(validated_plans),
        protocol=validated_config.protocol,
        endpoint=validated_config.endpoint,
    )


def _build_tracer_provider(sdk: _OtelSdk, resource: Any) -> Any:
    span_limits = sdk.span_limits(
        max_attributes=MAX_OTEL_ATTRIBUTES,
        max_events=MAX_OTEL_EVENTS,
        max_links=0,
        max_span_attributes=MAX_OTEL_ATTRIBUTES,
        max_event_attributes=MAX_OTEL_EVENT_ATTRIBUTES,
        max_link_attributes=0,
        max_attribute_length=MAX_OTEL_ATTRIBUTE_VALUE_CHARS,
        max_span_attribute_length=MAX_OTEL_ATTRIBUTE_VALUE_CHARS,
    )
    provider = sdk.tracer_provider(
        resource=resource,
        sampler=sdk.always_on_sampler,
        shutdown_on_exit=False,
        span_limits=span_limits,
    )
    if getattr(provider, "_disabled", None) is not False:
        try:
            provider.shutdown()
        except Exception:
            pass
        raise OpenTelemetryUnavailable(
            "OpenTelemetry SDK is disabled; refusing to report export success"
        )
    if getattr(provider, "sampler", None) is not sdk.always_on_sampler:
        try:
            provider.shutdown()
        except Exception:
            pass
        raise OpenTelemetryUnavailable(
            "OpenTelemetry SDK did not honor the required always-on sampler"
        )
    if getattr(provider, "_span_limits", None) is not span_limits:
        try:
            provider.shutdown()
        except Exception:
            pass
        raise OpenTelemetryUnavailable(
            "OpenTelemetry SDK did not honor the required explicit span limits"
        )
    return provider


def _build_exporter(sdk: _OtelSdk, config: OTelExportConfig) -> Any:
    if config.protocol == "console":
        return sdk.console_exporter()
    if sdk.otlp_exporter is None:
        raise OpenTelemetryUnavailable(
            "OTLP export requires opentelemetry-exporter-otlp-proto-http"
        )
    if config.endpoint is None:
        raise ValueError("OTLP HTTP export requires an explicit endpoint")
    if sdk.compression is None:
        raise OpenTelemetryUnavailable(
            "OTLP exporter does not expose the required compression policy"
        )
    try:
        no_compression = sdk.compression.NoCompression
    except AttributeError as exc:
        raise OpenTelemetryUnavailable(
            "OTLP exporter does not expose the required compression policy"
        ) from exc
    parsed_endpoint = urllib.parse.urlparse(config.endpoint)
    endpoint_host = normalize_endpoint_host(parsed_endpoint.hostname or "")
    pinned_addresses = _screen_otlp_endpoint(
        endpoint_host,
        timeout_seconds=config.timeout_seconds,
    )
    endpoint_port = parsed_endpoint.port or 443
    session = _new_hardened_requests_session(
        expected_host=endpoint_host,
        expected_port=endpoint_port,
        pinned_addresses=pinned_addresses,
        timeout_seconds=config.timeout_seconds,
    )
    headers = _explicit_export_headers(config)
    kwargs: dict[str, Any] = {
        # Explicit endpoint, headers, timeout, CA policy, and session prevent
        # the upstream exporter from falling back to their OTEL_* environment
        # channels. Client-certificate state is cleared immediately below.
        "certificate_file": True,
        "compression": no_compression,
        "endpoint": config.endpoint,
        "headers": headers,
        "session": session,
        "timeout": config.timeout_seconds,
    }
    try:
        exporter = sdk.otlp_exporter(**kwargs)
    except (AttributeError, TypeError) as exc:
        _close_transport_session(session)
        raise OpenTelemetryUnavailable(
            "OTLP exporter does not accept the required hardened transport contract"
        ) from exc
    try:
        expected_values = {
            "_certificate_file": True,
            "_endpoint": config.endpoint,
            "_headers": headers,
            "_timeout": config.timeout_seconds,
        }
        for attribute, expected in expected_values.items():
            if getattr(exporter, attribute) != expected:
                raise AttributeError(attribute)
        if exporter._compression is not no_compression:
            raise AttributeError("_compression")
        if exporter._session is not session:
            raise AttributeError("_session")
        for attribute in (
            "_client_cert",
            "_client_key_file",
            "_client_certificate_file",
        ):
            getattr(exporter, attribute)
        # The upstream constructor has no explicit "disable client certificate"
        # sentinel and otherwise consults OTEL_* client-key/certificate variables.
        # Clear the resolved transport credential before any request can run.
        exporter._client_cert = None
        exporter._client_key_file = None
        exporter._client_certificate_file = None
        if any(
            getattr(exporter, attribute) is not None
            for attribute in (
                "_client_cert",
                "_client_key_file",
                "_client_certificate_file",
            )
        ):
            raise AttributeError("client certificate state")
    except (AttributeError, TypeError) as exc:
        _close_transport_session(session)
        raise OpenTelemetryUnavailable(
            "OTLP exporter does not expose the required transport hardening contract"
        ) from exc
    return exporter


def _close_transport_session(session: Any) -> None:
    try:
        session.close()
    except (AttributeError, RuntimeError):
        pass


def _explicit_export_headers(config: OTelExportConfig) -> dict[str, str]:
    # The upstream exporter uses ``headers or parse_env_headers(...)``. Keep the
    # mapping non-empty even when the caller supplied no authentication header.
    default_header = OTelHeader(name="User-Agent", value=f"agent-assure/{__version__}")
    headers = {default_header.name: default_header.value}
    for header in config.headers:
        if header.name.lower() == "user-agent":
            headers["User-Agent"] = header.value
        else:
            headers[header.name] = header.value
    return headers


def _effective_otlp_request_timeout(
    configured_timeout_seconds: int,
    requested_timeout: object,
) -> float:
    configured = float(configured_timeout_seconds)
    if requested_timeout is None:
        return configured
    if isinstance(requested_timeout, bool) or not isinstance(requested_timeout, (int, float)):
        raise OpenTelemetryExportError(
            "OTLP HTTP transport received an unsupported timeout contract"
        )
    requested = float(requested_timeout)
    if not math.isfinite(requested) or requested <= 0:
        raise TimeoutError("OTLP HTTP request exceeded its total transport deadline")
    return min(configured, requested)


def _read_bounded_otlp_response(
    response: Any,
    *,
    transport_deadline: _OTLPTransportDeadline,
) -> bytes:
    raw_response = getattr(response, "raw", None)
    if raw_response is None or not callable(getattr(raw_response, "read", None)):
        raise OpenTelemetryExportError("OTLP HTTP transport returned an invalid response")
    response_headers = getattr(response, "headers", None)
    if response_headers is None or not callable(getattr(response_headers, "get", None)):
        raise OpenTelemetryExportError("OTLP HTTP transport returned invalid response headers")
    content_encoding = str(response_headers.get("Content-Encoding", "")).strip().casefold()
    if content_encoding not in {"", "identity"}:
        raise OpenTelemetryExportError(
            "OTLP HTTP transport rejected a non-identity response encoding"
        )
    content_length = response_headers.get("Content-Length")
    if content_length is not None:
        content_length_text = str(content_length).strip()
        if not content_length_text.isascii() or not content_length_text.isdecimal():
            raise OpenTelemetryExportError("OTLP HTTP transport returned an invalid Content-Length")
        if int(content_length_text) > MAX_OTLP_HTTP_RESPONSE_BYTES:
            raise OpenTelemetryExportError(
                "OTLP HTTP response exceeded the 65536-byte decoded body limit"
            )
    payload = bytearray()
    while True:
        transport_deadline.remaining_seconds()
        read_size = min(
            _OTLP_RESPONSE_READ_CHUNK_BYTES,
            MAX_OTLP_HTTP_RESPONSE_BYTES - len(payload) + 1,
        )
        chunk = raw_response.read(read_size, decode_content=True)
        transport_deadline.remaining_seconds()
        if not isinstance(chunk, bytes):
            raise OpenTelemetryExportError("OTLP HTTP transport returned a non-bytes response body")
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        if len(payload) > MAX_OTLP_HTTP_RESPONSE_BYTES:
            raise OpenTelemetryExportError(
                "OTLP HTTP response exceeded the 65536-byte decoded body limit"
            )


def _new_hardened_requests_session(
    *,
    expected_host: str,
    expected_port: int,
    pinned_addresses: tuple[str, ...],
    timeout_seconds: int,
) -> Any:
    try:
        import requests
        from urllib3.connection import HTTPSConnection
        from urllib3.connectionpool import HTTPSConnectionPool
        from urllib3.exceptions import ConnectTimeoutError, NewConnectionError
        from urllib3.poolmanager import PoolManager
    except ImportError as exc:
        raise OpenTelemetryUnavailable(
            "OTLP HTTP export requires the requests transport dependency"
        ) from exc

    if not pinned_addresses:
        raise OpenTelemetryUnavailable("OTLP HTTP transport requires screened endpoint addresses")

    class _PinnedOTLPHTTPSConnection(HTTPSConnection):
        _agent_assure_deadline: _OTLPTransportDeadline | None = None
        _agent_assure_raw_socket: socket.socket | None = None
        _agent_assure_watch_socket: socket.socket | None = None
        _agent_assure_tls_socket: socket.socket | None = None

        def _new_conn(self) -> socket.socket:
            if normalize_endpoint_host(self.host) != expected_host or self.port != expected_port:
                raise NewConnectionError(
                    self,
                    "OTLP transport refused an endpoint outside its pinned authority",
                )
            if self.proxy is not None:
                raise NewConnectionError(self, "OTLP pinned transport does not support proxies")
            if self.source_address is not None:
                raise NewConnectionError(
                    self,
                    "OTLP pinned transport does not support source-address overrides",
                )
            transport_deadline = _ACTIVE_OTLP_DEADLINE.get()
            if transport_deadline is None:
                raise NewConnectionError(
                    self,
                    "OTLP pinned transport has no active request deadline",
                )
            last_error: OSError | None = None
            for address_text in pinned_addresses:
                try:
                    remaining = transport_deadline.remaining_seconds()
                except TimeoutError as exc:
                    raise ConnectTimeoutError(
                        self,
                        f"Connection to {expected_host} timed out",
                    ) from exc
                address = ipaddress.ip_address(address_text)
                family = socket.AF_INET6 if address.version == 6 else socket.AF_INET
                transport_socket = socket.socket(family, socket.SOCK_STREAM)
                watch_socket: socket.socket | None = None
                try:
                    transport_socket.settimeout(remaining)
                    transport_deadline.register(transport_socket)
                    for option in self.socket_options or ():
                        transport_socket.setsockopt(*option)
                    destination: tuple[Any, ...]
                    if family == socket.AF_INET6:
                        destination = (str(address), self.port, 0, 0)
                    else:
                        destination = (str(address), self.port)
                    transport_socket.connect(destination)
                    # SSLContext.wrap_socket() detaches the raw socket before
                    # its blocking handshake. Keep a duplicate registered so
                    # the watchdog can still shutdown the underlying transport
                    # throughout that handoff.
                    watch_socket = transport_socket.dup()
                    transport_deadline.register(watch_socket)
                    self._agent_assure_deadline = transport_deadline
                    self._agent_assure_raw_socket = transport_socket
                    self._agent_assure_watch_socket = watch_socket
                    return transport_socket
                except TimeoutError as exc:
                    transport_deadline.unregister(transport_socket)
                    _close_otlp_socket(transport_socket, shutdown=True)
                    if watch_socket is not None:
                        transport_deadline.unregister(watch_socket)
                        _close_otlp_socket(watch_socket, shutdown=True)
                    raise ConnectTimeoutError(
                        self,
                        f"Connection to {expected_host} timed out",
                    ) from exc
                except OSError as exc:
                    last_error = exc
                    transport_deadline.unregister(transport_socket)
                    _close_otlp_socket(transport_socket, shutdown=True)
                    if watch_socket is not None:
                        transport_deadline.unregister(watch_socket)
                        _close_otlp_socket(watch_socket, shutdown=True)
                    try:
                        transport_deadline.remaining_seconds()
                    except TimeoutError as timeout_exc:
                        raise ConnectTimeoutError(
                            self,
                            f"Connection to {expected_host} timed out",
                        ) from timeout_exc
            raise NewConnectionError(
                self,
                f"Failed to connect to screened OTLP endpoint: "
                f"{last_error.__class__.__name__ if last_error is not None else 'no address'}",
            ) from last_error

        def connect(self) -> None:
            try:
                super().connect()
                transport_deadline = self._agent_assure_deadline
                tls_socket = self.sock
                if transport_deadline is None or tls_socket is None:
                    raise OSError("OTLP pinned transport did not establish a TLS socket")
                transport_deadline.register(tls_socket)
                self._agent_assure_tls_socket = tls_socket
                raw_socket = self._agent_assure_raw_socket
                if raw_socket is not None and raw_socket is not tls_socket:
                    transport_deadline.unregister(raw_socket)
                    _close_otlp_socket(raw_socket, shutdown=False)
                self._agent_assure_raw_socket = None
                watch_socket = self._agent_assure_watch_socket
                if watch_socket is not None:
                    transport_deadline.unregister(watch_socket)
                    _close_otlp_socket(watch_socket, shutdown=False)
                self._agent_assure_watch_socket = None
                transport_deadline.remaining_seconds()
            except BaseException:
                self._close_registered_transport(shutdown=True)
                try:
                    super().close()
                except (AttributeError, OSError):
                    pass
                raise

        def close(self) -> None:
            self._close_registered_transport(shutdown=False)
            super().close()

        def _close_registered_transport(self, *, shutdown: bool) -> None:
            transport_deadline = self._agent_assure_deadline
            sockets = (
                self._agent_assure_tls_socket,
                self._agent_assure_watch_socket,
                self._agent_assure_raw_socket,
            )
            self._agent_assure_tls_socket = None
            self._agent_assure_watch_socket = None
            self._agent_assure_raw_socket = None
            self._agent_assure_deadline = None
            seen: set[int] = set()
            for transport_socket in sockets:
                if transport_socket is None or id(transport_socket) in seen:
                    continue
                seen.add(id(transport_socket))
                if transport_deadline is not None:
                    transport_deadline.unregister(transport_socket)
                _close_otlp_socket(transport_socket, shutdown=shutdown)

    class _PinnedOTLPHTTPSConnectionPool(HTTPSConnectionPool):
        ConnectionCls = _PinnedOTLPHTTPSConnection

        def _put_conn(self, connection: Any) -> None:
            # Never reuse a socket outside the request-scoped watchdog that
            # registered it. Return an empty slot to preserve pool accounting.
            if connection is not None:
                connection.close()
            super()._put_conn(None)

    class _PinnedOTLPAdapter(requests.adapters.HTTPAdapter):
        def __init__(self) -> None:
            self._agent_assure_expected_host = expected_host
            self._agent_assure_expected_port = expected_port
            self._agent_assure_pinned_addresses = pinned_addresses
            super().__init__()

        def init_poolmanager(
            self,
            connections: int,
            maxsize: int,
            block: bool = False,
            **pool_kwargs: Any,
        ) -> None:
            self.poolmanager = PoolManager(
                num_pools=connections,
                maxsize=maxsize,
                block=block,
                **pool_kwargs,
            )
            self.poolmanager.pool_classes_by_scheme = dict(self.poolmanager.pool_classes_by_scheme)
            self.poolmanager.pool_classes_by_scheme["https"] = _PinnedOTLPHTTPSConnectionPool

        def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
            del proxy, proxy_kwargs
            raise RuntimeError("OTLP pinned transport does not support proxies")

        def send(self, request: Any, **kwargs: Any) -> Any:  # type: ignore[override]
            response = super().send(request, **kwargs)
            if 300 <= response.status_code < 400:
                response.close()
                raise requests.exceptions.TooManyRedirects(
                    "OTLP pinned transport does not permit redirects",
                    response=response,
                )
            return response

    class _HardenedRequestsSession(requests.Session):
        def request(  # type: ignore[override]
            self,
            method: str,
            url: str,
            **kwargs: Any,
        ) -> Any:
            # Session.get/post normally default to following redirects. Force the
            # request policy even if a future exporter explicitly asks to follow.
            kwargs["allow_redirects"] = False
            kwargs["cert"] = None
            kwargs["proxies"] = {}
            kwargs["verify"] = True
            return super().request(method, url, **kwargs)

        def send(
            self,
            request: Any,
            **kwargs: Any,
        ) -> Any:
            kwargs["allow_redirects"] = False
            kwargs["cert"] = None
            kwargs["proxies"] = {}
            kwargs["verify"] = True
            kwargs["stream"] = True
            request_headers = getattr(request, "headers", None)
            if request_headers is None or not hasattr(request_headers, "__setitem__"):
                raise OpenTelemetryExportError(
                    "OTLP HTTP transport received an invalid prepared request"
                )
            request_headers["Accept-Encoding"] = "identity"
            request_headers["Connection"] = "close"
            request_timeout = _effective_otlp_request_timeout(
                timeout_seconds,
                kwargs.get("timeout"),
            )
            kwargs["timeout"] = request_timeout
            response: Any | None = None
            transport_deadline = _OTLPTransportDeadline(request_timeout)
            with transport_deadline:
                token = _ACTIVE_OTLP_DEADLINE.set(transport_deadline)
                try:
                    response = super().send(request, **kwargs)
                    response_body = _read_bounded_otlp_response(
                        response,
                        transport_deadline=transport_deadline,
                    )
                    response._content = response_body
                    response._content_consumed = True
                    response.close()
                    transport_deadline.remaining_seconds()
                    return response
                except BaseException:
                    transport_deadline.abort()
                    if response is not None:
                        try:
                            response.close()
                        except (AttributeError, OSError):
                            pass
                    raise
                finally:
                    _ACTIVE_OTLP_DEADLINE.reset(token)

    session = _HardenedRequestsSession()
    # Disables HTTP(S)_PROXY, NO_PROXY, netrc credentials, REQUESTS_CA_BUNDLE,
    # and CURL_CA_BUNDLE ambient process configuration.
    session.trust_env = False
    session.adapters.pop("http://", None)
    pinned_adapter = _PinnedOTLPAdapter()
    session.mount("https://", pinned_adapter)
    return session


def _attributes(plan: SpanPlan) -> dict[str, str | int | bool]:
    return {attribute.key: attribute.value for attribute in plan.attributes}


def _event_attributes(event: Any) -> dict[str, str | int | bool]:
    return {attribute.key: attribute.value for attribute in event.attributes}


def _load_otel_sdk(*, require_otlp: bool) -> _OtelSdk:
    _assert_supported_otel_dependency_versions()
    try:
        from opentelemetry.context import (
            _SUPPRESS_INSTRUMENTATION_KEY,
            Context,
            attach,
            detach,
            set_value,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import SpanLimits, TracerProvider
        from opentelemetry.sdk.trace.export import ConsoleSpanExporter, SpanExportResult
        from opentelemetry.sdk.trace.sampling import ALWAYS_ON
        from opentelemetry.trace.propagation.tracecontext import (
            TraceContextTextMapPropagator,
        )
    except ImportError as exc:
        raise OpenTelemetryUnavailable(
            "OpenTelemetry SDK support requires installing agent-assure[otel]"
        ) from exc

    @contextmanager
    def suppress_instrumentation() -> Iterator[None]:
        token = attach(set_value(_SUPPRESS_INSTRUMENTATION_KEY, True, Context()))
        try:
            yield
        finally:
            detach(token)

    otlp_exporter: Any | None = None
    compression: Any | None = None
    if require_otlp:
        try:
            from opentelemetry.exporter.otlp.proto.http import Compression
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
        except ImportError as exc:
            raise OpenTelemetryUnavailable(
                "OTLP export requires installing agent-assure[otel]"
            ) from exc
        otlp_exporter = OTLPSpanExporter
        compression = Compression
    return _OtelSdk(
        always_on_sampler=ALWAYS_ON,
        compression=compression,
        context=Context,
        propagate=TraceContextTextMapPropagator(),
        tracer_provider=TracerProvider,
        span_export_result=SpanExportResult,
        span_limits=SpanLimits,
        suppress_instrumentation=suppress_instrumentation,
        console_exporter=ConsoleSpanExporter,
        otlp_exporter=otlp_exporter,
        resource=Resource,
    )


def _assert_supported_otel_dependency_versions() -> None:
    installed_versions: list[tuple[str, str]] = []
    for distribution in _OTEL_COMPATIBILITY_DISTRIBUTIONS:
        try:
            installed_version = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError as exc:
            raise OpenTelemetryUnavailable(
                "OpenTelemetry SDK support requires installing agent-assure[otel]"
            ) from exc
        installed_versions.append((distribution, installed_version))
    mismatches = tuple(
        distribution
        for distribution, installed_version in installed_versions
        if installed_version != _OTEL_COMPATIBILITY_VERSION
    )
    if mismatches:
        raise OpenTelemetryUnavailable(
            "OpenTelemetry API, SDK, and OTLP HTTP exporter must all use the "
            f"exact tested version {_OTEL_COMPATIBILITY_VERSION}; mismatched: "
            + ", ".join(mismatches)
        )
