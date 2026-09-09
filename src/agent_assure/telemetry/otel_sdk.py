from __future__ import annotations

import importlib.metadata
import re
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Literal, Self

from pydantic import Field
from pydantic.functional_validators import field_validator, model_validator

from agent_assure import __version__
from agent_assure.live.config import (
    assert_endpoint_resolution_allowed,
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
from agent_assure.telemetry.context import trace_context_carrier
from agent_assure.telemetry.privacy_filter import assert_span_plan_safe_for_export

_HEADER_NAME_PATTERN = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_FORBIDDEN_TRANSPORT_HEADERS = frozenset({"content-length", "host", "transfer-encoding"})
MAX_OTEL_HEADERS = 32
MAX_OTEL_HEADER_VALUE_CHARS = 8_192
_OTEL_COMPATIBILITY_VERSION = "1.44.0"
_OTEL_COMPATIBILITY_DISTRIBUTIONS = (
    "opentelemetry-api",
    "opentelemetry-sdk",
    "opentelemetry-exporter-otlp-proto-http",
)


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
        assert_endpoint_resolution_allowed(
            host,
            label="OTLP HTTP",
        )
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
    validated_plans = tuple(SpanPlan.model_validate(plan.model_dump(mode="json")) for plan in plans)
    for plan in validated_plans:
        assert_span_plan_safe_for_export(plan)
    validated_config = OTelExportConfig.model_validate(config.model_dump(mode="json"))
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
    session = _new_hardened_requests_session()
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


def _new_hardened_requests_session() -> Any:
    try:
        import requests
    except ImportError as exc:
        raise OpenTelemetryUnavailable(
            "OTLP HTTP export requires the requests transport dependency"
        ) from exc

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
            return super().send(request, **kwargs)

    session = _HardenedRequestsSession()
    # Disables HTTP(S)_PROXY, NO_PROXY, netrc credentials, REQUESTS_CA_BUNDLE,
    # and CURL_CA_BUNDLE ambient process configuration.
    session.trust_env = False
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
