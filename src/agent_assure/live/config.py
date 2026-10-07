from __future__ import annotations

import ipaddress
import math
import os
import re
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Literal, Self, cast
from urllib.parse import urlsplit

from pydantic import Field, ValidationInfo
from pydantic.functional_validators import field_validator, model_validator

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.io_limits import (
    MAX_CONFIG_TEXT_BYTES,
    MAX_PERSISTED_OBSERVATIONS,
    loads_json_bounded,
    read_text_bounded_from_filesystem_root,
)
from agent_assure.live._dns_worker import MAX_RESOLVED_ENDPOINT_ADDRESSES
from agent_assure.live.identity import (
    AGENT_ASSURE_EXECUTION_VERSION,
    LIVE_ADAPTER_IMPLEMENTATION_ID,
    LIVE_PROVIDER_REQUEST_ENVELOPE_ID,
)
from agent_assure.network_authority import (
    ENV_VAR_NAME_PATTERN,
    MAX_HOST_ENV_NAME_CHARS,
    PROVIDER_SECRET_ENV_NAME_PATTERN,
    is_disallowed_endpoint_host,
    normalize_endpoint_host,
    validate_api_key_environment_name,
)
from agent_assure.privacy.credential_uri import (
    PERSISTED_CREDENTIAL_NAMES,
    PERSISTED_CREDENTIAL_SUFFIXES,
    SENSITIVE_HEADER_NAMES,
    contains_persisted_credential,
    matches_credential_name,
)
from agent_assure.privacy.detectors import (
    MAX_PRIVACY_SCAN_CHARS,
    contains_sensitive_mapping_entry,
    contains_sensitive_value,
)
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import (
    MAX_SUMMARY_CHARS,
    DigestHex,
    MachineIdentifier,
    NonnegativeDecimal6String,
    ProviderModelIdentifier,
    TemperatureDecimal6String,
    coerce_tuple,
    validate_machine_identifier,
    validate_provider_model_identifier,
)

USD_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
DECIMAL_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
ENV_VAR_ALLOWLIST_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.()\-]*$"
EndpointResolver = Callable[..., Iterable[Any]]
_MAX_DNS_WORKER_OUTPUT_BYTES = 4_096
_DNS_WORKER_REAP_SECONDS = 0.5
MAX_LIVE_CASES = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_REPETITIONS = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_REQUESTS = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_RETRIES = 10
MAX_LIVE_ADAPTER_TIMEOUT_SECONDS = 300
MAX_LIVE_RETRY_BACKOFF_SECONDS = Decimal("300.000000")
_HEADER_OPTION_NAMES = frozenset({"header", "proxy-header"})


@dataclass(frozen=True)
class EndpointResolutionStatus:
    host: str
    addresses: tuple[str, ...]
    resolution_failed: bool = False
    error: str | None = None

    @property
    def has_disallowed_address(self) -> bool:
        return any(is_disallowed_endpoint_host(address) for address in self.addresses)


LiveExecutionProfile = Literal["ordinary_live", "preregistered_paired_study"]
ORDINARY_LIVE_EXECUTION_PROFILE: LiveExecutionProfile = "ordinary_live"
PREREGISTERED_PAIRED_STUDY_EXECUTION_PROFILE: LiveExecutionProfile = "preregistered_paired_study"


def _per_thousand_rate_to_per_million(value: object, *, field_name: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or re.fullmatch(USD_PATTERN, value) is None:
        raise ValueError(f"{field_name} must be a non-negative six-decimal USD string")
    whole, fractional = value.split(".", maxsplit=1)
    micro_usd_per_thousand = int(whole) * 1_000_000 + int(fractional)
    micro_usd_per_million = micro_usd_per_thousand * 1_000
    return f"{micro_usd_per_million // 1_000_000}.{micro_usd_per_million % 1_000_000:06d}"


class LiveScriptEnvVar(StrictModel):
    name: str = Field(min_length=1, max_length=128, pattern=ENV_VAR_NAME_PATTERN)
    value: str = Field(max_length=MAX_PRIVACY_SCAN_CHARS)

    @model_validator(mode="after")
    def _reject_persisted_secrets(self) -> Self:
        # Finalized live/repeated configs are durable evidence. Reconstruct the
        # assignment so split key/value credentials cannot evade scalar scans.
        # Secret values must instead enter at execution time through the
        # explicitly acknowledged host-environment allowlist.
        if (
            _contains_persisted_credential(f"{self.name}={self.value}")
            or _contains_persisted_credential(self.value)
            or contains_sensitive_mapping_entry(self.name, self.value)
        ):
            raise ValueError(
                "script_env must contain only non-sensitive configuration; "
                "use script_env_allowlist for secret host environment variables"
            )
        return self


class LiveAdapterConfig(StrictModel):
    adapter_id: str = Field(min_length=1, max_length=256)
    provider: str = Field(min_length=1, max_length=256)
    model: ProviderModelIdentifier
    endpoint_url: str | None = None
    api_key_env: str | None = Field(
        default=None,
        min_length=1,
        max_length=MAX_HOST_ENV_NAME_CHARS,
        pattern=PROVIDER_SECRET_ENV_NAME_PATTERN,
    )
    allowed_endpoint_hosts: tuple[str, ...] = ()
    response_jsonl_path: str | None = None
    response_jsonl_sha256: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    script_path: str | None = None
    script_sha256: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    script_executable: str | None = None
    script_args: tuple[str, ...] = ()
    script_cwd: str | None = None
    script_env: tuple[LiveScriptEnvVar, ...] = ()
    script_env_allowlist: tuple[str, ...] = Field(default=(), max_length=64)
    timeout_seconds: int = Field(
        default=60,
        ge=1,
        le=MAX_LIVE_ADAPTER_TIMEOUT_SECONDS,
    )
    temperature: TemperatureDecimal6String = "0.700000"
    max_output_tokens: int | None = Field(default=None, ge=1)
    allow_network: bool = False
    cost_per_million_prompt_tokens_usd: NonnegativeDecimal6String | None = None
    cost_per_million_completion_tokens_usd: NonnegativeDecimal6String | None = None
    api_version: str | None = Field(default=None, min_length=1, max_length=256)
    sdk_name: MachineIdentifier | None = None
    sdk_version: MachineIdentifier | None = None
    region: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="before")
    @classmethod
    def _migrate_per_thousand_pricing_fields(cls, value: object) -> object:
        """Read the pre-0.6.6 live pricing names without persisting mixed units."""

        if not isinstance(value, Mapping):
            return value
        migrated = dict(value)
        field_pairs = (
            (
                "cost_per_1k_prompt_tokens_usd",
                "cost_per_million_prompt_tokens_usd",
            ),
            (
                "cost_per_1k_completion_tokens_usd",
                "cost_per_million_completion_tokens_usd",
            ),
        )
        legacy_names = {legacy_name for legacy_name, _ in field_pairs}
        current_names = {current_name for _, current_name in field_pairs}
        if legacy_names.intersection(migrated) and current_names.intersection(migrated):
            raise ValueError(
                "live pricing must use either legacy per-1k fields or canonical "
                "per-million fields, not both"
            )
        for legacy_name, current_name in field_pairs:
            if legacy_name not in migrated:
                continue
            migrated[current_name] = _per_thousand_rate_to_per_million(
                migrated.pop(legacy_name),
                field_name=legacy_name,
            )
        return migrated

    @field_validator("temperature")
    @classmethod
    def _validate_temperature(cls, value: str) -> str:
        decimal = Decimal(value)
        if decimal < Decimal("0") or decimal > Decimal("2"):
            raise ValueError("temperature must be between 0.000000 and 2.000000")
        return value

    @field_validator("api_key_env", mode="before")
    @classmethod
    def _validate_api_key_environment_name(cls, value: object) -> object:
        return (
            value
            if value is None or not isinstance(value, str)
            else (validate_api_key_environment_name(value))
        )

    @field_validator(
        "adapter_id",
        "provider",
        "model",
        "response_jsonl_path",
        "script_path",
        "script_executable",
        "script_cwd",
        "api_version",
        "sdk_name",
        "sdk_version",
        "region",
        mode="before",
    )
    @classmethod
    def _reject_persisted_credentials_before_constraints(
        cls,
        value: object,
        info: ValidationInfo,
    ) -> object:
        if isinstance(value, str) and _contains_persisted_credential(value):
            raise ValueError(f"{info.field_name} must not persist credentials or sensitive values")
        return value

    @field_validator("endpoint_url")
    @classmethod
    def _reject_endpoint_credentials(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = urlsplit(value)
            _endpoint_port = parsed.port
        except ValueError as exc:
            raise ValueError("endpoint_url is not a safely parseable URL") from exc
        if parsed.netloc.endswith(":"):
            raise ValueError("endpoint_url is not a safely parseable URL")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("endpoint_url must not persist URL userinfo")
        if _contains_persisted_credential(value):
            raise ValueError("endpoint_url must not persist credentials")
        return value

    @field_validator(
        "allowed_endpoint_hosts",
        "script_args",
        "script_env",
        "script_env_allowlist",
        mode="before",
    )
    @classmethod
    def _coerce_script_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

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
            if _contains_persisted_credential(cleaned):
                raise ValueError(
                    "allowed_endpoint_hosts entries must not persist credentials "
                    "or sensitive values"
                )
            if is_disallowed_endpoint_host(cleaned):
                raise ValueError(
                    "allowed_endpoint_hosts entries must not target localhost, "
                    "private, link-local, reserved, or multicast hosts"
                )
            normalized.append(cleaned)
        return tuple(normalized)

    @field_validator("script_env_allowlist")
    @classmethod
    def _validate_script_environment_allowlist(
        cls,
        value: tuple[str, ...],
    ) -> tuple[str, ...]:
        for name in value:
            if len(name) > 128 or re.fullmatch(ENV_VAR_ALLOWLIST_NAME_PATTERN, name) is None:
                raise ValueError(
                    "script_env_allowlist entries must be bounded environment variable names"
                )
            if contains_sensitive_value(name):
                raise ValueError(
                    "script_env_allowlist must contain names, not credentials or sensitive values"
                )
        if value != tuple(sorted(set(value))):
            raise ValueError("script_env_allowlist entries must be unique and canonically sorted")
        return value

    @model_validator(mode="after")
    def _validate_adapter_capabilities(self) -> Self:
        if self.response_jsonl_sha256 is not None and self.response_jsonl_path is None:
            raise ValueError("response_jsonl_sha256 requires response_jsonl_path")
        if self.script_sha256 is not None and self.script_path is None:
            raise ValueError("script_sha256 requires script_path")
        if self.adapter_id == "static-jsonl":
            unsupported: list[str] = []
            if self.allow_network:
                unsupported.append("allow_network")
            if self.script_env_allowlist:
                unsupported.append("script_env_allowlist")
            if unsupported:
                raise ValueError(
                    "static-jsonl adapter does not support capability fields: "
                    + ", ".join(unsupported)
                )
        if self.adapter_id == "openai-chat-completions" and self.endpoint_url is not None:
            endpoint_port = urlsplit(self.endpoint_url).port
            if endpoint_port not in {None, 443}:
                raise ValueError("openai-chat-completions endpoint_url must use HTTPS port 443")
        return self

    @model_validator(mode="after")
    def _reject_persisted_credentials(self) -> Self:
        for field_name in (
            "adapter_id",
            "provider",
            "model",
            "response_jsonl_path",
            "script_path",
            "script_executable",
            "script_cwd",
            "api_version",
            "sdk_name",
            "sdk_version",
            "region",
        ):
            value = getattr(self, field_name)
            if value is not None and _contains_persisted_credential(value):
                raise ValueError(f"{field_name} must not persist credentials or sensitive values")
        _reject_sensitive_script_arguments(self.script_args)
        return self

    @model_validator(mode="after")
    def _validate_machine_metadata(self) -> Self:
        for field_name in (
            "adapter_id",
            "provider",
            "api_version",
            "region",
        ):
            value = getattr(self, field_name)
            if value is not None:
                validate_machine_identifier(value, field_name=field_name)
        validate_provider_model_identifier(self.model, field_name="model")
        return self

    @model_validator(mode="after")
    def _validate_pricing_rates(self) -> Self:
        rates = (
            self.cost_per_million_prompt_tokens_usd,
            self.cost_per_million_completion_tokens_usd,
        )
        if sum(rate is not None for rate in rates) == 1:
            raise ValueError("prompt and completion pricing rates must be configured together")
        sdk_identifier = live_sdk_identifier(self)
        if sdk_identifier is not None and len(sdk_identifier) > 256:
            raise ValueError("combined sdk_name/sdk_version identity exceeds 256 characters")
        return self


class LivePromptCase(StrictModel):
    case_id: str = Field(min_length=1)
    prompt_path: str = Field(min_length=1)
    input_summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    source_group_id: str | None = None

    @model_validator(mode="after")
    def _reject_persisted_sensitive_metadata(self) -> Self:
        for field_name in ("case_id", "prompt_path", "input_summary", "source_group_id"):
            value = getattr(self, field_name)
            if value is not None and _contains_persisted_credential(value):
                raise ValueError(f"{field_name} must not persist credentials or sensitive values")
        return self


def live_sdk_identifier(config: LiveAdapterConfig) -> str | None:
    """Return the canonical persisted SDK identity for a live adapter."""

    if config.sdk_name is None and config.sdk_version is None:
        return None
    if config.sdk_name is None:
        return config.sdk_version
    if config.sdk_version is None:
        return config.sdk_name
    return f"{config.sdk_name}/{config.sdk_version}"


class LiveRunConfig(StrictModel):
    agent_assure_execution_version: str = AGENT_ASSURE_EXECUTION_VERSION
    live_adapter_implementation_id: str = LIVE_ADAPTER_IMPLEMENTATION_ID
    provider_request_envelope_id: str = LIVE_PROVIDER_REQUEST_ENVELOPE_ID
    execution_profile: LiveExecutionProfile = ORDINARY_LIVE_EXECUTION_PROFILE
    variant_id: str = Field(min_length=1)
    pipeline_id: str = Field(min_length=1)
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    retrieval_corpus_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    retrieval_corpus_dir: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    knowledge_contract_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    knowledge_contract_path: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    evidence_sensitivity_design_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    study_manifest_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    adapter: LiveAdapterConfig
    cases: tuple[LivePromptCase, ...] = Field(min_length=1, max_length=MAX_LIVE_CASES)
    repetitions: int = Field(default=1, ge=1, le=MAX_LIVE_REPETITIONS)
    randomization_seed: int = Field(default=0, ge=0)
    max_requests: int | None = Field(default=None, ge=1, le=MAX_LIVE_REQUESTS)
    max_total_cost_usd: NonnegativeDecimal6String | None = None
    max_cost_per_observation_usd: NonnegativeDecimal6String = "0.000000"
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    fail_fast_on_excluded_response: bool = False
    max_retries: int = Field(default=2, ge=0, le=MAX_LIVE_RETRIES)
    retry_initial_backoff_seconds: NonnegativeDecimal6String = "1.000000"
    retry_max_backoff_seconds: NonnegativeDecimal6String = "8.000000"
    requests_per_minute: int | None = Field(default=None, ge=1)
    tokens_per_minute: int | None = Field(default=None, ge=1)
    max_rate_limit_events: int = Field(default=0, ge=0)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    safety_notes: tuple[str, ...] = ()

    @field_validator("cases", "safety_notes", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_planned_request_bounds(self) -> Self:
        if self.agent_assure_execution_version != AGENT_ASSURE_EXECUTION_VERSION:
            raise ValueError("live config agent-assure execution version is unsupported")
        if self.live_adapter_implementation_id != LIVE_ADAPTER_IMPLEMENTATION_ID:
            raise ValueError("live config adapter implementation identity is unsupported")
        if self.provider_request_envelope_id != LIVE_PROVIDER_REQUEST_ENVELOPE_ID:
            raise ValueError("live config provider request envelope identity is unsupported")
        if (
            self.execution_profile == ORDINARY_LIVE_EXECUTION_PROFILE
            and self.study_manifest_digest is not None
        ):
            raise ValueError(
                "ordinary_live execution profile cannot carry a study manifest backlink"
            )
        if (
            self.study_manifest_digest is not None
            and self.evidence_sensitivity_design_digest is None
        ):
            raise ValueError(
                "study manifest backlink requires an evidence sensitivity design backlink"
            )
        if self.retrieval_corpus_dir is not None and self.retrieval_corpus_digest is None:
            raise ValueError("retrieval_corpus_dir requires retrieval_corpus_digest")
        if self.knowledge_contract_path is not None and self.knowledge_contract_digest is None:
            raise ValueError("knowledge_contract_path requires knowledge_contract_digest")
        planned_observations = len(self.cases) * self.repetitions
        if planned_observations > MAX_LIVE_REQUESTS:
            raise ValueError(
                f"planned live observations ({planned_observations}) exceed the hard limit "
                f"({MAX_LIVE_REQUESTS})"
            )
        if self.max_requests is not None and planned_observations > self.max_requests:
            raise ValueError(
                f"planned live observations ({planned_observations}) exceed max_requests "
                f"({self.max_requests})"
            )
        initial_backoff = Decimal(self.retry_initial_backoff_seconds)
        maximum_backoff = Decimal(self.retry_max_backoff_seconds)
        if maximum_backoff > MAX_LIVE_RETRY_BACKOFF_SECONDS:
            raise ValueError(
                "retry_max_backoff_seconds exceeds the hard limit of "
                f"{MAX_LIVE_RETRY_BACKOFF_SECONDS} seconds"
            )
        if initial_backoff > maximum_backoff:
            raise ValueError(
                "retry_initial_backoff_seconds must not exceed retry_max_backoff_seconds"
            )
        return self

    @model_validator(mode="after")
    def _reject_sensitive_persisted_notes(self) -> Self:
        for field_name in (
            "variant_id",
            "pipeline_id",
            "retrieval_corpus_dir",
            "knowledge_contract_path",
            "protocol_id",
        ):
            value = getattr(self, field_name)
            if value is not None and _contains_persisted_credential(value):
                raise ValueError(f"{field_name} must not persist credentials or sensitive values")
        if any(_contains_persisted_credential(note) for note in self.safety_notes):
            raise ValueError("safety_notes must not persist credentials or sensitive values")
        return self


def _reject_sensitive_script_arguments(arguments: tuple[str, ...]) -> None:
    """Reject credentials split across argv tokens before configs reach disk."""

    for index, argument in enumerate(arguments):
        normalized = argument.strip()
        if _contains_persisted_credential(normalized):
            raise ValueError("script_args must not persist credentials or sensitive values")
        if normalized in {"-u", "-U"} or (
            normalized.startswith(("-u", "-U"))
            and not normalized.startswith("--")
            and ":" in normalized[2:]
        ):
            raise ValueError("script_args must not persist curl userinfo")
        option_name, inline_value = _normalized_long_option(normalized)
        if option_name is not None and _is_credential_option_name(option_name):
            raise ValueError("script_args must not persist credential-bearing options")
        if option_name in _HEADER_OPTION_NAMES:
            header_value = inline_value
            if header_value is None and index + 1 < len(arguments):
                header_value = arguments[index + 1]
            if header_value is None or _looks_like_sensitive_header(header_value):
                raise ValueError("script_args must not persist sensitive HTTP headers")
        if normalized == "-H":
            if index + 1 >= len(arguments) or _looks_like_sensitive_header(arguments[index + 1]):
                raise ValueError("script_args must not persist sensitive HTTP headers")
        elif normalized.startswith("-H") and _looks_like_sensitive_header(normalized[2:]):
            raise ValueError("script_args must not persist sensitive HTTP headers")
        candidates = (normalized,) if inline_value is None else (normalized, inline_value)
        if any(_contains_persisted_credential(candidate) for candidate in candidates):
            raise ValueError("script_args must not persist credentials or sensitive values")


def _normalized_long_option(value: str) -> tuple[str | None, str | None]:
    if not value.startswith("--") or value == "--":
        return None, None
    option, separator, inline_value = value[2:].partition("=")
    if not option:
        return None, None
    return option.casefold().replace("_", "-"), inline_value if separator else None


def _is_credential_option_name(value: str) -> bool:
    return matches_credential_name(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
    )


def _looks_like_sensitive_header(value: str) -> bool:
    header_name, separator, _header_value = value.partition(":")
    normalized_name = header_name.strip().casefold().replace("_", "-")
    return bool(separator) and (
        normalized_name in SENSITIVE_HEADER_NAMES or _is_credential_option_name(normalized_name)
    )


def _contains_persisted_credential(value: str) -> bool:
    """Apply the shared durable-text credential policy with live vocabularies."""

    return contains_persisted_credential(
        value,
        exact_names=PERSISTED_CREDENTIAL_NAMES,
        suffixes=PERSISTED_CREDENTIAL_SUFFIXES,
        sensitive_header_names=SENSITIVE_HEADER_NAMES,
    )


def load_live_run_config(path: Path) -> LiveRunConfig:
    text = read_text_bounded_from_filesystem_root(
        path,
        max_bytes=MAX_CONFIG_TEXT_BYTES,
        label="live run config",
    )
    if path.suffix.lower() == ".json":
        loaded = loads_json_bounded(text, label="live run config JSON")
    else:
        loaded = safe_load_yaml_text(text, label="live run config YAML")
    if not isinstance(loaded, dict):
        raise TypeError("live run config must be a mapping")
    return LiveRunConfig.model_validate(loaded)


def resolve_endpoint_host(
    host: str,
    *,
    resolver: EndpointResolver | None = None,
    timeout_seconds: float | None = None,
) -> EndpointResolutionStatus:
    normalized = normalize_endpoint_host(host)
    results: Iterable[Any]
    try:
        if resolver is None and timeout_seconds is not None:
            results = _bounded_getaddrinfo(normalized, timeout_seconds=timeout_seconds)
        else:
            resolver_func = socket.getaddrinfo if resolver is None else resolver
            results = resolver_func(normalized, None, type=socket.SOCK_STREAM)
    except TimeoutError:
        raise
    except (OSError, RuntimeError) as exc:
        return EndpointResolutionStatus(
            host=normalized,
            addresses=(),
            resolution_failed=True,
            error=f"{exc.__class__.__name__}: {exc}",
        )
    addresses: list[str] = []
    for result in results:
        try:
            socket_address = cast(Any, result)[4]
            address = ipaddress.ip_address(str(socket_address[0]))
        except (IndexError, TypeError, ValueError):
            continue
        addresses.append(str(address))
    unique_addresses = tuple(sorted(set(addresses)))
    if not unique_addresses:
        return EndpointResolutionStatus(
            host=normalized,
            addresses=(),
            resolution_failed=True,
            error="resolver returned no usable IP addresses",
        )
    return EndpointResolutionStatus(host=normalized, addresses=unique_addresses)


def _dns_worker_environment() -> dict[str, str]:
    """Return only the OS state required to launch the isolated resolver."""

    if os.name != "nt":
        return {}
    system_root = os.environ.get("SystemRoot") or os.environ.get("SYSTEMROOT")
    return {"SystemRoot": system_root} if system_root else {}


def _bounded_getaddrinfo(
    host: str,
    *,
    timeout_seconds: float,
) -> list[tuple[object, ...]]:
    """Resolve in a disposable process so an NSS stall can be terminated and reaped."""

    if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
        raise TimeoutError("endpoint DNS resolution exceeded its total transport deadline")
    started = time.monotonic()
    worker_path = Path(__file__).with_name("_dns_worker.py").resolve()
    command = (sys.executable, "-I", str(worker_path), host)
    try:
        process = subprocess.Popen(  # noqa: S603 - fixed interpreter/module, no shell
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            env=_dns_worker_environment(),
        )
    except OSError as exc:
        raise RuntimeError("could not start isolated endpoint DNS resolver") from exc

    try:
        remaining = timeout_seconds - (time.monotonic() - started)
        if remaining <= 0:
            _terminate_and_reap_dns_worker(process)
            raise TimeoutError("endpoint DNS resolution exceeded its total transport deadline")
        try:
            stdout, _ = process.communicate(timeout=remaining)
        except subprocess.TimeoutExpired as exc:
            _terminate_and_reap_dns_worker(process)
            raise TimeoutError(
                "endpoint DNS resolution exceeded its total transport deadline"
            ) from exc
        if process.returncode != 0:
            raise OSError("isolated endpoint DNS resolver failed closed")
        if len(stdout) > _MAX_DNS_WORKER_OUTPUT_BYTES:
            raise RuntimeError("isolated endpoint DNS resolver exceeded its output limit")
        try:
            address_strings = stdout.decode("ascii").splitlines()
        except UnicodeDecodeError as exc:
            raise RuntimeError("isolated endpoint DNS resolver returned invalid output") from exc
        if len(address_strings) > MAX_RESOLVED_ENDPOINT_ADDRESSES:
            raise RuntimeError("isolated endpoint DNS resolver exceeded its address limit")
        results: list[tuple[object, ...]] = []
        for address_text in address_strings:
            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as exc:
                raise RuntimeError(
                    "isolated endpoint DNS resolver returned an invalid address"
                ) from exc
            family = (
                socket.AF_INET if isinstance(address, ipaddress.IPv4Address) else socket.AF_INET6
            )
            results.append((family, socket.SOCK_STREAM, 0, "", (str(address), 0)))
        return results
    finally:
        if process.poll() is None:
            _terminate_and_reap_dns_worker(process)
        if process.stdout is not None:
            process.stdout.close()


def _terminate_and_reap_dns_worker(process: subprocess.Popen[bytes]) -> None:
    """Terminate a stuck resolver and synchronously reap its OS process handle."""

    if process.poll() is not None:
        return
    try:
        process.terminate()
    except OSError:
        if process.poll() is None:
            raise
    try:
        process.wait(timeout=_DNS_WORKER_REAP_SECONDS)
        return
    except subprocess.TimeoutExpired:
        process.kill()
    try:
        process.wait(timeout=_DNS_WORKER_REAP_SECONDS)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("could not reap isolated endpoint DNS resolver") from exc


def assert_endpoint_resolution_allowed(
    host: str,
    *,
    label: str,
    resolver: EndpointResolver | None = None,
    timeout_seconds: float | None = None,
) -> tuple[str, ...]:
    status = resolve_endpoint_host(
        host,
        resolver=resolver,
        timeout_seconds=timeout_seconds,
    )
    if status.resolution_failed:
        raise ValueError(f"{label} endpoint host could not be resolved for safety screening")
    if status.has_disallowed_address:
        raise ValueError(
            f"{label} endpoint host resolves to localhost, private, link-local, "
            "reserved, or multicast addresses"
        )
    return status.addresses
