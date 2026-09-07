from __future__ import annotations

import ipaddress
import re
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any, Self
from urllib.parse import urlsplit

from pydantic import Field
from pydantic.functional_validators import field_validator, model_validator

from agent_assure.authoring.yaml_nodes import safe_load_yaml_text
from agent_assure.io_limits import (
    MAX_CONFIG_TEXT_BYTES,
    MAX_PERSISTED_OBSERVATIONS,
    loads_json_bounded,
    read_text_bounded_from_filesystem_root,
)
from agent_assure.live.identity import (
    AGENT_ASSURE_EXECUTION_VERSION,
    LIVE_ADAPTER_IMPLEMENTATION_ID,
    LIVE_PROVIDER_REQUEST_ENVELOPE_ID,
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
    coerce_tuple,
)

USD_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
DECIMAL_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
ENV_VAR_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
ENV_VAR_ALLOWLIST_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_.()\-]*$"
EndpointResolver = Callable[..., Iterable[Any]]
DISALLOWED_ENDPOINT_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
    }
)
DISALLOWED_ENDPOINT_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)
MAX_LIVE_CASES = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_REPETITIONS = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_REQUESTS = MAX_PERSISTED_OBSERVATIONS
MAX_LIVE_RETRIES = 10
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
    adapter_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    endpoint_url: str | None = None
    api_key_env: str | None = None
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
    timeout_seconds: int = Field(default=60, ge=1)
    temperature: str = Field(default="0.700000", pattern=r"^(0|1|2)\.[0-9]{6}$")
    max_output_tokens: int | None = Field(default=None, ge=1)
    allow_network: bool = False
    cost_per_1k_prompt_tokens_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    cost_per_1k_completion_tokens_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    api_version: str | None = None
    sdk_name: MachineIdentifier | None = None
    sdk_version: MachineIdentifier | None = None
    region: str | None = None

    @field_validator("temperature")
    @classmethod
    def _validate_temperature(cls, value: str) -> str:
        decimal = Decimal(value)
        if decimal < Decimal("0") or decimal > Decimal("2"):
            raise ValueError("temperature must be between 0.000000 and 2.000000")
        return value

    @field_validator("api_key_env")
    @classmethod
    def _validate_api_key_environment_name(cls, value: str | None) -> str | None:
        if value is not None and re.fullmatch(ENV_VAR_NAME_PATTERN, value) is None:
            raise ValueError("api_key_env must name a host environment variable")
        return value

    @field_validator("endpoint_url")
    @classmethod
    def _reject_endpoint_credentials(cls, value: str | None) -> str | None:
        if value is None:
            return None
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("endpoint_url is not a safely parseable URL") from exc
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
    def _validate_pricing_rates(self) -> Self:
        rates = (
            self.cost_per_1k_prompt_tokens_usd,
            self.cost_per_1k_completion_tokens_usd,
        )
        if sum(rate is not None for rate in rates) == 1:
            raise ValueError("prompt and completion pricing rates must be configured together")
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
    max_total_cost_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    max_cost_per_observation_usd: str = Field(default="0.000000", pattern=USD_PATTERN)
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_retries: int = Field(default=2, ge=0, le=MAX_LIVE_RETRIES)
    retry_initial_backoff_seconds: str = Field(default="1.000000", pattern=DECIMAL_PATTERN)
    retry_max_backoff_seconds: str = Field(default="8.000000", pattern=DECIMAL_PATTERN)
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


def normalize_endpoint_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


def is_disallowed_endpoint_host(host: str) -> bool:
    normalized = normalize_endpoint_host(host)
    if normalized in DISALLOWED_ENDPOINT_HOSTNAMES:
        return True
    if normalized in {"localhost"} or normalized.endswith(".localhost"):
        return True
    try:
        address = ipaddress.ip_address(normalized)
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return any(
        (
            address.is_loopback,
            address.is_link_local,
            address.is_private,
            address.is_reserved,
            address.is_multicast,
            address.is_unspecified,
            any(address in network for network in DISALLOWED_ENDPOINT_NETWORKS),
        )
    )


def resolve_endpoint_host(
    host: str,
    *,
    resolver: EndpointResolver | None = None,
) -> EndpointResolutionStatus:
    normalized = normalize_endpoint_host(host)
    resolver_func = socket.getaddrinfo if resolver is None else resolver
    try:
        results = resolver_func(normalized, None, type=socket.SOCK_STREAM)
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
            address = ipaddress.ip_address(str(result[4][0]))
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


def assert_endpoint_resolution_allowed(
    host: str,
    *,
    label: str,
    resolver: EndpointResolver | None = None,
) -> None:
    status = resolve_endpoint_host(host, resolver=resolver)
    if status.resolution_failed:
        raise ValueError(f"{label} endpoint host could not be resolved for safety screening")
    if status.has_disallowed_address:
        raise ValueError(
            f"{label} endpoint host resolves to localhost, private, link-local, "
            "reserved, or multicast addresses"
        )
