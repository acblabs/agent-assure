from __future__ import annotations

import ipaddress
import json
import socket
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any

import yaml
from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.authoring.yaml_nodes import validate_yaml_nodes_text
from agent_assure.io_limits import MAX_CONFIG_TEXT_BYTES, read_text_bounded
from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import MAX_SUMMARY_CHARS, DigestHex, coerce_tuple

USD_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
DECIMAL_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
EndpointResolver = Callable[..., Iterable[Any]]
DISALLOWED_ENDPOINT_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
    }
)
DISALLOWED_ENDPOINT_NETWORKS = (ipaddress.ip_network("100.64.0.0/10"),)


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
    name: str = Field(min_length=1, pattern=r"^[A-Za-z_][A-Za-z0-9_]*$")
    value: str


class LiveAdapterConfig(StrictModel):
    adapter_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    endpoint_url: str | None = None
    api_key_env: str | None = None
    allowed_endpoint_hosts: tuple[str, ...] = ()
    response_jsonl_path: str | None = None
    script_path: str | None = None
    script_executable: str | None = None
    script_args: tuple[str, ...] = ()
    script_cwd: str | None = None
    script_env: tuple[LiveScriptEnvVar, ...] = ()
    script_env_allowlist: tuple[str, ...] = ()
    timeout_seconds: int = Field(default=60, ge=1)
    temperature: str = Field(default="0.700000", pattern=r"^(0|1|2)\.[0-9]{6}$")
    max_output_tokens: int | None = Field(default=None, ge=1)
    allow_network: bool = False
    cost_per_1k_prompt_tokens_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    cost_per_1k_completion_tokens_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    api_version: str | None = None
    sdk_name: str | None = None
    sdk_version: str | None = None
    region: str | None = None

    @field_validator("temperature")
    @classmethod
    def _validate_temperature(cls, value: str) -> str:
        decimal = Decimal(value)
        if decimal < Decimal("0") or decimal > Decimal("2"):
            raise ValueError("temperature must be between 0.000000 and 2.000000")
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
            if is_disallowed_endpoint_host(cleaned):
                raise ValueError(
                    "allowed_endpoint_hosts entries must not target localhost, "
                    "private, link-local, reserved, or multicast hosts"
                )
            normalized.append(cleaned)
        return tuple(normalized)


class LivePromptCase(StrictModel):
    case_id: str = Field(min_length=1)
    prompt_path: str = Field(min_length=1)
    input_summary: str = Field(min_length=1, max_length=MAX_SUMMARY_CHARS)
    source_group_id: str | None = None


class LiveRunConfig(StrictModel):
    variant_id: str = Field(min_length=1)
    pipeline_id: str = Field(min_length=1)
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    adapter: LiveAdapterConfig
    cases: tuple[LivePromptCase, ...]
    repetitions: int = Field(default=1, ge=1)
    randomization_seed: int = Field(default=0, ge=0)
    max_requests: int | None = Field(default=None, ge=1)
    max_total_cost_usd: str | None = Field(default=None, pattern=USD_PATTERN)
    max_cost_per_observation_usd: str = Field(default="0.000000", pattern=USD_PATTERN)
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_retries: int = Field(default=2, ge=0)
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


def load_live_run_config(path: Path) -> LiveRunConfig:
    text = read_text_bounded(path, max_bytes=MAX_CONFIG_TEXT_BYTES, label="live run config")
    if path.suffix.lower() == ".json":
        loaded = json.loads(text)
    else:
        validate_yaml_nodes_text(text, label="live run config YAML")
        loaded = yaml.safe_load(text)
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


def has_disallowed_resolved_address(
    host: str,
    *,
    resolver: EndpointResolver | None = None,
) -> bool:
    return resolve_endpoint_host(host, resolver=resolver).has_disallowed_address


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
            address = result[4][0]
        except (IndexError, TypeError):
            continue
        addresses.append(str(address))
    return EndpointResolutionStatus(host=normalized, addresses=tuple(sorted(set(addresses))))


def assert_endpoint_resolution_allowed(
    host: str,
    *,
    label: str,
    require_resolution: bool,
    resolver: EndpointResolver | None = None,
) -> None:
    status = resolve_endpoint_host(host, resolver=resolver)
    if status.resolution_failed:
        if require_resolution:
            raise ValueError(
                f"{label} endpoint host could not be resolved for safety screening"
            )
        return
    if status.has_disallowed_address:
        raise ValueError(
            f"{label} endpoint host resolves to localhost, private, link-local, "
            "reserved, or multicast addresses"
        )
