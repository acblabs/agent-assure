from __future__ import annotations

import json
from decimal import Decimal
from pathlib import Path

import yaml
from pydantic import Field
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import StrictModel
from agent_assure.schema.common import DigestHex, coerce_tuple

USD_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"
DECIMAL_PATTERN = r"^(0|[1-9][0-9]*)\.[0-9]{6}$"


class LiveAdapterConfig(StrictModel):
    adapter_id: str = Field(min_length=1)
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    endpoint_url: str | None = None
    api_key_env: str | None = None
    response_jsonl_path: str | None = None
    timeout_seconds: int = Field(default=60, ge=1)
    temperature: str = Field(default="0.000000", pattern=r"^(0|1|2)\.[0-9]{6}$")
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


class LivePromptCase(StrictModel):
    case_id: str = Field(min_length=1)
    prompt_path: str = Field(min_length=1)
    input_summary: str = Field(min_length=1)
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
    if path.suffix.lower() == ".json":
        loaded = json.loads(path.read_text(encoding="utf-8"))
    else:
        loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise TypeError("live run config must be a mapping")
    return LiveRunConfig.model_validate(loaded)
