from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Annotated, Any, Literal, cast

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.fixed_point import microusd_from_picousd
from agent_assure.schema.base import PersistedArtifact, StrictModel
from agent_assure.schema.common import (
    MACHINE_IDENTIFIER_MAX_CHARS,
    MACHINE_IDENTIFIER_PATTERN,
    PROVIDER_MODEL_IDENTIFIER_PATTERN,
    DigestHex,
    NonnegativeDecimal6String,
    coerce_tuple,
    validate_machine_identifier,
    validate_provider_model_identifier,
)

UsageAggregationMethod = Literal["sum_known_fields_v1", "sum_complete_fields_v2"]
UsageSchemaVersion = Literal["0.3.1", "0.4.3", "0.6.6"]
UsageLedgerSchemaVersion = UsageSchemaVersion
UsageCoverageBasis = Literal["usage_segment", "usage_summary", "run_record"]
UsageFieldPath = tuple[str, ...]
UsageComparisonState = Literal[
    "observed",
    "not_observed",
    "baseline_not_observed",
    "candidate_not_observed",
]
USAGE_SEGMENT_SUM_FIELDS = (
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cached_tokens",
    "reasoning_tokens",
    "tool_call_count",
    "retry_count",
    "latency_ms",
    "estimated_cost_microusd",
)
USAGE_SUMMARY_VALUE_FIELDS = (
    "aggregation_method",
    "coverage_basis",
    "source_count",
    "coverage_counts",
    "total_tokens",
    "total_tool_calls",
    "total_retries",
    "total_latency_ms",
    "estimated_cost_microusd",
    "estimated_cost_picousd",
    "currency",
    "cost_basis_ids",
    "pricing_snapshot_ids",
    "pricing_snapshot_digests",
    "cost_observation_count",
)
_USAGE_SEGMENT_V043_FIELDS = ("pricing_snapshot_digest",)
_USAGE_SEGMENT_V066_FIELDS = ("estimated_cost_picousd",)
_USAGE_JOIN_IDENTIFIER_JSON_SCHEMA: dict[str, object] = {
    "minLength": 1,
    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
    "pattern": MACHINE_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])",
}
_USAGE_MODEL_IDENTIFIER_JSON_SCHEMA: dict[str, object] = {
    "minLength": 1,
    "maxLength": MACHINE_IDENTIFIER_MAX_CHARS,
    "pattern": PROVIDER_MODEL_IDENTIFIER_PATTERN.removesuffix("$") + r"(?![\s\S])",
}
_USAGE_SEGMENT_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.3.1"}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]} for field_name in _USAGE_SEGMENT_V043_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]} for field_name in _USAGE_SEGMENT_V066_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["estimated_cost_microusd"],
                "properties": {"estimated_cost_microusd": {"type": "integer"}},
            },
            "then": {
                "required": ["limitations"],
                "properties": {
                    "currency": {"const": "USD"},
                    "limitations": {"minItems": 1},
                },
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
            "else": {
                "properties": {
                    "provider": dict(_USAGE_JOIN_IDENTIFIER_JSON_SCHEMA),
                    "model": dict(_USAGE_MODEL_IDENTIFIER_JSON_SCHEMA),
                }
            },
        },
    ]
}
_USAGE_LEDGER_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "$comment": (
        "Pydantic validation verifies that missingness equals the counts derived "
        "from segments. A current parent ledger also revalidates provider and model "
        "identifiers on every nested segment, including legacy-version segments. "
        "JSON Schema mirrors that parent-owned identifier boundary while validating "
        "shape and non-negative counts."
    ),
    "allOf": [
        {
            "if": {
                "required": ["aggregation_method"],
                "properties": {"aggregation_method": {"const": "sum_complete_fields_v2"}},
            },
            "then": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.6.6"}},
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.6.6"}},
            },
            "then": {
                "required": ["aggregation_method"],
                "properties": {"aggregation_method": {"const": "sum_complete_fields_v2"}},
            },
        },
        {
            "if": {
                "required": ["aggregation_method"],
                "properties": {"aggregation_method": {"const": "sum_known_fields_v1"}},
            },
            "then": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
            "else": {
                "properties": {
                    "segments": {
                        "items": {
                            "properties": {
                                "provider": dict(_USAGE_JOIN_IDENTIFIER_JSON_SCHEMA),
                                "model": dict(_USAGE_MODEL_IDENTIFIER_JSON_SCHEMA),
                            }
                        }
                    }
                }
            },
        },
    ],
}
_USAGE_SUMMARY_V043_FIELDS = (
    "cost_basis_ids",
    "pricing_snapshot_ids",
    "pricing_snapshot_digests",
    "cost_observation_count",
)
_USAGE_SUMMARY_V066_COVERAGE_FIELDS = (
    "aggregation_method",
    "coverage_basis",
    "source_count",
    "coverage_counts",
)
_USAGE_SUMMARY_V066_FIELDS = (
    *_USAGE_SUMMARY_V066_COVERAGE_FIELDS,
    "estimated_cost_picousd",
)
_USAGE_SUMMARY_COVERAGE_BY_VALUE = (
    ("total_tokens", "total_tokens"),
    ("total_tool_calls", "total_tool_calls"),
    ("total_retries", "total_retries"),
    ("total_latency_ms", "total_latency_ms"),
    ("estimated_cost_microusd", "estimated_cost_microusd"),
)
_USAGE_SUMMARY_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.3.1"}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]} for field_name in _USAGE_SUMMARY_V043_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]} for field_name in _USAGE_SUMMARY_V066_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.6.6"}},
            },
            "then": {
                "required": list(_USAGE_SUMMARY_V066_COVERAGE_FIELDS),
                "properties": {"aggregation_method": {"const": "sum_complete_fields_v2"}},
            },
        },
        {
            "if": {
                "required": ["schema_version", "estimated_cost_microusd"],
                "properties": {
                    "schema_version": {"const": "0.6.6"},
                    "estimated_cost_microusd": {"type": "integer"},
                },
            },
            "then": {"required": ["estimated_cost_picousd"]},
        },
        {
            "if": {
                "required": ["estimated_cost_microusd"],
                "properties": {"estimated_cost_microusd": {"type": "integer"}},
            },
            "then": {"properties": {"currency": {"const": "USD"}}},
        },
        *[
            {
                "if": {
                    "required": [value_field],
                    "properties": {value_field: {"type": "integer"}},
                },
                "then": {
                    "required": ["source_count", "coverage_counts"],
                    "properties": {
                        "source_count": {"minimum": 1},
                        "coverage_counts": {"properties": {coverage_field: {"minimum": 1}}},
                    },
                },
            }
            for value_field, coverage_field in _USAGE_SUMMARY_COVERAGE_BY_VALUE
        ],
    ]
}
_USAGE_SUMMARY_DELTA_V043_FIELDS = (
    "total_tokens_delta_bps",
    "total_tool_calls_delta_bps",
    "total_retries_delta_bps",
    "total_latency_ms_delta_bps",
    "estimated_cost_microusd_delta_bps",
)
_USAGE_SUMMARY_DELTA_V066_FIELDS = (
    "estimated_cost_picousd_delta",
    "estimated_cost_picousd_delta_bps",
)
_USAGE_SUMMARY_DELTA_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.3.1"}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in _USAGE_SUMMARY_DELTA_V043_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"enum": ["0.3.1", "0.4.3"]}},
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": [field_name]}
                        for field_name in _USAGE_SUMMARY_DELTA_V066_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["estimated_cost_microusd_delta"],
                "properties": {"estimated_cost_microusd_delta": {"type": "integer"}},
            },
            "then": {"properties": {"currency": {"const": "USD"}}},
        },
        {
            "if": {
                "required": ["estimated_cost_picousd_delta"],
                "properties": {"estimated_cost_picousd_delta": {"type": "integer"}},
            },
            "then": {"properties": {"currency": {"const": "USD"}}},
        },
        {
            "if": {
                "required": ["estimated_cost_microusd_delta"],
                "properties": {
                    "schema_version": {"const": "0.6.6"},
                    "estimated_cost_microusd_delta": {"type": "integer"},
                },
            },
            "then": {"required": ["estimated_cost_picousd_delta"]},
        },
        {
            "if": {
                "required": ["estimated_cost_picousd_delta"],
                "properties": {
                    "schema_version": {"const": "0.6.6"},
                    "estimated_cost_picousd_delta": {"type": "integer"},
                },
            },
            "then": {"required": ["estimated_cost_microusd_delta"]},
        },
        {
            "if": {
                "required": ["estimated_cost_picousd_delta_bps"],
                "properties": {"estimated_cost_picousd_delta_bps": {"type": "integer"}},
            },
            "then": {"required": ["estimated_cost_picousd_delta"]},
        },
    ]
}
_LEGACY_SCHEMA_VERSION = "0.2.0"
_ARRAY_ITEM_STEP = "*"
_CURRENT_USAGE_SCHEMA_VERSION: UsageSchemaVersion = "0.6.6"
_CURRENT_USAGE_LEDGER_SCHEMA_VERSION: UsageLedgerSchemaVersion = "0.6.6"
_INCOMPLETE_COST_PROVENANCE_LIMITATION = (
    "Declared estimated cost was not aggregated because every cost-bearing segment "
    "must declare cost_basis, pricing_snapshot_id, and pricing_snapshot_digest."
)
_UNKNOWN_COST_OBSERVATION_COUNT_LIMITATION = (
    "Declared estimated cost per cost observation was not rendered because "
    "multiple cost-bearing segments did not all declare run_id or case_id."
)
_CASE_ID_COST_OBSERVATION_COUNT_LIMITATION = (
    "Declared estimated cost per cost observation used distinct case_id values "
    "because cost-bearing segments did not all declare run_id."
)
_SINGLE_SEGMENT_COST_OBSERVATION_COUNT_LIMITATION = (
    "Declared estimated cost per cost observation treated one unlabeled "
    "cost-bearing segment as one observation because run_id and case_id were absent."
)


@dataclass(frozen=True)
class _CostAggregation:
    estimated_cost_microusd: int | None
    estimated_cost_picousd: int | None
    currency: str
    cost_basis_ids: tuple[str, ...]
    pricing_snapshot_ids: tuple[str, ...]
    pricing_snapshot_digests: tuple[DigestHex, ...]
    cost_observation_count: int | None
    limitations: list[str]


class UsageSegment(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_SEGMENT_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-segment"] = "usage-segment"
    schema_version: UsageSchemaVersion = _CURRENT_USAGE_SCHEMA_VERSION
    segment_id: str = Field(min_length=1)
    case_id: str | None = None
    run_id: str | None = None
    span_id: str | None = None
    parent_span_id: str | None = None
    event_range_start: int | None = Field(default=None, ge=0)
    event_range_end: int | None = Field(default=None, ge=0)

    provider: str | None = None
    model: str | None = None
    operation: str | None = None

    prompt_tokens: int | None = Field(default=None, ge=0)
    completion_tokens: int | None = Field(default=None, ge=0)
    total_tokens: int | None = Field(default=None, ge=0)
    cached_tokens: int | None = Field(default=None, ge=0)
    reasoning_tokens: int | None = Field(default=None, ge=0)

    tool_call_count: int | None = Field(default=None, ge=0)
    retry_count: int | None = Field(default=None, ge=0)
    latency_ms: int | None = Field(default=None, ge=0)

    estimated_cost_microusd: int | None = Field(default=None, ge=0)
    estimated_cost_picousd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    cost_basis: str | None = None
    pricing_snapshot_id: str | None = None
    pricing_snapshot_digest: DigestHex | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_event_range(self) -> UsageSegment:
        if self.schema_version == "0.3.1" and any(
            field_name in self.model_fields_set for field_name in _USAGE_SEGMENT_V043_FIELDS
        ):
            raise ValueError("pricing snapshot digest requires schema_version 0.4.3")
        if self.schema_version != "0.6.6" and any(
            field_name in self.model_fields_set for field_name in _USAGE_SEGMENT_V066_FIELDS
        ):
            raise ValueError("exact pico-USD cost requires schema_version 0.6.6")
        if self.schema_version == "0.6.6":
            if self.provider is not None:
                validate_machine_identifier(self.provider, field_name="provider")
            if self.model is not None:
                validate_provider_model_identifier(self.model, field_name="model")
        if (
            self.event_range_start is not None
            and self.event_range_end is not None
            and self.event_range_end < self.event_range_start
        ):
            raise ValueError("event_range_end must be greater than or equal to event_range_start")
        if self.estimated_cost_microusd is not None and not self.limitations:
            raise ValueError("cost-bearing usage segments require explicit limitations")
        if self.estimated_cost_microusd is not None and self.currency != "USD":
            raise ValueError("estimated_cost_microusd requires currency USD")
        if self.estimated_cost_picousd is not None:
            if self.estimated_cost_microusd is None:
                raise ValueError("estimated_cost_picousd requires estimated_cost_microusd")
            if self.currency != "USD":
                raise ValueError("estimated_cost_picousd requires currency USD")
            if microusd_from_picousd(self.estimated_cost_picousd) != self.estimated_cost_microusd:
                raise ValueError(
                    "estimated_cost_microusd must be the half-even projection "
                    "of estimated_cost_picousd"
                )
        if (
            self.cost_basis == "declared_pricing_snapshot_v2"
            and self.estimated_cost_microusd is not None
            and self.estimated_cost_picousd is None
        ):
            raise ValueError(
                "declared_pricing_snapshot_v2 cost requires exact estimated_cost_picousd"
            )
        if self.pricing_snapshot_digest is not None and self.pricing_snapshot_id is None:
            raise ValueError("pricing_snapshot_digest requires pricing_snapshot_id")
        return self


def usage_segment_missingness(segments: tuple[UsageSegment, ...]) -> dict[str, int]:
    counts = {
        field: sum(1 for segment in segments if getattr(segment, field) is None)
        for field in USAGE_SEGMENT_SUM_FIELDS
    }
    return {field: count for field, count in sorted(counts.items()) if count}


class UsageLedger(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_LEDGER_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-ledger"] = "usage-ledger"
    schema_version: UsageLedgerSchemaVersion = _CURRENT_USAGE_LEDGER_SCHEMA_VERSION
    segments: tuple[UsageSegment, ...] = ()
    aggregation_method: UsageAggregationMethod = "sum_complete_fields_v2"
    missingness: dict[str, Annotated[int, Field(ge=0)]] = Field(
        default_factory=dict,
        description=(
            "Counts of segment fields that were missing during aggregation; "
            "Pydantic validation requires this to match the contributing segments."
        ),
    )

    @model_validator(mode="before")
    @classmethod
    def _default_versioned_aggregation_method(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if "aggregation_method" in payload:
            return payload
        payload["aggregation_method"] = (
            "sum_complete_fields_v2"
            if payload.get("schema_version", _CURRENT_USAGE_LEDGER_SCHEMA_VERSION)
            == _CURRENT_USAGE_LEDGER_SCHEMA_VERSION
            else "sum_known_fields_v1"
        )
        return payload

    @field_validator("segments", mode="before")
    @classmethod
    def _coerce_segments(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_missingness(self) -> UsageLedger:
        if (
            self.aggregation_method == "sum_complete_fields_v2"
            and self.schema_version != _CURRENT_USAGE_LEDGER_SCHEMA_VERSION
        ):
            raise ValueError("sum_complete_fields_v2 requires usage-ledger schema_version 0.6.6")
        if (
            self.schema_version == _CURRENT_USAGE_LEDGER_SCHEMA_VERSION
            and self.aggregation_method != "sum_complete_fields_v2"
        ):
            raise ValueError("usage-ledger schema_version 0.6.6 requires sum_complete_fields_v2")
        if self.schema_version == _CURRENT_USAGE_LEDGER_SCHEMA_VERSION:
            for segment_index, segment in enumerate(self.segments):
                if segment.provider is not None:
                    validate_machine_identifier(
                        segment.provider,
                        field_name=f"segments[{segment_index}].provider",
                    )
                if segment.model is not None:
                    validate_provider_model_identifier(
                        segment.model,
                        field_name=f"segments[{segment_index}].model",
                    )
        expected = usage_segment_missingness(self.segments)
        if self.missingness != expected:
            raise ValueError("usage ledger missingness must match segments")
        return self


class UsageMetricCoverage(StrictModel):
    total_tokens: int = Field(default=0, ge=0)
    total_tool_calls: int = Field(default=0, ge=0)
    total_retries: int = Field(default=0, ge=0)
    total_latency_ms: int = Field(default=0, ge=0)
    estimated_cost_microusd: int = Field(default=0, ge=0)


class UsageSummary(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_SUMMARY_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-summary"] = "usage-summary"
    schema_version: UsageSchemaVersion = _CURRENT_USAGE_SCHEMA_VERSION
    aggregation_method: UsageAggregationMethod | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    coverage_basis: UsageCoverageBasis | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    source_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    coverage_counts: UsageMetricCoverage | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    total_tokens: int | None = Field(default=None, ge=0)
    total_tool_calls: int | None = Field(default=None, ge=0)
    total_retries: int | None = Field(default=None, ge=0)
    total_latency_ms: int | None = Field(default=None, ge=0)
    estimated_cost_microusd: int | None = Field(default=None, ge=0)
    estimated_cost_picousd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    cost_basis_ids: tuple[str, ...] = Field(
        default=(),
        exclude_if=lambda value: len(value) == 0,
    )
    pricing_snapshot_ids: tuple[str, ...] = Field(
        default=(),
        exclude_if=lambda value: len(value) == 0,
    )
    pricing_snapshot_digests: tuple[DigestHex, ...] = Field(
        default=(),
        exclude_if=lambda value: len(value) == 0,
    )
    cost_observation_count: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    limitations: tuple[str, ...] = ()

    @model_validator(mode="before")
    @classmethod
    def _populate_direct_current_coverage(cls, value: object) -> object:
        if not isinstance(value, Mapping):
            return value
        payload = dict(value)
        if payload.get("schema_version", _CURRENT_USAGE_SCHEMA_VERSION) != "0.6.6":
            return payload
        if any(field_name in payload for field_name in _USAGE_SUMMARY_V066_COVERAGE_FIELDS):
            return payload
        value_fields = {
            "total_tokens": "total_tokens",
            "total_tool_calls": "total_tool_calls",
            "total_retries": "total_retries",
            "total_latency_ms": "total_latency_ms",
            "estimated_cost_microusd": "estimated_cost_microusd",
        }
        observed = any(payload.get(field_name) is not None for field_name in value_fields)
        payload["aggregation_method"] = "sum_complete_fields_v2"
        payload["coverage_basis"] = "usage_summary"
        payload["source_count"] = 1 if observed else 0
        payload["coverage_counts"] = {
            coverage_field: int(observed and payload.get(value_field) is not None)
            for value_field, coverage_field in value_fields.items()
        }
        return payload

    @field_validator(
        "cost_basis_ids",
        "pricing_snapshot_ids",
        "pricing_snapshot_digests",
        "limitations",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_versioned_fields(self) -> UsageSummary:
        if self.schema_version == "0.3.1" and any(
            field_name in self.model_fields_set for field_name in _USAGE_SUMMARY_V043_FIELDS
        ):
            raise ValueError("pricing provenance summary fields require schema_version 0.4.3")
        if self.schema_version != "0.6.6" and any(
            field_name in self.model_fields_set
            for field_name in _USAGE_SUMMARY_V066_COVERAGE_FIELDS
        ):
            raise ValueError("usage coverage fields require schema_version 0.6.6")
        if self.schema_version != "0.6.6" and "estimated_cost_picousd" in self.model_fields_set:
            raise ValueError("exact pico-USD cost requires schema_version 0.6.6")
        if self.schema_version == "0.6.6":
            if (
                self.aggregation_method != "sum_complete_fields_v2"
                or self.coverage_basis is None
                or self.source_count is None
                or self.coverage_counts is None
            ):
                raise ValueError(
                    "schema_version 0.6.6 usage summaries require complete-coverage metadata"
                )
            coverage_by_value = {
                value_field: getattr(self.coverage_counts, coverage_field)
                for value_field, coverage_field in _USAGE_SUMMARY_COVERAGE_BY_VALUE
            }
            for field_name, coverage_count in coverage_by_value.items():
                if coverage_count > self.source_count:
                    raise ValueError(f"usage coverage count for {field_name} exceeds source_count")
                if getattr(self, field_name) is not None:
                    if self.source_count == 0:
                        raise ValueError(f"{field_name} requires a positive usage source_count")
                    if coverage_count != self.source_count:
                        raise ValueError(f"{field_name} requires complete metric coverage")
        if self.estimated_cost_microusd is not None and self.currency != "USD":
            raise ValueError("estimated_cost_microusd requires currency USD")
        if self.estimated_cost_picousd is not None:
            if self.estimated_cost_microusd is None:
                raise ValueError("estimated_cost_picousd requires estimated_cost_microusd")
            if self.currency != "USD":
                raise ValueError("estimated_cost_picousd requires currency USD")
            if microusd_from_picousd(self.estimated_cost_picousd) != self.estimated_cost_microusd:
                raise ValueError(
                    "estimated_cost_microusd must be the half-even projection "
                    "of estimated_cost_picousd"
                )
        if (
            self.schema_version == "0.6.6"
            and self.estimated_cost_microusd is not None
            and self.estimated_cost_picousd is None
        ):
            raise ValueError("schema_version 0.6.6 cost requires exact estimated_cost_picousd")
        if self.pricing_snapshot_digests and not self.pricing_snapshot_ids:
            raise ValueError("pricing_snapshot_digests require pricing_snapshot_ids")
        if self.cost_observation_count is not None and self.estimated_cost_microusd is None:
            raise ValueError("cost_observation_count requires estimated_cost_microusd")
        return self


def summarize_usage_segments(
    segments: tuple[UsageSegment, ...],
    *,
    aggregation_method: UsageAggregationMethod = "sum_known_fields_v1",
) -> UsageSummary:
    missingness = usage_segment_missingness(segments)
    limitations = sorted({limitation for segment in segments for limitation in segment.limitations})
    if not segments:
        limitations.append("Measured usage was not observed.")
    if missingness:
        missing_fields = ", ".join(
            f"{field}={count}" for field, count in sorted(missingness.items())
        )
        limitations.append(
            "Usage summary does not aggregate incomplete metric fields; "
            f"missing segment fields: {missing_fields}."
        )
    sum_values = _sum_known if aggregation_method == "sum_known_fields_v1" else _sum_complete
    cost = _sum_cost(segments, aggregation_method=aggregation_method)
    limitations.extend(cost.limitations)
    payload: dict[str, object] = {
        "artifact_kind": "usage-summary",
        "schema_version": ("0.6.6" if aggregation_method == "sum_complete_fields_v2" else "0.4.3"),
        "total_tokens": sum_values(segment.total_tokens for segment in segments),
        "total_tool_calls": sum_values(segment.tool_call_count for segment in segments),
        "total_retries": sum_values(segment.retry_count for segment in segments),
        "total_latency_ms": sum_values(segment.latency_ms for segment in segments),
        "estimated_cost_microusd": cost.estimated_cost_microusd,
        "currency": cost.currency,
        "cost_basis_ids": cost.cost_basis_ids,
        "pricing_snapshot_ids": cost.pricing_snapshot_ids,
        "pricing_snapshot_digests": cost.pricing_snapshot_digests,
        "cost_observation_count": cost.cost_observation_count,
        "limitations": tuple(sorted(set(limitations))),
    }
    if aggregation_method == "sum_complete_fields_v2":
        payload.update(
            {
                "aggregation_method": aggregation_method,
                "coverage_basis": "usage_segment",
                "source_count": len(segments),
                "coverage_counts": _usage_metric_coverage(segments),
                "estimated_cost_picousd": cost.estimated_cost_picousd,
            }
        )
    return UsageSummary.model_validate(payload)


def _usage_metric_coverage(
    segments: tuple[UsageSegment, ...],
) -> UsageMetricCoverage:
    return UsageMetricCoverage(
        total_tokens=sum(segment.total_tokens is not None for segment in segments),
        total_tool_calls=sum(segment.tool_call_count is not None for segment in segments),
        total_retries=sum(segment.retry_count is not None for segment in segments),
        total_latency_ms=sum(segment.latency_ms is not None for segment in segments),
        estimated_cost_microusd=sum(
            segment.estimated_cost_microusd is not None for segment in segments
        ),
    )


def usage_summary_from_ledger(ledger: UsageLedger) -> UsageSummary:
    return summarize_usage_segments(
        ledger.segments,
        aggregation_method=ledger.aggregation_method,
    )


def validate_usage_summary_consistency(
    ledger: UsageLedger | None,
    summary: UsageSummary | None,
    *,
    owner: str,
) -> None:
    if ledger is None or summary is None:
        return
    expected = usage_summary_from_ledger(ledger)
    value_fields = tuple(
        field
        for field in USAGE_SUMMARY_VALUE_FIELDS
        if not (summary.schema_version == "0.3.1" and field in _USAGE_SUMMARY_V043_FIELDS)
        and not (summary.schema_version != "0.6.6" and field in _USAGE_SUMMARY_V066_FIELDS)
    )
    mismatched_fields = [
        field for field in value_fields if getattr(summary, field) != getattr(expected, field)
    ]
    missing_limitations = sorted(set(expected.limitations) - set(summary.limitations))
    if mismatched_fields or missing_limitations:
        details = []
        if mismatched_fields:
            details.append("fields: " + ", ".join(mismatched_fields))
        if missing_limitations:
            details.append("missing limitations: " + "; ".join(missing_limitations))
        detail = "; ".join(details)
        raise ValueError(f"{owner} usage_summary does not match usage_ledger ({detail})")


def usage_container_json_schema_extra(*field_paths: str | UsageFieldPath) -> dict[str, Any]:
    normalized = tuple(_normalize_usage_field_path(path) for path in field_paths)
    return {
        "allOf": [
            {
                "if": {
                    "required": ["schema_version"],
                    "properties": {"schema_version": {"const": _LEGACY_SCHEMA_VERSION}},
                },
                "then": {
                    "not": {
                        "anyOf": [_usage_field_path_required_schema(path) for path in normalized]
                    }
                },
            }
        ]
    }


def validate_usage_field_paths_schema_version(
    schema_version: str,
    *,
    owner: str,
    root: object,
    field_paths: Iterable[str | UsageFieldPath],
) -> None:
    if schema_version != _LEGACY_SCHEMA_VERSION:
        return
    present = [
        _format_usage_field_path(path)
        for path in (_normalize_usage_field_path(path) for path in field_paths)
        if _usage_field_path_is_present(root, path)
    ]
    if present:
        fields = ", ".join(sorted(present))
        raise ValueError(f"{owner} usage fields require schema_version 0.3.1: {fields}")


class UsageSummaryDelta(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_SUMMARY_DELTA_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-summary-delta"] = "usage-summary-delta"
    schema_version: UsageSchemaVersion = _CURRENT_USAGE_SCHEMA_VERSION
    comparison_state: UsageComparisonState
    baseline_observed: bool
    candidate_observed: bool
    total_tokens_delta: int | None = None
    total_tokens_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    total_tool_calls_delta: int | None = None
    total_tool_calls_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    total_retries_delta: int | None = None
    total_retries_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    total_latency_ms_delta: int | None = None
    total_latency_ms_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    estimated_cost_microusd_delta: int | None = None
    estimated_cost_microusd_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    estimated_cost_picousd_delta: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    estimated_cost_picousd_delta_bps: int | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_versioned_fields(self) -> UsageSummaryDelta:
        if self.schema_version == "0.3.1" and any(
            field_name in self.model_fields_set for field_name in _USAGE_SUMMARY_DELTA_V043_FIELDS
        ):
            raise ValueError("basis-point usage deltas require schema_version 0.4.3")
        if self.schema_version != "0.6.6" and any(
            field_name in self.model_fields_set for field_name in _USAGE_SUMMARY_DELTA_V066_FIELDS
        ):
            raise ValueError("exact pico-USD usage deltas require schema_version 0.6.6")
        if self.estimated_cost_microusd_delta is not None and self.currency != "USD":
            raise ValueError("estimated_cost_microusd_delta requires currency USD")
        if self.estimated_cost_picousd_delta is not None and self.currency != "USD":
            raise ValueError("estimated_cost_picousd_delta requires currency USD")
        if self.schema_version == "0.6.6" and (
            (self.estimated_cost_microusd_delta is None)
            != (self.estimated_cost_picousd_delta is None)
        ):
            raise ValueError(
                "schema_version 0.6.6 cost deltas require exact pico-USD and "
                "projected micro-USD values"
            )
        if (
            self.estimated_cost_picousd_delta_bps is not None
            and self.estimated_cost_picousd_delta is None
        ):
            raise ValueError(
                "estimated_cost_picousd_delta_bps requires estimated_cost_picousd_delta"
            )
        return self


_LEGACY_PRICING_RATE_FIELDS = (
    "input_token_microusd",
    "output_token_microusd",
    "cached_input_token_microusd",
    "reasoning_token_microusd",
)
_PRECISE_PRICING_RATE_FIELDS = (
    "input_million_tokens_usd",
    "output_million_tokens_usd",
    "cached_input_million_tokens_usd",
    "reasoning_million_tokens_usd",
)
_USAGE_PRICING_MODEL_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "oneOf": [
        {
            "required": ["input_token_microusd", "output_token_microusd"],
            "properties": {
                "input_token_microusd": {"type": "integer"},
                "output_token_microusd": {"type": "integer"},
            },
            "not": {
                "anyOf": [{"required": [field_name]} for field_name in _PRECISE_PRICING_RATE_FIELDS]
            },
        },
        {
            "required": [
                "input_million_tokens_usd",
                "output_million_tokens_usd",
            ],
            "properties": {
                "input_million_tokens_usd": {"type": "string"},
                "output_million_tokens_usd": {"type": "string"},
            },
            "not": {
                "anyOf": [{"required": [field_name]} for field_name in _LEGACY_PRICING_RATE_FIELDS]
            },
        },
    ]
}
_USAGE_PRICING_SNAPSHOT_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "allOf": [
        {
            "if": {
                "required": ["schema_version"],
                "properties": {"schema_version": {"const": "0.4.3"}},
            },
            "then": {
                "properties": {
                    "models": {
                        "items": {
                            "required": [
                                "input_token_microusd",
                                "output_token_microusd",
                            ]
                        }
                    }
                }
            },
        },
        {
            "if": {
                "properties": {"schema_version": {"const": "0.6.6"}},
            },
            "then": {
                "properties": {
                    "models": {
                        "items": {
                            "required": [
                                "input_million_tokens_usd",
                                "output_million_tokens_usd",
                            ],
                            "properties": {
                                "provider": dict(_USAGE_JOIN_IDENTIFIER_JSON_SCHEMA),
                                "model": dict(_USAGE_MODEL_IDENTIFIER_JSON_SCHEMA),
                            },
                        }
                    }
                }
            },
        },
    ]
}


class UsagePricingModel(StrictModel):
    model_config = ConfigDict(json_schema_extra=_USAGE_PRICING_MODEL_JSON_SCHEMA_EXTRA)

    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    input_token_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    output_token_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    cached_input_token_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    reasoning_token_microusd: int | None = Field(
        default=None,
        ge=0,
        exclude_if=lambda value: value is None,
    )
    input_million_tokens_usd: NonnegativeDecimal6String | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    output_million_tokens_usd: NonnegativeDecimal6String | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    cached_input_million_tokens_usd: NonnegativeDecimal6String | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    reasoning_million_tokens_usd: NonnegativeDecimal6String | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )

    @model_validator(mode="after")
    def _validate_rate_family(self) -> UsagePricingModel:
        legacy_required = (self.input_token_microusd, self.output_token_microusd)
        precise_required = (
            self.input_million_tokens_usd,
            self.output_million_tokens_usd,
        )
        has_legacy = any(value is not None for value in legacy_required)
        has_precise = any(value is not None for value in precise_required)
        if has_legacy == has_precise:
            raise ValueError(
                "pricing model requires exactly one complete legacy or per-million rate family"
            )
        if has_legacy and any(value is None for value in legacy_required):
            raise ValueError("legacy input and output token rates must be configured together")
        if has_precise and any(value is None for value in precise_required):
            raise ValueError("per-million input and output rates must be configured together")
        if has_legacy and (
            self.cached_input_million_tokens_usd is not None
            or self.reasoning_million_tokens_usd is not None
        ):
            raise ValueError("pricing model cannot mix legacy and per-million rates")
        if has_precise and (
            self.cached_input_token_microusd is not None
            or self.reasoning_token_microusd is not None
        ):
            raise ValueError("pricing model cannot mix legacy and per-million rates")
        return self


class UsagePricingSnapshot(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_PRICING_SNAPSHOT_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-pricing-snapshot"] = "usage-pricing-snapshot"
    schema_version: Literal["0.4.3", "0.6.6"] = "0.6.6"
    pricing_snapshot_id: str = Field(min_length=1)
    currency: str = Field(
        default="USD",
        pattern=r"^[A-Z]{3}$",
        json_schema_extra={"const": "USD"},
    )
    models: tuple[UsagePricingModel, ...] = Field(min_length=1)
    limitations: tuple[str, ...] = Field(min_length=1)

    @field_validator("models", "limitations", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_unique_model_prices(self) -> UsagePricingSnapshot:
        if self.currency != "USD":
            raise ValueError("usage pricing snapshots require currency USD")
        for model in self.models:
            uses_precise_rates = model.input_million_tokens_usd is not None
            if self.schema_version == "0.4.3" and uses_precise_rates:
                raise ValueError("schema_version 0.4.3 requires legacy per-token rates")
            if self.schema_version == "0.6.6" and not uses_precise_rates:
                raise ValueError("schema_version 0.6.6 requires precise per-million rates")
            if self.schema_version == "0.6.6":
                validate_machine_identifier(model.provider, field_name="models[].provider")
                validate_provider_model_identifier(model.model, field_name="models[].model")
        keys = [(model.provider, model.model) for model in self.models]
        duplicate_keys = sorted({key for key in keys if keys.count(key) > 1})
        if duplicate_keys:
            labels = ", ".join(f"{provider}/{model}" for provider, model in duplicate_keys)
            raise ValueError("pricing snapshot contains duplicate provider/model rates: " + labels)
        return self


def _sum_known(values: Iterable[int | None]) -> int | None:
    known = tuple(value for value in values if value is not None)
    if not known:
        return None
    return sum(known)


def _sum_complete(values: Iterable[int | None]) -> int | None:
    materialized = tuple(values)
    if not materialized or any(value is None for value in materialized):
        return None
    return sum(value for value in materialized if value is not None)


def _sum_cost(
    segments: tuple[UsageSegment, ...],
    *,
    aggregation_method: UsageAggregationMethod,
) -> _CostAggregation:
    cost_segments = tuple(
        segment for segment in segments if segment.estimated_cost_microusd is not None
    )
    if not cost_segments:
        currency = segments[0].currency if segments else "USD"
        return _CostAggregation(None, None, currency, (), (), (), None, [])
    if aggregation_method == "sum_complete_fields_v2" and len(cost_segments) != len(segments):
        return _CostAggregation(
            None,
            None,
            cost_segments[0].currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because cost coverage "
                "was incomplete across usage segments."
            ],
        )
    currencies = {segment.currency for segment in cost_segments}
    if len(currencies) != 1:
        return _CostAggregation(
            None,
            None,
            sorted(currencies)[0],
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because multiple currencies "
                "were observed."
            ],
        )
    currency = next(iter(currencies))
    if currency != "USD":
        return _CostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because currency is not USD."],
        )

    if (
        any(segment.cost_basis is None for segment in cost_segments)
        or any(segment.pricing_snapshot_id is None for segment in cost_segments)
        or any(segment.pricing_snapshot_digest is None for segment in cost_segments)
    ):
        return _CostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            [_INCOMPLETE_COST_PROVENANCE_LIMITATION],
        )
    cost_basis_ids = tuple(sorted({cast(str, segment.cost_basis) for segment in cost_segments}))
    pricing_snapshot_ids = tuple(
        sorted({cast(str, segment.pricing_snapshot_id) for segment in cost_segments})
    )
    pricing_snapshot_digests = tuple(
        sorted({cast(DigestHex, segment.pricing_snapshot_digest) for segment in cost_segments})
    )
    if len(cost_basis_ids) != 1:
        return _CostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because cost bases differ."],
        )
    if len(pricing_snapshot_ids) != 1:
        return _CostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because pricing snapshot IDs differ."],
        )
    if len(pricing_snapshot_digests) != 1:
        return _CostAggregation(
            None,
            None,
            currency,
            (),
            (),
            (),
            None,
            ["Declared estimated cost was not aggregated because pricing snapshot digests differ."],
        )
    cost_observation_count, count_limitations = _cost_observation_count(cost_segments)
    if aggregation_method == "sum_known_fields_v1":
        return _CostAggregation(
            sum(segment.estimated_cost_microusd or 0 for segment in cost_segments),
            None,
            currency,
            cost_basis_ids,
            pricing_snapshot_ids,
            pricing_snapshot_digests,
            cost_observation_count,
            count_limitations,
        )
    exact_picousd = tuple(
        segment.estimated_cost_picousd
        for segment in cost_segments
        if segment.estimated_cost_picousd is not None
    )
    if len(exact_picousd) != len(cost_segments):
        return _CostAggregation(
            None,
            None,
            currency,
            cost_basis_ids,
            pricing_snapshot_ids,
            pricing_snapshot_digests,
            None,
            [
                *count_limitations,
                "Declared estimated cost was not aggregated because exact pico-USD "
                "coverage was incomplete across usage segments.",
            ],
        )
    aggregate_cost_picousd = sum(exact_picousd)
    aggregate_cost = microusd_from_picousd(aggregate_cost_picousd)
    return _CostAggregation(
        aggregate_cost,
        aggregate_cost_picousd,
        currency,
        cost_basis_ids,
        pricing_snapshot_ids,
        pricing_snapshot_digests,
        cost_observation_count,
        count_limitations,
    )


def _cost_observation_count(
    cost_segments: tuple[UsageSegment, ...],
) -> tuple[int | None, list[str]]:
    run_ids = {segment.run_id for segment in cost_segments if segment.run_id is not None}
    if len(run_ids) == len({segment.run_id for segment in cost_segments}):
        return len(run_ids), []
    case_ids = {segment.case_id for segment in cost_segments if segment.case_id is not None}
    if len(case_ids) == len({segment.case_id for segment in cost_segments}):
        return len(case_ids), [_CASE_ID_COST_OBSERVATION_COUNT_LIMITATION]
    if len(cost_segments) == 1:
        return 1, [_SINGLE_SEGMENT_COST_OBSERVATION_COUNT_LIMITATION]
    return None, [_UNKNOWN_COST_OBSERVATION_COUNT_LIMITATION]


def _normalize_usage_field_path(path: str | UsageFieldPath) -> UsageFieldPath:
    if isinstance(path, str):
        return (path,)
    return path


def _usage_field_path_required_schema(path: UsageFieldPath) -> dict[str, Any]:
    return _usage_field_path_schema(path, root=True)


def _usage_field_path_schema(path: UsageFieldPath, *, root: bool) -> dict[str, Any]:
    if not path:
        return {}
    first, *remaining = path
    if first == _ARRAY_ITEM_STEP:
        return {
            "type": "array",
            "contains": _usage_field_path_schema(tuple(remaining), root=False),
        }
    if not remaining:
        schema: dict[str, Any] = {"required": [first]}
    else:
        schema = {
            "required": [first],
            "properties": {
                first: _usage_field_path_schema(tuple(remaining), root=False),
            },
        }
    if root:
        return schema
    return {
        "type": "object",
        **schema,
    }


def _usage_field_path_is_present(root: object, path: UsageFieldPath) -> bool:
    if root is None or not path:
        return False
    first, *remaining = path
    if first == _ARRAY_ITEM_STEP:
        if isinstance(root, Sequence) and not isinstance(root, str | bytes | bytearray):
            sequence = cast(Sequence[object], root)
            return any(_usage_field_path_is_present(item, tuple(remaining)) for item in sequence)
        return False
    value = _field_value(root, first)
    if not remaining:
        return value is not None or _field_was_set(root, first)
    if value is None and not _field_was_set(root, first):
        return False
    return _usage_field_path_is_present(value, tuple(remaining))


def _field_value(root: object, field_name: str) -> object:
    if isinstance(root, Mapping):
        return root.get(field_name)
    return getattr(root, field_name, None)


def _field_was_set(root: object, field_name: str) -> bool:
    if isinstance(root, Mapping):
        return field_name in root
    fields_set: AbstractSet[str] = getattr(root, "model_fields_set", frozenset())
    return field_name in fields_set


def _format_usage_field_path(path: UsageFieldPath) -> str:
    return ".".join(part for part in path if part != _ARRAY_ITEM_STEP)
