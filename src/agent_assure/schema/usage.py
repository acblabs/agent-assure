from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from typing import Annotated, Any, Literal, cast

from pydantic import ConfigDict, Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact, StrictModel
from agent_assure.schema.common import DigestHex, coerce_tuple

UsageAggregationMethod = Literal["sum_known_fields_v1"]
UsageSchemaVersion = Literal["0.3.1", "0.4.3"]
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
    "total_tokens",
    "total_tool_calls",
    "total_retries",
    "total_latency_ms",
    "estimated_cost_microusd",
    "currency",
    "cost_basis_ids",
    "pricing_snapshot_ids",
    "pricing_snapshot_digests",
    "cost_observation_count",
)
_USAGE_SEGMENT_V043_FIELDS = ("pricing_snapshot_digest",)
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
                        {"required": [field_name]}
                        for field_name in _USAGE_SEGMENT_V043_FIELDS
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
        }
    ]
}
_USAGE_LEDGER_JSON_SCHEMA_EXTRA: dict[str, Any] = {
    "$comment": (
        "Pydantic validation verifies that missingness equals the counts derived "
        "from segments. JSON Schema validates shape and non-negative counts."
    )
}
_USAGE_SUMMARY_V043_FIELDS = (
    "cost_basis_ids",
    "pricing_snapshot_ids",
    "pricing_snapshot_digests",
    "cost_observation_count",
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
                        {"required": [field_name]}
                        for field_name in _USAGE_SUMMARY_V043_FIELDS
                    ]
                }
            },
        },
        {
            "if": {
                "required": ["estimated_cost_microusd"],
                "properties": {"estimated_cost_microusd": {"type": "integer"}},
            },
            "then": {"properties": {"currency": {"const": "USD"}}},
        },
    ]
}
_USAGE_SUMMARY_DELTA_V043_FIELDS = (
    "total_tokens_delta_bps",
    "total_tool_calls_delta_bps",
    "total_retries_delta_bps",
    "total_latency_ms_delta_bps",
    "estimated_cost_microusd_delta_bps",
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
                "required": ["estimated_cost_microusd_delta"],
                "properties": {"estimated_cost_microusd_delta": {"type": "integer"}},
            },
            "then": {"properties": {"currency": {"const": "USD"}}},
        },
    ]
}
_LEGACY_SCHEMA_VERSION = "0.2.0"
_ARRAY_ITEM_STEP = "*"
_CURRENT_USAGE_SCHEMA_VERSION: UsageSchemaVersion = "0.4.3"
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
    schema_version: UsageSchemaVersion = _CURRENT_USAGE_SCHEMA_VERSION
    segments: tuple[UsageSegment, ...] = ()
    aggregation_method: UsageAggregationMethod = "sum_known_fields_v1"
    missingness: dict[str, Annotated[int, Field(ge=0)]] = Field(
        default_factory=dict,
        description=(
            "Counts of segment fields that were missing during aggregation; "
            "Pydantic validation requires this to match the contributing segments."
        ),
    )

    @field_validator("segments", mode="before")
    @classmethod
    def _coerce_segments(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_missingness(self) -> UsageLedger:
        expected = usage_segment_missingness(self.segments)
        if self.missingness != expected:
            raise ValueError("usage ledger missingness must match segments")
        return self


class UsageSummary(PersistedArtifact):
    model_config = ConfigDict(json_schema_extra=_USAGE_SUMMARY_JSON_SCHEMA_EXTRA)

    artifact_kind: Literal["usage-summary"] = "usage-summary"
    schema_version: UsageSchemaVersion = _CURRENT_USAGE_SCHEMA_VERSION
    total_tokens: int | None = Field(default=None, ge=0)
    total_tool_calls: int | None = Field(default=None, ge=0)
    total_retries: int | None = Field(default=None, ge=0)
    total_latency_ms: int | None = Field(default=None, ge=0)
    estimated_cost_microusd: int | None = Field(default=None, ge=0)
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
        if self.estimated_cost_microusd is not None and self.currency != "USD":
            raise ValueError("estimated_cost_microusd requires currency USD")
        if self.pricing_snapshot_digests and not self.pricing_snapshot_ids:
            raise ValueError("pricing_snapshot_digests require pricing_snapshot_ids")
        if self.cost_observation_count is not None and self.estimated_cost_microusd is None:
            raise ValueError("cost_observation_count requires estimated_cost_microusd")
        return self


def summarize_usage_segments(segments: tuple[UsageSegment, ...]) -> UsageSummary:
    missingness = usage_segment_missingness(segments)
    limitations = sorted({limitation for segment in segments for limitation in segment.limitations})
    if not segments:
        limitations.append("Measured usage was not observed.")
    if missingness:
        missing_fields = ", ".join(
            f"{field}={count}" for field, count in sorted(missingness.items())
        )
        limitations.append(
            "Usage summary sums known fields only; missing segment fields: "
            f"{missing_fields}."
        )
    cost = _sum_cost(segments)
    limitations.extend(cost.limitations)
    return UsageSummary(
        artifact_kind="usage-summary",
        total_tokens=_sum_known(segment.total_tokens for segment in segments),
        total_tool_calls=_sum_known(segment.tool_call_count for segment in segments),
        total_retries=_sum_known(segment.retry_count for segment in segments),
        total_latency_ms=_sum_known(segment.latency_ms for segment in segments),
        estimated_cost_microusd=cost.estimated_cost_microusd,
        currency=cost.currency,
        cost_basis_ids=cost.cost_basis_ids,
        pricing_snapshot_ids=cost.pricing_snapshot_ids,
        pricing_snapshot_digests=cost.pricing_snapshot_digests,
        cost_observation_count=cost.cost_observation_count,
        limitations=tuple(sorted(set(limitations))),
    )


def usage_summary_from_ledger(ledger: UsageLedger) -> UsageSummary:
    return summarize_usage_segments(ledger.segments)


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
    )
    mismatched_fields = [
        field
        for field in value_fields
        if getattr(summary, field) != getattr(expected, field)
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
                        "anyOf": [
                            _usage_field_path_required_schema(path) for path in normalized
                        ]
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
    currency: str = Field(default="USD", pattern=r"^[A-Z]{3}$")
    limitations: tuple[str, ...] = ()

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_versioned_fields(self) -> UsageSummaryDelta:
        if self.schema_version == "0.3.1" and any(
            field_name in self.model_fields_set
            for field_name in _USAGE_SUMMARY_DELTA_V043_FIELDS
        ):
            raise ValueError("basis-point usage deltas require schema_version 0.4.3")
        if self.estimated_cost_microusd_delta is not None and self.currency != "USD":
            raise ValueError("estimated_cost_microusd_delta requires currency USD")
        return self


class UsagePricingModel(StrictModel):
    provider: str = Field(min_length=1)
    model: str = Field(min_length=1)
    input_token_microusd: int = Field(ge=0)
    output_token_microusd: int = Field(ge=0)
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


class UsagePricingSnapshot(PersistedArtifact):
    artifact_kind: Literal["usage-pricing-snapshot"] = "usage-pricing-snapshot"
    schema_version: Literal["0.4.3"] = "0.4.3"
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


def _sum_cost(segments: tuple[UsageSegment, ...]) -> _CostAggregation:
    cost_segments = tuple(
        segment for segment in segments if segment.estimated_cost_microusd is not None
    )
    if not cost_segments:
        currency = segments[0].currency if segments else "USD"
        return _CostAggregation(None, currency, (), (), (), None, [])
    currencies = {segment.currency for segment in cost_segments}
    if len(currencies) != 1:
        return _CostAggregation(
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
            currency,
            (),
            (),
            (),
            None,
            [_INCOMPLETE_COST_PROVENANCE_LIMITATION],
        )
    cost_basis_ids = tuple(
        sorted({cast(str, segment.cost_basis) for segment in cost_segments})
    )
    pricing_snapshot_ids = tuple(
        sorted({cast(str, segment.pricing_snapshot_id) for segment in cost_segments})
    )
    pricing_snapshot_digests = tuple(
        sorted(
            {
                cast(DigestHex, segment.pricing_snapshot_digest)
                for segment in cost_segments
            }
        )
    )
    if len(cost_basis_ids) != 1:
        return _CostAggregation(
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
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "IDs differ."
            ],
        )
    if len(pricing_snapshot_digests) != 1:
        return _CostAggregation(
            None,
            currency,
            (),
            (),
            (),
            None,
            [
                "Declared estimated cost was not aggregated because pricing snapshot "
                "digests differ."
            ],
        )
    cost_observation_count, count_limitations = _cost_observation_count(cost_segments)
    return _CostAggregation(
        sum(segment.estimated_cost_microusd or 0 for segment in cost_segments),
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
            return any(
                _usage_field_path_is_present(item, tuple(remaining)) for item in sequence
            )
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
