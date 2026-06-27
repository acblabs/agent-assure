from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal
from typing import Literal

from pydantic import Field, model_validator
from pydantic.functional_validators import field_validator

from agent_assure.schema.base import PersistedArtifact
from agent_assure.schema.common import (
    DigestHex,
    GateState,
    ReasonCode,
    coerce_enum,
    coerce_tuple,
)
from agent_assure.schema.evaluation import Finding

DecimalString = str
SignedDecimalString = str
_SIX_PLACES = Decimal("0.000001")


def _decimal(value: str | int) -> Decimal:
    return Decimal(str(value))


def _decimal_string(value: Decimal) -> str:
    return f"{value.quantize(_SIX_PLACES, rounding=ROUND_HALF_UP):f}"


class LiveProtocolRecord(PersistedArtifact):
    artifact_kind: Literal["live-protocol-record"] = "live-protocol-record"
    protocol_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    suite_digest: DigestHex
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] = "concurrent_paired"
    hypothesis_family: Literal[
        "governance_control_non_inferiority",
        "provider_model_comparison",
        "regression_detection",
    ] = "governance_control_non_inferiority"
    primary_endpoint: Literal["expectation_pass_rate", "reason_code_rate"] = (
        "expectation_pass_rate"
    )
    analysis_method: Literal[
        "paired_cluster_t_interval",
        "paired_cluster_bootstrap_percentile",
        "fixed_reference_cluster_t_interval",
        "cluster_t_interval",
        "exploratory",
    ] = "paired_cluster_t_interval"
    baseline_group_id: str = "overall"
    candidate_group_id: str = "overall"
    fixed_reference_pass_rate: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_observations: int = Field(ge=1)
    planned_clusters: int = Field(ge=1)
    planned_observations_per_cluster: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    planned_effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    sample_size_rationale: str = Field(min_length=1)
    planned_repetitions: int = Field(ge=1)
    randomization_seed: int = Field(ge=0)
    randomization_blocking: Literal["balanced_case_blocks"] = "balanced_case_blocks"
    max_requests: int = Field(ge=1)
    max_total_cost_usd: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max_cost_per_observation_usd: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    max_generated_tokens: int | None = Field(default=None, ge=1)
    max_total_tokens: int | None = Field(default=None, ge=1)
    max_retries: int = Field(default=2, ge=0)
    retry_initial_backoff_seconds: DecimalString = Field(
        default="1.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    retry_max_backoff_seconds: DecimalString = Field(
        default="8.000000",
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    requests_per_minute: int | None = Field(default=None, ge=1)
    tokens_per_minute: int | None = Field(default=None, ge=1)
    max_rate_limit_events: int = Field(default=0, ge=0)
    exclusion_policy: str = Field(min_length=1)
    allowed_exclusion_reasons: tuple[str, ...] = ()
    max_exclusion_rate: DecimalString = Field(default="0.000000", pattern=r"^0\.[0-9]{6}$")
    provider_version_capture: tuple[str, ...] = ()
    stopping_rules: tuple[str, ...] = ()
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    analysis_digest: DigestHex
    approved_data_boundary: str = Field(min_length=1)
    safety_limits: tuple[str, ...] = ()

    @field_validator(
        "allowed_exclusion_reasons",
        "provider_version_capture",
        "stopping_rules",
        "safety_limits",
        mode="before",
    )
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @model_validator(mode="after")
    def _validate_protocol_plan(self) -> LiveProtocolRecord:
        if self.baseline_mode == "fixed_reference" and self.fixed_reference_pass_rate is None:
            raise ValueError("fixed_reference baseline_mode requires fixed_reference_pass_rate")
        if self.baseline_mode == "concurrent_paired" and self.fixed_reference_pass_rate is not None:
            raise ValueError(
                "concurrent_paired baseline_mode must not set fixed_reference_pass_rate"
            )
        if (
            self.baseline_mode == "fixed_reference"
            and self.analysis_method not in {"fixed_reference_cluster_t_interval", "exploratory"}
        ):
            raise ValueError(
                "fixed_reference baseline_mode requires fixed_reference_cluster_t_interval analysis"
            )
        if (
            self.baseline_mode == "concurrent_paired"
            and self.analysis_method
            not in {
                "paired_cluster_t_interval",
                "paired_cluster_bootstrap_percentile",
                "exploratory",
            }
        ):
            raise ValueError(
                "concurrent_paired baseline_mode requires a paired cluster analysis"
            )
        planned_mean = _decimal(self.planned_observations) / _decimal(self.planned_clusters)
        if self.planned_observations_per_cluster != _decimal_string(planned_mean):
            raise ValueError(
                "planned_observations_per_cluster must equal planned_observations / "
                "planned_clusters"
            )
        cluster_size = _decimal(self.planned_observations_per_cluster)
        rho = _decimal(self.assumed_intraclass_correlation)
        design_effect = Decimal("1") + (cluster_size - Decimal("1")) * rho
        if self.design_effect != _decimal_string(design_effect):
            raise ValueError("design_effect must equal 1 + (m - 1) * rho")
        effective_n = _decimal(self.planned_observations) / design_effect
        if self.planned_effective_n != _decimal_string(effective_n):
            raise ValueError("planned_effective_n must equal planned_observations / design_effect")
        return self


class LiveRate(PersistedArtifact):
    artifact_kind: Literal["live-rate"] = "live-rate"
    label: str = Field(min_length=1)
    numerator: int = Field(ge=0)
    denominator: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    largest_cluster_size: int = Field(ge=0)
    largest_cluster_design_effect: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    largest_cluster_effective_n: DecimalString = Field(
        pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    assumed_intraclass_correlation: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    cluster_mean_rate: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    confidence_level: Literal["0.950000"] = "0.950000"
    ci_lower: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")
    ci_upper: DecimalString = Field(pattern=r"^(0|1)\.[0-9]{6}$")


class LiveDistribution(PersistedArtifact):
    artifact_kind: Literal["live-distribution"] = "live-distribution"
    metric: Literal["latency_ms", "estimated_cost_usd"]
    count: int = Field(ge=0)
    min: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p50: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    p95: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    max: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    mean: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    total: DecimalString | None = Field(default=None, pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")


class LiveObservationResult(PersistedArtifact):
    artifact_kind: Literal["live-observation-result"] = "live-observation-result"
    observation_id: str = Field(min_length=1)
    run_id: str = Field(min_length=1)
    case_id: str = Field(min_length=1)
    repetition_index: int = Field(ge=0)
    provider: str | None = None
    model: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    cluster_id: str = Field(min_length=1)
    source_group_id: str | None = None
    observation_status: Literal["included", "excluded"] = "included"
    exclusion_reason: str | None = None
    attempt_count: int | None = Field(default=None, ge=1)
    retry_count: int | None = Field(default=None, ge=0)
    rate_limit_events: int | None = Field(default=None, ge=0)
    tool_schema_digest: DigestHex
    policy_bundle_digest: DigestHex
    state: GateState
    reason_codes: tuple[ReasonCode, ...] = ()
    findings: tuple[Finding, ...] = ()

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("reason_codes", mode="before")
    @classmethod
    def _coerce_reason_codes(cls, value: object) -> object:
        if isinstance(value, list | tuple):
            return tuple(coerce_enum(ReasonCode, item) for item in value)
        return value

    @field_validator("findings", mode="before")
    @classmethod
    def _coerce_findings(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveGroupSummary(PersistedArtifact):
    artifact_kind: Literal["live-group-summary"] = "live-group-summary"
    group_id: str = Field(min_length=1)
    provider: str | None = None
    model: str | None = None
    adapter_id: str | None = None
    pipeline_id: str = Field(min_length=1)
    observations: int = Field(ge=0)
    included_observations: int = Field(ge=0)
    excluded_observations: int = Field(ge=0)
    cluster_count: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    design_effect: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    exclusion_rate: LiveRate
    expectation_pass_rate: LiveRate
    outcome_rates: tuple[LiveRate, ...] = ()
    reason_code_rates: tuple[LiveRate, ...] = ()
    latency_ms: LiveDistribution
    estimated_cost_usd: LiveDistribution

    @field_validator("outcome_rates", "reason_code_rates", mode="before")
    @classmethod
    def _coerce_rates(cls, value: object) -> object:
        return coerce_tuple(value)


class LiveEvaluationReport(PersistedArtifact):
    artifact_kind: Literal["live-evaluation-report"] = "live-evaluation-report"
    runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    protocol_id: str | None = None
    protocol_digest: DigestHex | None = None
    baseline_mode: Literal["concurrent_paired", "fixed_reference"] | None = None
    analysis_method: str = Field(default="cluster_t_interval", min_length=1)
    cluster_by: Literal["case_id", "source_group_id"] = "case_id"
    planned_repetitions: int | None = Field(default=None, ge=1)
    planned_observations: int | None = Field(default=None, ge=1)
    planned_clusters: int | None = Field(default=None, ge=1)
    completion_status: Literal["complete", "incomplete"] = "complete"
    stop_reasons: tuple[str, ...] = ()
    budget_exceeded: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    observations: tuple[LiveObservationResult, ...]
    overall: LiveGroupSummary
    groups: tuple[LiveGroupSummary, ...]
    limitations: tuple[str, ...] = (
        "live evaluation is time-bound to the declared provider, model, adapter, "
        "configuration, and execution window",
        "aggregate rates do not certify safety, compliance, clinical validity, or provider "
        "superiority in general",
    )

    @field_validator("observations", "groups", "limitations", "stop_reasons", mode="before")
    @classmethod
    def _coerce_sequences(cls, value: object) -> object:
        return coerce_tuple(value)

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)


class LiveComparisonReport(PersistedArtifact):
    artifact_kind: Literal["live-comparison-report"] = "live-comparison-report"
    baseline_runset_id: str = Field(min_length=1)
    candidate_runset_id: str = Field(min_length=1)
    suite_id: str = Field(min_length=1)
    suite_version: str = Field(min_length=1)
    baseline_group_id: str = Field(min_length=1)
    candidate_group_id: str = Field(min_length=1)
    protocol_id: str = Field(min_length=1)
    protocol_digest: DigestHex
    baseline_mode: Literal["concurrent_paired", "fixed_reference"]
    analysis_method: str = Field(min_length=1)
    exploratory: bool = False
    state: GateState
    confidence_level: Literal["0.950000"] = "0.950000"
    non_inferiority_margin: DecimalString = Field(pattern=r"^0\.[0-9]{6}$")
    baseline_pass_rate: LiveRate
    candidate_pass_rate: LiveRate
    pass_rate_difference: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    difference_ci_lower: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    difference_ci_upper: SignedDecimalString = Field(pattern=r"^-?(0|1)\.[0-9]{6}$")
    compared_clusters: int = Field(ge=0)
    effective_n: DecimalString = Field(pattern=r"^(0|[1-9][0-9]*)\.[0-9]{6}$")
    fixed_reference_pass_rate: DecimalString | None = Field(
        default=None,
        pattern=r"^(0|1)\.[0-9]{6}$",
    )
    latency_p50_difference_ms: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    cost_total_difference_usd: DecimalString | None = Field(
        default=None,
        pattern=r"^-?(0|[1-9][0-9]*)\.[0-9]{6}$",
    )
    limitations: tuple[str, ...] = (
        "live comparison intervals are descriptive unless the protocol predeclares the "
        "comparison as confirmatory",
    )

    @field_validator("state", mode="before")
    @classmethod
    def _coerce_state(cls, value: object) -> GateState:
        return coerce_enum(GateState, value)

    @field_validator("limitations", mode="before")
    @classmethod
    def _coerce_limitations(cls, value: object) -> object:
        return coerce_tuple(value)
